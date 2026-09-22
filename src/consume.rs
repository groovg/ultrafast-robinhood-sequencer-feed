//! Read frames from one or more Nitro feeds and hand the decoded messages over.
//!
//! ```no_run
//! # async fn run() {
//! let mut feed = rhfeed::Feed::builder()
//!     .source(rhfeed::MAINNET_FEED)
//!     .source(rhfeed::LOCAL_RELAY)
//!     .verify(rhfeed::MAINNET_VERIFIER.clone())
//!     .spawn();
//! while let Some(msg) = feed.recv().await {
//!     for tx in &msg.txs { /* ... */ }
//! }
//! # }
//! ```
//!
//! **Several sources, first copy wins.** Each source is a connection with its own task:
//! it reads, parses, verifies and decodes on its own, so a slow consumer or a slow
//! source never delays the others. Every sequence number is delivered once, from
//! whichever source had it first; later copies are counted per source with how far
//! behind the first they arrived (`Stats::sources`), which is how you find out which
//! endpoint is actually fastest from where you run.
//!
//! The rest follows the baseline's `consume.py` — its docstring is the reference:
//!
//! - **Backlog.** A new connection is replayed the relay's backlog first. It is
//!   counted, not decoded and not delivered; a message is live once the sequencer's own
//!   timestamp on it is seconds old.
//! - **Reconnects** re-request the *last* seen sequence number, not the next: one past
//!   the tail is a failed lookup, and Nitro answers that with the entire backlog.
//! - **Reorgs.** Nitro has no reorg message; the replacement arrives under a sequence
//!   number already seen, with a different block hash. That is delivered with
//!   `reorg` set and rewinds the watermark. With several sources, a lagging one can
//!   still be sending the pre-reorg blocks; those match a remembered hash and are
//!   dropped as duplicates.
//! - **Verification** happens before the watermark moves, so an injected frame cannot
//!   make a reconnect skip real messages. A copy of an already-delivered message
//!   (same sequence number, same block hash) is dropped without verifying: the block
//!   hash is signed, and the first copy was checked.
//! - **Silence** is narrated through `log`: which source cannot connect, which one is
//!   connected but quiet.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{info, warn};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinSet;
use yawc::{HttpRequestBuilder, MaybeTlsStream, OpCode, Options, WebSocket};

use crate::codec::{Entry, FeedMessage, Frame, l2_msg, parse_entry_with};
use crate::verify::Verifier;

/// Where a local Nitro relay listens by default (see README.md for running one).
pub const LOCAL_RELAY: &str = "ws://127.0.0.1:9642";

/// Robinhood's public endpoints. Rate-limited per client, not per connection.
pub const MAINNET_FEED: &str = "wss://feed.mainnet.chain.robinhood.com";
pub const TESTNET_FEED: &str = "wss://feed.testnet.chain.robinhood.com";

const FEED_CLIENT_VERSION: &str = "Arbitrum-Feed-Client-Version";
const REQUESTED_SEQ: &str = "Arbitrum-Requested-Sequence-Number";

/// A message stamped this recently by the sequencer is live.
const LIVE_THRESHOLD: f64 = 5.0;
/// Fallback for a skewed clock: the backlog is finite, so stop waiting for it.
const MAX_BACKLOG: Duration = Duration::from_secs(120);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub frames: u64,
    pub backlog_messages: u64,
    pub live_messages: u64,
    pub duplicate_messages: u64,
    pub unverified_messages: u64,
    pub reconnects: u64,
    pub reorgs: u64,
    pub sources: Vec<SourceStats>,
}

/// Per-source counters: who delivered first, and how far behind the rest were.
#[derive(Debug, Default, Clone)]
pub struct SourceStats {
    pub url: String,
    pub connected: bool,
    pub frames: u64,
    pub reconnects: u64,
    /// Messages this source delivered before any other.
    pub first: u64,
    /// Live copies of messages another source had already delivered.
    pub late: u64,
    pub lag_total: Duration,
    pub lag_max: Duration,
}

impl SourceStats {
    /// Mean delay behind the first copy, over this source's late copies.
    pub fn lag_mean(&self) -> Option<Duration> {
        (self.late > 0).then(|| self.lag_total / self.late as u32)
    }
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

// --------------------------------------------------------------------------- //
// the shared state every source reports into
// --------------------------------------------------------------------------- //

struct Seen {
    hash: Option<String>,
    at: Instant,
}

enum Verdict {
    New,
    Reorg,
    Duplicate,
}

struct State {
    highest_seq: i64,
    seen: HashMap<i64, Seen>,
    stats: Stats,
    warned_unverified: bool,
}

impl State {
    fn classify(&self, seq: i64, hash: Option<&str>) -> Verdict {
        match self.seen.get(&seq) {
            // Same number, different block: a reorg if it rewinds, or the replacement
            // for a block an earlier reorg already rewound past.
            Some(prev) if hash.is_some() && prev.hash.is_some() && prev.hash.as_deref() != hash => {
                if seq > self.highest_seq {
                    Verdict::New
                } else {
                    Verdict::Reorg
                }
            }
            // Same block, or unknown on either side: better a missed reorg than a
            // rewind we cannot justify.
            Some(_) => Verdict::Duplicate,
            None if seq > self.highest_seq => Verdict::New,
            None => Verdict::Duplicate,
        }
    }

    fn late_copy(&mut self, source: usize, seq: i64, live: bool, now: Instant) {
        self.stats.duplicate_messages += 1;
        // Only live copies say anything about latency: a replayed backlog is late by
        // however long the connection was down.
        if let (true, Some(first)) = (live, self.seen.get(&seq)) {
            let lag = now.saturating_duration_since(first.at);
            let s = &mut self.stats.sources[source];
            s.late += 1;
            s.lag_total += lag;
            s.lag_max = s.lag_max.max(lag);
        }
    }

    fn remember(&mut self, seq: i64, hash: Option<&str>, now: Instant, window: i64) {
        self.seen.insert(
            seq,
            Seen {
                hash: hash.map(str::to_owned),
                at: now,
            },
        );
        if self.seen.len() as i64 > window * 2 {
            let cutoff = self.highest_seq - window;
            self.seen.retain(|&s, _| s > cutoff);
        }
    }
}

struct Shared {
    verify: Option<Verifier>,
    reorg_window: i64,
    state: Mutex<State>,
}

impl Shared {
    fn new(urls: &[String], verify: Option<Verifier>, reorg_window: i64) -> Self {
        let sources = urls
            .iter()
            .map(|url| SourceStats {
                url: url.clone(),
                ..SourceStats::default()
            })
            .collect();
        Self {
            verify,
            reorg_window,
            state: Mutex::new(State {
                highest_seq: -1,
                seen: HashMap::new(),
                stats: Stats {
                    sources,
                    ..Stats::default()
                },
                warned_unverified: false,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while holding this lock leaves counters, nothing that can be torn.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Every message in `frame` this source is first to deliver, verified, with `live`
    /// set and transactions decoded when live. The lock is never held across
    /// verification or decoding, so sources do that work in parallel.
    fn ingest(
        &self,
        source: usize,
        frame: &Frame,
        live: bool,
        received_at: f64,
        now: Instant,
    ) -> Vec<FeedMessage> {
        {
            let mut st = self.lock();
            st.stats.frames += 1;
            st.stats.sources[source].frames += 1;
        }
        let mut out = Vec::new();
        for entry in frame.entries() {
            let seq = entry.sequence_number.unwrap_or(-1);
            let hash = entry.block_hash.as_deref();
            {
                let mut st = self.lock();
                if let Verdict::Duplicate = st.classify(seq, hash) {
                    st.late_copy(source, seq, live, now);
                    continue;
                }
            }
            // Decoded once, for the signature and the transactions both; a backlog
            // message that is not being verified needs neither.
            let l2 = if live || self.verify.is_some() {
                l2_msg(entry)
            } else {
                Ok(None)
            };
            if let Some(v) = &self.verify {
                let good = l2
                    .as_ref()
                    .is_ok_and(|l2| v.accepts_with(entry, l2.as_deref()));
                if !good {
                    self.reject(entry, seq);
                    continue;
                }
            }
            let l2 = if live { l2.ok().flatten() } else { None };
            let mut msg = parse_entry_with(entry, l2.as_ref());

            let mut st = self.lock();
            match st.classify(seq, hash) {
                // Another source got here while this one was verifying and decoding.
                Verdict::Duplicate => {
                    st.late_copy(source, seq, live, now);
                    continue;
                }
                Verdict::Reorg => {
                    st.stats.reorgs += 1;
                    msg.reorg = true;
                    warn!(
                        "feed reorg at seq {seq}: block hash changed from {} to {}. \
                         Anything you derived from the old block is now stale",
                        st.seen
                            .get(&seq)
                            .and_then(|s| s.hash.as_deref())
                            .unwrap_or("None"),
                        hash.unwrap_or("None"),
                    );
                }
                Verdict::New => {}
            }
            st.highest_seq = seq;
            st.remember(seq, hash, now, self.reorg_window);
            st.stats.sources[source].first += 1;
            if live {
                st.stats.live_messages += 1;
            } else {
                st.stats.backlog_messages += 1;
            }
            msg.live = live;
            msg.source = source;
            msg.received_at = received_at;
            out.push(msg);
        }
        out
    }

    /// Drop an unverified message without advancing the watermark — otherwise one
    /// injected frame could make the next reconnect skip the real messages behind it.
    fn reject(&self, entry: &Entry, seq: i64) {
        {
            let mut st = self.lock();
            st.stats.unverified_messages += 1;
            // Once, then counted: a wrong chain id rejects *every* message.
            if std::mem::replace(&mut st.warned_unverified, true) {
                return;
            }
        }
        let Some(verify) = &self.verify else { return };
        let mut expected: Vec<String> = verify
            .signers
            .iter()
            .map(|s| format!("0x{}", hex::encode(s)))
            .collect();
        expected.sort();
        warn!(
            "dropping unverified message at seq {seq}: {}, expected one of {}. \
             Further ones are counted in stats.unverified_messages but not logged. \
             Check the verifier's chain id ({}) and signer set before suspecting the feed",
            verify
                .signer_of(entry)
                .map_or("no usable signature".into(), |s| format!(
                    "signed by 0x{}",
                    hex::encode(s)
                )),
            expected.join(", "),
            verify.chain_id,
        );
    }
}

// --------------------------------------------------------------------------- //
// the public handle
// --------------------------------------------------------------------------- //

/// A running feed: one task per source, merged into one stream of live messages.
/// Dropping it stops every source.
pub struct Feed {
    rx: mpsc::Receiver<FeedMessage>,
    shared: Arc<Shared>,
    _tasks: JoinSet<()>,
}

impl Feed {
    pub fn builder() -> FeedBuilder {
        FeedBuilder {
            sources: Vec::new(),
            verify: None,
            reconnect_delay: Duration::from_millis(500),
            stall_warning: Duration::from_secs(30),
            reorg_window: 1024,
            capacity: 1024,
        }
    }

    /// The next live message, from whichever source had it first. `None` only if every
    /// source task has stopped, which they do not do on their own.
    pub async fn recv(&mut self) -> Option<FeedMessage> {
        self.rx.recv().await
    }

    pub fn stats(&self) -> Stats {
        self.shared.lock().stats.clone()
    }

    /// Highest sequence number delivered or skipped. On this chain, the L2 block number.
    pub fn highest_seq(&self) -> i64 {
        self.shared.lock().highest_seq
    }
}

pub struct FeedBuilder {
    sources: Vec<String>,
    verify: Option<Verifier>,
    reconnect_delay: Duration,
    stall_warning: Duration,
    reorg_window: i64,
    capacity: usize,
}

impl FeedBuilder {
    /// Add a feed URL. Several sources race; each message comes from the fastest.
    pub fn source(mut self, url: impl Into<String>) -> Self {
        self.sources.push(url.into());
        self
    }

    /// Drop messages without a good signature from an allowed signer. Costs one ECDSA
    /// recovery per new message; late copies are not re-checked.
    pub fn verify(mut self, verifier: Verifier) -> Self {
        self.verify = Some(verifier);
        self
    }

    /// First retry delay after a failure, doubling up to 30 s.
    pub fn reconnect_delay(mut self, delay: Duration) -> Self {
        self.reconnect_delay = delay;
        self
    }

    /// Warn after this long connected with no frames. Zero disables the check.
    pub fn stall_warning(mut self, after: Duration) -> Self {
        self.stall_warning = after;
        self
    }

    /// How many recent block hashes to keep for reorg and duplicate detection.
    pub fn reorg_window(mut self, blocks: i64) -> Self {
        self.reorg_window = blocks;
        self
    }

    /// Messages buffered for a consumer that is behind. When full, sources stop
    /// reading until it catches up, and say so.
    pub fn capacity(mut self, messages: usize) -> Self {
        self.capacity = messages;
        self
    }

    /// Start every source on the current tokio runtime. Panics with no sources.
    pub fn spawn(self) -> Feed {
        assert!(!self.sources.is_empty(), "a feed needs at least one source");
        let shared = Arc::new(Shared::new(&self.sources, self.verify, self.reorg_window));
        let (tx, rx) = mpsc::channel(self.capacity.max(1));
        let mut tasks = JoinSet::new();
        for (index, url) in self.sources.into_iter().enumerate() {
            tasks.spawn(
                Source {
                    index,
                    url,
                    shared: shared.clone(),
                    tx: tx.clone(),
                    reconnect_delay: self.reconnect_delay,
                    stall_warning: self.stall_warning,
                }
                .run(),
            );
        }
        Feed {
            rx,
            shared,
            _tasks: tasks,
        }
    }
}

// --------------------------------------------------------------------------- //
// one source
// --------------------------------------------------------------------------- //

struct Source {
    index: usize,
    url: String,
    shared: Arc<Shared>,
    tx: mpsc::Sender<FeedMessage>,
    reconnect_delay: Duration,
    stall_warning: Duration,
}

/// Why a connection ended.
enum End {
    /// The `Feed` was dropped; stop for good.
    Stopped,
    Failed(String),
}

impl Source {
    async fn run(self) {
        let mut delay = self.reconnect_delay;
        let mut failures = 0u32;
        loop {
            info!("connecting to {}", self.url);
            let err = match self.connect().await {
                Err(err) => err,
                Ok(ws) => {
                    if failures > 0 {
                        warn!("{} is reachable again", self.url);
                    }
                    failures = 0;
                    delay = self.reconnect_delay;
                    self.set_connected(true);
                    let end = self.read(ws).await;
                    self.set_connected(false);
                    match end {
                        End::Stopped => return,
                        End::Failed(err) => err,
                    }
                }
            };
            failures += 1;
            {
                let mut st = self.shared.lock();
                st.stats.reconnects += 1;
                st.stats.sources[self.index].reconnects += 1;
            }
            if err.contains("429") {
                // The public feed admits two connections per client IP and answers the
                // rest with 429. Retrying fast only keeps hitting the limit.
                delay = MAX_RECONNECT_DELAY;
                warn!(
                    "{} refused the connection as rate-limited (HTTP 429): the public feed allows \
                     two connections per IP. Retrying every {}s",
                    self.url,
                    delay.as_secs()
                );
                tokio::time::sleep(delay).await;
                continue;
            }
            // Never fail silently: the retry loop would otherwise hide an unreachable
            // feed forever behind an empty terminal.
            warn!(
                "cannot read {} ({err}) — retrying in {:.1}s{}",
                self.url,
                delay.as_secs_f64(),
                if failures == 1 {
                    "; is the URL right and reachable?"
                } else {
                    ""
                },
            );
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(MAX_RECONNECT_DELAY);
        }
    }

    fn set_connected(&self, connected: bool) {
        self.shared.lock().stats.sources[self.index].connected = connected;
    }

    async fn connect(&self) -> Result<Socket, String> {
        let url = self.url.parse().map_err(|e| format!("bad URL: {e}"))?;
        let mut request = HttpRequestBuilder::new().header(FEED_CLIENT_VERSION, "2");
        let highest = self.shared.lock().highest_seq;
        if highest >= 0 {
            request = request.header(REQUESTED_SEQ, highest.to_string());
        }
        // Since 2026-09-17 the public feed refuses a handshake that does not offer
        // permessage-deflate. A local relay serves uncompressed and ignores the offer.
        let options = Options::default()
            .with_limits(1 << 24, 1 << 25)
            .with_low_latency_compression()
            .with_no_delay();
        WebSocket::connect(url)
            .with_options(options)
            .with_request(request)
            .await
            .map_err(|e| e.to_string())
    }

    fn poll_interval(&self) -> Duration {
        // Well inside the threshold, or a stall starting just after a tick goes
        // unreported for twice as long as advertised.
        if self.stall_warning.is_zero() {
            Duration::from_secs(3600)
        } else {
            (self.stall_warning / 4).max(Duration::from_millis(100))
        }
    }

    async fn read(&self, mut ws: Socket) -> End {
        let interval = self.poll_interval();
        let started = Instant::now();
        let mut live = false;
        let mut last_frame = started;
        let mut last_narrated = started;
        let mut stall_warned = false;
        let mut warned_full = false;
        loop {
            let frame = match tokio::time::timeout(interval, ws.next_frame()).await {
                Err(_) => {
                    let idle = last_frame.elapsed();
                    if !self.stall_warning.is_zero() && idle >= self.stall_warning && !stall_warned
                    {
                        stall_warned = true; // once per stall, not once per poll
                        warn!(
                            "no frames from {} for {:.0}s — connected, but nothing is \
                             arriving. For a relay, usually its own upstream is down",
                            self.url,
                            idle.as_secs_f64(),
                        );
                    }
                    continue;
                }
                Ok(Err(err)) => return End::Failed(err.to_string()),
                Ok(Ok(frame)) => frame,
            };
            match frame.opcode() {
                OpCode::Text | OpCode::Binary => {}
                OpCode::Close => return End::Failed("closed by the server".into()),
                _ => continue,
            }
            let received_at = unix_now();
            let now = Instant::now();
            last_frame = now;
            stall_warned = false;

            let parsed: Frame = match serde_json::from_slice(frame.payload()) {
                Ok(parsed) => parsed,
                Err(err) => return End::Failed(format!("unreadable frame: {err}")),
            };
            if !live {
                let stamp = parsed
                    .entries()
                    .last()
                    .and_then(|e| e.header())
                    .and_then(|h| h.timestamp)
                    .unwrap_or(0);
                live = (stamp != 0 && received_at - stamp as f64 <= LIVE_THRESHOLD)
                    || started.elapsed() > MAX_BACKLOG;
                if live {
                    info!("{} is live", self.url);
                } else if last_narrated.elapsed() >= interval {
                    // Frames flowing, none current yet: a relay replaying its backlog.
                    last_narrated = now;
                    info!("{}: draining backlog, none current yet", self.url);
                }
            }

            for msg in self
                .shared
                .ingest(self.index, &parsed, live, received_at, now)
            {
                if !msg.live {
                    continue;
                }
                match self.tx.try_send(msg) {
                    Ok(()) => {}
                    Err(TrySendError::Closed(_)) => return End::Stopped,
                    Err(TrySendError::Full(msg)) => {
                        if !std::mem::replace(&mut warned_full, true) {
                            warn!(
                                "consumer is falling behind: {} messages buffered, \
                                 {} waits until it catches up",
                                self.tx.max_capacity(),
                                self.url
                            );
                        }
                        if self.tx.send(msg).await.is_err() {
                            return End::Stopped;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::MAINNET_VERIFIER;

    fn entry_json(seq: i64, block_hash: &str) -> String {
        let now = unix_now() as u64;
        format!(
            r#"{{"sequenceNumber":{seq},"blockHash":"{block_hash}","message":{{"delayedMessagesRead":500,
            "message":{{"header":{{"kind":3,"sender":"0xa4b000000000000000000073657175656e636572",
            "blockNumber":25000000,"timestamp":{now}}},"l2Msg":"BAAAAAAAAAAA"}}}}}}"#
        )
    }

    fn shared(sources: usize, verify: Option<Verifier>) -> Shared {
        let urls: Vec<String> = (0..sources).map(|i| format!("ws://source{i}")).collect();
        Shared::new(&urls, verify, 1024)
    }

    fn feed_at(
        s: &Shared,
        source: usize,
        live: bool,
        now: Instant,
        entries: &[String],
    ) -> Vec<(i64, bool)> {
        let json = format!(r#"{{"version":1,"messages":[{}]}}"#, entries.join(","));
        let frame: Frame = serde_json::from_str(&json).unwrap();
        s.ingest(source, &frame, live, 0.0, now)
            .iter()
            .map(|m| (m.seq, m.reorg))
            .collect()
    }

    fn feed(s: &Shared, source: usize, entries: &[String]) -> Vec<(i64, bool)> {
        feed_at(s, source, true, Instant::now(), entries)
    }

    fn hash_of(n: u8) -> String {
        format!("0x{}", format!("{n:02x}").repeat(32))
    }

    #[test]
    fn a_duplicate_is_dropped_silently() {
        let s = shared(1, None);
        assert_eq!(feed(&s, 0, &[entry_json(1, &hash_of(1))]), [(1, false)]);
        assert!(feed(&s, 0, &[entry_json(1, &hash_of(1))]).is_empty());
        let st = s.lock();
        assert_eq!((st.stats.duplicate_messages, st.stats.reorgs), (1, 0));
    }

    #[test]
    fn a_changed_block_hash_is_a_reorg_and_rewinds_the_watermark() {
        let s = shared(1, None);
        feed(&s, 0, &[1, 2, 3].map(|n| entry_json(n, &hash_of(n as u8))));
        let out = feed(
            &s,
            0,
            &[entry_json(2, &hash_of(0xAA)), entry_json(3, &hash_of(0xBB))],
        );
        assert_eq!(out, [(2, true), (3, false)]);
        let st = s.lock();
        assert_eq!((st.stats.reorgs, st.highest_seq), (1, 3));
    }

    #[test]
    fn the_window_is_bounded_and_an_unknown_hash_is_not_a_reorg() {
        let s = Shared::new(&["ws://a".into()], None, 2);
        let seqs: Vec<String> = (1..=10).map(|n| entry_json(n, &hash_of(n as u8))).collect();
        feed(&s, 0, &seqs);
        assert!(s.lock().seen.len() <= 5);
        assert!(feed(&s, 0, &[entry_json(1, &hash_of(0xEE))]).is_empty());
        assert_eq!(s.lock().stats.reorgs, 0);
    }

    #[test]
    fn a_verifying_feed_drops_a_forgery_without_advancing() {
        let s = shared(1, Some(MAINNET_VERIFIER.clone()));
        assert!(feed(&s, 0, &[entry_json(99_999_999, &hash_of(1))]).is_empty());
        let st = s.lock();
        assert_eq!((st.stats.unverified_messages, st.highest_seq), (1, -1));
    }

    #[test]
    fn a_backlog_message_is_counted_but_not_decoded() {
        let s = shared(1, None);
        let json = format!(r#"{{"messages":[{}]}}"#, entry_json(1, &hash_of(1)));
        let frame: Frame = serde_json::from_str(&json).unwrap();
        let out = s.ingest(0, &frame, false, 0.0, Instant::now());
        assert!(!out[0].live && out[0].txs.is_empty());
        assert_eq!(s.lock().stats.backlog_messages, 1);
    }

    #[test]
    fn the_first_source_wins_and_the_second_is_measured() {
        let s = shared(2, None);
        let t0 = Instant::now();
        assert_eq!(
            feed_at(&s, 1, true, t0, &[entry_json(7, &hash_of(7))]),
            [(7, false)]
        );
        let t1 = t0 + Duration::from_millis(12);
        assert!(feed_at(&s, 0, true, t1, &[entry_json(7, &hash_of(7))]).is_empty());
        let st = s.lock();
        let (a, b) = (&st.stats.sources[0], &st.stats.sources[1]);
        assert_eq!((a.first, a.late, b.first, b.late), (0, 1, 1, 0));
        assert_eq!(a.lag_mean(), Some(Duration::from_millis(12)));
    }

    #[test]
    fn backlog_copies_do_not_count_as_lag() {
        let s = shared(2, None);
        let t0 = Instant::now();
        feed_at(&s, 0, true, t0, &[entry_json(7, &hash_of(7))]);
        feed_at(
            &s,
            1,
            false,
            t0 + Duration::from_secs(60),
            &[entry_json(7, &hash_of(7))],
        );
        assert_eq!(s.lock().stats.sources[1].late, 0);
    }

    #[test]
    fn a_lagging_source_cannot_resurrect_pre_reorg_blocks() {
        let s = shared(2, None);
        // Source 0 sees 1..=3, then a reorg replacing 2 and 3.
        feed(&s, 0, &[1, 2, 3].map(|n| entry_json(n, &hash_of(n as u8))));
        assert_eq!(feed(&s, 0, &[entry_json(2, &hash_of(0xA2))]), [(2, true)]);
        // Source 1 is behind and still sending the old block 3.
        assert!(feed(&s, 1, &[entry_json(3, &hash_of(3))]).is_empty());
        // The real replacement for 3 still goes through, and is not a second reorg.
        assert_eq!(feed(&s, 0, &[entry_json(3, &hash_of(0xA3))]), [(3, false)]);
        assert_eq!(s.lock().stats.reorgs, 1);
    }
}
