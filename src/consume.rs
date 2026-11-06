//! Read one or more Nitro feeds and hand over decoded messages.
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
//! Each source gets its own connection and its own task, which reads, parses, verifies
//! and decodes. A slow source or a slow consumer doesn't hold up the others. Every
//! sequence number is delivered once, from the source that had it first. Later copies
//! are counted per source along with how late they were (`Stats::sources`), so you can
//! see which endpoint is fastest from where you are.
//!
//! The rest works like the Python version's `consume.py`:
//!
//! - Backlog: a new connection first gets replayed the relay's backlog. We count those
//!   messages but don't decode or deliver them. A message counts as live once its
//!   sequencer timestamp is only a few seconds old.
//! - Reconnects: we ask for the last sequence number we saw, not the one after it. If
//!   you ask for a number past the end, Nitro can't find it and sends the whole backlog.
//! - Reorgs: Nitro has no reorg message. The new block just arrives again under a
//!   sequence number we've already seen, with a different block hash. We deliver it with
//!   `reorg` set and move the watermark back. With several sources, a slower one may
//!   still send the old blocks afterwards. Those match a hash we remember and get dropped.
//! - Verification happens before the watermark moves, so a forged frame can't make a
//!   reconnect skip real messages. A copy of a message we already delivered (same
//!   sequence number, same block hash) is dropped without checking it again. The block
//!   hash is part of the signed data and the first copy was already checked.
//! - Problems are logged: which source can't connect, which one is connected but silent.
//!   A connection that sends nothing at all for 15 s, not even a ping, is replaced.

use std::borrow::Cow;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use log::{error, info, warn};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::crypto::{CryptoProvider, ring};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use yawc::{HttpRequestBuilder, MaybeTlsStream, OpCode, Options, WebSocket};

use crate::codec::{
    Entry, FeedMessage, Frame, SenderPool, entry_texts, frame_from_slice, l2_msg, parse_entry_on,
    parse_entry_with,
};
use crate::verify::{MAINNET_CHAIN_ID, Verifier};

/// Where a local Nitro relay listens by default (see README.md for running one).
pub const LOCAL_RELAY: &str = "ws://127.0.0.1:9642";

/// Robinhood's public endpoints. At most two connections per IP.
pub const MAINNET_FEED: &str = "wss://feed.mainnet.chain.robinhood.com";
pub const TESTNET_FEED: &str = "wss://feed.testnet.chain.robinhood.com";
/// eth_chainId on Robinhood Chain testnet.
pub const TESTNET_CHAIN_ID: u64 = 46630;

const FEED_CLIENT_VERSION: &str = "Arbitrum-Feed-Client-Version";
const REQUESTED_SEQ: &str = "Arbitrum-Requested-Sequence-Number";
const CHAIN_ID: &str = "Arbitrum-Chain-Id";

/// A message stamped this recently by the sequencer is live.
const LIVE_THRESHOLD: f64 = 5.0;
/// Fallback for a skewed clock: the backlog is finite, so stop waiting for it.
const MAX_BACKLOG: Duration = Duration::from_secs(120);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);
/// A source that was first on fewer than 1 in `SLOW_SHARE` of its last `SLOW_WINDOW`
/// live messages gets a new connection. Measured in Virginia: most connections split
/// the wins about evenly, but now and then one lands on a path that's ~9 ms slower and
/// stays there.
const SLOW_WINDOW: u32 = 500;
const SLOW_SHARE: u32 = 10;
/// Warn after this long connected with no frames.
const STALL_WARNING: Duration = Duration::from_secs(30);
/// Reconnect after this long without any frame at all. Nitro servers ping every 5 s by
/// default and the public feed every 2 s, so this means the connection is dead.
const SILENCE_LIMIT: Duration = Duration::from_secs(15);
/// How often a waiting source checks for a stall or silence, so either is caught soon
/// after it crosses its threshold.
const POLL_INTERVAL: Duration = Duration::from_millis(2500);
/// With `busy_poll`, how long a source waits for a frame before running the last one
/// through the path again to keep it in cache.
const WARM_INTERVAL: Duration = Duration::from_millis(1);
/// How many recent block hashes to keep for reorg and duplicate detection (~2 minutes).
const REORG_WINDOW: i64 = 1024;

type Socket = WebSocket<Stamped<MaybeTlsStream<Stamped<TcpStream>>>>;

/// When a message's frame finished each stage of `Feed`. The difference between two
/// neighbouring fields is what that stage took. Add your own `Instant::now()` after
/// `recv()` to see the hand-off. `rhfeed --timing` prints percentiles of all of them.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// First socket read with bytes of this frame. If an earlier read already brought
    /// the whole frame, the same as `last_read`.
    pub first_read: Instant,
    /// Last socket read the frame needed. Before this, the frame was still arriving.
    pub last_read: Instant,
    /// TLS has decrypted the frame's last bytes.
    pub decrypted: Instant,
    /// The WebSocket layer returned the whole frame, inflated.
    pub inflated: Instant,
    pub parsed: Instant,
    /// Signature checked (equal to `parsed` without a verifier). With
    /// `FeedBuilder::senders`, also every sender recovered, and `decoded` is the same.
    pub verified: Instant,
    pub decoded: Instant,
    /// Just before the message went into the channel.
    pub sent: Instant,
}

/// When reads on a stream returned bytes: the first since the last `take` and the most
/// recent. Written from inside yawc by `Stamped`, read by the source once per frame.
#[derive(Default)]
struct ReadTimes(Mutex<(Option<Instant>, Option<Instant>)>);

impl ReadTimes {
    fn record(&self) {
        let now = Instant::now();
        let mut t = self.0.lock().unwrap_or_else(|e| e.into_inner());
        t.0.get_or_insert(now);
        t.1 = Some(now);
    }

    fn take(&self) -> (Instant, Instant) {
        let mut t = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let last = t.1.unwrap_or_else(Instant::now);
        (t.0.take().unwrap_or(last), last)
    }
}

/// A stream that notes when its reads return bytes. One sits under TLS and one above
/// it, which separates waiting for the network from decrypting.
struct Stamped<S> {
    inner: S,
    times: Arc<ReadTimes>,
    /// Collects the first bytes read, up to the end of the HTTP response head, because
    /// yawc doesn't hand the handshake response back. None once that's done.
    head: Option<Arc<Mutex<Vec<u8>>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Stamped<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.times.record();
            if let Some(head) = &self.head {
                let mut head = head.lock().unwrap_or_else(|e| e.into_inner());
                head.extend_from_slice(&buf.filled()[before..]);
                let done = head_end(&head).is_some() || head.len() > 64 << 10;
                drop(head);
                if done {
                    self.head = None;
                }
            }
        }
        res
    }
}

fn head_end(head: &[u8]) -> Option<usize> {
    head.windows(4).position(|w| w == b"\r\n\r\n")
}

/// The chain a feed announces in its handshake response. Nitro relays and Conduit's feeds
/// do, Robinhood's public feeds don't. Decimal or 0x hex, the first value that parses.
fn announced_chain_id(head: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(&head[..head_end(head)?]).ok()?;
    text.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case(CHAIN_ID) {
            return None;
        }
        let value = value.trim();
        match value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => value.parse().ok(),
        }
    })
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Stamped<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The same TLS setup yawc uses on its own: webpki roots, HTTP/1.1 by ALPN, the process
/// default crypto provider if one is installed and ring otherwise. We build it
/// ourselves so the socket underneath can be `Stamped`.
static TLS: LazyLock<TlsConnector> = LazyLock::new(|| {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let provider = CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(ring::default_provider()));
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the crypto provider supports TLS 1.2 and 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(config))
});

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub backlog_messages: u64,
    pub live_messages: u64,
    pub duplicate_messages: u64,
    pub unverified_messages: u64,
    pub reorgs: u64,
    pub sources: Vec<SourceStats>,
}

/// Per-source counters: who delivered first, and how far behind the rest were.
#[derive(Debug, Default, Clone)]
pub struct SourceStats {
    /// The source URL as it is safe to log (see `redact`).
    pub url: String,
    pub connected: bool,
    /// Why this source stopped for good, if it did. Today only for a feed that
    /// announces a different chain than the verifier checks.
    pub error: Option<String>,
    pub reconnects: u64,
    /// Messages this source delivered before any other.
    pub first: u64,
    /// Live copies of messages another source had already delivered.
    pub late: u64,
    pub lag_total: Duration,
    pub lag_max: Duration,
    /// Times this source's connection was replaced for being slower than the others.
    pub replaced: u64,
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

/// A feed URL as it is safe to log: scheme, host and port. Third-party feeds take the
/// access key in the path, the query or `user:pass@`, so anything after the host is cut.
/// A URL with nothing after the host, like Robinhood's feeds, comes back unchanged.
fn redact(url: &str) -> Cow<'_, str> {
    let start = url.find("://").map_or(0, |i| i + 3);
    let rest = &url[start..];
    let (authority, tail) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host.len() == authority.len() && tail.trim_matches('/').is_empty() {
        return Cow::Borrowed(url);
    }
    Cow::Owned(format!("{}{host}/…", &url[..start]))
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
    /// Per source: (first, late) live messages since its window last reset.
    recent: Vec<(u32, u32)>,
    /// Per source: it should drop its connection and open a new one.
    replace: Vec<bool>,
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
            // Same block, or a hash missing on one side. If we can't tell, we treat it
            // as a duplicate rather than rewinding on a guess.
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
            self.recent[source].1 += 1;
            self.check_slow(source);
        }
    }

    /// Mark `source` for a new connection if it has been losing nearly every race.
    fn check_slow(&mut self, source: usize) {
        let (first, late) = self.recent[source];
        if first + late < SLOW_WINDOW {
            return;
        }
        self.recent[source] = (0, 0);
        let others = self.stats.sources.iter().filter(|s| s.connected).count() > 1;
        if others && first * SLOW_SHARE < first + late {
            self.replace[source] = true;
        }
    }

    fn remember(&mut self, seq: i64, hash: Option<&str>, now: Instant) {
        self.seen.insert(
            seq,
            Seen {
                hash: hash.map(str::to_owned),
                at: now,
            },
        );
        if self.seen.len() as i64 > REORG_WINDOW * 2 {
            let cutoff = self.highest_seq - REORG_WINDOW;
            self.seen.retain(|&s, _| s > cutoff);
        }
    }
}

struct Shared {
    verify: Option<Verifier>,
    /// With `FeedBuilder::senders`.
    senders: Option<Mutex<SenderPool>>,
    state: Mutex<State>,
    /// When `warm` last ran.
    warmed: Mutex<Instant>,
}

impl Shared {
    fn new(urls: &[String], verify: Option<Verifier>, senders: Option<SenderPool>) -> Self {
        let sources = urls
            .iter()
            .map(|url| SourceStats {
                url: redact(url).into_owned(),
                ..SourceStats::default()
            })
            .collect();
        Self {
            verify,
            senders: senders.map(Mutex::new),
            state: Mutex::new(State {
                highest_seq: -1,
                seen: HashMap::new(),
                stats: Stats {
                    sources,
                    ..Stats::default()
                },
                warned_unverified: false,
                recent: vec![(0, 0); urls.len()],
                replace: vec![false; urls.len()],
            }),
            warmed: Mutex::new(Instant::now()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // The lock only guards counters and a map, so a poisoned lock is still usable.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Every message in `frame` this source is first to deliver, verified, with `live`
    /// set and transactions decoded when live. The lock is never held across
    /// verification or decoding, so sources do that work in parallel.
    ///
    /// Until the connection is `live`, each entry is judged on its own timestamp. A relay
    /// replays its backlog in frames of hundreds of messages, so the frame's last entry
    /// says nothing about the ones before it. Only an entry that passes verification can
    /// end the backlog: a forged one with a fresh timestamp must not promote the older,
    /// real entries behind it.
    fn ingest(
        &self,
        source: usize,
        frame: &Frame,
        is_live: &mut bool,
        chain_id: Option<u64>,
        received_at: f64,
        mut timing: Timing,
    ) -> Vec<FeedMessage> {
        let now = timing.inflated;
        let mut out = Vec::new();
        for entry in frame.entries() {
            let seq = entry.sequence_number.unwrap_or(-1);
            let hash = entry.block_hash.as_deref();
            let live_now = *is_live || {
                let stamp = entry.header().and_then(|h| h.timestamp).unwrap_or(0);
                stamp != 0 && received_at - stamp as f64 <= LIVE_THRESHOLD
            };
            {
                let mut st = self.lock();
                if let Verdict::Duplicate = st.classify(seq, hash) {
                    st.late_copy(source, seq, live_now, now);
                    continue;
                }
            }
            let live = live_now;
            // Decode l2Msg once and use it for both the signature and the transactions.
            // A backlog message that isn't being verified needs neither.
            let l2 = if live || self.verify.is_some() {
                l2_msg(entry)
            } else {
                Ok(None)
            };
            let accepted = || match &self.verify {
                None => true,
                Some(v) => l2
                    .as_ref()
                    .is_ok_and(|l2| v.accepts_with(entry, l2.as_deref())),
            };
            let decodable = if live {
                l2.as_ref().ok().and_then(Option::as_ref)
            } else {
                None
            };
            let mut msg = match (&self.senders, live) {
                // Decode first, so the pool recovers the senders while this thread
                // checks the signature.
                (Some(pool), true) => {
                    let msg = parse_entry_on(entry, decodable, chain_id);
                    let mut pool = pool.lock().unwrap_or_else(|e| e.into_inner());
                    let good = pool.recover_while(&msg.txs, accepted);
                    timing.verified = Instant::now();
                    timing.decoded = timing.verified;
                    if !good {
                        self.reject(entry, seq);
                        continue;
                    }
                    msg
                }
                _ => {
                    if !accepted() {
                        self.reject(entry, seq);
                        continue;
                    }
                    timing.verified = Instant::now();
                    let msg = parse_entry_on(entry, decodable, chain_id);
                    timing.decoded = Instant::now();
                    msg
                }
            };

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
            st.remember(seq, hash, now);
            st.stats.sources[source].first += 1;
            if live {
                st.recent[source].0 += 1;
                st.check_slow(source);
                st.stats.live_messages += 1;
            } else {
                st.stats.backlog_messages += 1;
            }
            drop(st);
            *is_live |= live;
            msg.live = live;
            msg.source = source;
            msg.received_at = received_at;
            msg.timing = Some(timing);
            out.push(msg);
        }
        out
    }

    /// Whether it's time for another warm-up. Once per interval between all sources,
    /// since a frame that arrives during one waits for it.
    fn may_warm(&self) -> bool {
        let mut warmed = self.warmed.lock().unwrap_or_else(|e| e.into_inner());
        if warmed.elapsed() < WARM_INTERVAL {
            return false;
        }
        *warmed = Instant::now();
        true
    }

    /// Run a frame through parsing, the signature check and decoding, and throw the
    /// result away. Keeps that code and its tables in cache for the next real frame.
    fn warm(&self, payload: &[u8]) {
        let Ok(frame) = frame_from_slice(payload) else {
            return;
        };
        for entry in frame.entries() {
            let l2 = l2_msg(entry).ok().flatten();
            if let Some(v) = &self.verify {
                std::hint::black_box(v.accepts_with(entry, l2.as_deref()));
            }
            std::hint::black_box(parse_entry_with(entry, l2.as_ref()));
        }
    }

    /// Drop an unverified message without moving the watermark. Otherwise one
    /// injected frame could make the next reconnect skip the real messages behind it.
    fn reject(&self, entry: &Entry, seq: i64) {
        {
            let mut st = self.lock();
            st.stats.unverified_messages += 1;
            // Log only the first one. With a wrong chain id every message fails.
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
            crate::verify::recover_signer(entry, verify.chain_id).map_or(
                "no usable signature".into(),
                |s| format!("signed by 0x{}", hex::encode(s))
            ),
            expected.join(", "),
            verify.chain_id,
        );
    }
}

/// A recent frame for `busy_poll` to rerun while it waits, as JSON and deflated.
#[derive(Default)]
struct Warm {
    json: Vec<u8>,
    deflated: Vec<u8>,
    inflater: Option<Decompress>,
    out: Vec<u8>,
}

impl Warm {
    /// Keep `payload` for the next warm-ups. Call it after delivering the message.
    fn keep(&mut self, payload: &[u8]) {
        self.json.clear();
        self.json.extend_from_slice(payload);
        if self.deflated.is_empty() {
            // Only once: deflating takes ~0.1 ms, and any frame warms the inflater.
            let mut deflate = Compress::new(Compression::default(), false);
            self.deflated.reserve(payload.len() + 1024);
            if deflate
                .compress_vec(payload, &mut self.deflated, FlushCompress::Sync)
                .is_err()
            {
                self.deflated.clear();
            }
            self.out = vec![0; payload.len() + 1024];
        }
    }

    /// Inflate, parse, check and decode the kept frame, and throw the results away.
    fn run(&mut self, shared: &Shared) {
        if self.json.is_empty() || !shared.may_warm() {
            return;
        }
        let inflater = self.inflater.get_or_insert_with(|| Decompress::new(false));
        inflater.reset(false);
        let _ = inflater.decompress(&self.deflated, &mut self.out, FlushDecompress::Sync);
        shared.warm(&self.json);
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
    busy: bool,
}

impl Feed {
    pub fn builder() -> FeedBuilder {
        FeedBuilder {
            sources: Vec::new(),
            verify: None,
            reconnect_delay: Duration::from_millis(500),
            capacity: 1024,
            busy_poll: false,
            senders: 0,
            chain_id: None,
        }
    }

    /// The next live message, from whichever source had it first. `None` only if every
    /// source task has stopped, which they do not do on their own.
    ///
    /// Call this from a task you `tokio::spawn`, not straight from `#[tokio::main]`'s
    /// body. The body runs on its own thread, so every message has to wake that thread
    /// (~14 us on our machine). A spawned task is woken on the worker that just received
    /// the message (~4 us).
    ///
    /// With `busy_poll` this spins instead of waiting to be woken, yielding to other
    /// tasks between tries, so the thread it runs on stays busy too.
    pub async fn recv(&mut self) -> Option<FeedMessage> {
        if !self.busy {
            return self.rx.recv().await;
        }
        loop {
            match self.rx.try_recv() {
                Ok(msg) => return Some(msg),
                Err(mpsc::error::TryRecvError::Empty) => tokio::task::yield_now().await,
                Err(mpsc::error::TryRecvError::Disconnected) => return None,
            }
        }
    }

    pub fn stats(&self) -> Stats {
        self.shared.lock().stats.clone()
    }
}

pub struct FeedBuilder {
    sources: Vec<String>,
    verify: Option<Verifier>,
    reconnect_delay: Duration,
    capacity: usize,
    busy_poll: bool,
    senders: usize,
    chain_id: Option<u64>,
}

impl FeedBuilder {
    /// Add a feed URL. Several sources race; each message comes from the fastest.
    pub fn source(mut self, url: impl Into<String>) -> Self {
        self.sources.push(url.into());
        self
    }

    /// Drop messages without a good signature from an allowed signer. Costs one ECDSA
    /// check per new message (see `Verifier`); late copies are not re-checked.
    pub fn verify(mut self, verifier: Verifier) -> Self {
        self.verify = Some(verifier);
        self
    }

    /// First retry delay after a failure, doubling up to 30 s.
    pub fn reconnect_delay(mut self, delay: Duration) -> Self {
        self.reconnect_delay = delay;
        self
    }

    /// Messages buffered for a consumer that is behind. When full, sources stop
    /// reading until it catches up, and say so.
    pub fn capacity(mut self, messages: usize) -> Self {
        self.capacity = messages;
        self
    }

    /// Run the sources on a thread of their own that never sleeps: it keeps polling the
    /// sockets instead of waiting for the OS to wake it. A frame is then picked up as
    /// soon as it arrives, and the caches stay warm between frames. It costs one core
    /// at 100%.
    ///
    /// `recv()` then spins as well, so the task that calls it keeps its thread busy.
    pub fn busy_poll(mut self, on: bool) -> Self {
        self.busy_poll = on;
        self
    }

    /// The chain id to build SubmitRetryable and EthDeposit transactions with, whose
    /// hashes cover it. Without it, each source uses what its feed announces, Robinhood's
    /// chain id for its own feeds, or the verifier's.
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Recover every transaction's sender before handing a message over, on a
    /// `SenderPool` of `threads` spinning threads, while the source checks the feed
    /// signature. `tx.sender()` is then free. Each thread keeps a core at 100%.
    pub fn senders(mut self, threads: usize) -> Self {
        self.senders = threads;
        self
    }

    /// Start every source on the current tokio runtime, or on a thread of its own with
    /// `busy_poll`. Panics with no sources.
    pub fn spawn(self) -> Feed {
        assert!(!self.sources.is_empty(), "a feed needs at least one source");
        let senders = (self.senders > 0).then(|| SenderPool::new(self.senders));
        let shared = Arc::new(Shared::new(&self.sources, self.verify, senders));
        let (tx, rx) = mpsc::channel(self.capacity.max(1));
        let sources: Vec<Source> = (self.sources.into_iter().enumerate())
            .map(|(index, url)| Source {
                index,
                name: redact(&url).into_owned(),
                url,
                shared: shared.clone(),
                tx: tx.clone(),
                reconnect_delay: self.reconnect_delay,
                chain_id: self.chain_id,
                warm: self.busy_poll,
            })
            .collect();
        let mut tasks = JoinSet::new();
        if self.busy_poll {
            std::thread::Builder::new()
                .name("rhfeed".into())
                .spawn(move || busy_poll(sources, tx))
                .expect("cannot start the rhfeed thread");
        } else {
            for source in sources {
                tasks.spawn(source.run());
            }
        }
        Feed {
            rx,
            shared,
            _tasks: tasks,
            busy: self.busy_poll,
        }
    }
}

/// Run `sources` on this thread until the `Feed` is dropped, without ever parking it.
fn busy_poll(sources: Vec<Source>, tx: mpsc::Sender<FeedMessage>) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("cannot build a tokio runtime");
    runtime.block_on(async move {
        let mut tasks: JoinSet<()> = sources.into_iter().map(Source::run).collect();
        // While a task has yielded, the scheduler checks the sockets with a zero timeout
        // instead of parking the thread until one is ready. Stops when the `Feed` is
        // dropped, or when every source has stopped for good, so `recv()` sees the end.
        while !tx.is_closed() && !tasks.is_empty() {
            while tasks.try_join_next().is_some() {}
            tokio::task::yield_now().await;
        }
    });
}

// --------------------------------------------------------------------------- //
// one source
// --------------------------------------------------------------------------- //

struct Source {
    index: usize,
    url: String,
    /// `url` as it is safe to log, see `redact`.
    name: String,
    shared: Arc<Shared>,
    tx: mpsc::Sender<FeedMessage>,
    reconnect_delay: Duration,
    /// Set with `FeedBuilder::chain_id`, otherwise found on each connection.
    chain_id: Option<u64>,
    /// Rerun the last frame whenever idle for `WARM_INTERVAL` (with `busy_poll`).
    warm: bool,
}

/// Why a connection ended.
enum End {
    /// The `Feed` was dropped; stop for good.
    Stopped,
    /// This connection keeps losing to the others; open a new one right away.
    Slow,
    Failed(String),
}

impl Source {
    async fn run(self) {
        let mut delay = self.reconnect_delay;
        let mut failures = 0u32;
        loop {
            info!("connecting to {}", self.name);
            let err = match self.connect().await {
                Err(err) => err,
                Ok((ws, times, chain_id)) => {
                    if let Err(wrong) = self.check_chain(chain_id) {
                        // Every message would fail verification, and reconnecting can't
                        // change that. Nitro's own client treats it as fatal too. Dropping
                        // the socket aborts the connection without a close handshake.
                        error!("{wrong}");
                        self.shared.lock().stats.sources[self.index].error = Some(wrong);
                        return;
                    }
                    if failures > 0 {
                        warn!("{} is reachable again", self.name);
                    }
                    failures = 0;
                    delay = self.reconnect_delay;
                    self.set_connected(true);
                    let end = self.read(ws, times, self.chain_for(chain_id)).await;
                    self.set_connected(false);
                    match end {
                        End::Stopped => return,
                        End::Slow => {
                            info!(
                                "{}: first on under 1 in {SLOW_SHARE} of the last \
                                 {SLOW_WINDOW} messages, trying a new connection",
                                self.name
                            );
                            self.shared.lock().stats.sources[self.index].replaced += 1;
                            continue;
                        }
                        End::Failed(err) => err,
                    }
                }
            };
            // An error can quote the URL, key and all.
            let err = err.replace(self.url.as_str(), &self.name);
            failures += 1;
            self.shared.lock().stats.sources[self.index].reconnects += 1;
            if err.contains("429") {
                // The public feed allows two connections per IP and answers the rest with
                // 429. Retrying quickly would just hit the limit again.
                delay = MAX_RECONNECT_DELAY;
                warn!(
                    "{} refused the connection as rate-limited (HTTP 429): the public feed allows \
                     two connections per IP. Retrying every {}s",
                    self.name,
                    delay.as_secs()
                );
                tokio::time::sleep(delay).await;
                continue;
            }
            // Always log the failure. Otherwise a feed that can't be reached just looks
            // like a quiet feed.
            warn!(
                "cannot read {} ({err}), retrying in {:.1}s{}",
                self.name,
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

    /// The chain id deposits and retryables are built with: the one set on the builder,
    /// else what the feed announced, else Robinhood's for its own feeds, else the
    /// verifier's. None leaves those messages without transactions.
    fn chain_for(&self, announced: Option<u64>) -> Option<u64> {
        self.chain_id.or(announced).or(match self.url.as_str() {
            MAINNET_FEED => Some(MAINNET_CHAIN_ID),
            TESTNET_FEED => Some(TESTNET_CHAIN_ID),
            _ => self.shared.verify.as_ref().map(|v| v.chain_id),
        })
    }

    /// Refuse a feed that announces a chain other than the verifier's. A feed that
    /// announces none is read as before.
    fn check_chain(&self, announced: Option<u64>) -> Result<(), String> {
        match (&self.shared.verify, announced) {
            (Some(v), Some(chain)) if chain != v.chain_id => Err(format!(
                "{} serves chain {chain}, and the verifier checks chain {}, so it would drop \n                 every message. Not retrying",
                self.name, v.chain_id
            )),
            _ => Ok(()),
        }
    }

    /// A WebSocket over TLS over TCP, with the reads on both sides of TLS `Stamped`.
    /// Returns the stamps of the (TCP, TLS) reads and the chain id the feed announced.
    async fn connect(&self) -> Result<(Socket, [Arc<ReadTimes>; 2], Option<u64>), String> {
        let url: url::Url = self.url.parse().map_err(|e| format!("bad URL: {e}"))?;
        let host = url.host_str().ok_or("URL without a host")?.to_owned();
        let port = url.port_or_known_default().ok_or("URL without a port")?;
        let mut request = HttpRequestBuilder::new().header(FEED_CLIENT_VERSION, "2");
        let highest = self.shared.lock().highest_seq;
        if highest >= 0 {
            request = request.header(REQUESTED_SEQ, highest.to_string());
        }
        let err = |e: std::io::Error| e.to_string();
        // host_str keeps an IPv6 address in brackets, which connect wants and TLS doesn't.
        let tcp = TcpStream::connect(format!("{host}:{port}"))
            .await
            .map_err(err)?;
        tcp.set_nodelay(true).map_err(err)?;
        let times = [Arc::default(), Arc::default()];
        let tcp = Stamped {
            inner: tcp,
            times: Arc::clone(&times[0]),
            head: None,
        };
        let stream = match url.scheme() {
            "ws" => MaybeTlsStream::Plain(tcp),
            "wss" => {
                let name = host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned();
                let name = ServerName::try_from(name).map_err(|e| e.to_string())?;
                MaybeTlsStream::Tls(TLS.connect(name, tcp).await.map_err(err)?)
            }
            other => return Err(format!("not a WebSocket URL scheme: {other}")),
        };
        let head = Arc::default();
        let stream = Stamped {
            inner: stream,
            times: Arc::clone(&times[1]),
            head: Some(Arc::clone(&head)),
        };
        // Since 2026-09-17 the public feed refuses a handshake that does not offer
        // permessage-deflate. A local relay serves uncompressed and ignores the offer.
        let options = Options::default()
            .with_limits(1 << 24, 1 << 25)
            .with_low_latency_compression();
        let ws = WebSocket::handshake_with_request(url, stream, options, request)
            .await
            .map_err(|e| e.to_string())?;
        let chain_id = announced_chain_id(&head.lock().unwrap_or_else(|e| e.into_inner()));
        Ok((ws, times, chain_id))
    }

    async fn read(
        &self,
        mut ws: Socket,
        [tcp, tls]: [Arc<ReadTimes>; 2],
        chain_id: Option<u64>,
    ) -> End {
        let started = Instant::now();
        let mut live = false;
        let mut backlog = 0;
        let mut last_frame = started;
        let mut last_heard = started;
        let mut last_narrated = started;
        let mut stall_warned = false;
        let mut warned_full = false;
        let mut warm = Warm::default();
        let poll = if self.warm {
            WARM_INTERVAL
        } else {
            POLL_INTERVAL
        };
        loop {
            let frame = match tokio::time::timeout(poll, ws.next_frame()).await {
                Err(_) => {
                    warm.run(&self.shared);
                    if last_heard.elapsed() >= SILENCE_LIMIT {
                        return End::Failed(format!(
                            "nothing received for {}s, not even a ping",
                            SILENCE_LIMIT.as_secs()
                        ));
                    }
                    let idle = last_frame.elapsed();
                    if idle >= STALL_WARNING && !stall_warned {
                        stall_warned = true; // once per stall, not once per poll
                        warn!(
                            "no frames from {} for {:.0}s. Connected, but nothing is \
                             arriving. For a relay, usually its own upstream is down",
                            self.name,
                            idle.as_secs_f64(),
                        );
                    }
                    continue;
                }
                Ok(Err(err)) => return End::Failed(err.to_string()),
                Ok(Ok(frame)) => frame,
            };
            let now = Instant::now();
            let (first_read, last_read) = tcp.take();
            let (_, decrypted) = tls.take();
            last_heard = now;
            match frame.opcode() {
                OpCode::Text | OpCode::Binary => {}
                OpCode::Close => return End::Failed("closed by the server".into()),
                _ => continue,
            }
            let received_at = unix_now();
            last_frame = now;
            stall_warned = false;

            let texts: Vec<String>;
            let parsed = match frame_from_slice(frame.payload()) {
                Ok(parsed) => parsed,
                Err(err) => {
                    let Some(t) = entry_texts(frame.payload()) else {
                        return End::Failed(format!("unreadable frame: {err}"));
                    };
                    // JSON, but an entry has a field of the wrong type. Nitro can't read it
                    // either. Reconnecting would only get the same frame again, so keep
                    // the entries that parse.
                    texts = t;
                    let entries: Vec<Entry> = texts
                        .iter()
                        .filter_map(|t| sonic_rs::from_str(t).ok())
                        .collect();
                    warn!(
                        "{}: dropped {} of {} messages in a frame ({err})",
                        self.name,
                        texts.len() - entries.len(),
                        texts.len()
                    );
                    Frame {
                        messages: Some(entries),
                    }
                }
            };
            let at = Instant::now();
            let timing = Timing {
                first_read,
                last_read,
                decrypted,
                inflated: now,
                parsed: at,
                verified: at,
                decoded: at,
                sent: at,
            };
            let was_live = live;
            // Fallback for a skewed clock: the backlog is finite, so stop waiting for it.
            live |= started.elapsed() > MAX_BACKLOG;
            let msgs = self.shared.ingest(
                self.index,
                &parsed,
                &mut live,
                chain_id,
                received_at,
                timing,
            );
            if !was_live {
                backlog += msgs.iter().filter(|m| !m.live).count();
                if let Some(first) = msgs.iter().find(|m| m.live) {
                    info!(
                        "{} is live at seq {}, {backlog} backlog messages skipped",
                        self.name, first.seq
                    );
                } else if !live && last_narrated.elapsed() >= POLL_INTERVAL {
                    // Frames are arriving but none are recent yet, so we're still in the backlog.
                    last_narrated = now;
                    info!("{}: draining backlog, none current yet", self.name);
                }
            }
            let slow = std::mem::take(&mut self.shared.lock().replace[self.index]);
            for mut msg in msgs {
                if !msg.live {
                    continue;
                }
                if let Some(t) = &mut msg.timing {
                    t.sent = Instant::now();
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
                                self.name
                            );
                        }
                        if self.tx.send(msg).await.is_err() {
                            return End::Stopped;
                        }
                    }
                }
            }
            if self.warm && live {
                warm.keep(frame.payload());
            }
            if slow {
                return End::Slow;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::MAINNET_VERIFIER;

    fn entry_json(seq: i64, block_hash: &str) -> String {
        entry_at(seq, block_hash, unix_now() as u64)
    }

    fn entry_at(seq: i64, block_hash: &str, now: u64) -> String {
        format!(
            r#"{{"sequenceNumber":{seq},"blockHash":"{block_hash}","message":{{"delayedMessagesRead":500,
            "message":{{"header":{{"kind":3,"sender":"0xa4b000000000000000000073657175656e636572",
            "blockNumber":25000000,"timestamp":{now}}},"l2Msg":"BMmAgICAgICAgIA="}}}}}}"#
        )
    }

    fn stamps(t: Instant) -> Timing {
        Timing {
            first_read: t,
            last_read: t,
            decrypted: t,
            inflated: t,
            parsed: t,
            verified: t,
            decoded: t,
            sent: t,
        }
    }

    fn shared(sources: usize, verify: Option<Verifier>) -> Shared {
        let urls: Vec<String> = (0..sources).map(|i| format!("ws://source{i}")).collect();
        Shared::new(&urls, verify, None)
    }

    fn feed_at(
        s: &Shared,
        source: usize,
        mut live: bool,
        now: Instant,
        entries: &[String],
    ) -> Vec<(i64, bool)> {
        let json = format!(r#"{{"version":1,"messages":[{}]}}"#, entries.join(","));
        let frame = frame_from_slice(json.as_bytes()).unwrap();
        s.ingest(source, &frame, &mut live, None, unix_now(), stamps(now))
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
    fn the_announced_chain_id_is_read_from_the_response_head() {
        let head = |headers: &str| {
            // A frame's binary bytes can follow the head in the same read.
            let head = format!("HTTP/1.1 101 Switching Protocols\r\n{headers}\r\n");
            [head.as_bytes(), b"\x81\x05\xff\xfe"].concat()
        };
        let cases = [
            (
                "Upgrade: websocket\r\nArbitrum-Chain-Id: 4663\r\n",
                Some(4663),
            ),
            ("arbitrum-chain-id:0x1237\r\n", Some(4663)),
            (
                "Arbitrum-Chain-Id: nope\r\nArbitrum-Chain-Id: 46630\r\n",
                Some(46630),
            ),
            ("Upgrade: websocket\r\n", None),
        ];
        for (headers, want) in cases {
            assert_eq!(announced_chain_id(&head(headers)), want, "{headers:?}");
        }
        // Not the whole head yet.
        assert_eq!(
            announced_chain_id(b"HTTP/1.1 101\r\nArbitrum-Chain-Id: 1\r\n"),
            None
        );
    }

    #[test]
    fn a_key_in_the_url_stays_out_of_the_log() {
        for (url, want) in [
            (MAINNET_FEED, MAINNET_FEED),
            ("ws://127.0.0.1:9642", "ws://127.0.0.1:9642"),
            ("ws://127.0.0.1:9642/", "ws://127.0.0.1:9642/"),
            ("wss://feed.example.com/SECRET", "wss://feed.example.com/…"),
            (
                "wss://feed.example.com?key=SECRET",
                "wss://feed.example.com/…",
            ),
            (
                "wss://user:SECRET@feed.example.com:443",
                "wss://feed.example.com:443/…",
            ),
            ("wss://u:SECRET@h/p?k=SECRET#f", "wss://h/…"),
        ] {
            assert_eq!(redact(url), want, "{url}");
        }
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
        let s = shared(1, None);
        let last = REORG_WINDOW * 2 + 10;
        let seqs: Vec<String> = (1..=last)
            .map(|n| entry_json(n, &hash_of(n as u8)))
            .collect();
        feed(&s, 0, &seqs);
        assert!(s.lock().seen.len() as i64 <= REORG_WINDOW * 2);
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

    fn ingest(s: &Shared, live: &mut bool, entries: &[String]) -> Vec<FeedMessage> {
        let json = format!(r#"{{"messages":[{}]}}"#, entries.join(","));
        let frame = frame_from_slice(json.as_bytes()).unwrap();
        s.ingest(0, &frame, live, None, unix_now(), stamps(Instant::now()))
    }

    #[test]
    fn a_backlog_message_is_counted_but_not_decoded() {
        let s = shared(1, None);
        let mut live = false;
        let out = ingest(&s, &mut live, &[entry_at(1, &hash_of(1), 1_000)]);
        assert!(!out[0].live && out[0].txs.is_empty() && !live);
        assert_eq!(s.lock().stats.backlog_messages, 1);
    }

    #[test]
    fn each_entry_of_a_frame_is_judged_on_its_own_timestamp() {
        let s = shared(1, None);
        let mut live = false;
        let now = unix_now() as u64;
        let entries = [
            entry_at(1, &hash_of(1), now - 30),
            entry_at(2, &hash_of(2), now - 1),
            entry_at(3, &hash_of(3), now - 40), // live already, whatever its stamp
        ];
        let out = ingest(&s, &mut live, &entries);
        let got: Vec<_> = out.iter().map(|m| (m.seq, m.live, m.txs.len())).collect();
        assert_eq!(got, [(1, false, 0), (2, true, 1), (3, true, 1)]);
        assert!(live);
    }

    #[test]
    fn a_forged_fresh_entry_does_not_end_the_backlog() {
        let s = shared(1, Some(MAINNET_VERIFIER.clone()));
        let mut live = false;
        // A real, verified mainnet message from 2026, behind a forgery stamped now.
        let real = include_str!("../tests/fixtures/verified_message.json").trim();
        let out = ingest(&s, &mut live, &[entry_json(1, &hash_of(1)), real.into()]);
        assert!(!live);
        assert_eq!(out.len(), 1);
        assert!(!out[0].live);
        assert_eq!(s.lock().stats.unverified_messages, 1);
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
    fn a_source_that_keeps_losing_is_marked_for_a_new_connection() {
        let s = shared(2, None);
        s.lock()
            .stats
            .sources
            .iter_mut()
            .for_each(|x| x.connected = true);
        let t0 = Instant::now();
        for seq in 1..=SLOW_WINDOW as i64 {
            let e = [entry_json(seq, &hash_of((seq % 250) as u8))];
            feed_at(&s, 0, true, t0, &e);
            feed_at(&s, 1, true, t0 + Duration::from_millis(9), &e);
        }
        assert_eq!(s.lock().replace, [false, true]);
    }

    #[test]
    fn an_even_split_replaces_nothing() {
        let s = shared(2, None);
        s.lock()
            .stats
            .sources
            .iter_mut()
            .for_each(|x| x.connected = true);
        let t0 = Instant::now();
        for seq in 1..=SLOW_WINDOW as i64 {
            let e = [entry_json(seq, &hash_of((seq % 250) as u8))];
            let (a, b) = if seq % 2 == 0 { (0, 1) } else { (1, 0) };
            feed_at(&s, a, true, t0, &e);
            feed_at(&s, b, true, t0 + Duration::from_millis(3), &e);
        }
        assert_eq!(s.lock().replace, [false, false]);
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
            &[entry_at(7, &hash_of(7), 1_000)],
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
