//! Read frames from a Nitro relay and hand them to the decoder.
//!
//! ```no_run
//! # async fn run() {
//! let mut feed = rhfeed::FeedConsumer::new(rhfeed::DEFAULT_RELAY);
//! loop {
//!     let msg = feed.next_live().await;
//!     for tx in &msg.txs { /* ... */ }
//! }
//! # }
//! ```
//!
//! Port of upstream `src/rhfeed/consume.py`. Its docstring is the reference for the behaviour
//! kept here: skipping the backlog without decoding it, re-requesting the *last* seen
//! sequence number on reconnect, telling a reorg from a duplicate by block hash,
//! verifying before the watermark moves, and saying which kind of silence it is.
//!
//! One structural difference: Rust has no async generators, so this is pull-based.
//! The stall monitor Python runs as a side task is a read timeout here instead.

use std::collections::{HashMap, VecDeque};
use std::fmt::Display;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{info, warn};
use tokio::net::TcpStream;
use yawc::{HttpRequestBuilder, MaybeTlsStream, OpCode, Options, WebSocket};

use crate::codec::{Entry, FeedMessage, Frame, parse_frame};
use crate::verify::Verifier;

/// A relay you run. The default because it is what you should be pointing at.
pub const DEFAULT_RELAY: &str = "ws://127.0.0.1:9642";

/// Robinhood's public endpoints. Rate-limited per client — point a relay at these.
pub const MAINNET_FEED: &str = "wss://feed.mainnet.chain.robinhood.com";
pub const TESTNET_FEED: &str = "wss://feed.testnet.chain.robinhood.com";

const FEED_CLIENT_VERSION: &str = "Arbitrum-Feed-Client-Version";
const REQUESTED_SEQ: &str = "Arbitrum-Requested-Sequence-Number";

/// A message stamped this recently by the sequencer is live.
const LIVE_THRESHOLD: f64 = 5.0;
/// Fallback for a skewed clock: the backlog is finite, so stop waiting for it.
const MAX_BACKLOG: Duration = Duration::from_secs(120);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub frames: u64,
    pub backlog_messages: u64,
    pub live_messages: u64,
    pub duplicate_messages: u64,
    pub unverified_messages: u64,
    pub reconnects: u64,
    pub reorgs: u64,
}

/// One connection to a relay, reconnecting, with backlog and duplicate handling.
pub struct FeedConsumer {
    pub url: String,
    /// Drop messages without a good signature from an allowed signer. Off by default
    /// for parity with the Python package, not because it is unnecessary.
    pub verify: Option<Verifier>,
    pub reconnect_delay: Duration,
    /// Warn after this long connected with no frames. Zero disables the check.
    pub stall_warning: Duration,
    /// How many recent block hashes to keep for reorg detection (~2 minutes).
    pub reorg_window: i64,
    pub stats: Stats,

    ws: Option<WebSocket<MaybeTlsStream<TcpStream>>>,
    pending: VecDeque<FeedMessage>,
    live: bool,
    highest_seq: i64,
    hashes: HashMap<i64, String>,
    warned_unverified: bool,
    failures: u32,
    delay: Duration,
    backoff: Option<Duration>,
    started: Instant,
    last_frame: Instant,
    last_narrated: Instant,
    stall_warned: bool,
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

impl FeedConsumer {
    pub fn new(url: impl Into<String>) -> Self {
        let now = Instant::now();
        Self {
            url: url.into(),
            verify: None,
            reconnect_delay: Duration::from_millis(500),
            stall_warning: Duration::from_secs(30),
            reorg_window: 1024,
            stats: Stats::default(),
            ws: None,
            pending: VecDeque::new(),
            live: false,
            highest_seq: -1,
            hashes: HashMap::new(),
            warned_unverified: false,
            failures: 0,
            delay: Duration::ZERO,
            backoff: None,
            started: now,
            last_frame: now,
            last_narrated: now,
            stall_warned: false,
        }
    }

    pub fn with_verifier(mut self, verifier: Verifier) -> Self {
        self.verify = Some(verifier);
        self
    }

    /// Highest sequence number seen. On this chain, the L2 block number.
    pub fn highest_seq(&self) -> i64 {
        self.highest_seq
    }

    /// The next message from after the backlog drained, reconnecting as long as it takes.
    pub async fn next_live(&mut self) -> FeedMessage {
        loop {
            while let Some(msg) = self.pending.pop_front() {
                if msg.live {
                    return msg;
                }
            }
            self.read().await;
        }
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

    async fn read(&mut self) {
        let interval = self.poll_interval();
        let Some(ws) = self.ws.as_mut() else {
            return self.connect().await;
        };
        match tokio::time::timeout(interval, ws.next_frame()).await {
            Err(_) => self.narrate_silence(),
            Ok(Err(err)) => self.fail(err),
            Ok(Ok(frame)) => match frame.opcode() {
                OpCode::Text | OpCode::Binary => {
                    if let Err(err) = self.on_frame(frame.payload()) {
                        self.fail(format_args!("unreadable frame: {err}"));
                    }
                }
                OpCode::Close => self.fail("closed by the server"),
                _ => {}
            },
        }
    }

    async fn connect(&mut self) {
        if let Some(delay) = self.backoff.take() {
            tokio::time::sleep(delay).await;
        }
        info!("connecting to {}", self.url);
        let url = match self.url.parse() {
            Ok(url) => url,
            Err(err) => return self.fail(err),
        };
        let mut request = HttpRequestBuilder::new().header(FEED_CLIENT_VERSION, "2");
        if self.highest_seq >= 0 {
            // Re-request the last seen number, not the next: one past the relay's tail
            // is a failed lookup, and Nitro answers that with the entire backlog.
            request = request.header(REQUESTED_SEQ, self.highest_seq.to_string());
        }
        // Since 2026-09-17 the public feed refuses a handshake that does not offer
        // permessage-deflate. A local relay serves uncompressed and ignores the offer.
        let options = Options::default()
            .with_limits(1 << 24, 1 << 25)
            .with_low_latency_compression();
        match WebSocket::connect(url)
            .with_options(options)
            .with_request(request)
            .await
        {
            Ok(ws) => {
                if self.failures > 0 {
                    warn!("{} is reachable again", self.url);
                }
                self.failures = 0;
                self.live = false;
                self.started = Instant::now();
                self.last_frame = self.started;
                self.stall_warned = false;
                self.ws = Some(ws);
            }
            Err(err) => self.fail(err),
        }
    }

    fn fail(&mut self, err: impl Display) {
        self.ws = None;
        self.failures += 1;
        self.stats.reconnects += 1;
        if self.failures == 1 {
            self.delay = self.reconnect_delay;
        }
        // Never fail silently: a relay that was never started is the most common way to
        // end up staring at an empty terminal, and the retry loop would hide it forever.
        warn!(
            "cannot read {} ({err}) — retrying in {:.1}s{}",
            self.url,
            self.delay.as_secs_f64(),
            if self.failures == 1 {
                "; is the relay running? (docker compose up -d relay)"
            } else {
                ""
            },
        );
        self.backoff = Some(self.delay);
        self.delay = (self.delay * 2).min(MAX_RECONNECT_DELAY);
    }

    /// Connected, and nothing for a whole poll interval.
    fn narrate_silence(&mut self) {
        let idle = self.last_frame.elapsed();
        if !self.stall_warning.is_zero() && idle >= self.stall_warning && !self.stall_warned {
            self.stall_warned = true; // once per stall, not once per poll
            warn!(
                "no frames from {} for {:.0}s — connected, but nothing is arriving. \
                 Usually the relay's own upstream is down (check: docker compose logs relay)",
                self.url,
                idle.as_secs_f64(),
            );
        }
    }

    fn on_frame(&mut self, payload: &[u8]) -> Result<(), serde_json::Error> {
        self.stats.frames += 1;
        let received = unix_now();
        self.last_frame = Instant::now();
        self.stall_warned = false;

        let frame: Frame = serde_json::from_slice(payload)?;
        for mut msg in self.process(&frame, self.started) {
            msg.received_at = received;
            self.pending.push_back(msg);
        }

        // Frames flowing but none current yet: normal on a relay replaying its backlog.
        if !self.live && self.last_narrated.elapsed() >= self.poll_interval() {
            self.last_narrated = Instant::now();
            info!(
                "draining backlog — {} messages so far, none current yet",
                self.stats.backlog_messages
            );
        }
        Ok(())
    }

    fn judge_live(&mut self, timestamp: u64, started: Instant) -> bool {
        if !self.live {
            self.live = (timestamp != 0 && unix_now() - timestamp as f64 <= LIVE_THRESHOLD)
                || started.elapsed() > MAX_BACKLOG;
            if self.live {
                info!(
                    "live — {} backlog messages skipped, at seq {}",
                    self.stats.backlog_messages, self.highest_seq
                );
            }
        }
        self.live
    }

    /// Every message in a frame that passes verification and is not a duplicate, with
    /// `live` set. Transactions are decoded only once the backlog has drained.
    pub(crate) fn process(&mut self, frame: &Frame, started: Instant) -> Vec<FeedMessage> {
        let entries = frame.entries();
        let Some(last) = entries.last() else {
            return Vec::new();
        };
        // Liveness from the frame's own timestamps first, to decide whether to decode.
        let live = self.judge_live(
            last.header().and_then(|h| h.timestamp).unwrap_or(0),
            started,
        );

        let mut out = Vec::with_capacity(entries.len());
        // parse_frame returns one message per entry, in order.
        for (entry, mut msg) in entries.iter().zip(parse_frame(frame, live)) {
            // Verify before the watermark is consulted: both branches below move it.
            if !self.verify.as_ref().is_none_or(|v| v.accepts(entry)) {
                self.reject(entry, msg.seq);
                continue;
            }
            if msg.seq <= self.highest_seq {
                if !self.is_reorg(&msg) {
                    self.stats.duplicate_messages += 1;
                    continue;
                }
                // A reorg replaces this sequence number and everything after it; the
                // replacements that follow arrive as ordinary new messages.
                self.stats.reorgs += 1;
                msg.reorg = true;
                warn!(
                    "feed reorg at seq {}: block hash changed from {} to {}. \
                     Anything you derived from the old block is now stale",
                    msg.seq,
                    self.hashes.get(&msg.seq).map_or("None", String::as_str),
                    msg.block_hash.as_deref().unwrap_or("None"),
                );
            }
            self.highest_seq = msg.seq;
            self.remember(&msg);
            msg.live = live;
            if live {
                self.stats.live_messages += 1;
            } else {
                self.stats.backlog_messages += 1;
            }
            out.push(msg);
        }
        out
    }

    /// A re-sent sequence number with a different block hash. Unknown on either side
    /// means unknown, so no: better a missed reorg than a rewind we cannot justify.
    fn is_reorg(&self, msg: &FeedMessage) -> bool {
        match (self.hashes.get(&msg.seq), &msg.block_hash) {
            (Some(previous), Some(current)) => previous != current,
            _ => false,
        }
    }

    fn remember(&mut self, msg: &FeedMessage) {
        let Some(hash) = &msg.block_hash else { return };
        self.hashes.insert(msg.seq, hash.clone());
        if self.hashes.len() as i64 > self.reorg_window * 2 {
            let cutoff = self.highest_seq - self.reorg_window;
            self.hashes.retain(|&seq, _| seq > cutoff);
        }
    }

    /// Drop an unverified message without advancing the watermark — otherwise one
    /// injected frame could make the next reconnect skip the real messages behind it.
    fn reject(&mut self, entry: &Entry, seq: i64) {
        self.stats.unverified_messages += 1;
        if self.warned_unverified {
            return;
        }
        // Once, then counted: a wrong chain id rejects *every* message.
        self.warned_unverified = true;
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

    fn feed(consumer: &mut FeedConsumer, entries: &[String]) -> Vec<FeedMessage> {
        let json = format!(r#"{{"version":1,"messages":[{}]}}"#, entries.join(","));
        let frame: Frame = serde_json::from_str(&json).unwrap();
        consumer.process(&frame, Instant::now())
    }

    fn hash_of(n: u8) -> String {
        format!("0x{}", format!("{n:02x}").repeat(32))
    }

    #[test]
    fn a_duplicate_is_dropped_silently() {
        let mut c = FeedConsumer::new(DEFAULT_RELAY);
        assert_eq!(feed(&mut c, &[entry_json(1, &hash_of(1))]).len(), 1);
        assert!(feed(&mut c, &[entry_json(1, &hash_of(1))]).is_empty());
        assert_eq!((c.stats.duplicate_messages, c.stats.reorgs), (1, 0));
    }

    #[test]
    fn a_changed_block_hash_is_a_reorg_and_rewinds_the_watermark() {
        let mut c = FeedConsumer::new(DEFAULT_RELAY);
        feed(
            &mut c,
            &[
                entry_json(1, &hash_of(1)),
                entry_json(2, &hash_of(2)),
                entry_json(3, &hash_of(3)),
            ],
        );
        let out = feed(
            &mut c,
            &[entry_json(2, &hash_of(0xAA)), entry_json(3, &hash_of(0xBB))],
        );
        assert_eq!(
            out.iter().map(|m| (m.seq, m.reorg)).collect::<Vec<_>>(),
            [(2, true), (3, false)]
        );
        assert_eq!((c.stats.reorgs, c.highest_seq()), (1, 3));
    }

    #[test]
    fn an_unknown_hash_is_not_a_reorg() {
        let mut c = FeedConsumer::new(DEFAULT_RELAY);
        c.reorg_window = 2;
        let seqs: Vec<String> = (1..=10).map(|n| entry_json(n, &hash_of(n as u8))).collect();
        feed(&mut c, &seqs);
        assert!(
            c.hashes.len() <= 5,
            "window not bounded: {}",
            c.hashes.len()
        );
        assert!(feed(&mut c, &[entry_json(1, &hash_of(0xEE))]).is_empty());
        assert_eq!(c.stats.reorgs, 0);
    }

    #[test]
    fn a_verifying_consumer_drops_a_forgery_without_advancing() {
        let mut c = FeedConsumer::new(DEFAULT_RELAY).with_verifier(MAINNET_VERIFIER.clone());
        assert!(feed(&mut c, &[entry_json(99_999_999, &hash_of(1))]).is_empty());
        assert_eq!((c.stats.unverified_messages, c.highest_seq()), (1, -1));
    }

    #[test]
    fn a_backlog_message_is_not_decoded() {
        let mut c = FeedConsumer::new(DEFAULT_RELAY);
        let old = r#"{"sequenceNumber":1,"message":{"message":{"header":{"kind":3,"timestamp":1},"l2Msg":"BAAAAAAAAAAA"}}}"#;
        let out = feed(&mut c, &[old.to_string()]);
        assert!(!out[0].live && out[0].txs.is_empty());
        assert_eq!(c.stats.backlog_messages, 1);
    }
}
