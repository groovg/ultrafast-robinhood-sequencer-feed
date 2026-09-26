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

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{info, warn};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::crypto::{CryptoProvider, ring};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use yawc::{HttpRequestBuilder, MaybeTlsStream, OpCode, Options, WebSocket};

use crate::codec::{Entry, FeedMessage, Frame, frame_from_slice, l2_msg, parse_entry_with};
use crate::verify::Verifier;

/// Where a local Nitro relay listens by default (see README.md for running one).
pub const LOCAL_RELAY: &str = "ws://127.0.0.1:9642";

/// Robinhood's public endpoints. At most two connections per IP.
pub const MAINNET_FEED: &str = "wss://feed.mainnet.chain.robinhood.com";
pub const TESTNET_FEED: &str = "wss://feed.testnet.chain.robinhood.com";

const FEED_CLIENT_VERSION: &str = "Arbitrum-Feed-Client-Version";
const REQUESTED_SEQ: &str = "Arbitrum-Requested-Sequence-Number";

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
/// Check for a stall four times per `STALL_WARNING`, so it's reported close to when it
/// crosses the threshold.
const POLL_INTERVAL: Duration = Duration::from_millis(7500);
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
    /// Signature checked (equal to `parsed` without a verifier).
    pub verified: Instant,
    pub decoded: Instant,
    /// Just before the message went into the channel.
    pub sent: Instant,
}

/// Instants stored as nanoseconds since this, so they fit in an atomic. 0 means unset.
static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

fn to_nanos(t: Instant) -> u64 {
    (t.saturating_duration_since(*EPOCH).as_nanos() as u64).max(1)
}

fn from_nanos(n: u64) -> Instant {
    *EPOCH + Duration::from_nanos(n)
}

/// When reads on a stream returned bytes: the first since the last `take` and the most
/// recent. Written from inside yawc by `Stamped`, read by the source once per frame.
#[derive(Default)]
struct ReadTimes {
    first: AtomicU64,
    last: AtomicU64,
}

impl ReadTimes {
    fn record(&self) {
        let now = to_nanos(Instant::now());
        self.last.store(now, Relaxed);
        if self.first.load(Relaxed) == 0 {
            self.first.store(now, Relaxed);
        }
    }

    fn take(&self) -> (Instant, Instant) {
        let last = self.last.load(Relaxed);
        let first = match self.first.swap(0, Relaxed) {
            0 => last,
            first => first,
        };
        (from_nanos(first), from_nanos(last))
    }
}

/// A stream that notes when its reads return bytes. One sits under TLS and one above
/// it, which separates waiting for the network from decrypting.
struct Stamped<S> {
    inner: S,
    times: Arc<ReadTimes>,
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
        }
        res
    }
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
    pub reconnects: u64,
    pub reorgs: u64,
    pub sources: Vec<SourceStats>,
}

/// Per-source counters: who delivered first, and how far behind the rest were.
#[derive(Debug, Default, Clone)]
pub struct SourceStats {
    pub url: String,
    pub connected: bool,
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
                recent: vec![(0, 0); urls.len()],
                replace: vec![false; urls.len()],
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // The lock only guards counters and a map, so a poisoned lock is still usable.
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
        mut timing: Timing,
    ) -> Vec<FeedMessage> {
        let now = timing.inflated;
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
            // Decode l2Msg once and use it for both the signature and the transactions.
            // A backlog message that isn't being verified needs neither.
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
                timing.verified = Instant::now();
            }
            let l2 = if live { l2.ok().flatten() } else { None };
            let mut msg = parse_entry_with(entry, l2.as_ref());
            timing.decoded = Instant::now();

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
                st.recent[source].0 += 1;
                st.check_slow(source);
                st.stats.live_messages += 1;
            } else {
                st.stats.backlog_messages += 1;
            }
            msg.live = live;
            msg.source = source;
            msg.received_at = received_at;
            msg.timing = Some(timing);
            out.push(msg);
        }
        out
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
            capacity: 1024,
        }
    }

    /// The next live message, from whichever source had it first. `None` only if every
    /// source task has stopped, which they do not do on their own.
    ///
    /// Call this from a task you `tokio::spawn`, not straight from `#[tokio::main]`'s
    /// body. The body runs on its own thread, so every message has to wake that thread
    /// (~14 us on our machine). A spawned task is woken on the worker that just received
    /// the message (~4 us).
    pub async fn recv(&mut self) -> Option<FeedMessage> {
        self.rx.recv().await
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

    /// Messages buffered for a consumer that is behind. When full, sources stop
    /// reading until it catches up, and say so.
    pub fn capacity(mut self, messages: usize) -> Self {
        self.capacity = messages;
        self
    }

    /// Start every source on the current tokio runtime. Panics with no sources.
    pub fn spawn(self) -> Feed {
        assert!(!self.sources.is_empty(), "a feed needs at least one source");
        let shared = Arc::new(Shared::new(&self.sources, self.verify, REORG_WINDOW));
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
            info!("connecting to {}", self.url);
            let err = match self.connect().await {
                Err(err) => err,
                Ok((ws, times)) => {
                    if failures > 0 {
                        warn!("{} is reachable again", self.url);
                    }
                    failures = 0;
                    delay = self.reconnect_delay;
                    self.set_connected(true);
                    let end = self.read(ws, times).await;
                    self.set_connected(false);
                    match end {
                        End::Stopped => return,
                        End::Slow => {
                            info!(
                                "{}: first on under 1 in {SLOW_SHARE} of the last \
                                 {SLOW_WINDOW} messages, trying a new connection",
                                self.url
                            );
                            self.shared.lock().stats.sources[self.index].replaced += 1;
                            continue;
                        }
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
                // The public feed allows two connections per IP and answers the rest with
                // 429. Retrying quickly would just hit the limit again.
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
            // Always log the failure. Otherwise a feed that can't be reached just looks
            // like a quiet feed.
            warn!(
                "cannot read {} ({err}), retrying in {:.1}s{}",
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

    /// A WebSocket over TLS over TCP, with the reads on both sides of TLS `Stamped`.
    /// Returns the stamps of the (TCP, TLS) reads.
    async fn connect(&self) -> Result<(Socket, [Arc<ReadTimes>; 2]), String> {
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
        let stream = Stamped {
            inner: stream,
            times: Arc::clone(&times[1]),
        };
        // Since 2026-09-17 the public feed refuses a handshake that does not offer
        // permessage-deflate. A local relay serves uncompressed and ignores the offer.
        let options = Options::default()
            .with_limits(1 << 24, 1 << 25)
            .with_low_latency_compression();
        let ws = WebSocket::handshake_with_request(url, stream, options, request)
            .await
            .map_err(|e| e.to_string())?;
        Ok((ws, times))
    }

    async fn read(&self, mut ws: Socket, [tcp, tls]: [Arc<ReadTimes>; 2]) -> End {
        let started = Instant::now();
        let mut live = false;
        let mut last_frame = started;
        let mut last_narrated = started;
        let mut stall_warned = false;
        let mut warned_full = false;
        loop {
            let frame = match tokio::time::timeout(POLL_INTERVAL, ws.next_frame()).await {
                Err(_) => {
                    let idle = last_frame.elapsed();
                    if idle >= STALL_WARNING && !stall_warned {
                        stall_warned = true; // once per stall, not once per poll
                        warn!(
                            "no frames from {} for {:.0}s. Connected, but nothing is \
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
            let now = Instant::now();
            let (first_read, last_read) = tcp.take();
            let (_, decrypted) = tls.take();
            match frame.opcode() {
                OpCode::Text | OpCode::Binary => {}
                OpCode::Close => return End::Failed("closed by the server".into()),
                _ => continue,
            }
            let received_at = unix_now();
            last_frame = now;
            stall_warned = false;

            let parsed = match frame_from_slice(frame.payload()) {
                Ok(parsed) => parsed,
                Err(err) => return End::Failed(format!("unreadable frame: {err}")),
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
                } else if last_narrated.elapsed() >= POLL_INTERVAL {
                    // Frames are arriving but none are recent yet, so we're still in the backlog.
                    last_narrated = now;
                    info!("{}: draining backlog, none current yet", self.url);
                }
            }

            let msgs = self
                .shared
                .ingest(self.index, &parsed, live, received_at, timing);
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
                                self.url
                            );
                        }
                        if self.tx.send(msg).await.is_err() {
                            return End::Stopped;
                        }
                    }
                }
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
        let now = unix_now() as u64;
        format!(
            r#"{{"sequenceNumber":{seq},"blockHash":"{block_hash}","message":{{"delayedMessagesRead":500,
            "message":{{"header":{{"kind":3,"sender":"0xa4b000000000000000000073657175656e636572",
            "blockNumber":25000000,"timestamp":{now}}},"l2Msg":"BAAAAAAAAAAA"}}}}}}"#
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
        let frame = frame_from_slice(json.as_bytes()).unwrap();
        s.ingest(source, &frame, live, 0.0, stamps(now))
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
        let frame = frame_from_slice(json.as_bytes()).unwrap();
        let out = s.ingest(0, &frame, false, 0.0, stamps(Instant::now()));
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
