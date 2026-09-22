//! The `rhfeed` command: stream decoded transactions from the feed. It takes the same
//! flags and prints the same output as the Python version's `cli.py`, so you can diff
//! the two.

use std::collections::HashSet;
use std::process::exit;
use std::time::Duration;

use clap::Parser;
use serde::Serialize;
use serde_json::value::RawValue;

use rhfeed::{
    Feed, FeedMessage, LOCAL_RELAY, MAINNET_FEED, MAINNET_VERIFIER, TESTNET_FEED, Tx, addr, sel,
};

/// How many characters of an address to print. Hashes are printed in full because
/// people paste them into explorers. Full addresses would make the lines too long.
const ADDR_WIDTH: usize = 10;

/// Stream decoded transactions from Robinhood Chain's sequencer feed.
///
/// Defaults to the public mainnet feed. Progress and problems go to stderr,
/// transactions to stdout.
#[derive(Parser)]
#[command(name = "rhfeed", version)]
struct Args {
    /// 'mainnet', 'testnet', 'relay' (ws://127.0.0.1:9642), or any feed URL. Repeat it
    /// to race several sources; each message is taken from whichever has it first
    #[arg(long, default_value = "mainnet")]
    feed: Vec<String>,
    /// Stop after this long, whether or not anything arrives
    #[arg(long)]
    seconds: Option<f64>,
    /// One JSON object per message
    #[arg(long)]
    json: bool,
    /// Accept messages without checking they are signed by Robinhood Chain mainnet's
    /// sequencer key. Checking is the default; it costs one signature recovery per
    /// message and only knows mainnet, so testnet needs this flag
    #[arg(long)]
    no_verify: bool,
    /// Only transactions to this address
    #[arg(long)]
    to: Vec<String>,
    /// Only calls with this 4-byte selector
    #[arg(long)]
    selector: Vec<String>,
    /// Only transactions from this address, and show who sent each one. Forces a
    /// signature recovery per transaction
    #[arg(long)]
    sender: Vec<String>,
}

/// The filters, cheapest first. `to` and `selector` are just set lookups. `sender` needs
/// an ECDSA recovery, so it's checked last.
struct Filter {
    to: Option<HashSet<[u8; 20]>>,
    selector: Option<HashSet<[u8; 4]>>,
    sender: Option<HashSet<[u8; 20]>>,
}

fn set<T: std::hash::Hash + Eq>(
    values: &[String],
    parse: fn(&str) -> Result<T, String>,
) -> Result<Option<HashSet<T>>, String> {
    if values.is_empty() {
        return Ok(None);
    }
    values
        .iter()
        .map(|v| parse(v))
        .collect::<Result<_, _>>()
        .map(Some)
}

impl Filter {
    fn new(args: &Args) -> Result<Self, String> {
        Ok(Self {
            to: set(&args.to, addr)?,
            selector: set(&args.selector, sel)?,
            sender: set(&args.sender, addr)?,
        })
    }

    fn active(&self) -> bool {
        self.to.is_some() || self.selector.is_some() || self.sender.is_some()
    }

    /// The filters that need no ECDSA: `to` and `selector`.
    fn cheap(&self, tx: &Tx) -> bool {
        self.to
            .as_ref()
            .is_none_or(|s| tx.to_bytes.is_some_and(|v| s.contains(&v)))
            && self
                .selector
                .as_ref()
                .is_none_or(|s| tx.selector.is_some_and(|v| s.contains(&v)))
    }

    /// The `sender` filter. Run `recover_senders` on the candidates first, so this
    /// reads cached senders instead of recovering them one at a time.
    fn sender(&self, tx: &Tx) -> bool {
        self.sender
            .as_ref()
            .is_none_or(|s| tx.sender_bytes().is_some_and(|v| s.contains(&v)))
    }
}

fn short(address: Option<String>, placeholder: &str) -> String {
    match address {
        None => format!("{placeholder:<width$}", width = ADDR_WIDTH + 3),
        Some(a) => format!("{}…", &a[..ADDR_WIDTH + 2]),
    }
}

#[derive(Serialize)]
struct JsonTx {
    hash: String,
    tx_type: u8,
    to: Option<String>,
    /// Written as a raw JSON number like the Python version does, since wei can exceed u64.
    value: Box<RawValue>,
    nonce: u64,
    gas: u64,
    selector: Option<String>,
    kind: &'static str,
    raw_len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender: Option<Option<String>>,
}

#[derive(Serialize)]
struct JsonMsg {
    seq: i64,
    timestamp: u64,
    received_at: f64,
    kind: String,
    from_parent_chain: bool,
    txs: Vec<JsonTx>,
}

fn json_line(msg: &FeedMessage, txs: &[&Tx], show_sender: bool) -> String {
    let line = JsonMsg {
        seq: msg.seq,
        timestamp: msg.timestamp,
        received_at: (msg.received_at * 1e6).round() / 1e6,
        kind: msg.l1_kind_name().into_owned(),
        from_parent_chain: msg.from_parent_chain(),
        txs: txs
            .iter()
            .map(|t| JsonTx {
                hash: t.hash_hex(),
                tx_type: t.tx_type,
                to: t.to(),
                value: RawValue::from_string(t.value_dec()).unwrap(),
                nonce: t.nonce,
                gas: t.gas,
                selector: t.selector_hex(),
                kind: t.kind(),
                raw_len: t.raw.len(),
                sender: show_sender.then(|| t.sender()),
            })
            .collect(),
    };
    serde_json::to_string(&line).unwrap()
}

/// Logs go to stderr with a `#` prefix, so they stay visible when stdout is redirected.
struct StderrLog;

impl log::Log for StderrLog {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("# {}", record.args());
        }
    }
    fn flush(&self) {}
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    log::set_logger(&StderrLog)
        .map(|()| log::set_max_level(log::LevelFilter::Info))
        .unwrap();

    let urls: Vec<&str> = args
        .feed
        .iter()
        .map(|f| match f.as_str() {
            "mainnet" => MAINNET_FEED,
            "testnet" => TESTNET_FEED,
            "relay" => LOCAL_RELAY,
            other => other,
        })
        .collect();
    let verify = !args.no_verify;
    if verify && urls.contains(&TESTNET_FEED) {
        // The chain id is part of the signed data, so every testnet message would fail
        // and it would look like the feed is dead.
        eprintln!(
            "rhfeed: verification only knows mainnet's chain id and signer, and the chain id \
             is signed, so every testnet message would be dropped. Pass --no-verify, or build a \
             Verifier with the testnet chain id and signer and pass it to Feed::builder() directly."
        );
        exit(1);
    }
    let keep = Filter::new(&args).unwrap_or_else(|err| {
        eprintln!("rhfeed: {err}");
        exit(1);
    });

    let mut builder = urls.iter().fold(Feed::builder(), |b, url| b.source(*url));
    if verify {
        builder = builder.verify(MAINNET_VERIFIER.clone());
    }
    let mut feed = builder.spawn();
    // Recovering a sender costs about 15 times more than all other fields together, so
    // we only show senders when --sender already made us recover them.
    let show_sender = keep.sender.is_some();
    let mut shown = 0usize;

    let stream = async {
        while let Some(msg) = feed.recv().await {
            let mut txs: Vec<&Tx> = msg.txs.iter().filter(|t| keep.cheap(t)).collect();
            if show_sender {
                // All of this message's senders at once, spread over the cores.
                rhfeed::recover_senders(txs.iter().copied());
                txs.retain(|t| keep.sender(t));
            }
            if txs.is_empty() && keep.active() {
                continue;
            }
            shown += txs.len();
            if args.json {
                println!("{}", json_line(&msg, &txs, show_sender));
                continue;
            }
            let tag = if msg.from_parent_chain() {
                format!(" [{}]", msg.l1_kind_name())
            } else {
                String::new()
            };
            println!("seq {}{tag}  {} tx", msg.seq, txs.len());
            for t in txs {
                let who = if show_sender {
                    format!("{} -> ", short(t.sender(), "?"))
                } else {
                    String::new()
                };
                println!(
                    "    {}  {:<8} {who}{}  {}",
                    t.hash_hex(),
                    t.kind(),
                    short(t.to(), "deploy"),
                    t.selector_hex().unwrap_or_default()
                );
            }
        }
    };
    // A timer instead of checking the time per message, so --seconds works even when
    // nothing arrives.
    let deadline = async {
        match args.seconds {
            Some(s) => tokio::time::sleep(Duration::from_secs_f64(s)).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        () = stream => {}
        () = deadline => {}
        _ = tokio::signal::ctrl_c() => {}
    }

    let s = feed.stats();
    let counted = if keep.active() { "matched" } else { "seen" };
    // Print the count even when it's zero, so you can see the check ran.
    let checked = if verify {
        format!(", {} unverified dropped", s.unverified_messages)
    } else {
        String::new()
    };
    eprintln!(
        "# {shown} transactions {counted} | {} live messages, {} backlog skipped{checked}, \
         {} failed connections",
        s.live_messages, s.backlog_messages, s.reconnects
    );
    if s.sources.len() > 1 {
        // Shows which source was fastest from this machine.
        for src in &s.sources {
            let lag = src.lag_mean().map_or("-".into(), |m| {
                format!("{:.1} ms mean, {:.1} ms max", ms(m), ms(src.lag_max))
            });
            eprintln!(
                "#   {}: first on {} messages, behind on {} ({lag})",
                src.url, src.first, src.late
            );
        }
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}
