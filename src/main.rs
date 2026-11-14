//! The `rhfeed` command: stream decoded transactions from the feed. It takes the same
//! flags and prints the same output as the Python version's `cli.py`, so you can diff
//! the two.

use std::collections::HashSet;
use std::process::exit;
use std::time::{Duration, Instant};

use clap::Parser;
use serde::Serialize;
use sonic_rs::RawNumber;

use rhfeed::{
    Feed, FeedMessage, Intent, LOCAL_RELAY, MAINNET_FEED, MAINNET_VERIFIER, TESTNET_FEED, Tx, addr,
    decode_intents, sel,
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
    /// sequencer key. Checking is the default; it costs one signature check per
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
    /// Only transactions whose decoded intent is for this wallet (the user inside a 4337
    /// bundle or the wallet a Relay fill delivers to) or, when the calldata names no one,
    /// that it sent. Shows senders
    #[arg(long)]
    actor: Vec<String>,
    /// At the end, print how long each stage took per message (p50, p99, max), from
    /// the socket read to this program receiving the message
    #[arg(long)]
    timing: bool,
    /// Read the feed on a thread that never sleeps, and spin waiting for its messages.
    /// Lower latency, at the cost of two cores at 100%, plus up to 7 more for --sender
    #[arg(long)]
    busy_poll: bool,
}

/// The filters, cheapest first. `to` and `selector` are just set lookups. Then the
/// calldata is decoded for `actor`, and `sender` goes last because it needs an ECDSA
/// recovery. `actor` needs the sender only when some intent names no actor, and keeps
/// only the followed actors' intents: one bundle can carry several wallets' trades.
struct Filter {
    to: Option<HashSet<[u8; 20]>>,
    selector: Option<HashSet<[u8; 4]>>,
    sender: Option<HashSet<[u8; 20]>>,
    actor: Option<HashSet<[u8; 20]>>,
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
            actor: set(&args.actor, addr)?,
        })
    }

    fn active(&self) -> bool {
        self.to.is_some() || self.selector.is_some() || self.wants_sender()
    }

    /// Both `sender` and `actor` show who sent each transaction.
    fn wants_sender(&self) -> bool {
        self.sender.is_some() || self.actor.is_some()
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

    /// Whether `finish` will need this transaction's sender: always for `sender`; for
    /// `actor` when an intent names no actor or names a followed one, since a kept
    /// transaction shows its sender.
    fn needs_sender(&self, intents: &[Intent]) -> bool {
        self.sender.is_some()
            || self.actor.as_ref().is_some_and(|follow| {
                intents.is_empty()
                    || intents
                        .iter()
                        .any(|i| i.actor.is_none_or(|a| follow.contains(&a)))
            })
    }

    /// The `actor` and `sender` filters. Run `recover_senders` on the transactions
    /// `needs_sender` picks first, so this reads cached senders instead of recovering
    /// them one at a time.
    fn finish(&self, tx: &Tx, intents: &mut Vec<Intent>) -> bool {
        if let Some(follow) = &self.actor {
            match actors_intents(std::mem::take(intents), || tx.sender_bytes(), follow) {
                Some(mine) => *intents = mine,
                None => return false,
            }
        }
        self.sender
            .as_ref()
            .is_none_or(|s| tx.sender_bytes().is_some_and(|v| s.contains(&v)))
    }
}

/// The intents of a followed actor, or None if the transaction has none. An intent with
/// no decoded actor, or a call with nothing decoded at all, is the sender's own, so the
/// sender is asked for only then.
fn actors_intents(
    intents: Vec<Intent>,
    sender: impl FnOnce() -> Option<[u8; 20]>,
    follow: &HashSet<[u8; 20]>,
) -> Option<Vec<Intent>> {
    let decoded = !intents.is_empty();
    let unclaimed = !decoded || intents.iter().any(|i| i.actor.is_none());
    let followed = unclaimed && sender().is_some_and(|s| follow.contains(&s));
    let mine: Vec<Intent> = intents
        .into_iter()
        .filter(|i| i.actor.map_or(followed, |a| follow.contains(&a)))
        .collect();
    (!mine.is_empty() || (!decoded && followed)).then_some(mine)
}

fn short(address: Option<String>, placeholder: &str) -> String {
    match address {
        None => format!("{placeholder:<width$}", width = ADDR_WIDTH + 3),
        Some(a) => format!("{}…", &a[..ADDR_WIDTH + 2]),
    }
}

#[derive(Serialize)]
struct JsonTx<'a> {
    hash: String,
    tx_type: u8,
    to: Option<String>,
    /// Written as a raw JSON number like the Python version does, since wei can exceed u64.
    value: RawNumber,
    nonce: u64,
    gas: u64,
    selector: Option<String>,
    kind: &'static str,
    raw_len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender: Option<Option<String>>,
    intents: &'a [Intent],
}

#[derive(Serialize)]
struct JsonMsg<'a> {
    seq: i64,
    timestamp: u64,
    received_at: f64,
    kind: String,
    from_parent_chain: bool,
    txs: Vec<JsonTx<'a>>,
}

fn json_line(msg: &FeedMessage, txs: &[(&Tx, Vec<Intent>)], show_sender: bool) -> String {
    let line = JsonMsg {
        seq: msg.seq,
        timestamp: msg.timestamp,
        received_at: (msg.received_at * 1e6).round() / 1e6,
        kind: msg.l1_kind_name().into_owned(),
        from_parent_chain: msg.from_parent_chain(),
        txs: txs
            .iter()
            .map(|(t, intents)| JsonTx {
                hash: t.hash_hex(),
                tx_type: t.tx_type,
                to: t.to(),
                value: sonic_rs::from_str(&t.value_dec()).unwrap(),
                nonce: t.nonce,
                gas: t.gas,
                selector: t.selector_hex(),
                kind: t.kind(),
                raw_len: t.raw.len(),
                sender: show_sender.then(|| t.sender()),
                intents,
            })
            .collect(),
    };
    sonic_rs::to_string(&line).unwrap()
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
    // Consume in a task rather than on main's own thread. A message then wakes it on the
    // worker that received the message, ~4 us, instead of waking another thread, ~14 us.
    tokio::spawn(run()).await.unwrap();
}

async fn run() {
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
    let seconds = args.seconds.map(|s| {
        Duration::try_from_secs_f64(s).unwrap_or_else(|_| {
            eprintln!("rhfeed: --seconds needs a number of seconds of 0 or more, not {s}");
            exit(1);
        })
    });

    let mut builder = urls
        .iter()
        .fold(Feed::builder(), |b, url| b.source(*url))
        .busy_poll(args.busy_poll);
    if verify {
        builder = builder.verify(MAINNET_VERIFIER.clone());
    }
    // Recovering a sender costs about 15 times more than all other fields together, so
    // we only show senders when --sender or --actor already made us recover them.
    let show_sender = keep.wants_sender();
    // With --busy-poll, the feed recovers the senders itself while it checks the
    // signature, on spinning threads: as many as a typical message has transactions
    // (7), leaving cores for the rest.
    let pooled = args.busy_poll && show_sender;
    if pooled {
        let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
        builder = builder.senders(cores.saturating_sub(3).clamp(1, 7));
    }
    let mut feed = builder.spawn();
    let mut shown = 0usize;
    let mut stages: Vec<[Duration; STAGES.len()]> = Vec::new();

    let stream = async {
        while let Some(msg) = feed.recv().await {
            if let (true, Some(t)) = (args.timing, msg.timing) {
                let received = Instant::now();
                let at = [
                    t.first_read,
                    t.last_read,
                    t.decrypted,
                    t.inflated,
                    t.parsed,
                    t.verified,
                    t.decoded,
                    t.sent,
                    received,
                ];
                let mut row = [Duration::ZERO; STAGES.len()];
                for (i, d) in row.iter_mut().enumerate().take(at.len() - 1) {
                    *d = at[i + 1].saturating_duration_since(at[i]);
                }
                row[STAGES.len() - 1] = received.saturating_duration_since(t.last_read);
                stages.push(row);
            }
            let mut txs: Vec<(&Tx, Vec<Intent>)> = msg
                .txs
                .iter()
                .filter(|t| keep.cheap(t))
                .map(|t| (t, decode_intents(t)))
                .collect();
            if show_sender {
                if !pooled {
                    // The senders this message needs, all at once, spread over the cores.
                    let needed = txs.iter().filter(|(_, i)| keep.needs_sender(i));
                    rhfeed::recover_senders(needed.map(|(t, _)| *t));
                }
                txs.retain_mut(|(t, intents)| keep.finish(t, intents));
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
            for (t, intents) in txs {
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
                for i in intents {
                    println!("        ↳ {}", i.describe());
                }
            }
        }
    };
    // A timer instead of checking the time per message, so --seconds works even when
    // nothing arrives.
    let deadline = async {
        match seconds {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending().await,
        }
    };
    // The stream ends on its own only when every source has stopped for good.
    let ended = tokio::select! {
        () = stream => true,
        () = deadline => false,
        _ = tokio::signal::ctrl_c() => false,
    };

    if args.timing && !stages.is_empty() {
        print_timing(&mut stages);
    }
    let s = feed.stats();
    let counted = if keep.active() { "matched" } else { "seen" };
    // Print the count even when it's zero, so you can see the check ran.
    let checked = if verify {
        format!(", {} unverified dropped", s.unverified_messages)
    } else {
        String::new()
    };
    let checked = match s.malformed_messages {
        0 => checked,
        n => format!("{checked}, {n} malformed dropped"),
    };
    eprintln!(
        "# {shown} transactions {counted} | {} live messages, {} backlog skipped{checked}, \
         {} failed connections",
        s.live_messages,
        s.backlog_messages,
        s.sources.iter().map(|src| src.reconnects).sum::<u64>()
    );
    if s.sources.len() > 1 {
        // Shows which source was fastest from this machine.
        for src in &s.sources {
            let lag = src.lag_mean().map_or("-".into(), |m| {
                format!("{:.1} ms mean, {:.1} ms max", ms(m), ms(src.lag_max))
            });
            eprintln!(
                "#   {}: first on {} messages, behind on {} ({lag}){}",
                src.url,
                src.first,
                src.late,
                match src.replaced {
                    0 => String::new(),
                    n => format!(", reconnected {n}x for being slow"),
                }
            );
        }
    }
    if ended {
        for err in s.sources.iter().filter_map(|src| src.error.as_deref()) {
            eprintln!("rhfeed: {err}");
        }
        exit(1);
    }
}

/// What `--timing` reports, one row per stage of `rhfeed::consume::Timing`.
const STAGES: [&str; 9] = [
    "rest of the frame arriving",
    "TLS decrypt",
    "WebSocket + inflate",
    "JSON parse",
    "signature check",
    "decode transactions",
    "dedup, queue",
    "channel to recv()",
    "total: last read to recv()",
];

fn print_timing(stages: &mut [[Duration; STAGES.len()]]) {
    eprintln!("# per message, µs ({} live messages):", stages.len());
    eprintln!("#   {:<28}{:>9}{:>9}{:>9}", "stage", "p50", "p99", "max");
    for (i, name) in STAGES.iter().enumerate() {
        stages.sort_unstable_by_key(|row| row[i]);
        let at = |q: f64| {
            let row = &stages[((stages.len() - 1) as f64 * q).round() as usize];
            row[i].as_secs_f64() * 1e6
        };
        eprintln!(
            "#   {name:<28}{:>9.1}{:>9.1}{:>9.1}",
            at(0.5),
            at(0.99),
            at(1.0)
        );
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhfeed::intents::{Kind, decode};

    const FOLLOWED: [u8; 20] = [0x05; 20];
    const NOBODY: [u8; 20] = [0x11; 20];
    const SENDER: [u8; 20] = [0x22; 20];

    /// A swap for `actor`, or an approve with no actor when None.
    fn intent(actor: Option<[u8; 20]>) -> Intent {
        let mut data = vec![0x09, 0x5e, 0xa7, 0xb3];
        data.extend([0u8; 64]);
        let mut i = decode(Some([1; 20]), &[], &data).remove(0);
        if actor.is_some() {
            i.kind = Kind::Swap;
            i.actor = actor;
        }
        i
    }

    fn follow(a: [u8; 20]) -> HashSet<[u8; 20]> {
        HashSet::from([a])
    }

    #[test]
    fn only_the_followed_actors_intents_are_kept() {
        let (mine, theirs) = (intent(Some(FOLLOWED)), intent(Some(NOBODY)));
        let both = vec![mine.clone(), theirs];
        let kept = actors_intents(
            both,
            || panic!("nothing needs the sender"),
            &follow(FOLLOWED),
        );
        assert_eq!(kept, Some(vec![mine]));
    }

    #[test]
    fn unclaimed_intents_are_kept_only_for_a_followed_sender() {
        let (claimed, unclaimed) = (intent(Some(NOBODY)), intent(None));
        let both = || vec![claimed.clone(), unclaimed.clone()];
        let sender = || Some(SENDER);
        let kept = |a| actors_intents(both(), sender, &follow(a));
        assert_eq!(kept(SENDER), Some(vec![unclaimed.clone()]));
        assert_eq!(kept(NOBODY), Some(vec![claimed.clone()]));
        assert_eq!(kept(FOLLOWED), None);
    }

    #[test]
    fn a_call_with_nothing_decoded_is_the_senders() {
        assert_eq!(
            actors_intents(vec![], || Some(SENDER), &follow(SENDER)),
            Some(vec![])
        );
        assert_eq!(
            actors_intents(vec![], || Some(SENDER), &follow(NOBODY)),
            None
        );
        assert_eq!(actors_intents(vec![], || None, &follow(NOBODY)), None);
    }
}
