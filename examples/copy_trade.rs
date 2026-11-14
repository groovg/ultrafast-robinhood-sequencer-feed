//! Follow some wallets and print a signal as soon as the sequencer orders a trade of
//! theirs that we can decode. The decode half of a copy-trading bot: what to do with a
//! signal is up to you.
//!
//!     cargo run --release --example copy_trade -- 0xabc... 0xdef...
//!     cargo run --release --example copy_trade -- --busy 0xabc...
//!
//! A trade is a swap, a Relay fill or a Relay sell. A followed wallet's transaction that
//! decodes to no trade (nothing at all, or only an approve or a transfer) prints
//! nothing.
//!
//! The wallet is the intent's `actor` when the calldata names one: the user inside a
//! 4337 bundle, or the wallet a Relay fill delivers to. That is a set lookup. Only a
//! trade whose calldata names no one (a plain wallet trading through a router) needs its
//! sender recovered to tell whose it is, and each signal recovers its sender for the
//! `sender` field.
//!
//! `--busy` trades CPU for latency: the feed is read by a thread that never sleeps,
//! messages are picked up by spinning, and the feed recovers the senders on 7 spinning
//! threads while it checks the signature (`FeedBuilder::senders`). That's 9 cores at
//! 100%, and a message's senders are known about 250 µs sooner.
//!
//! One JSON line per signal on stdout. The transaction has been ordered but not
//! executed yet, so it can still revert. And `actor` is only what the calldata claims:
//! anyone can send a transaction naming a wallet you follow. The receipt confirms it.

use std::collections::HashSet;

use serde::Serialize;

use rhfeed::intents::Kind;
use rhfeed::{Feed, Intent, MAINNET_FEED, MAINNET_VERIFIER, addr, decode_intents, recover_senders};

#[derive(Serialize)]
struct Signal<'a> {
    block: i64,
    seen_at: f64,
    hash: String,
    intent: &'a Intent,
    /// Who signed, so you can see when the claimed actor differs.
    sender: Option<String>,
    /// Posted on Ethereum, not ordered by the sequencer: nobody checked its signature,
    /// nonce or balance, and a node skips it without a receipt if one doesn't hold.
    from_parent_chain: bool,
}

fn is_trade(i: &Intent) -> bool {
    matches!(i.kind, Kind::Swap | Kind::RelayFill | Kind::RelaySell)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let busy = args.iter().any(|a| a == "--busy");
    let follow: HashSet<[u8; 20]> = args
        .iter()
        .filter(|a| *a != "--busy")
        .map(|a| addr(a).unwrap_or_else(|e| panic!("{e}")))
        .collect();
    if follow.is_empty() {
        eprintln!("usage: copy_trade <wallet> [wallet...]");
        std::process::exit(1);
    }

    // If the wallets you follow only trade through known routers, list them here. It
    // checks the transaction's `to`, which is right for plain wallets and wrong for
    // 4337 bundles and Relay fills, where `to` is the EntryPoint or the Relay router.
    let contracts: HashSet<[u8; 20]> = HashSet::new();

    // Two connections: each message comes from whichever gets it first.
    let mut feed = Feed::builder()
        .source(MAINNET_FEED)
        .source(MAINNET_FEED)
        .verify(MAINNET_VERIFIER.clone())
        .busy_poll(busy)
        .senders(if busy { 7 } else { 0 })
        .spawn();

    // Read from a spawned task, not main's own thread: see Feed::recv.
    tokio::spawn(async move {
        while let Some(msg) = feed.recv().await {
            // Every trade in the message, with the transaction it came from.
            let trades: Vec<_> = msg
                .txs
                .iter()
                .filter(|t| {
                    contracts.is_empty() || t.to_bytes.is_some_and(|to| contracts.contains(&to))
                })
                .flat_map(|t| decode_intents(t).into_iter().map(move |i| (t, i)))
                .filter(|(_, i)| is_trade(i))
                .filter(|(_, i)| i.actor.is_none_or(|a| follow.contains(&a)))
                .collect();
            // The senders still needed, all at once, spread over the cores. With --busy
            // the feed has recovered them already.
            if !busy {
                recover_senders(trades.iter().map(|(t, _)| *t));
            }
            for (tx, intent) in &trades {
                if !intent
                    .actor
                    .or_else(|| tx.sender_bytes())
                    .is_some_and(|a| follow.contains(&a))
                {
                    continue;
                }
                let signal = Signal {
                    block: msg.seq,
                    seen_at: msg.received_at,
                    hash: tx.hash_hex(),
                    intent,
                    sender: tx.sender(),
                    from_parent_chain: msg.from_parent_chain(),
                };
                println!("{}", sonic_rs::to_string(&signal).unwrap());
            }
        }
    })
    .await
    .unwrap();
}
