//! Print a JSON line when the sequencer orders a trade (swap, Relay fill or sell) by a
//! followed wallet. The trade can still revert, and `actor` is only what the calldata
//! claims: anyone can name a wallet you follow.
//!
//!     cargo run --release --example copy_trade -- 0xabc... 0xdef...
//!     cargo run --release --example copy_trade -- --busy 0xabc...   # 9 cores at 100%

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
    /// Who signed, to compare with the claimed actor.
    sender: Option<String>,
    /// Posted on Ethereum: nobody checked it, and a node may skip it without a receipt.
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

    // Routers your wallets trade through, if known. Wrong for 4337 bundles and Relay
    // fills, whose `to` is the EntryPoint or the Relay router.
    let contracts: HashSet<[u8; 20]> = HashSet::new();

    let mut feed = Feed::builder()
        .source(MAINNET_FEED)
        .source(MAINNET_FEED)
        .verify(MAINNET_VERIFIER.clone())
        .busy_poll(busy)
        .senders(if busy { 7 } else { 0 })
        .spawn();

    // A spawned task, not main's own thread: see Feed::recv.
    tokio::spawn(async move {
        while let Some(msg) = feed.recv().await {
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
            // With --busy the feed has recovered them already.
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
