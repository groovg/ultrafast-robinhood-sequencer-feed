//! Follow some wallets and print a signal as soon as the sequencer orders one of their
//! transactions. The decode half of a copy-trading bot: what to do with a signal is up
//! to you.
//!
//!     cargo run --release --example copy_trade -- 0xabc... 0xdef...
//!     cargo run --release --example copy_trade -- --busy 0xabc...
//!
//! `--busy` trades CPU for latency: the feed is read by a thread that never sleeps,
//! messages are picked up by spinning, and the feed recovers the senders on 7 spinning
//! threads while it checks the signature (`FeedBuilder::senders`). That's 9 cores at
//! 100%, and a message's senders are known about 250 µs sooner.
//!
//! One JSON line per matching transaction on stdout. The transaction has been ordered
//! but not executed yet, so it can still revert.

use std::collections::HashSet;

use rhfeed::{Feed, MAINNET_FEED, MAINNET_VERIFIER, addr, recover_senders, selector_of};

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

    // If the wallets you follow only trade through known contracts, list them here.
    // Checking `to` costs nothing, so it throws most of the feed away before any ECDSA.
    let contracts: HashSet<[u8; 20]> = HashSet::new();

    let names = [
        (selector_of("transfer(address,uint256)"), "transfer"),
        (selector_of("approve(address,uint256)"), "approve"),
        (
            selector_of("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"),
            "swap",
        ),
        (
            selector_of(
                "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
            ),
            "swapV3",
        ),
    ];

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
            let candidates: Vec<_> = msg
                .txs
                .iter()
                .filter(|t| {
                    contracts.is_empty() || t.to_bytes.is_some_and(|to| contracts.contains(&to))
                })
                .collect();
            // Every sender in the message at once, spread over the cores. With --busy the
            // feed has done it already.
            if !busy {
                recover_senders(candidates.iter().copied());
            }
            for tx in candidates {
                let Some(from) = tx.sender_bytes().filter(|s| follow.contains(s)) else {
                    continue;
                };
                let action = tx
                    .selector
                    .and_then(|s| names.iter().find(|(sel, _)| *sel == s))
                    .map_or(tx.kind(), |(_, name)| *name);
                println!(
                    "{}",
                    serde_json::json!({
                        "block": msg.seq,
                        "seen_at": msg.received_at,
                        "hash": tx.hash_hex(),
                        "from": rhfeed::checksum(&from),
                        "to": tx.to(),
                        "action": action,
                        "selector": tx.selector_hex(),
                        "value_wei": tx.value_dec(),
                    })
                );
            }
        }
    })
    .await
    .unwrap();
}
