//! The Rust half of the Python vs Rust benchmark. `bench/bench.py` is the Python half and
//! measures the same things the same way (best of N rounds).
//!
//!     cargo run --release --example bench [capture.jsonl]
//!     cargo run --release --example bench --features ufsecp [capture.jsonl]
//!
//! Each per-transaction row reads one more field than the row above it, so the
//! difference between two rows is what that field costs.

use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

use base64::Engine;
use bytes::Bytes;

use rhfeed::codec::Frame;
use rhfeed::{
    MAINNET_CHAIN_ID, MAINNET_VERIFIER, decode_transaction, frame_from_slice, keccak, parse_frame,
    recover_signer, signature_payload,
};

/// A digest, r, s and recovery id.
type Sig = ([u8; 32], [u8; 32], [u8; 32], u8);
type Recover = fn(&[u8; 32], &[u8; 32], &[u8; 32], u8) -> Option<[u8; 20]>;

/// Microseconds per item, best round. Best rather than mean: noise only ever adds time.
fn best_of(rounds: usize, items: usize, mut f: impl FnMut()) -> f64 {
    f(); // warm up: caches, and ufsecp's one-time precompute tables
    let mut best = f64::INFINITY;
    for _ in 0..rounds {
        let started = Instant::now();
        f();
        best = best.min(started.elapsed().as_secs_f64() / items as f64);
    }
    best * 1e6
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/frames.jsonl")
        });
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let frames: Vec<Frame> = lines
        .iter()
        .map(|l| frame_from_slice(l.as_bytes()).unwrap())
        .collect();
    let messages: usize = frames.iter().map(|f| f.entries().len()).sum();
    let raws: Vec<Bytes> = frames
        .iter()
        .flat_map(|f| parse_frame(f, true))
        .flat_map(|m| m.txs)
        .map(|t| t.raw)
        .collect();
    let entries: Vec<_> = frames
        .iter()
        .flat_map(|f| f.entries())
        .filter(|e| e.signature_v2.is_some())
        .collect();

    let backend = if cfg!(feature = "ufsecp") {
        "ufsecp"
    } else {
        "libsecp256k1"
    };
    println!(
        "{} frames, {messages} messages, {} tx from {}",
        lines.len(),
        raws.len(),
        path.display()
    );
    println!("recovery backend: {backend}\n");
    println!("{:<44}{:>10}", "per transaction", "us");

    let row = |label: &str, rounds: usize, f: &dyn Fn(&rhfeed::Tx)| {
        let us = best_of(rounds, raws.len(), || {
            for raw in &raws {
                f(black_box(&decode_transaction(raw.clone()).unwrap()));
            }
        });
        println!("{label:<44}{us:>10.3}");
    };
    row("to_bytes, selector, value, nonce, gas", 200, &|t| {
        black_box((t.to_bytes, t.selector, t.value_be(), t.nonce, t.gas));
    });
    row("+ hash", 200, &|t| {
        black_box((t.to_bytes, t.selector, t.hash()));
    });
    row("+ to (checksummed)", 100, &|t| {
        black_box((t.to_bytes, t.selector, t.hash(), t.to()));
    });
    row("+ sender", 20, &|t| {
        black_box((t.to_bytes, t.selector, t.hash(), t.to(), t.sender()));
    });

    println!("\n{:<44}{:>10}", "per message", "us");
    let frame_us = best_of(50, messages, || {
        for line in &lines {
            let frame = frame_from_slice(black_box(line).as_bytes()).unwrap();
            black_box(parse_frame(&frame, true));
        }
    });
    println!("{:<44}{frame_us:>10.3}", "frame JSON -> decoded txs");
    // Where that goes: the JSON alone, then the base64 inside it.
    let json_us = best_of(50, messages, || {
        for line in &lines {
            black_box(serde_json::from_str::<Frame>(black_box(line)).unwrap());
        }
    });
    println!(
        "{:<44}{json_us:>10.3}",
        "  of which JSON parse (serde_json)"
    );
    let sonic_us = best_of(50, messages, || {
        for line in &lines {
            black_box(frame_from_slice(black_box(line).as_bytes()).unwrap());
        }
    });
    println!(
        "{:<44}{sonic_us:>10.3}",
        "  of which JSON parse (sonic-rs, used)"
    );
    let b64_us = best_of(50, messages, || {
        for f in &frames {
            for e in f.entries() {
                if let Some(m) = e.incoming().and_then(|i| i.l2_msg.as_deref()) {
                    black_box(base64_simd::STANDARD.decode_to_vec(m).unwrap());
                }
            }
        }
    });
    println!("{:<44}{b64_us:>10.3}", "  of which base64 l2Msg");
    let verify_us = best_of(20, entries.len(), || {
        for e in &entries {
            black_box(recover_signer(e, MAINNET_CHAIN_ID));
        }
    });
    println!("{:<44}{verify_us:>10.3}", "feed signature check");
    // What Feed does to every new live message before handing it over: the latency
    // this crate adds on top of the network.
    let path_us = best_of(20, messages, || {
        for line in &lines {
            let frame = frame_from_slice(black_box(line).as_bytes()).unwrap();
            for e in frame.entries() {
                let l2 = rhfeed::codec::l2_msg(e).unwrap();
                if MAINNET_VERIFIER.accepts_with(e, l2.as_deref()) {
                    black_box(rhfeed::codec::parse_entry_with(e, l2.as_ref()));
                }
            }
        }
    });
    println!("{:<44}{path_us:>10.3}", "feed path: parse, verify, decode");
    let full_us = best_of(10, messages, || {
        for line in &lines {
            let frame = frame_from_slice(black_box(line).as_bytes()).unwrap();
            for (e, m) in frame.entries().iter().zip(parse_frame(&frame, true)) {
                black_box(recover_signer(e, MAINNET_CHAIN_ID));
                for t in &m.txs {
                    black_box((t.hash(), t.to(), t.sender()));
                }
            }
        }
    });
    println!(
        "{:<44}{full_us:>10.3}",
        "all of it: frame, signature, every sender"
    );

    // The bare primitive, on the feed signatures' real digests.
    let sigs: Vec<Sig> = entries
        .iter()
        .map(|e| {
            let sig = base64::engine::general_purpose::STANDARD
                .decode(e.signature_v2.as_deref().unwrap())
                .unwrap();
            let digest = keccak(&signature_payload(e, MAINNET_CHAIN_ID).unwrap());
            (
                digest,
                sig[..32].try_into().unwrap(),
                sig[32..64].try_into().unwrap(),
                sig[64] % 27,
            )
        })
        .collect();
    println!("\n{:<44}{:>10}", "ECDSA recover -> address", "us");
    let prim = |label: &str, f: Recover| {
        let us = best_of(50, sigs.len(), || {
            for (d, r, s, v) in &sigs {
                black_box(f(d, r, s, *v));
            }
        });
        println!("{label:<44}{us:>10.3}");
    };
    prim("libsecp256k1", rhfeed::secp::libsecp::recover);
    #[cfg(feature = "ufsecp")]
    prim("ufsecp", rhfeed::secp::ufsecp::recover);

    println!("\none core, full decode incl. sender: ~{:.0} tx/s", {
        let us = best_of(20, raws.len(), || {
            for raw in &raws {
                black_box(decode_transaction(raw.clone()).unwrap().sender());
            }
        });
        1e6 / us
    });
}
