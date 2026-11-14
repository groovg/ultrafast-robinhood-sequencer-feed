//! Runs `Feed` against real WebSocket servers on localhost. Covers what the unit tests
//! can't: handshake headers, the backlog, reconnects, and two sources at once.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::SinkExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

use rhfeed::{Feed, FeedMessage};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn entry(seq: i64, timestamp: u64) -> String {
    format!(
        r#"{{"sequenceNumber":{seq},"blockHash":"0x{:064x}","message":{{"delayedMessagesRead":1,
        "message":{{"header":{{"kind":3,"sender":"0xa4b000000000000000000073657175656e636572",
        "blockNumber":1,"timestamp":{timestamp}}},"l2Msg":"BMmAgICAgICAgIA="}}}}}}"#,
        seq
    )
}

fn frame(entries: &[String]) -> Message {
    Message::text(format!(
        r#"{{"version":1,"messages":[{}]}}"#,
        entries.join(",")
    ))
}

async fn server(scripts: Vec<Vec<Message>>) -> (String, mpsc::UnboundedReceiver<Option<String>>) {
    server_with(scripts, None).await
}

/// A feed server. Each accepted connection reports its requested sequence number, then
/// gets the next script from `scripts` sent to it, frame by frame, and is closed. With
/// `chain`, the handshake response announces that chain id, as Nitro relays do.
// The handshake callback's error type is tungstenite's, not ours to shrink.
#[allow(clippy::result_large_err)]
async fn server_with(
    scripts: Vec<Vec<Message>>,
    chain: Option<&'static str>,
) -> (String, mpsc::UnboundedReceiver<Option<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let (requested_tx, requested_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        for script in scripts {
            let (stream, _) = listener.accept().await.unwrap();
            let requested = Arc::new(Mutex::new(None));
            let seen = requested.clone();
            let mut ws = tokio_tungstenite::accept_hdr_async(
                stream,
                move |req: &Request, mut res: Response| {
                    *seen.lock().unwrap() = req
                        .headers()
                        .get("Arbitrum-Requested-Sequence-Number")
                        .map(|v| v.to_str().unwrap().to_owned());
                    if let Some(chain) = chain {
                        res.headers_mut()
                            .insert("Arbitrum-Chain-Id", chain.parse().unwrap());
                    }
                    Ok(res)
                },
            )
            .await
            .unwrap();
            // A test that does not care about the header has dropped the receiver.
            let _ = requested_tx.send(requested.lock().unwrap().clone());
            for msg in script {
                // The client may have hung up, which some tests expect.
                let _ = ws.send(msg).await;
            }
            let _ = ws.close(None).await;
        }
        // Keep the listener open so reconnects queue instead of failing fast.
        std::future::pending::<()>().await;
    });
    (url, requested_rx)
}

async fn next(feed: &mut Feed) -> FeedMessage {
    tokio::time::timeout(Duration::from_secs(5), feed.recv())
        .await
        .expect("no message within 5 s")
        .unwrap()
}

#[tokio::test]
async fn the_backlog_is_skipped_and_live_messages_delivered() {
    let (url, _) = server(vec![vec![
        frame(&[entry(1, 1_000), entry(2, 1_000)]),
        frame(&[entry(3, now())]),
    ]])
    .await;
    let mut feed = Feed::builder().source(url).spawn();
    let msg = next(&mut feed).await;
    assert_eq!((msg.seq, msg.live, msg.txs.len()), (3, true, 1));
    let stats = feed.stats();
    assert_eq!((stats.backlog_messages, stats.live_messages), (2, 1));
}

#[tokio::test]
async fn a_frame_that_ends_the_backlog_delivers_only_its_live_part() {
    let t = now();
    let (url, _) = server(vec![vec![frame(&[
        entry(1, t - 30),
        entry(2, t - 20),
        entry(3, t),
    ])]])
    .await;
    let mut feed = Feed::builder().source(url).spawn();
    let msg = next(&mut feed).await;
    assert_eq!((msg.seq, msg.live), (3, true));
    let stats = feed.stats();
    assert_eq!((stats.backlog_messages, stats.live_messages), (2, 1));
}

#[tokio::test]
async fn a_reconnect_re_requests_the_last_seen_number_and_drops_the_duplicate() {
    let t = now();
    let (url, mut requested) = server(vec![
        vec![frame(&[entry(10, t)])],
        vec![frame(&[entry(10, t)]), frame(&[entry(11, t)])],
    ])
    .await;
    let mut feed = Feed::builder()
        .source(url)
        .reconnect_delay(Duration::from_millis(10))
        .spawn();
    assert_eq!(next(&mut feed).await.seq, 10);
    assert_eq!(next(&mut feed).await.seq, 11);
    assert_eq!(requested.recv().await.unwrap(), None);
    assert_eq!(requested.recv().await.unwrap().as_deref(), Some("10"));
    let stats = feed.stats();
    // Each closed connection counts; the second may or may not have closed yet.
    assert_eq!(stats.duplicate_messages, 1);
    assert!(stats.sources[0].reconnects >= 1);
}

#[tokio::test]
async fn two_sources_deliver_every_message_once() {
    let t = now();
    let script = || vec![frame(&(1..=20).map(|s| entry(s, t)).collect::<Vec<_>>())];
    let (a, _) = server(vec![script()]).await;
    let (b, _) = server(vec![script()]).await;
    let mut feed = Feed::builder().source(a).source(b).spawn();
    let mut got = Vec::new();
    for _ in 0..20 {
        got.push(next(&mut feed).await.seq);
    }
    assert_eq!(got, (1..=20).collect::<Vec<_>>());
    // Nothing more: every second copy was a duplicate.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), feed.recv())
            .await
            .is_err()
    );
    let stats = feed.stats();
    let firsts: u64 = stats.sources.iter().map(|s| s.first).sum();
    assert_eq!((firsts, stats.duplicate_messages), (20, 20));
}

#[tokio::test]
async fn busy_polling_delivers() {
    let t = now();
    let (url, _) = server(vec![vec![frame(&[entry(5, t)]), frame(&[entry(6, t)])]]).await;
    let mut feed = Feed::builder().source(url).busy_poll(true).spawn();
    assert_eq!(next(&mut feed).await.seq, 5);
    let msg = next(&mut feed).await;
    assert_eq!((msg.seq, msg.live), (6, true));
    assert!(msg.timing.is_some());
}

#[tokio::test]
async fn a_feed_can_recover_the_senders_itself() {
    let (url, _) = server(vec![vec![frame(&[entry(8, now())])]]).await;
    let mut feed = Feed::builder().source(url).senders(2).spawn();
    let msg = next(&mut feed).await;
    assert_eq!((msg.seq, msg.txs.len()), (8, 1));
    // The test transaction has an empty signature, so it has no sender either way.
    assert_eq!(msg.txs[0].sender_bytes(), None);
}

#[tokio::test]
async fn a_feed_of_another_chain_is_refused_when_verifying() {
    let t = now();
    for busy in [false, true] {
        let (url, _) = server_with(vec![vec![frame(&[entry(1, t)])]], Some("46630")).await;
        let mut feed = Feed::builder()
            .source(url)
            .verify(rhfeed::MAINNET_VERIFIER.clone())
            .busy_poll(busy)
            .spawn();
        // The only source stops for good, so the stream ends instead of retrying.
        let end = tokio::time::timeout(Duration::from_secs(5), feed.recv()).await;
        assert!(matches!(end, Ok(None)), "busy {busy}");
        let err = feed.stats().sources[0].error.clone().unwrap();
        assert!(
            err.contains("chain 46630") && err.contains("chain 4663,"),
            "{err}"
        );
    }
}

#[tokio::test]
async fn an_announced_chain_is_ignored_without_verification() {
    let (url, _) = server_with(vec![vec![frame(&[entry(4, now())])]], Some("0xb626")).await;
    let mut feed = Feed::builder().source(url).spawn();
    assert_eq!(next(&mut feed).await.seq, 4);
    assert!(feed.stats().sources[0].error.is_none());
}

/// An EthDeposit entry on chain 4663 with a fresh timestamp, from the golden fixture.
fn deposit(seq: i64) -> String {
    let golden = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden.jsonl"),
    )
    .unwrap();
    let case: serde_json::Value = golden
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .find(|g: &serde_json::Value| g["parent"] == "100868052")
        .unwrap();
    let mut entry = case["entry"].clone();
    entry["sequenceNumber"] = seq.into();
    entry["message"]["message"]["header"]["timestamp"] = now().into();
    entry.to_string()
}

#[tokio::test]
async fn a_deposit_carries_its_transaction_with_the_chain_id_set() {
    let (url, _) = server(vec![vec![frame(&[deposit(1)])]]).await;
    let mut feed = Feed::builder().source(url).chain_id(4663).spawn();
    let msg = next(&mut feed).await;
    assert!(msg.from_parent_chain());
    assert_eq!(
        msg.txs[0].hash_hex(),
        "0xcb29b668d7f387ca6fa429853959d4354f7f918458bf4492846bfdeea759a313"
    );
}

#[tokio::test]
async fn a_feed_that_announces_its_chain_needs_no_chain_id() {
    let (url, _) = server_with(vec![vec![frame(&[deposit(1)])]], Some("4663")).await;
    let mut feed = Feed::builder().source(url).spawn();
    assert_eq!(next(&mut feed).await.txs.len(), 1);
}

#[tokio::test]
async fn an_entry_with_a_mistyped_field_is_dropped_and_the_rest_kept() {
    let t = now();
    let bad = entry(1, t).replace(r#""blockNumber":1"#, r#""blockNumber":1,"requestId":7"#);
    let (url, _) = server(vec![vec![frame(&[bad, entry(2, t)])]]).await;
    let mut feed = Feed::builder().source(url).spawn();
    // Failing the frame would reconnect, and this server has nothing more to send.
    assert_eq!(next(&mut feed).await.seq, 2);
    assert_eq!(feed.stats().malformed_messages, 1);
}
