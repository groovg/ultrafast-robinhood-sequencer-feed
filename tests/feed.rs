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
        "blockNumber":1,"timestamp":{timestamp}}},"l2Msg":"BAAAAAAAAAAA"}}}}}}"#,
        seq
    )
}

fn frame(entries: &[String]) -> Message {
    Message::text(format!(
        r#"{{"version":1,"messages":[{}]}}"#,
        entries.join(",")
    ))
}

/// A feed server. Each accepted connection reports its requested sequence number, then
/// gets the next script from `scripts` sent to it, frame by frame, and is closed.
// The handshake callback's error type is tungstenite's, not ours to shrink.
#[allow(clippy::result_large_err)]
async fn server(scripts: Vec<Vec<Message>>) -> (String, mpsc::UnboundedReceiver<Option<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let (requested_tx, requested_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        for script in scripts {
            let (stream, _) = listener.accept().await.unwrap();
            let requested = Arc::new(Mutex::new(None));
            let seen = requested.clone();
            let mut ws =
                tokio_tungstenite::accept_hdr_async(stream, move |req: &Request, res: Response| {
                    *seen.lock().unwrap() = req
                        .headers()
                        .get("Arbitrum-Requested-Sequence-Number")
                        .map(|v| v.to_str().unwrap().to_owned());
                    Ok(res)
                })
                .await
                .unwrap();
            // A test that does not care about the header has dropped the receiver.
            let _ = requested_tx.send(requested.lock().unwrap().clone());
            for msg in script {
                ws.send(msg).await.unwrap();
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
    assert!(stats.reconnects >= 1);
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
async fn busy_polling_delivers_through_try_recv() {
    let t = now();
    let (url, _) = server(vec![vec![frame(&[entry(5, t)]), frame(&[entry(6, t)])]]).await;
    let mut feed = Feed::builder().source(url).busy_poll(true).spawn();
    assert_eq!(next(&mut feed).await.seq, 5);
    // try_recv never waits; the second message shows up soon.
    let started = std::time::Instant::now();
    let msg = loop {
        if let Some(msg) = feed.try_recv() {
            break msg;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "no message within 5 s"
        );
        tokio::task::yield_now().await;
    };
    assert_eq!((msg.seq, msg.live), (6, true));
    assert!(msg.timing.is_some());
}
