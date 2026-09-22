//! Read Robinhood Chain's sequencer feed and decode it quickly.
//!
//! Ported from Chainstack's Python package `rhfeed`
//! (github.com/chainstacklabs/robinhood-chain-sequencer-feed). The Python module
//! docstrings explain the design in more detail (why RLP is scanned instead of parsed,
//! why `hash` and `sender` are computed lazily, what the feed signature covers, how
//! reorgs show up). The code here follows them closely.

pub mod codec;
pub mod consume;
pub mod secp;
pub mod verify;

pub use codec::{
    FeedMessage, Frame, Tx, addr, checksum, decode_l2_message, decode_transaction,
    frame_from_slice, is_filtered_call, keccak, parse_frame, sel, selector_of,
};
pub use consume::{Feed, FeedBuilder, LOCAL_RELAY, MAINNET_FEED, SourceStats, Stats, TESTNET_FEED};
pub use verify::{
    FEED_PREFIX, MAINNET_CHAIN_ID, MAINNET_SIGNER, MAINNET_VERIFIER, Verifier, recover_signer,
    recover_signer_with, signature_payload,
};
