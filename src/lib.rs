//! Decode an Arbitrum Orbit sequencer feed, fast enough to act on it.
//!
//! A port of the Python package `rhfeed` (github.com/chainstacklabs/robinhood-chain-sequencer-feed), which stays as the baseline. The design
//! notes — why the RLP scanner copies nothing, why `hash` and `sender` are lazy, what the
//! feed signature covers, how reorgs show up — live in the Python module docstrings and
//! are not repeated here; the code follows them line for line.

pub mod codec;
pub mod consume;
pub mod secp;
pub mod verify;

pub use codec::{
    FeedMessage, Frame, Tx, addr, checksum, decode_l2_message, decode_transaction,
    is_filtered_call, keccak, parse_frame, sel, selector_of,
};
pub use consume::{Feed, FeedBuilder, LOCAL_RELAY, MAINNET_FEED, SourceStats, Stats, TESTNET_FEED};
pub use verify::{
    FEED_PREFIX, MAINNET_CHAIN_ID, MAINNET_SIGNER, MAINNET_VERIFIER, Verifier, recover_signer,
    recover_signer_with, signature_payload,
};
