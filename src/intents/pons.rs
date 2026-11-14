//! Pons's buy, `0xc1120e3d`. No public ABI: the layout was read from calldata and checked
//! against receipts. `value` is the ETH spent. Ten static words:
//!
//! ```text
//! 0 router (a Universal Router deployment)   5 recipient
//! 1 PoolManager (the chain's V4 singleton)   6 deadline, unix seconds
//! 2 token bought                             7 fee
//! 3 not read: nothing observed explains it   8 tickSpacing
//! 4 amountOutMin                             9 hooks, zero
//! ```

use super::abi::{Result, WORD, address, token, uint};
use super::{Call, Intent, Kind};

/// 0x8366a39CC670B4001A1121B8F6A443A643e40951
const V4_POOL_MANAGER: [u8; 20] = [
    0x83, 0x66, 0xa3, 0x9c, 0xc6, 0x70, 0xb4, 0x00, 0x1a, 0x11, 0x21, 0xb8, 0xf6, 0xa4, 0x43, 0xa6,
    0x43, 0xe4, 0x09, 0x51,
];

pub fn buy(call: &Call, out: &mut Vec<Intent>) -> Result<()> {
    let d = &call.data[4..];
    // The selector alone could belong to anything; the PoolManager in word 1 confirms it.
    if d.len() != 10 * WORD || address(d, 1)? != V4_POOL_MANAGER {
        return Ok(());
    }
    out.push(Intent {
        token_in: None,
        amount_in: Some(call.value),
        token_out: token(d, 2)?,
        amount_out: Some(uint(d, 4)?),
        recipient: Some(address(d, 5)?),
        ..Intent::new(Kind::Swap, call)
    });
    Ok(())
}
