//! Uniswap V3 SwapRouter and SwapRouter02, the V2 router, and their multicall wrappers.
//!
//! A V3 path is `token (20) fee (3) token (20) [fee token ...]`. For exact-output calls
//! Uniswap reverses it, so the output token comes first.

use super::abi::{NATIVE, Result, bytes_array, dynamic, static_array, token, tuple_at, uint};
use super::{Call, Intent, Kind, decode_call};

/// (first token, last token) of a V3 path. None for the 0xeeee… native marker.
pub fn v3_path_ends(path: &[u8]) -> (Option<[u8; 20]>, Option<[u8; 20]>) {
    if path.len() < 20 {
        return (None, None);
    }
    let first: [u8; 20] = path[..20].try_into().unwrap();
    let last: [u8; 20] = path[path.len() - 20..].try_into().unwrap();
    (
        (first != NATIVE).then_some(first),
        (last != NATIVE).then_some(last),
    )
}

pub fn amounts(intent: &mut Intent, first: [u8; 32], second: [u8; 32], exact_in: bool) {
    (intent.amount_in, intent.amount_out) = if exact_in {
        (Some(first), Some(second))
    } else {
        (Some(second), Some(first))
    };
    intent.exact_in = exact_in;
}

/// `*Single` structs are static and sit inline. `slots`: recipient, first, second amount.
pub fn single(call: &Call, out: &mut Vec<Intent>, slots: [usize; 3], exact_in: bool) -> Result<()> {
    let d = &call.data[4..];
    let [recipient, first, second] = slots;
    let mut intent = Intent {
        token_in: token(d, 0)?,
        token_out: token(d, 1)?,
        recipient: token(d, recipient)?,
        ..Intent::new(Kind::Swap, call)
    };
    amounts(&mut intent, uint(d, first)?, uint(d, second)?, exact_in);
    out.push(intent);
    Ok(())
}

pub fn path(call: &Call, out: &mut Vec<Intent>, slots: [usize; 3], exact_in: bool) -> Result<()> {
    let body = tuple_at(&call.data[4..], 0)?;
    let [recipient, first, second] = slots;
    let (a, b) = v3_path_ends(dynamic(body, 0)?);
    let (token_in, token_out) = if exact_in { (a, b) } else { (b, a) };
    let mut intent = Intent {
        token_in,
        token_out,
        recipient: token(body, recipient)?,
        ..Intent::new(Kind::Swap, call)
    };
    amounts(
        &mut intent,
        uint(body, first)?,
        uint(body, second)?,
        exact_in,
    );
    out.push(intent);
    Ok(())
}

/// Slots of a V2 router call. `amount_in` None means msg.value.
struct V2 {
    amount_in: Option<usize>,
    amount_out: usize,
    path: usize,
    to: usize,
    exact_in: bool,
    eth_in: bool,
    eth_out: bool,
}

const fn v2_layout(selector: u32) -> V2 {
    use super::*;
    let (amount_in, amount_out, path, to, exact_in, eth_in, eth_out) = match selector {
        V2_EXACT_TOKENS_FOR_TOKENS | V2_EXACT_TOKENS_FOR_TOKENS_FOT => {
            (Some(0), 1, 2, 3, true, false, false)
        }
        V2_EXACT_TOKENS_FOR_ETH | V2_EXACT_TOKENS_FOR_ETH_FOT => {
            (Some(0), 1, 2, 3, true, false, true)
        }
        V2_EXACT_ETH_FOR_TOKENS | V2_EXACT_ETH_FOR_TOKENS_FOT => (None, 0, 1, 2, true, true, false),
        V2_TOKENS_FOR_EXACT_TOKENS => (Some(1), 0, 2, 3, false, false, false),
        V2_TOKENS_FOR_EXACT_ETH => (Some(1), 0, 2, 3, false, false, true),
        // V2_ETH_FOR_EXACT_TOKENS, the only one left.
        _ => (None, 0, 1, 2, false, true, false),
    };
    V2 {
        amount_in,
        amount_out,
        path,
        to,
        exact_in,
        eth_in,
        eth_out,
    }
}

pub fn v2(call: &Call, out: &mut Vec<Intent>, selector: u32) -> Result<()> {
    let l = v2_layout(selector);
    let d = &call.data[4..];
    let hops = static_array(d, l.path, 1)?;
    let (Some(first), Some(last)) = (hops.clone().next(), hops.last()) else {
        return Ok(());
    };
    out.push(Intent {
        token_in: if l.eth_in { None } else { token(first, 0)? },
        token_out: if l.eth_out { None } else { token(last, 0)? },
        amount_in: Some(match l.amount_in {
            None => call.value,
            Some(i) => uint(d, i)?,
        }),
        amount_out: Some(uint(d, l.amount_out)?),
        exact_in: l.exact_in,
        recipient: token(d, l.to)?,
        ..Intent::new(Kind::Swap, call)
    });
    Ok(())
}

/// Same contract, same msg.value: multicall is a `delegatecall` to itself.
pub fn multicall(call: &Call, depth: usize, out: &mut Vec<Intent>, blobs: usize) -> Result<()> {
    for blob in bytes_array(&call.data[4..], blobs, call.budget)?.iter() {
        decode_call(
            &Call {
                data: blob,
                ..*call
            },
            depth + 1,
            out,
        );
    }
    Ok(())
}
