//! Uniswap Universal Router: `execute(commands, inputs[, deadline])`. Only swap commands
//! are read. A bad input voids the whole call, as the router reverts it unless the
//! allow-revert flag (0x80) is set. Constants from `Commands.sol` and `Actions.sol`.

use super::abi::{
    Malformed, Result, address, bytes_array, dynamic, static_array, token, tuple_array, tuple_at,
    uint,
};
use super::uniswap::{amounts, v3_path_ends};
use super::{Call, Intent, Kind};

const COMMAND_MASK: u8 = 0x7f;
const V3_SWAP_EXACT_IN: u8 = 0x00;
const V3_SWAP_EXACT_OUT: u8 = 0x01;
const V2_SWAP_EXACT_IN: u8 = 0x08;
const V2_SWAP_EXACT_OUT: u8 = 0x09;
const V4_SWAP: u8 = 0x10;

const SWAP_EXACT_IN_SINGLE: u8 = 0x06;
const SWAP_EXACT_IN: u8 = 0x07;
const SWAP_EXACT_OUT_SINGLE: u8 = 0x08;
const SWAP_EXACT_OUT: u8 = 0x09;

/// Recipient sentinels in router inputs.
const MSG_SENDER: [u8; 20] = {
    let mut a = [0; 20];
    a[19] = 1;
    a
};
const ADDRESS_THIS: [u8; 20] = {
    let mut a = [0; 20];
    a[19] = 2;
    a
};

fn recipient(raw: [u8; 20], call: &Call) -> Option<[u8; 20]> {
    match raw {
        MSG_SENDER => call.actor,
        ADDRESS_THIS => call.to,
        _ => Some(raw),
    }
}

fn v3(call: &Call, p: &[u8], exact_in: bool) -> Result<Intent> {
    let (first, second) = (uint(p, 1)?, uint(p, 2)?);
    let (a, b) = v3_path_ends(dynamic(p, 3)?);
    let (token_in, token_out) = if exact_in { (a, b) } else { (b, a) };
    let mut intent = Intent {
        token_in,
        token_out,
        recipient: recipient(address(p, 0)?, call),
        ..Intent::new(Kind::Swap, call)
    };
    amounts(&mut intent, first, second, exact_in);
    Ok(intent)
}

fn v2(call: &Call, p: &[u8], exact_in: bool) -> Result<Option<Intent>> {
    let hops = static_array(p, 3, 1)?;
    let (Some(first_hop), Some(last_hop)) = (hops.clone().next(), hops.last()) else {
        return Ok(None);
    };
    let (first, second) = (uint(p, 1)?, uint(p, 2)?);
    let mut intent = Intent {
        token_in: token(first_hop, 0)?,
        token_out: token(last_hop, 0)?,
        recipient: recipient(address(p, 0)?, call),
        ..Intent::new(Kind::Swap, call)
    };
    amounts(&mut intent, first, second, exact_in);
    Ok(Some(intent))
}

/// (poolKey{currency0, currency1, fee, tickSpacing, hooks}, zeroForOne, amount, amount,
/// hookData)
fn v4_single(call: &Call, p: &[u8], exact_in: bool) -> Result<Intent> {
    let body = tuple_at(p, 0)?;
    let (c0, c1) = (token(body, 0)?, token(body, 1)?);
    let zero_for_one = uint(body, 5)? != [0; 32];
    let (first, second) = (uint(body, 6)?, uint(body, 7)?);
    let (token_in, token_out) = if zero_for_one { (c0, c1) } else { (c1, c0) };
    let mut intent = Intent {
        token_in,
        token_out,
        ..Intent::new(Kind::Swap, call)
    };
    amounts(&mut intent, first, second, exact_in);
    Ok(intent)
}

/// (currency, PathKey[] path, amount, amount). Exact-in names the input currency and
/// the path ends at the output; exact-out names the output and path[0] is the input.
fn v4_multi(call: &Call, p: &[u8], exact_in: bool) -> Result<Option<Intent>> {
    let body = tuple_at(p, 0)?;
    let named = token(body, 0)?;
    let path = tuple_array(body, 1, call.budget)?;
    let (Some(head), Some(tail)) = (path.first(), path.last()) else {
        return Ok(None);
    };
    let (first, second) = (uint(body, 2)?, uint(body, 3)?);
    let (token_in, token_out) = if exact_in {
        (named, token(tail, 0)?)
    } else {
        (token(head, 0)?, named)
    };
    let mut intent = Intent {
        token_in,
        token_out,
        ..Intent::new(Kind::Swap, call)
    };
    amounts(&mut intent, first, second, exact_in);
    Ok(Some(intent))
}

fn v4(call: &Call, p: &[u8], out: &mut Vec<Intent>) -> Result<()> {
    let actions = dynamic(p, 0)?;
    let params = bytes_array(p, 1, call.budget)?;
    if params.len() < actions.len() {
        return Err(Malformed);
    }
    for (k, &action) in actions.iter().enumerate() {
        let param = params.get(k);
        match action {
            SWAP_EXACT_IN_SINGLE => out.push(v4_single(call, param, true)?),
            SWAP_EXACT_OUT_SINGLE => out.push(v4_single(call, param, false)?),
            SWAP_EXACT_IN => out.extend(v4_multi(call, param, true)?),
            SWAP_EXACT_OUT => out.extend(v4_multi(call, param, false)?),
            _ => {}
        }
    }
    Ok(())
}

pub fn execute(call: &Call, out: &mut Vec<Intent>) -> Result<()> {
    let d = &call.data[4..];
    let commands = dynamic(d, 0)?;
    let inputs = bytes_array(d, 1, call.budget)?;
    if inputs.len() < commands.len() {
        return Err(Malformed);
    }
    for (k, &command) in commands.iter().enumerate() {
        let p = inputs.get(k);
        match command & COMMAND_MASK {
            V3_SWAP_EXACT_IN => out.push(v3(call, p, true)?),
            V3_SWAP_EXACT_OUT => out.push(v3(call, p, false)?),
            kind @ (V2_SWAP_EXACT_IN | V2_SWAP_EXACT_OUT) => {
                out.extend(v2(call, p, kind == V2_SWAP_EXACT_IN)?);
            }
            V4_SWAP => v4(call, p, out)?,
            _ => {}
        }
    }
    Ok(())
}
