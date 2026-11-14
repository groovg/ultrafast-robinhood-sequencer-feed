//! Relay's router: a solver's fill (the wallet is only `refundTo`) and a wallet's sell
//! (proceeds go to Relay). The inner swap folds into the one Relay intent, so a consumer
//! counting trades sees one. Executor calls are unverified contracts read by shape: the
//! first `address[]` names the token.

use super::abi::{
    Result, WORD, address, dynamic, small, static_array, tuple_array, tuple_at, uint, word,
};
use super::{Call, Intent, Kind, decode_call};

/// Executor entry points, read by shape, never dispatched.
const EXECUTOR_SWEEP: [u8; 4] = [0x9b, 0xb4, 0x37, 0x18];
const EXECUTOR_DEPOSIT: [u8; 4] = [0x73, 0xb7, 0xbb, 0x2f];

fn first_token(executor_data: &[u8]) -> Result<Option<[u8; 20]>> {
    match static_array(&executor_data[4..], 0, 1)?.next() {
        Some(t) => Ok(Some(address(t, 0)?)),
        None => Ok(None),
    }
}

/// Decodes the inner calls into `found` and returns the token named by the executor.
fn walk(
    call: &Call,
    calls: &[u8],
    depth: usize,
    found: &mut Vec<Intent>,
) -> Result<Option<[u8; 20]>> {
    let mut executor_token = None;
    for c in tuple_array(calls, 2, call.budget)?.iter() {
        let (target, value, data) = (address(c, 0)?, uint(c, 2)?, dynamic(c, 3)?);
        if data
            .get(..4)
            .is_some_and(|s| s == EXECUTOR_SWEEP || s == EXECUTOR_DEPOSIT)
        {
            executor_token = first_token(data)?.or(executor_token);
            continue;
        }
        decode_call(&call.inner(target, value, data, None)?, depth + 1, found);
    }
    Ok(executor_token)
}

/// The word after the ABI body, which ends with the last dynamic argument at `last_slot`.
fn trailing_word(d: &[u8], last_slot: usize) -> Result<Option<[u8; 32]>> {
    let off = small(word(d, last_slot)?).unwrap_or(usize::MAX);
    let n = word(d.get(off..).unwrap_or_default(), 0)?;
    let end = small(n)
        .and_then(|n| n.checked_add(WORD - 1))
        .and_then(|n| (n / WORD).checked_mul(WORD))
        .and_then(|padded| off.checked_add(WORD)?.checked_add(padded));
    Ok(end
        .filter(|&end| d.len().checked_sub(end) == Some(WORD))
        .map(|end| d[end..].try_into().unwrap()))
}

fn swap_out(found: &[Intent]) -> (Option<[u8; 20]>, Option<[u8; 32]>) {
    found
        .iter()
        .find(|i| i.kind == Kind::Swap && i.token_out.is_some())
        .map_or((None, None), |i| (i.token_out, i.amount_out))
}

pub fn fill(call: &Call, depth: usize, out: &mut Vec<Intent>) -> Result<()> {
    let d = &call.data[4..];
    let permit = tuple_at(d, 1)?;
    let Some(permitted) = static_array(permit, 0, 2)?.next() else {
        return Ok(());
    };
    let wallet = address(d, 3)?;
    let mut found = Vec::new();
    let executor_token = walk(call, d, depth, &mut found)?;
    let (token_out, amount_out) = swap_out(&found);
    out.push(Intent {
        actor: Some(wallet),
        payer: Some(address(d, 0)?),
        token_in: Some(address(permitted, 0)?),
        token_out: executor_token.or(token_out),
        amount_in: Some(uint(permitted, 1)?),
        amount_out,
        recipient: Some(wallet),
        order_id: trailing_word(d, 6)?,
        ..Intent::new(Kind::RelayFill, call)
    });
    Ok(())
}

pub fn sell(call: &Call, depth: usize, out: &mut Vec<Intent>) -> Result<()> {
    let d = &call.data[4..];
    let (mut tokens, mut amounts) = (static_array(d, 0, 1)?, static_array(d, 1, 1)?);
    let (Some(token), Some(amount)) = (tokens.next(), amounts.next()) else {
        return Ok(());
    };
    let mut found = Vec::new();
    let executor_token = walk(call, d, depth, &mut found)?;
    let (token_out, amount_out) = swap_out(&found);
    out.push(Intent {
        token_in: Some(address(token, 0)?),
        token_out: executor_token.or(token_out),
        amount_in: Some(uint(amount, 0)?),
        amount_out,
        order_id: trailing_word(d, 5)?,
        ..Intent::new(Kind::RelaySell, call)
    });
    Ok(())
}
