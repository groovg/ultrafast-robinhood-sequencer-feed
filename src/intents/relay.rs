//! Relay's router: a solver's fill and a wallet's sell, one intent each.
//!
//! A buy is paid on Solana and filled here by a solver spending its own money through
//! `permit2TransferAndMulticall`; the wallet appears only as `refundTo`. A sell runs
//! inside the wallet's own 4337 operation through `transferAndMulticall`, and the
//! proceeds go to Relay, not back to the wallet.
//!
//! Both carry a `calls` array of [approve, AllowanceHolder.exec, executor sweep or
//! deposit]. The swap inside is decoded through the table, but its output is folded
//! into the one Relay intent rather than returned beside it, so a consumer counting
//! trades sees one.
//!
//! The executor's calls are unverified contracts read by shape: four dynamic arrays,
//! the first of them `address[] tokens`. The Python version's authors confirmed against
//! receipts on 2026-10-07 that a fill's sweep names the delivered token, a sell's
//! deposit names what Relay receives, and the word Relay appends after the ABI body of
//! both router calls is the order id.

use super::abi::{
    Result, WORD, address, dynamic, small, static_array, tuple_array, tuple_at, uint, word,
};
use super::{Call, Intent, Kind, decode_call};

/// Executor entry points seen under the router. Read by shape, never dispatched.
const EXECUTOR_SWEEP: [u8; 4] = [0x9b, 0xb4, 0x37, 0x18];
const EXECUTOR_DEPOSIT: [u8; 4] = [0x73, 0xb7, 0xbb, 0x2f];

/// First address of the first array in an executor call.
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
    for c in tuple_array(calls, 2)?.iter() {
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

/// The word Relay appends after the ABI body, or None when there is none. `last_slot`
/// holds the offset of the final dynamic argument; the body ends where that argument's
/// padded bytes end.
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

/// Output named by an inner swap's slippage check, when there was one.
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
