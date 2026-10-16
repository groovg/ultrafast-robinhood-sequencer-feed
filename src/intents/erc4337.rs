//! ERC-4337 bundles and the account calls inside them.
//!
//! The transaction sender is a bundler and tells you nothing. Each operation's `sender`
//! is the wallet, and becomes `actor` for everything decoded under it. Its `callData` is
//! a call on the wallet: `execute`, or one of the `executeBatch` shapes
//! (Simple7702Account's tuple array, SimpleAccount v0.7's three parallel arrays, and the
//! older two arrays without values). Those carry the calls the user wanted.
//!
//! v0.7 and v0.8 share the packed struct and the selector. v0.6 is unpacked, keyed
//! differently, and not here.

use super::abi::{
    Malformed, Result, address, bytes_array, dynamic, static_array, tuple_array, uint,
};
use super::{Call, Intent, decode_call};

pub fn handle_ops(call: &Call, depth: usize, out: &mut Vec<Intent>) -> Result<()> {
    for op in tuple_array(&call.data[4..], 0)?.iter() {
        let wallet = address(op, 0)?;
        let inner = call.inner(wallet, [0; 32], dynamic(op, 3)?, Some(wallet))?;
        decode_call(&inner, depth + 1, out);
    }
    Ok(())
}

pub fn execute(call: &Call, depth: usize, out: &mut Vec<Intent>) -> Result<()> {
    let d = &call.data[4..];
    let inner = call.inner(address(d, 0)?, uint(d, 1)?, dynamic(d, 2)?, None)?;
    decode_call(&inner, depth + 1, out);
    Ok(())
}

pub fn execute_batch(call: &Call, depth: usize, out: &mut Vec<Intent>) -> Result<()> {
    for c in tuple_array(&call.data[4..], 0)?.iter() {
        let inner = call.inner(address(c, 0)?, uint(c, 1)?, dynamic(c, 2)?, None)?;
        decode_call(&inner, depth + 1, out);
    }
    Ok(())
}

pub fn execute_batch_parallel(call: &Call, depth: usize, out: &mut Vec<Intent>) -> Result<()> {
    let d = &call.data[4..];
    let (targets, values, datas) = (
        static_array(d, 0, 1)?,
        static_array(d, 1, 1)?,
        bytes_array(d, 2)?,
    );
    if targets.len() != values.len() || values.len() != datas.len() {
        return Err(Malformed);
    }
    for ((t, v), data) in targets.zip(values).zip(datas.iter()) {
        let inner = call.inner(address(t, 0)?, uint(v, 0)?, data, None)?;
        decode_call(&inner, depth + 1, out);
    }
    Ok(())
}

pub fn execute_batch_no_values(call: &Call, depth: usize, out: &mut Vec<Intent>) -> Result<()> {
    let d = &call.data[4..];
    let (targets, datas) = (static_array(d, 0, 1)?, bytes_array(d, 1)?);
    if targets.len() != datas.len() {
        return Err(Malformed);
    }
    for (t, data) in targets.zip(datas.iter()) {
        let inner = call.inner(address(t, 0)?, [0; 32], data, None)?;
        decode_call(&inner, depth + 1, out);
    }
    Ok(())
}
