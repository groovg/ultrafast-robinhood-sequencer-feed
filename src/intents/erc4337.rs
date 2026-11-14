//! ERC-4337 bundles. Each operation's `sender` is the wallet and becomes `actor`.
//! EntryPoint v0.7 and v0.8 share the packed struct; v0.6 isn't handled.

use super::abi::{
    Malformed, Result, address, bytes_array, dynamic, static_array, tuple_array, uint,
};
use super::{Call, Intent, decode_call};

pub fn handle_ops(call: &Call, depth: usize, out: &mut Vec<Intent>) -> Result<()> {
    for op in tuple_array(&call.data[4..], 0, call.budget)?.iter() {
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
    for c in tuple_array(&call.data[4..], 0, call.budget)?.iter() {
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
        bytes_array(d, 2, call.budget)?,
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
    let (targets, datas) = (static_array(d, 0, 1)?, bytes_array(d, 1, call.budget)?);
    if targets.len() != datas.len() {
        return Err(Malformed);
    }
    for (t, data) in targets.zip(datas.iter()) {
        let inner = call.inner(address(t, 0)?, [0; 32], data, None)?;
        decode_call(&inner, depth + 1, out);
    }
    Ok(())
}
