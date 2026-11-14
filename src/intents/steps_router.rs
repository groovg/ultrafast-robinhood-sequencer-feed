//! An unnamed aggregator: `swap(steps[], recipient, amountIn, amountOutMin[, deadline])`.
//! No published source; slot 1 of a step is the input token, slot 2 the output.

use super::abi::{Result, token, tuple_array, uint};
use super::{Call, Intent, Kind};

pub fn swap(call: &Call, out: &mut Vec<Intent>) -> Result<()> {
    let d = &call.data[4..];
    let steps = tuple_array(d, 0, call.budget)?;
    let (Some(first), Some(last)) = (steps.first(), steps.last()) else {
        return Ok(());
    };
    out.push(Intent {
        token_in: token(first, 1)?,
        token_out: token(last, 2)?,
        amount_in: Some(uint(d, 2)?),
        amount_out: Some(uint(d, 3)?),
        // The zero address means the caller, so None resolves to the actor downstream.
        recipient: token(d, 1)?,
        ..Intent::new(Kind::Swap, call)
    });
    Ok(())
}
