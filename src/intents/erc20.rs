//! ERC-20 transfers and approvals, and Permit2's approve. The token is the contract
//! called, except on Permit2 where it is the first argument.

use super::abi::{Result, address, uint};
use super::{Call, Intent, Kind};

pub fn transfer(call: &Call, out: &mut Vec<Intent>) -> Result<()> {
    let d = &call.data[4..];
    out.push(Intent {
        token_in: call.to,
        amount_in: Some(uint(d, 1)?),
        recipient: Some(address(d, 0)?),
        ..Intent::new(Kind::Transfer, call)
    });
    Ok(())
}

pub fn transfer_from(call: &Call, out: &mut Vec<Intent>) -> Result<()> {
    let d = &call.data[4..];
    out.push(Intent {
        payer: Some(address(d, 0)?),
        token_in: call.to,
        amount_in: Some(uint(d, 2)?),
        recipient: Some(address(d, 1)?),
        ..Intent::new(Kind::Transfer, call)
    });
    Ok(())
}

pub fn approve(call: &Call, out: &mut Vec<Intent>) -> Result<()> {
    let d = &call.data[4..];
    out.push(Intent {
        token_in: call.to,
        amount_in: Some(uint(d, 1)?),
        recipient: Some(address(d, 0)?),
        ..Intent::new(Kind::Approve, call)
    });
    Ok(())
}

pub fn permit2_approve(call: &Call, out: &mut Vec<Intent>) -> Result<()> {
    let d = &call.data[4..];
    out.push(Intent {
        token_in: Some(address(d, 0)?),
        amount_in: Some(uint(d, 2)?),
        recipient: Some(address(d, 1)?),
        ..Intent::new(Kind::Approve, call)
    });
    Ok(())
}
