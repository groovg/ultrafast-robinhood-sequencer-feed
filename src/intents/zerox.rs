//! 0x Protocol v2: AllowanceHolder.exec hands tokens to a Settler, which runs the route.
//!
//! `exec` names what is sold. Settler's leading slippage tuple names who receives,
//! which token, and the minimum, unless it is all zeros, which tells Settler to skip the
//! check and tells us nothing. The route itself is not read.

use super::abi::{Result, ZERO, address, dynamic, token, uint};
use super::{Call, Intent, Kind, SETTLER_EXECUTE};

pub fn exec(call: &Call, out: &mut Vec<Intent>) -> Result<()> {
    let d = &call.data[4..];
    let target = address(d, 3)?;
    let mut intent = Intent {
        via: call.via.with(target)?,
        token_in: token(d, 1)?,
        amount_in: Some(uint(d, 2)?),
        ..Intent::new(Kind::Swap, call)
    };
    let inner = dynamic(d, 4)?;
    if inner.get(..4) == Some(&SETTLER_EXECUTE.to_be_bytes()[..]) {
        let s = &inner[4..];
        let recipient = address(s, 0)?;
        if recipient != ZERO {
            intent.recipient = Some(recipient);
            intent.token_out = token(s, 1)?;
            intent.amount_out = Some(uint(s, 2)?);
        }
    }
    out.push(intent);
    Ok(())
}
