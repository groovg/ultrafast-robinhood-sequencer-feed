//! Turn calldata into trade intents.
//!
//! ```no_run
//! # fn f(tx: &rhfeed::Tx, watch: &std::collections::HashSet<[u8; 20]>) {
//! use rhfeed::intents::{Kind, decode_intents};
//! for intent in decode_intents(tx) {
//!     if intent.kind == Kind::Swap && intent.token_out.is_some_and(|t| watch.contains(&t)) {
//!         // ...
//!     }
//! }
//! # }
//! ```
//!
//! `actor` is not the transaction sender: in a 4337 bundle it is the user inside, in a
//! Relay fill the wallet delivered to. `None` means the sender, left unrecovered.

mod abi;
mod erc20;
mod erc4337;
mod pons;
mod relay;
mod steps_router;
mod uniswap;
mod universal_router;
mod zerox;

use std::fmt::Write as _;
use std::sync::LazyLock;

use serde::ser::{Serialize, SerializeStruct, Serializer};

use crate::codec::{Tx, addr, checksum, decimal};
use abi::{Malformed, Result};

/// Five deep is seen on mainnet; eight leaves room and stops a self-nesting payload.
pub const MAX_DEPTH: usize = 8;

/// The `to`, one per nesting level, one for a 0x target, and room to spare.
const VIA_MAX: usize = 12;

/// What an intent asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `token_in` sold, `token_out` bought, `recipient` gets the output.
    Swap,
    /// `token_in` moved to `recipient`; `payer` set when not the actor.
    Transfer,
    /// `token_in` approved to `recipient` for `amount_in`.
    Approve,
    /// A solver delivers `token_out` to `recipient` (the actor).
    RelayFill,
    /// The actor sells `token_in` for Relay credit paid out elsewhere.
    RelaySell,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Swap => "swap",
            Kind::Transfer => "transfer",
            Kind::Approve => "approve",
            Kind::RelayFill => "relay_fill",
            Kind::RelaySell => "relay_sell",
        }
    }
}

/// Contracts walked to reach a call, outermost first. Inline, so nesting doesn't allocate.
#[derive(Clone, Copy)]
pub struct Via {
    len: u8,
    path: [[u8; 20]; VIA_MAX],
}

impl Via {
    pub const EMPTY: Via = Via {
        len: 0,
        path: [[0; 20]; VIA_MAX],
    };

    pub fn from_slice(path: &[[u8; 20]]) -> Option<Via> {
        let mut via = Via::EMPTY;
        via.path.get_mut(..path.len())?.copy_from_slice(path);
        via.len = path.len() as u8;
        Some(via)
    }

    fn with(&self, to: [u8; 20]) -> Result<Via> {
        let mut via = *self;
        *via.path.get_mut(usize::from(via.len)).ok_or(Malformed)? = to;
        via.len += 1;
        Ok(via)
    }
}

impl std::ops::Deref for Via {
    type Target = [[u8; 20]];
    fn deref(&self) -> &[[u8; 20]] {
        &self.path[..usize::from(self.len)]
    }
}

impl PartialEq for Via {
    fn eq(&self, other: &Via) -> bool {
        **self == **other
    }
}

impl Eq for Via {}

impl std::fmt::Debug for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.iter().map(|a| format!("0x{}", hex::encode(a))))
            .finish()
    }
}

/// The top-level transaction, or a call nested inside one.
#[derive(Clone, Copy)]
pub struct Call<'a> {
    pub to: Option<[u8; 20]>,
    pub value: [u8; 32],
    pub data: &'a [u8],
    /// None means the transaction sender.
    pub actor: Option<[u8; 20]>,
    pub via: Via,
}

impl<'a> Call<'a> {
    fn inner(
        &self,
        to: [u8; 20],
        value: [u8; 32],
        data: &'a [u8],
        actor: Option<[u8; 20]>,
    ) -> Result<Call<'a>> {
        Ok(Call {
            to: Some(to),
            value,
            data,
            actor: actor.or(self.actor),
            via: self.via.with(to)?,
        })
    }
}

/// What a call asks for, not what it got. Amounts are big-endian uint256: `amount_in`
/// exact and `amount_out` a minimum when `exact_in`, the other way round otherwise. A
/// token of None is native ETH.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    pub kind: Kind,
    pub actor: Option<[u8; 20]>,
    pub via: Via,
    pub payer: Option<[u8; 20]>,
    pub token_in: Option<[u8; 20]>,
    pub token_out: Option<[u8; 20]>,
    pub amount_in: Option<[u8; 32]>,
    pub amount_out: Option<[u8; 32]>,
    pub exact_in: bool,
    pub recipient: Option<[u8; 20]>,
    /// The word Relay appends after the ABI body.
    pub order_id: Option<[u8; 32]>,
}

impl Intent {
    fn new(kind: Kind, call: &Call) -> Intent {
        Intent {
            kind,
            actor: call.actor,
            via: call.via,
            payer: None,
            token_in: None,
            token_out: None,
            amount_in: None,
            amount_out: None,
            exact_in: true,
            recipient: None,
            order_id: None,
        }
    }

    /// The one-line summary the Python CLI prints.
    pub fn describe(&self) -> String {
        let mut out = format!("{:<12}", self.kind.as_str());
        if self.token_in.is_some() || self.amount_in.is_some() {
            let side = token_label(self.token_in, self.amount_in.is_some());
            write!(out, "  in {side}").unwrap();
            if let Some(a) = &self.amount_in {
                write!(out, " {}", decimal(a)).unwrap();
            }
        }
        if matches!(self.kind, Kind::Swap | Kind::RelayFill | Kind::RelaySell) {
            let side = token_label(self.token_out, self.amount_out.is_some());
            write!(out, "  out {side}").unwrap();
            if let Some(a) = &self.amount_out {
                let bound = if self.exact_in { "min" } else { "exact" };
                write!(out, " {bound} {}", decimal(a)).unwrap();
            }
        }
        if let Some(r) = &self.recipient {
            let actor = if Some(*r) == self.actor {
                " (actor)"
            } else {
                ""
            };
            write!(out, "  → {}{actor}", label(r)).unwrap();
        }
        if !self.via.is_empty() {
            let path: Vec<String> = self.via.iter().map(label).collect();
            write!(out, "  via {}", path.join(" > ")).unwrap();
        }
        out
    }
}

/// A missing token is ETH only when an amount says so; otherwise it is unknown.
fn token_label(token: Option<[u8; 20]>, has_amount: bool) -> String {
    match token {
        Some(t) => label(&t),
        None if has_amount => "ETH".into(),
        None => "?".into(),
    }
}

/// The Python version's `Intent.as_dict()`: amounts as plain JSON numbers however big.
impl Serialize for Intent {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let a = |v: &Option<[u8; 20]>| v.as_ref().map(|v| checksum(v));
        let n = |v: &Option<[u8; 32]>| {
            v.as_ref()
                .map(|v| sonic_rs::from_str::<sonic_rs::RawNumber>(&decimal(v)).unwrap())
        };
        let mut st = s.serialize_struct("Intent", 11)?;
        st.serialize_field("kind", self.kind.as_str())?;
        st.serialize_field("actor", &a(&self.actor))?;
        let via: Vec<String> = self.via.iter().map(|v| checksum(v)).collect();
        st.serialize_field("via", &via)?;
        st.serialize_field("payer", &a(&self.payer))?;
        st.serialize_field("token_in", &a(&self.token_in))?;
        st.serialize_field("token_out", &a(&self.token_out))?;
        st.serialize_field("amount_in", &n(&self.amount_in))?;
        st.serialize_field("amount_out", &n(&self.amount_out))?;
        st.serialize_field("exact_in", &self.exact_in)?;
        st.serialize_field("recipient", &a(&self.recipient))?;
        let order = self.order_id.map(|o| format!("0x{}", hex::encode(o)));
        st.serialize_field("order_id", &order)?;
        st.end()
    }
}

macro_rules! selectors {
    ($($name:ident = $hex:literal, $sig:literal;)*) => {
        $(pub(crate) const $name: u32 = $hex;)*
        #[cfg(test)]
        const SIGNATURES: &[(u32, &str)] = &[$(($hex, $sig)),*];
    };
}

selectors! {
    TRANSFER = 0xa9059cbb, "transfer(address,uint256)";
    TRANSFER_FROM = 0x23b872dd, "transferFrom(address,address,uint256)";
    APPROVE = 0x095ea7b3, "approve(address,uint256)";
    PERMIT2_APPROVE = 0x87517c45, "approve(address,address,uint160,uint48)";
    EXACT_INPUT_SINGLE = 0x04e45aaf, "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))";
    EXACT_INPUT_SINGLE_V1 = 0x414bf389, "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))";
    EXACT_OUTPUT_SINGLE = 0x5023b4df, "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))";
    EXACT_OUTPUT_SINGLE_V1 = 0xdb3e2198, "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))";
    EXACT_INPUT = 0xb858183f, "exactInput((bytes,address,uint256,uint256))";
    EXACT_INPUT_V1 = 0xc04b8d59, "exactInput((bytes,address,uint256,uint256,uint256))";
    EXACT_OUTPUT = 0x09b81346, "exactOutput((bytes,address,uint256,uint256))";
    EXACT_OUTPUT_V1 = 0xf28c0498, "exactOutput((bytes,address,uint256,uint256,uint256))";
    V2_EXACT_TOKENS_FOR_TOKENS = 0x38ed1739, "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)";
    V2_EXACT_TOKENS_FOR_TOKENS_FOT = 0x5c11d795, "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)";
    V2_EXACT_TOKENS_FOR_ETH = 0x18cbafe5, "swapExactTokensForETH(uint256,uint256,address[],address,uint256)";
    V2_EXACT_TOKENS_FOR_ETH_FOT = 0x791ac947, "swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)";
    V2_EXACT_ETH_FOR_TOKENS = 0x7ff36ab5, "swapExactETHForTokens(uint256,address[],address,uint256)";
    V2_EXACT_ETH_FOR_TOKENS_FOT = 0xb6f9de95, "swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)";
    V2_TOKENS_FOR_EXACT_TOKENS = 0x8803dbee, "swapTokensForExactTokens(uint256,uint256,address[],address,uint256)";
    V2_TOKENS_FOR_EXACT_ETH = 0x4a25d94a, "swapTokensForExactETH(uint256,uint256,address[],address,uint256)";
    V2_ETH_FOR_EXACT_TOKENS = 0xfb3bdb41, "swapETHForExactTokens(uint256,address[],address,uint256)";
    MULTICALL = 0xac9650d8, "multicall(bytes[])";
    MULTICALL_DEADLINE = 0x5ae401dc, "multicall(uint256,bytes[])";
    MULTICALL_BLOCKHASH = 0x1f0464d1, "multicall(bytes32,bytes[])";
    UR_EXECUTE_DEADLINE = 0x3593564c, "execute(bytes,bytes[],uint256)";
    UR_EXECUTE = 0x24856bc3, "execute(bytes,bytes[])";
    HANDLE_OPS = 0x765e827f, "handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)";
    ACCOUNT_EXECUTE = 0xb61d27f6, "execute(address,uint256,bytes)";
    EXECUTE_BATCH = 0x34fcd5be, "executeBatch((address,uint256,bytes)[])";
    EXECUTE_BATCH_PARALLEL = 0x47e1da2a, "executeBatch(address[],uint256[],bytes[])";
    EXECUTE_BATCH_NO_VALUES = 0x18dfb3c7, "executeBatch(address[],bytes[])";
    RELAY_FILL = 0x0a2b8f36, "permit2TransferAndMulticall(address,((address,uint256)[],uint256,uint256),(address,bool,uint256,bytes)[],address,address,bytes,bytes)";
    RELAY_SELL = 0xf9e4bab4, "transferAndMulticall(address[],uint256[],(address,bool,uint256,bytes)[],address,address,bytes)";
    ZEROX_EXEC = 0x2213bc0b, "exec(address,address,uint256,address,bytes)";
    SETTLER_EXECUTE = 0x1fff991f, "execute((address,address,uint256),bytes[],bytes32)";
    STEPS_SWAP = 0x4d819a2a, "swap((uint8,address,address,address,uint24,int24,address,bytes,address,bytes32)[],address,uint256,uint256,uint256)";
    STEPS_SWAP_V1 = 0xe6cb474f, "swap((uint8,address,address,address,uint24,int24,address,bytes)[],address,uint256,uint256)";
}

/// Pons's buy. No signature database knows it; see `pons.rs`.
pub(crate) const PONS_BUY: u32 = 0xc1120e3d;

/// Append `call`'s intents to `out`. One that doesn't fit its layout adds nothing.
pub fn decode_call(call: &Call, depth: usize, out: &mut Vec<Intent>) {
    if depth > MAX_DEPTH || call.data.len() < 4 {
        return;
    }
    let selector = u32::from_be_bytes(call.data[..4].try_into().unwrap());
    let start = out.len();
    let decoded = match selector {
        TRANSFER => erc20::transfer(call, out),
        TRANSFER_FROM => erc20::transfer_from(call, out),
        APPROVE => erc20::approve(call, out),
        PERMIT2_APPROVE => erc20::permit2_approve(call, out),
        EXACT_INPUT_SINGLE => uniswap::single(call, out, [3, 4, 5], true),
        EXACT_INPUT_SINGLE_V1 => uniswap::single(call, out, [3, 5, 6], true),
        EXACT_OUTPUT_SINGLE => uniswap::single(call, out, [3, 4, 5], false),
        EXACT_OUTPUT_SINGLE_V1 => uniswap::single(call, out, [3, 5, 6], false),
        EXACT_INPUT => uniswap::path(call, out, [1, 2, 3], true),
        EXACT_INPUT_V1 => uniswap::path(call, out, [1, 3, 4], true),
        EXACT_OUTPUT => uniswap::path(call, out, [1, 2, 3], false),
        EXACT_OUTPUT_V1 => uniswap::path(call, out, [1, 3, 4], false),
        V2_EXACT_TOKENS_FOR_TOKENS
        | V2_EXACT_TOKENS_FOR_TOKENS_FOT
        | V2_EXACT_TOKENS_FOR_ETH
        | V2_EXACT_TOKENS_FOR_ETH_FOT
        | V2_EXACT_ETH_FOR_TOKENS
        | V2_EXACT_ETH_FOR_TOKENS_FOT
        | V2_TOKENS_FOR_EXACT_TOKENS
        | V2_TOKENS_FOR_EXACT_ETH
        | V2_ETH_FOR_EXACT_TOKENS => uniswap::v2(call, out, selector),
        MULTICALL => uniswap::multicall(call, depth, out, 0),
        MULTICALL_DEADLINE | MULTICALL_BLOCKHASH => uniswap::multicall(call, depth, out, 1),
        UR_EXECUTE_DEADLINE | UR_EXECUTE => universal_router::execute(call, out),
        HANDLE_OPS => erc4337::handle_ops(call, depth, out),
        ACCOUNT_EXECUTE => erc4337::execute(call, depth, out),
        EXECUTE_BATCH => erc4337::execute_batch(call, depth, out),
        EXECUTE_BATCH_PARALLEL => erc4337::execute_batch_parallel(call, depth, out),
        EXECUTE_BATCH_NO_VALUES => erc4337::execute_batch_no_values(call, depth, out),
        RELAY_FILL => relay::fill(call, depth, out),
        RELAY_SELL => relay::sell(call, depth, out),
        ZEROX_EXEC => zerox::exec(call, out),
        PONS_BUY => pons::buy(call, out),
        STEPS_SWAP | STEPS_SWAP_V1 => steps_router::swap(call, out),
        _ => return,
    };
    if decoded.is_err() {
        out.truncate(start);
    }
}

/// `decode_intents` on loose parts. `value` is big-endian, of any length.
pub fn decode(to: Option<[u8; 20]>, value: &[u8], data: &[u8]) -> Vec<Intent> {
    let skip = value.iter().take_while(|&&b| b == 0).count();
    let Some(pad) = 32usize.checked_sub(value.len() - skip) else {
        return Vec::new(); // over 256 bits: no slot can hold it
    };
    let mut v = [0u8; 32];
    v[pad..].copy_from_slice(&value[skip..]);
    let call = Call {
        to,
        value: v,
        data,
        actor: None,
        via: to.map_or(Via::EMPTY, |t| Via::EMPTY.with(t).unwrap()),
    };
    if let (Some(to), true, true) = (to, data.is_empty(), skip < value.len()) {
        return vec![Intent {
            amount_in: Some(v),
            recipient: Some(to),
            ..Intent::new(Kind::Transfer, &call)
        }];
    }
    let mut out = Vec::new();
    decode_call(&call, 0, &mut out);
    out
}

/// Every intent in one transaction. One with no known selector allocates nothing.
pub fn decode_intents(tx: &Tx) -> Vec<Intent> {
    decode(tx.to_bytes, tx.value_be(), tx.data())
}

/// Display names for `via`. Nothing dispatches on them.
const LABELS: &[(&str, &str)] = &[
    (
        "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108",
        "entrypoint_v08",
    ),
    (
        "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
        "entrypoint_v07",
    ),
    (
        "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",
        "entrypoint_v06",
    ),
    ("0xCcC88a9d1B4ED6b0EABA998850414b24f1c315bE", "relay_router"),
    (
        "0xb92fe925DC43a0ECdE6c8b1a2709c170Ec4fFf4f",
        "relay_executor",
    ),
    (
        "0x4cD00E387622C35bDDB9b4c962C136462338BC31",
        "relay_depository",
    ),
    (
        "0xf70da97812cb96acdf810712aa562db8dfa3dbef",
        "relay_solver_treasury",
    ),
    (
        "0x0000000000001fF3684f28c67538d4D072C22734",
        "allowance_holder",
    ),
    ("0x39b38686a19836ac10162c490e4558e120cbbe5f", "settler"),
    ("0x1d4b86491ec211257cbedd77a4380a7494624eff", "settler"),
    (
        "0xcaf681a66d020601342297493863e78c959e5cb2",
        "swap_router02",
    ),
    (
        "0x73991a25c818bf1f1128deaab1492d45638de0d3",
        "v3_position_manager",
    ),
    (
        "0x8366a39CC670B4001A1121B8F6A443A643e40951",
        "v4_pool_manager",
    ),
    ("0x1cbaF24D53fe930fCe8EFF149fA797D2611Da149", "pons"),
    ("0x000000000022D473030F116dDEE9F6B43aC78BA3", "permit2"),
    ("0x65050a9b7e5075a2ba5ced7b1b64ee66262c40dc", "steps_router"),
    ("0xe492912f37c2a4eca45d42dc67548f4c6cd7ce2b", "steps_router"),
    (
        "0x5b8d85ebabf17cf6b67bfa2fe6795623951cd70e",
        "steps_router_v1",
    ),
    ("0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", "USDG"),
    ("0x0bd7d308f8e1639fab988df18a8011f41eacad73", "WETH"),
];

static LABEL_BYTES: LazyLock<Vec<([u8; 20], &str)>> = LazyLock::new(|| {
    LABELS
        .iter()
        .map(|(a, name)| (addr(a).unwrap(), *name))
        .collect()
});

/// A known contract's name, or the address's first four bytes.
pub fn label(address: &[u8; 20]) -> String {
    match LABEL_BYTES.iter().find(|(a, _)| a == address) {
        Some((_, name)) => (*name).into(),
        None => format!("0x{}…", hex::encode(&address[..4])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::selector_of;

    #[test]
    fn every_selector_matches_its_signature() {
        for &(selector, signature) in SIGNATURES {
            assert_eq!(
                selector.to_be_bytes(),
                selector_of(signature),
                "{signature}"
            );
        }
    }

    #[test]
    fn a_selector_outside_the_table_yields_nothing() {
        let data = [0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0];
        assert!(decode(Some([1; 20]), &[], &data).is_empty());
        assert!(decode(Some([1; 20]), &[], &data[..2]).is_empty());
    }

    #[test]
    fn a_plain_eth_transfer_is_a_transfer() {
        let to = [7; 20];
        let out = decode(Some(to), &[0, 5], &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, Kind::Transfer);
        assert_eq!(out[0].recipient, Some(to));
        assert_eq!(out[0].amount_in.unwrap()[31], 5);
        assert!(decode(Some(to), &[0], &[]).is_empty());
    }
}
