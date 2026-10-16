//! Read ABI-encoded arguments slot by slot, without a type interpreter.
//!
//! Calldata after the selector is a run of 32-byte slots. A static value sits in its
//! slot; a dynamic one leaves an offset there and its body further on. Each reader here
//! slices once and returns `Malformed` when the payload can't hold what was asked.
//! `decode_call` turns that into "no intent". Same rules as the Python version's
//! `abi.py`, including which bad inputs are refused.

pub const WORD: usize = 32;
pub const ZERO: [u8; 20] = [0; 20];
/// What Uniswap, 0x and others use for native ETH where an ERC-20 address is expected.
pub const NATIVE: [u8; 20] = [0xee; 20];

/// The payload does not hold what the ABI layout says it should.
#[derive(Debug)]
pub struct Malformed;

pub type Result<T> = std::result::Result<T, Malformed>;

pub fn word(d: &[u8], i: usize) -> Result<&[u8; 32]> {
    let start = i.checked_mul(WORD).ok_or(Malformed)?;
    let end = start.checked_add(WORD).ok_or(Malformed)?;
    d.get(start..end)
        .map(|w| w.try_into().unwrap())
        .ok_or(Malformed)
}

pub fn uint(d: &[u8], i: usize) -> Result<[u8; 32]> {
    word(d, i).copied()
}

/// A slot as a length or offset. None when it doesn't fit 64 bits, which every caller
/// treats as past the end, as the Python version's unbounded ints do.
pub fn small(w: &[u8; 32]) -> Option<usize> {
    if w[..24].iter().any(|&b| b != 0) {
        return None;
    }
    usize::try_from(u64::from_be_bytes(w[24..].try_into().unwrap())).ok()
}

pub fn address(d: &[u8], i: usize) -> Result<[u8; 20]> {
    let w = word(d, i)?;
    if w[..12].iter().any(|&b| b != 0) {
        return Err(Malformed);
    }
    Ok(w[12..].try_into().unwrap())
}

/// An address slot where the zero address or 0xeeee…eeee means native ETH.
pub fn token(d: &[u8], i: usize) -> Result<Option<[u8; 20]>> {
    let a = address(d, i)?;
    Ok((a != ZERO && a != NATIVE).then_some(a))
}

fn offset(d: &[u8], i: usize) -> Result<usize> {
    small(word(d, i)?)
        .filter(|off| off % WORD == 0 && off.checked_add(WORD).is_some_and(|e| e <= d.len()))
        .ok_or(Malformed)
}

/// The `bytes` (or `string`) whose offset is in slot `i`.
pub fn dynamic(d: &[u8], i: usize) -> Result<&[u8]> {
    let off = offset(d, i)?;
    let start = off + WORD;
    small(d[off..start].try_into().unwrap())
        .and_then(|n| d.get(start..start.checked_add(n)?))
        .ok_or(Malformed)
}

/// Body of the dynamic tuple whose offset is in slot `i`. Slots inside are relative.
pub fn tuple_at(d: &[u8], i: usize) -> Result<&[u8]> {
    Ok(&d[offset(d, i)?..])
}

/// (element area, count) of the array whose offset is in slot `i`.
fn elements(d: &[u8], i: usize, width: usize) -> Result<(&[u8], usize)> {
    let body = tuple_at(d, i)?;
    let area = &body[WORD..];
    let n = small(word(body, 0)?)
        .filter(|&n| n <= area.len() / (width * WORD))
        .ok_or(Malformed)?;
    Ok((area, n))
}

/// Array of static elements, each `width` slots wide. One slice per element.
pub fn static_array(d: &[u8], i: usize, width: usize) -> Result<std::slice::ChunksExact<'_, u8>> {
    let (area, n) = elements(d, i, width)?;
    Ok(area[..n * width * WORD].chunks_exact(width * WORD))
}

/// Elements of an array of dynamic values, every offset checked up front, as the
/// Python version's list comprehensions do before any element is used.
#[derive(Clone, Copy)]
pub struct Dynamic<'a> {
    area: &'a [u8],
    n: usize,
    bytes: bool,
}

impl<'a> Dynamic<'a> {
    pub fn len(&self) -> usize {
        self.n
    }

    fn at(&self, k: usize) -> Result<&'a [u8]> {
        let off = offset(self.area, k)?;
        if !self.bytes {
            return Ok(&self.area[off..]);
        }
        let start = off + WORD;
        small(self.area[off..start].try_into().unwrap())
            .and_then(|size| self.area.get(start..start.checked_add(size)?))
            .ok_or(Malformed)
    }

    /// Element `k`. Every element was checked when the array was read.
    pub fn get(&self, k: usize) -> &'a [u8] {
        self.at(k).unwrap_or_default()
    }

    pub fn first(&self) -> Option<&'a [u8]> {
        (self.n > 0).then(|| self.get(0))
    }

    pub fn last(&self) -> Option<&'a [u8]> {
        (self.n > 0).then(|| self.get(self.n - 1))
    }

    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        (0..self.n).map(|k| self.get(k))
    }
}

fn checked(area: &[u8], n: usize, bytes: bool) -> Result<Dynamic<'_>> {
    let array = Dynamic { area, n, bytes };
    for k in 0..n {
        array.at(k)?;
    }
    Ok(array)
}

/// Array of dynamic tuples. Each element's offset is relative to the element area.
pub fn tuple_array(d: &[u8], i: usize) -> Result<Dynamic<'_>> {
    let (area, n) = elements(d, i, 1)?;
    checked(area, n, false)
}

/// `bytes[]`: each element is a length-prefixed blob at its own offset.
pub fn bytes_array(d: &[u8], i: usize) -> Result<Dynamic<'_>> {
    let (area, n) = elements(d, i, 1)?;
    checked(area, n, true)
}
