use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use miden_core::{Word, field::PrimeField64};
pub use miden_processor::Felt as RawFelt;
#[cfg(feature = "proptest")]
use proptest::{
    arbitrary::Arbitrary,
    strategy::{BoxedStrategy, Strategy},
};
use serde::Deserialize;
use smallvec::{SmallVec, smallvec};

pub trait ToMidenRepr {
    /// Convert this type into its raw byte representation
    ///
    /// The order of bytes in the resulting vector should be little-endian, i.e. the least
    /// significant bytes come first.
    fn to_bytes(&self) -> SmallVec<[u8; 16]>;
    /// Convert this type into one or more field elements, where the order of the elements is such
    /// that the byte representation of `self` is in little-endian order, i.e. the least significant
    /// bytes come first.
    fn to_felts(&self) -> SmallVec<[RawFelt; 4]> {
        let bytes = self.to_bytes();
        let num_felts = bytes.len().div_ceil(4);
        let mut felts = SmallVec::<[RawFelt; 4]>::with_capacity(num_felts);
        let (chunks, remainder) = bytes.as_chunks::<4>();
        for chunk in chunks {
            felts.push(
                RawFelt::new(u32::from_ne_bytes(*chunk) as u64)
                    .expect("value exceeds field modulus"),
            );
        }
        if !remainder.is_empty() {
            let mut chunk = [0u8; 4];
            for (i, byte) in remainder.iter().enumerate() {
                chunk[i] = *byte;
            }
            felts.push(
                RawFelt::new(u32::from_ne_bytes(chunk) as u64)
                    .expect("value exceeds field modulus"),
            );
        }
        felts
    }
    /// Convert this type into one or more words, zero-padding as needed, such that:
    ///
    /// * The field elements within each word is in little-endian order, i.e. the least significant
    ///   bytes of come first.
    /// * Each word, if pushed on the operand stack element-by-element, would leave the element
    ///   with the most significant bytes on top of the stack (including padding)
    fn to_words(&self) -> SmallVec<[Word; 1]> {
        let felts = self.to_felts();
        let num_words = felts.len().div_ceil(4);
        let mut words = SmallVec::<[Word; 1]>::with_capacity(num_words);
        let (chunks, remainder) = felts.as_chunks::<4>();
        for mut word in chunks.iter().copied() {
            word.reverse();
            words.push(Word::new(word));
        }
        if !remainder.is_empty() {
            let mut word = [RawFelt::ZERO; 4];
            for (i, felt) in remainder.iter().enumerate() {
                word[i] = *felt;
            }
            word.reverse();
            words.push(Word::new(word));
        }
        words
    }

    /// Push this value on the given operand stack using [Self::to_felts] representation
    ///
    /// If pushing arguments for functions compiled from Wasm, consider using
    /// [`push_wasm_ty_to_operand_stack`] instead.
    fn push_to_operand_stack(&self, stack: &mut Vec<RawFelt>) {
        stack.extend(self.to_felts());
    }

    /// Push this value in its [Self::to_words] representation, on the given stack.
    ///
    /// This function is designed for encoding values that will be placed on the advice stack and
    /// copied into Miden VM memory by the compiler-emitted test harness.
    ///
    /// Returns the number of words that were pushed on the stack
    fn push_words_to_advice_stack(&self, stack: &mut Vec<RawFelt>) -> usize {
        let words = self.to_words();
        let num_words = words.len();
        for word in words.into_iter().rev() {
            for felt in word.into_iter() {
                stack.push(felt);
            }
        }
        num_words
    }
}

pub trait FromMidenRepr: Sized {
    /// Returns the size of this type as encoded by [ToMidenRepr::to_felts]
    fn size_in_felts() -> usize;
    /// Extract a value of this type from `bytes`, where:
    ///
    /// * It is assumed that bytes is always padded out to 4 byte alignment
    /// * It is assumed that the bytes are in little-endian order, as encoded by [ToMidenRepr]
    fn from_bytes(bytes: &[u8]) -> Self;
    /// Extract a value of this type as encoded in a vector of field elements, where:
    ///
    /// * The order of the field elements is little-endian, i.e. the element holding the least
    ///   significant bytes comes first.
    fn from_felts(felts: &[RawFelt]) -> Self {
        let mut bytes = SmallVec::<[u8; 16]>::with_capacity(felts.len() * 4);
        for felt in felts {
            let chunk = (felt.as_canonical_u64() as u32).to_ne_bytes();
            bytes.extend(chunk);
        }
        Self::from_bytes(&bytes)
    }
    /// Extract a value of this type as encoded in a vector of words, where:
    ///
    /// * The order of the words is little-endian, i.e. the word holding the least significant
    ///   bytes comes first.
    /// * The order of the field elements in each word is in big-endian order, i.e. the element
    ///   with the most significant byte is at the start of the word, and the element with the
    ///   least significant byte is at the end of the word. This corresponds to the order in
    ///   which elements are placed on the operand stack when preparing to read or write them
    ///   from Miden's memory.
    fn from_words(words: &[Word]) -> Self {
        let mut felts = SmallVec::<[RawFelt; 4]>::with_capacity(words.len() * 4);
        for word in words {
            for felt in word.iter().copied().rev() {
                felts.push(felt);
            }
        }
        Self::from_felts(&felts)
    }

    /// Pop a value of this type from `stack` based on the canonical representation of this type
    /// on the operand stack when writing it to memory (and as read from memory).
    fn pop_from_stack(stack: &mut Vec<RawFelt>) -> Self {
        let needed = Self::size_in_felts();
        let mut felts = SmallVec::<[RawFelt; 4]>::with_capacity(needed);
        for _ in 0..needed {
            felts.push(stack.pop().unwrap());
        }
        Self::from_felts(&felts)
    }
}

impl ToMidenRepr for bool {
    fn to_bytes(&self) -> SmallVec<[u8; 16]> {
        smallvec![*self as u8]
    }

    fn to_felts(&self) -> SmallVec<[RawFelt; 4]> {
        smallvec![RawFelt::new(*self as u64).expect("value exceeds field modulus")]
    }

    fn push_to_operand_stack(&self, stack: &mut Vec<RawFelt>) {
        stack.push(RawFelt::new(*self as u64).expect("value exceeds field modulus"));
    }
}

impl FromMidenRepr for bool {
    #[inline(always)]
    fn size_in_felts() -> usize {
        1
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        match bytes[0] {
            0 => false,
            1 => true,
            n => panic!("invalid byte representation for boolean: {n:0x}"),
        }
    }

    fn from_felts(felts: &[RawFelt]) -> Self {
        match felts[0].as_canonical_u64() {
            0 => false,
            1 => true,
            n => panic!("invalid byte representation for boolean: {n:0x}"),
        }
    }

    fn pop_from_stack(stack: &mut Vec<RawFelt>) -> Self {
        match stack.pop().unwrap().as_canonical_u64() {
            0 => false,
            1 => true,
            n => panic!("invalid byte representation for boolean: {n:0x}"),
        }
    }
}

impl ToMidenRepr for u8 {
    fn to_bytes(&self) -> SmallVec<[u8; 16]> {
        smallvec![*self]
    }

    fn to_felts(&self) -> SmallVec<[RawFelt; 4]> {
        smallvec![RawFelt::new(*self as u64).expect("value exceeds field modulus")]
    }

    fn push_to_operand_stack(&self, stack: &mut Vec<RawFelt>) {
        stack.push(RawFelt::new(*self as u64).expect("value exceeds field modulus"));
    }
}

impl FromMidenRepr for u8 {
    #[inline(always)]
    fn size_in_felts() -> usize {
        1
    }

    #[inline(always)]
    fn from_bytes(bytes: &[u8]) -> Self {
        bytes[0]
    }

    fn from_felts(felts: &[RawFelt]) -> Self {
        felts[0].as_canonical_u64() as u8
    }

    fn pop_from_stack(stack: &mut Vec<RawFelt>) -> Self {
        stack.pop().unwrap().as_canonical_u64() as u8
    }
}

impl ToMidenRepr for i8 {
    fn to_bytes(&self) -> SmallVec<[u8; 16]> {
        smallvec![*self as u8]
    }

    fn to_felts(&self) -> SmallVec<[RawFelt; 4]> {
        smallvec![RawFelt::new(*self as u8 as u64).expect("value exceeds field modulus")]
    }

    fn push_to_operand_stack(&self, stack: &mut Vec<RawFelt>) {
        stack.push(RawFelt::new(*self as u8 as u64).expect("value exceeds field modulus"));
    }
}

impl FromMidenRepr for i8 {
    #[inline(always)]
    fn size_in_felts() -> usize {
        1
    }

    #[inline(always)]
    fn from_bytes(bytes: &[u8]) -> Self {
        bytes[0] as i8
    }

    fn from_felts(felts: &[RawFelt]) -> Self {
        felts[0].as_canonical_u64() as u8 as i8
    }

    fn pop_from_stack(stack: &mut Vec<RawFelt>) -> Self {
        stack.pop().unwrap().as_canonical_u64() as u8 as i8
    }
}

impl ToMidenRepr for u16 {
    fn to_bytes(&self) -> SmallVec<[u8; 16]> {
        SmallVec::from_slice(&self.to_ne_bytes())
    }

    fn to_felts(&self) -> SmallVec<[RawFelt; 4]> {
        smallvec![RawFelt::new(*self as u64).expect("value exceeds field modulus")]
    }

    fn push_to_operand_stack(&self, stack: &mut Vec<RawFelt>) {
        stack.push(RawFelt::new(*self as u64).expect("value exceeds field modulus"));
    }
}

impl FromMidenRepr for u16 {
    #[inline(always)]
    fn size_in_felts() -> usize {
        1
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 2);
        u16::from_ne_bytes([bytes[0], bytes[1]])
    }

    fn from_felts(felts: &[RawFelt]) -> Self {
        felts[0].as_canonical_u64() as u16
    }

    fn pop_from_stack(stack: &mut Vec<RawFelt>) -> Self {
        stack.pop().unwrap().as_canonical_u64() as u16
    }
}

impl ToMidenRepr for i16 {
    fn to_bytes(&self) -> SmallVec<[u8; 16]> {
        SmallVec::from_slice(&self.to_ne_bytes())
    }

    fn to_felts(&self) -> SmallVec<[RawFelt; 4]> {
        smallvec![RawFelt::new(*self as u16 as u64).expect("value exceeds field modulus")]
    }

    fn push_to_operand_stack(&self, stack: &mut Vec<RawFelt>) {
        stack.push(RawFelt::new(*self as u16 as u64).expect("value exceeds field modulus"));
    }
}

impl FromMidenRepr for i16 {
    #[inline(always)]
    fn size_in_felts() -> usize {
        1
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 2);
        i16::from_ne_bytes([bytes[0], bytes[1]])
    }

    fn from_felts(felts: &[RawFelt]) -> Self {
        felts[0].as_canonical_u64() as u16 as i16
    }

    fn pop_from_stack(stack: &mut Vec<RawFelt>) -> Self {
        stack.pop().unwrap().as_canonical_u64() as u16 as i16
    }
}

impl ToMidenRepr for u32 {
    fn to_bytes(&self) -> SmallVec<[u8; 16]> {
        SmallVec::from_slice(&self.to_ne_bytes())
    }

    fn to_felts(&self) -> SmallVec<[RawFelt; 4]> {
        smallvec![RawFelt::new(*self as u64).expect("value exceeds field modulus")]
    }

    fn push_to_operand_stack(&self, stack: &mut Vec<RawFelt>) {
        stack.push(RawFelt::new(*self as u64).expect("value exceeds field modulus"));
    }
}

impl FromMidenRepr for u32 {
    #[inline(always)]
    fn size_in_felts() -> usize {
        1
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 4);
        u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn from_felts(felts: &[RawFelt]) -> Self {
        felts[0].as_canonical_u64() as u32
    }

    fn pop_from_stack(stack: &mut Vec<RawFelt>) -> Self {
        stack.pop().unwrap().as_canonical_u64() as u32
    }
}

impl ToMidenRepr for i32 {
    fn to_bytes(&self) -> SmallVec<[u8; 16]> {
        SmallVec::from_slice(&self.to_ne_bytes())
    }

    fn to_felts(&self) -> SmallVec<[RawFelt; 4]> {
        smallvec![RawFelt::new(*self as u32 as u64).expect("value exceeds field modulus")]
    }

    fn push_to_operand_stack(&self, stack: &mut Vec<RawFelt>) {
        stack.push(RawFelt::new(*self as u32 as u64).expect("value exceeds field modulus"));
    }
}

impl FromMidenRepr for i32 {
    #[inline(always)]
    fn size_in_felts() -> usize {
        1
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 4);
        i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn from_felts(felts: &[RawFelt]) -> Self {
        felts[0].as_canonical_u64() as u32 as i32
    }

    fn pop_from_stack(stack: &mut Vec<RawFelt>) -> Self {
        stack.pop().unwrap().as_canonical_u64() as u32 as i32
    }
}

impl ToMidenRepr for u64 {
    fn to_bytes(&self) -> SmallVec<[u8; 16]> {
        SmallVec::from_slice(&self.to_le_bytes())
    }

    fn to_felts(&self) -> SmallVec<[RawFelt; 4]> {
        let lo = (*self as u32) as u64;
        let hi = *self >> 32;
        smallvec![
            RawFelt::new(lo).expect("value exceeds field modulus"),
            RawFelt::new(hi).expect("value exceeds field modulus"),
        ]
    }
}

impl FromMidenRepr for u64 {
    #[inline(always)]
    fn size_in_felts() -> usize {
        2
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 8);
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }

    fn from_felts(felts: &[RawFelt]) -> Self {
        assert!(felts.len() >= 2);
        let lo = felts[0].as_canonical_u64() as u32 as u64;
        let hi = felts[1].as_canonical_u64() as u32 as u64;
        lo | (hi << 32)
    }
}

impl ToMidenRepr for i64 {
    fn to_bytes(&self) -> SmallVec<[u8; 16]> {
        SmallVec::from_slice(&self.to_le_bytes())
    }

    fn to_felts(&self) -> SmallVec<[RawFelt; 4]> {
        (*self as u64).to_felts()
    }
}

impl FromMidenRepr for i64 {
    #[inline(always)]
    fn size_in_felts() -> usize {
        2
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        u64::from_bytes(bytes) as i64
    }

    fn from_felts(felts: &[RawFelt]) -> Self {
        u64::from_felts(felts) as i64
    }
}

impl ToMidenRepr for u128 {
    fn to_bytes(&self) -> SmallVec<[u8; 16]> {
        SmallVec::from_slice(&self.to_le_bytes())
    }

    fn to_felts(&self) -> SmallVec<[RawFelt; 4]> {
        let lo_lo = RawFelt::new((*self as u32) as u64).expect("value exceeds field modulus");
        let lo_hi =
            RawFelt::new(((*self >> 32) as u32) as u64).expect("value exceeds field modulus");
        let hi_lo =
            RawFelt::new(((*self >> 64) as u32) as u64).expect("value exceeds field modulus");
        let hi_hi =
            RawFelt::new(((*self >> 96) as u32) as u64).expect("value exceeds field modulus");
        smallvec![lo_lo, lo_hi, hi_lo, hi_hi]
    }
}

impl FromMidenRepr for u128 {
    #[inline(always)]
    fn size_in_felts() -> usize {
        4
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 16);
        u128::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ])
    }

    fn from_felts(felts: &[RawFelt]) -> Self {
        assert!(felts.len() >= 4);
        let lo_lo = felts[0].as_canonical_u64() as u32 as u128;
        let lo_hi = felts[1].as_canonical_u64() as u32 as u128;
        let hi_lo = felts[2].as_canonical_u64() as u32 as u128;
        let hi_hi = felts[3].as_canonical_u64() as u32 as u128;
        lo_lo | (lo_hi << 32) | (hi_lo << 64) | (hi_hi << 96)
    }
}

impl ToMidenRepr for i128 {
    fn to_bytes(&self) -> SmallVec<[u8; 16]> {
        SmallVec::from_slice(&self.to_le_bytes())
    }

    fn to_felts(&self) -> SmallVec<[RawFelt; 4]> {
        (*self as u128).to_felts()
    }
}

impl FromMidenRepr for i128 {
    #[inline(always)]
    fn size_in_felts() -> usize {
        4
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        u128::from_bytes(bytes) as i128
    }

    fn from_felts(felts: &[RawFelt]) -> Self {
        u128::from_felts(felts) as i128
    }
}

impl ToMidenRepr for RawFelt {
    fn to_bytes(&self) -> SmallVec<[u8; 16]> {
        panic!("field elements have no canonical byte representation")
    }

    fn to_felts(&self) -> SmallVec<[RawFelt; 4]> {
        smallvec![*self]
    }

    fn to_words(&self) -> SmallVec<[Word; 1]> {
        let mut word = [RawFelt::ZERO; 4];
        word[0] = *self;
        smallvec![Word::new(word)]
    }
}

impl FromMidenRepr for RawFelt {
    #[inline(always)]
    fn size_in_felts() -> usize {
        1
    }

    fn from_bytes(_bytes: &[u8]) -> Self {
        panic!("field elements have no canonical byte representation")
    }

    #[inline(always)]
    fn from_felts(felts: &[RawFelt]) -> Self {
        felts[0]
    }

    #[inline(always)]
    fn from_words(words: &[Word]) -> Self {
        words[0][0]
    }
}

impl ToMidenRepr for Felt {
    fn to_bytes(&self) -> SmallVec<[u8; 16]> {
        panic!("field elements have no canonical byte representation")
    }

    fn to_felts(&self) -> SmallVec<[RawFelt; 4]> {
        smallvec![self.0]
    }

    fn to_words(&self) -> SmallVec<[Word; 1]> {
        let mut word = [RawFelt::ZERO; 4];
        word[0] = self.0;
        smallvec![Word::new(word)]
    }
}

impl FromMidenRepr for Felt {
    #[inline(always)]
    fn size_in_felts() -> usize {
        1
    }

    fn from_bytes(_bytes: &[u8]) -> Self {
        panic!("field elements have no canonical byte representation")
    }

    #[inline(always)]
    fn from_felts(felts: &[RawFelt]) -> Self {
        Felt(felts[0])
    }

    #[inline(always)]
    fn from_words(words: &[Word]) -> Self {
        Felt(words[0][0])
    }
}

impl<const N: usize> ToMidenRepr for [u8; N] {
    #[inline]
    fn to_bytes(&self) -> SmallVec<[u8; 16]> {
        SmallVec::from_slice(self)
    }
}

impl<const N: usize> FromMidenRepr for [u8; N] {
    #[inline(always)]
    fn size_in_felts() -> usize {
        N.div_ceil(4)
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= N, "insufficient bytes");
        Self::try_from(&bytes[..N]).unwrap()
    }
}

impl FromMidenRepr for [Felt; 4] {
    #[inline(always)]
    fn size_in_felts() -> usize {
        4
    }

    fn from_bytes(_bytes: &[u8]) -> Self {
        panic!("field elements have no canonical byte representation")
    }

    #[inline(always)]
    fn from_felts(felts: &[RawFelt]) -> Self {
        [Felt(felts[0]), Felt(felts[1]), Felt(felts[2]), Felt(felts[3])]
    }
}

/// Convert a byte array to an equivalent vector of words
///
/// Given a byte slice laid out like so:
///
/// [b0, b1, b2, b3, b4, b5, b6, b7, .., b31]
///
/// This will produce a vector of words laid out like so:
///
/// [[{b12, ..b15}, {b8..b11}, {b4, ..b7}, {b0, ..b3}], [{b31, ..}, ..]]
///
/// In short, it produces words that when placed on the stack and written to memory word-by-word,
/// the original bytes will be laid out in Miden's memory in the correct order.
pub fn bytes_to_words(bytes: &[u8]) -> Vec<[RawFelt; 4]> {
    // 1. Chunk bytes up into felts
    let (chunks, remainder) = bytes.as_chunks::<4>();
    let padded_bytes = bytes.len().next_multiple_of(16);
    let num_felts = padded_bytes / 4;
    let mut buf = Vec::with_capacity(num_felts);
    for chunk in chunks {
        let n = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        buf.push(n);
    }
    // Zero-pad the buffer to nearest whole element
    if !remainder.is_empty() {
        let mut n_buf = [0u8; 4];
        for (i, byte) in remainder.iter().enumerate() {
            n_buf[i] = *byte;
        }
        buf.push(u32::from_ne_bytes(n_buf));
    }
    // Zero-pad the buffer to nearest whole word
    buf.resize(num_felts, 0);
    // Chunk into words, and push them in largest-address first order
    let num_words = num_felts / 4;
    let mut words = Vec::with_capacity(num_words);
    let (chunks, remainder) = buf.as_chunks::<4>();
    for chunk in chunks {
        words.push([
            RawFelt::new(chunk[3] as u64).expect("value exceeds field modulus"),
            RawFelt::new(chunk[2] as u64).expect("value exceeds field modulus"),
            RawFelt::new(chunk[1] as u64).expect("value exceeds field modulus"),
            RawFelt::new(chunk[0] as u64).expect("value exceeds field modulus"),
        ]);
    }
    if !remainder.is_empty() {
        let mut word = [RawFelt::ZERO; 4];
        for (i, n) in remainder.iter().enumerate() {
            word[i] = RawFelt::new(*n as u64).expect("value exceeds field modulus");
        }
        word.reverse();
        words.push(word);
    }
    words
}

/// Wrapper around `miden_processor::Felt` that implements useful traits that are not implemented
/// for that type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Felt(pub RawFelt);
impl Felt {
    #[inline]
    pub fn new(value: u64) -> Self {
        Self(RawFelt::new(value).expect("value exceeds field modulus"))
    }
}

impl<'de> Deserialize<'de> for Felt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u64::deserialize(deserializer).and_then(|n| {
            if n >= RawFelt::ORDER_U64 {
                Err(serde::de::Error::custom(
                    "invalid field element value: exceeds the field modulus",
                ))
            } else {
                Ok(Felt(RawFelt::new(n).expect("value exceeds field modulus")))
            }
        })
    }
}

#[cfg(feature = "std")]
impl clap::builder::ValueParserFactory for Felt {
    type Parser = FeltParser;

    fn value_parser() -> Self::Parser {
        FeltParser
    }
}

#[doc(hidden)]
#[cfg(feature = "std")]
#[derive(Clone)]
pub struct FeltParser;
#[cfg(feature = "std")]
impl clap::builder::TypedValueParser for FeltParser {
    type Value = Felt;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::error::Error> {
        use clap::error::{Error, ErrorKind};

        let value = value.to_str().ok_or_else(|| Error::new(ErrorKind::InvalidUtf8))?.trim();
        value.parse().map_err(|err| Error::raw(ErrorKind::ValueValidation, err))
    }
}

impl core::str::FromStr for Felt {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = if let Some(value) = s.strip_prefix("0x") {
            u64::from_str_radix(value, 16)
                .map_err(|err| format!("invalid field element value: {err}"))?
        } else {
            s.parse::<u64>().map_err(|err| format!("invalid field element value: {err}"))?
        };

        if value >= RawFelt::ORDER_U64 {
            Err("invalid field element value: exceeds the field modulus".to_string())
        } else {
            Ok(Felt(RawFelt::new(value).expect("value exceeds field modulus")))
        }
    }
}

impl From<Felt> for miden_processor::Felt {
    fn from(f: Felt) -> Self {
        f.0
    }
}

impl From<bool> for Felt {
    fn from(b: bool) -> Self {
        Self(RawFelt::new(b as u64).expect("value exceeds field modulus"))
    }
}

impl From<u8> for Felt {
    fn from(t: u8) -> Self {
        Self(RawFelt::new(t as u64).expect("value exceeds field modulus"))
    }
}

impl From<i8> for Felt {
    fn from(t: i8) -> Self {
        Self(RawFelt::new(t as u8 as u64).expect("value exceeds field modulus"))
    }
}

impl From<i16> for Felt {
    fn from(t: i16) -> Self {
        Self(RawFelt::new(t as u16 as u64).expect("value exceeds field modulus"))
    }
}

impl From<u16> for Felt {
    fn from(t: u16) -> Self {
        Self(RawFelt::new(t as u64).expect("value exceeds field modulus"))
    }
}

impl From<i32> for Felt {
    fn from(t: i32) -> Self {
        Self(RawFelt::new(t as u32 as u64).expect("value exceeds field modulus"))
    }
}

impl From<u32> for Felt {
    fn from(t: u32) -> Self {
        Self(RawFelt::new(t as u64).expect("value exceeds field modulus"))
    }
}

impl From<u64> for Felt {
    fn from(t: u64) -> Self {
        Self(RawFelt::new(t).expect("value exceeds field modulus"))
    }
}

impl From<i64> for Felt {
    fn from(t: i64) -> Self {
        Self(RawFelt::new(t as u64).expect("value exceeds field modulus"))
    }
}

// Reverse Felt to Rust types conversion

impl From<Felt> for bool {
    fn from(f: Felt) -> Self {
        f.0.as_canonical_u64() != 0
    }
}

impl From<Felt> for u8 {
    fn from(f: Felt) -> Self {
        f.0.as_canonical_u64() as u8
    }
}

impl From<Felt> for i8 {
    fn from(f: Felt) -> Self {
        f.0.as_canonical_u64() as i8
    }
}

impl From<Felt> for u16 {
    fn from(f: Felt) -> Self {
        f.0.as_canonical_u64() as u16
    }
}

impl From<Felt> for i16 {
    fn from(f: Felt) -> Self {
        f.0.as_canonical_u64() as i16
    }
}

impl From<Felt> for u32 {
    fn from(f: Felt) -> Self {
        f.0.as_canonical_u64() as u32
    }
}

impl From<Felt> for i32 {
    fn from(f: Felt) -> Self {
        f.0.as_canonical_u64() as i32
    }
}

impl From<Felt> for u64 {
    fn from(f: Felt) -> Self {
        f.0.as_canonical_u64()
    }
}

impl From<Felt> for i64 {
    fn from(f: Felt) -> Self {
        f.0.as_canonical_u64() as i64
    }
}

#[cfg(feature = "proptest")]
impl Arbitrary for Felt {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (0u64..RawFelt::ORDER_U64)
            .prop_map(|v| Felt(RawFelt::new(v).expect("value exceeds field modulus")))
            .boxed()
    }
}

/// Converts `value` to its corresponding Wasm ABI type and pushes it to the stack.
///
/// It differs from [`ToMidenRepr::push_to_operand_stack`] because it sign-extends `i8` and `i16`
/// values to `i32` before pushing them to the stack.
pub fn push_wasm_ty_to_operand_stack<T>(value: T, stack: &mut Vec<RawFelt>)
where
    T: ToMidenRepr + num_traits::PrimInt,
{
    let ty_size = core::mem::size_of::<T>();
    if ty_size > 2 {
        value.push_to_operand_stack(stack);
        return;
    }

    let is_signed = T::min_value() < T::zero();
    // The unwraps below are safe because `value` is at most 16 bits wide.
    let value_u32 = if is_signed {
        value.to_i32().unwrap() as u32
    } else {
        value.to_u32().unwrap()
    };
    value_u32.push_to_operand_stack(stack);
}

#[cfg(test)]
mod tests;
