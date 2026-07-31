use core::fmt;

use miden_core::{
    Felt,
    field::PrimeField64,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// PUSH VALUE
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushValue {
    Int(IntValue),
    Word(WordValue),
}

impl From<u8> for PushValue {
    fn from(value: u8) -> Self {
        Self::Int(value.into())
    }
}

impl From<u16> for PushValue {
    fn from(value: u16) -> Self {
        Self::Int(value.into())
    }
}

impl From<u32> for PushValue {
    fn from(value: u32) -> Self {
        Self::Int(value.into())
    }
}

impl From<Felt> for PushValue {
    fn from(value: Felt) -> Self {
        Self::Int(value.into())
    }
}

impl From<IntValue> for PushValue {
    fn from(value: IntValue) -> Self {
        Self::Int(value)
    }
}

impl From<WordValue> for PushValue {
    fn from(value: WordValue) -> Self {
        Self::Word(value)
    }
}

impl fmt::Display for PushValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(value) => fmt::Display::fmt(value, f),
            Self::Word(value) => fmt::Display::fmt(value, f),
        }
    }
}

impl crate::prettier::PrettyPrint for PushValue {
    fn render(&self) -> crate::prettier::Document {
        match self {
            Self::Int(value) => value.render(),
            Self::Word(value) => value.render(),
        }
    }
}

// WORD VALUE
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
pub struct WordValue(pub [Felt; 4]);

impl fmt::Display for WordValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_list();
        for value in self.0 {
            builder.entry(&value.as_canonical_u64());
        }
        builder.finish()
    }
}

impl crate::prettier::PrettyPrint for WordValue {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        const_text("[")
            + self
                .0
                .iter()
                .copied()
                .map(display)
                .reduce(|acc, doc| acc + const_text(",") + doc)
                .unwrap_or_default()
            + const_text("]")
    }
}

impl PartialOrd for WordValue {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WordValue {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        let (WordValue([l0, l1, l2, l3]), WordValue([r0, r1, r2, r3])) = (self, other);
        l0.as_canonical_u64()
            .cmp(&r0.as_canonical_u64())
            .then_with(|| l1.as_canonical_u64().cmp(&r1.as_canonical_u64()))
            .then_with(|| l2.as_canonical_u64().cmp(&r2.as_canonical_u64()))
            .then_with(|| l3.as_canonical_u64().cmp(&r3.as_canonical_u64()))
    }
}

impl core::hash::Hash for WordValue {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        let WordValue([a, b, c, d]) = self;
        [
            a.as_canonical_u64(),
            b.as_canonical_u64(),
            c.as_canonical_u64(),
            d.as_canonical_u64(),
        ]
        .hash(state)
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for WordValue {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{array::uniform4, strategy::Strategy};
        uniform4((0..crate::FIELD_MODULUS).prop_map(Felt::new_unchecked))
            .prop_map(WordValue)
            .no_shrink()
            .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

impl Serializable for WordValue {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0[0].write_into(target);
        self.0[1].write_into(target);
        self.0[2].write_into(target);
        self.0[3].write_into(target);
    }
}

impl Deserializable for WordValue {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let a = Felt::read_from(source)?;
        let b = Felt::read_from(source)?;
        let c = Felt::read_from(source)?;
        let d = Felt::read_from(source)?;
        Ok(Self([a, b, c, d]))
    }
}

// INT VALUE
// ================================================================================================

/// Represents one of the various types of values that have a hex-encoded representation in Miden
/// Assembly source files.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
pub enum IntValue {
    /// A tiny value
    U8(u8),
    /// A small value
    U16(u16),
    /// A u32 constant, typically represents a memory address
    U32(u32),
    /// A single field element, 8 bytes, encoded as 16 hex digits
    Felt(Felt),
}

impl From<u8> for IntValue {
    fn from(value: u8) -> Self {
        Self::U8(value)
    }
}

impl From<u16> for IntValue {
    fn from(value: u16) -> Self {
        Self::U16(value)
    }
}

impl From<u32> for IntValue {
    fn from(value: u32) -> Self {
        Self::U32(value)
    }
}

impl From<Felt> for IntValue {
    fn from(value: Felt) -> Self {
        Self::Felt(value)
    }
}

impl IntValue {
    pub fn as_int(&self) -> u64 {
        match self {
            Self::U8(value) => *value as u64,
            Self::U16(value) => *value as u64,
            Self::U32(value) => *value as u64,
            Self::Felt(value) => value.as_canonical_u64(),
        }
    }

    /// Returns the value as a `u64`.
    ///
    /// This is an alias for [`as_int`](Self::as_int) that matches the `Felt` API.
    pub fn as_canonical_u64(&self) -> u64 {
        self.as_int()
    }

    pub fn checked_add(&self, rhs: Self) -> Option<Self> {
        let value = self.as_int().checked_add(rhs.as_int())?;
        if value >= crate::FIELD_MODULUS {
            return None;
        }
        Some(shrink_u64_hex(value))
    }

    pub fn checked_sub(&self, rhs: Self) -> Option<Self> {
        let value = self.as_int().checked_sub(rhs.as_int())?;
        if value >= crate::FIELD_MODULUS {
            return None;
        }
        Some(shrink_u64_hex(value))
    }

    pub fn checked_mul(&self, rhs: Self) -> Option<Self> {
        let value = self.as_int().checked_mul(rhs.as_int())?;
        if value >= crate::FIELD_MODULUS {
            return None;
        }
        Some(shrink_u64_hex(value))
    }

    pub fn checked_div(&self, rhs: Self) -> Option<Self> {
        let value = self.as_int().checked_div(rhs.as_int())?;
        if value >= crate::FIELD_MODULUS {
            return None;
        }
        Some(shrink_u64_hex(value))
    }
}

impl core::ops::Add<IntValue> for IntValue {
    type Output = IntValue;

    fn add(self, rhs: IntValue) -> Self::Output {
        shrink_u64_hex(self.as_int() + rhs.as_int())
    }
}

impl core::ops::Sub<IntValue> for IntValue {
    type Output = IntValue;

    fn sub(self, rhs: IntValue) -> Self::Output {
        shrink_u64_hex(self.as_int() - rhs.as_int())
    }
}

impl core::ops::Mul<IntValue> for IntValue {
    type Output = IntValue;

    fn mul(self, rhs: IntValue) -> Self::Output {
        shrink_u64_hex(self.as_int() * rhs.as_int())
    }
}

impl core::ops::Div<IntValue> for IntValue {
    type Output = IntValue;

    fn div(self, rhs: IntValue) -> Self::Output {
        shrink_u64_hex(self.as_int() / rhs.as_int())
    }
}

impl PartialEq<Felt> for IntValue {
    fn eq(&self, other: &Felt) -> bool {
        match self {
            Self::U8(lhs) => (*lhs as u64) == other.as_canonical_u64(),
            Self::U16(lhs) => (*lhs as u64) == other.as_canonical_u64(),
            Self::U32(lhs) => (*lhs as u64) == other.as_canonical_u64(),
            Self::Felt(lhs) => lhs == other,
        }
    }
}

impl fmt::Display for IntValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U8(value) => write!(f, "{value}"),
            Self::U16(value) => write!(f, "{value}"),
            Self::U32(value) => write!(f, "{value:#04x}"),
            Self::Felt(value) => write!(f, "{:#08x}", value.as_canonical_u64().to_be()),
        }
    }
}

impl crate::prettier::PrettyPrint for IntValue {
    fn render(&self) -> crate::prettier::Document {
        match self {
            Self::U8(v) => v.render(),
            Self::U16(v) => v.render(),
            Self::U32(v) => v.render(),
            Self::Felt(v) => v.as_canonical_u64().render(),
        }
    }
}

impl PartialOrd for IntValue {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IntValue {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        match (self, other) {
            (Self::U8(l), Self::U8(r)) => l.cmp(r),
            (Self::U8(_), _) => Ordering::Less,
            (Self::U16(_), Self::U8(_)) => Ordering::Greater,
            (Self::U16(l), Self::U16(r)) => l.cmp(r),
            (Self::U16(_), _) => Ordering::Less,
            (Self::U32(_), Self::U8(_) | Self::U16(_)) => Ordering::Greater,
            (Self::U32(l), Self::U32(r)) => l.cmp(r),
            (Self::U32(_), _) => Ordering::Less,
            (Self::Felt(_), Self::U8(_) | Self::U16(_) | Self::U32(_)) => Ordering::Greater,
            (Self::Felt(l), Self::Felt(r)) => l.as_canonical_u64().cmp(&r.as_canonical_u64()),
        }
    }
}

impl core::hash::Hash for IntValue {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::U8(value) => value.hash(state),
            Self::U16(value) => value.hash(state),
            Self::U32(value) => value.hash(state),
            Self::Felt(value) => value.as_canonical_u64().hash(state),
        }
    }
}

impl Serializable for IntValue {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.as_int().write_into(target)
    }
}

impl Deserializable for IntValue {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let raw = source.read_u64()?;
        if raw >= Felt::ORDER_U64 {
            Err(DeserializationError::InvalidValue(
                "int value is greater than field modulus".into(),
            ))
        } else {
            Ok(shrink_u64_hex(raw))
        }
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for IntValue {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{num, prop_oneof, strategy::Strategy};
        prop_oneof![
            num::u8::ANY.prop_map(IntValue::U8),
            (u8::MAX as u16 + 1..=u16::MAX).prop_map(IntValue::U16),
            (u16::MAX as u32 + 1..=u32::MAX).prop_map(IntValue::U32),
            (num::u64::ANY).prop_filter_map("valid felt value", |n| {
                if n > u32::MAX as u64 && n < crate::FIELD_MODULUS {
                    Some(IntValue::Felt(Felt::new_unchecked(n)))
                } else {
                    None
                }
            }),
        ]
        .no_shrink()
        .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

#[inline]
pub(crate) fn shrink_u64_hex(n: u64) -> IntValue {
    if n <= (u8::MAX as u64) {
        IntValue::U8(n as u8)
    } else if n <= (u16::MAX as u64) {
        IntValue::U16(n as u16)
    } else if n <= (u32::MAX as u64) {
        IntValue::U32(n as u32)
    } else {
        IntValue::Felt(Felt::new_unchecked(n))
    }
}
