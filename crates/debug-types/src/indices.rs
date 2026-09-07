use core::fmt;

use miden_serde_utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;

/// An index representing a byte offset from the start of a source.
#[derive(
    Default,
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct ByteIndex(pub u32);

impl ByteIndex {
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    pub const fn to_usize(self) -> usize {
        self.0 as usize
    }

    pub const fn to_u32(self) -> u32 {
        self.0
    }
}

impl From<u32> for ByteIndex {
    fn from(index: u32) -> Self {
        Self(index)
    }
}

impl From<ByteIndex> for u32 {
    fn from(index: ByteIndex) -> Self {
        index.0
    }
}

impl core::ops::Add<u32> for ByteIndex {
    type Output = Self;

    fn add(self, offset: u32) -> Self {
        Self(self.0.checked_add(offset).expect("byte index overflow"))
    }
}

impl core::ops::Sub<u32> for ByteIndex {
    type Output = Self;

    fn sub(self, offset: u32) -> Self {
        Self(self.0.checked_sub(offset).expect("byte index underflow"))
    }
}

impl fmt::Display for ByteIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for ByteIndex {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<u32>().prop_map(Self).boxed()
    }
}

impl Serializable for ByteIndex {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.0);
    }
}

impl Deserializable for ByteIndex {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_u32().map(Self)
    }
}
