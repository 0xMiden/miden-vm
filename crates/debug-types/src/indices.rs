use core::{fmt, num::NonZeroU32};

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

macro_rules! declare_coordinate_types {
    ($index:ident, $number:ident, $label:literal) => {
        #[doc = concat!("A zero-indexed ", $label, " coordinate.")]
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
        pub struct $index(pub u32);

        impl $index {
            pub const fn to_usize(self) -> usize {
                self.0 as usize
            }

            pub const fn to_u32(self) -> u32 {
                self.0
            }

            pub fn number(self) -> Option<$number> {
                self.0.checked_add(1).and_then($number::new)
            }
        }

        impl From<u32> for $index {
            fn from(value: u32) -> Self {
                Self(value)
            }
        }

        impl From<$number> for $index {
            fn from(value: $number) -> Self {
                value.to_index()
            }
        }

        impl fmt::Display for $index {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, formatter)
            }
        }

        #[cfg(feature = "arbitrary")]
        impl Arbitrary for $index {
            type Parameters = ();
            type Strategy = BoxedStrategy<Self>;

            fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
                any::<u32>().prop_map(Self).boxed()
            }
        }

        impl Serializable for $index {
            fn write_into<W: ByteWriter>(&self, target: &mut W) {
                target.write_u32(self.to_u32());
            }
        }

        impl Deserializable for $index {
            fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
                source.read_u32().map(Self)
            }
        }

        #[doc = concat!("A one-indexed ", $label, " coordinate.")]
        #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(
            all(feature = "arbitrary", test),
            miden_test_serialization_macros::serialization_test
        )]
        pub struct $number(NonZeroU32);

        impl $number {
            pub const fn new(number: u32) -> Option<Self> {
                match NonZeroU32::new(number) {
                    Some(number) => Some(Self(number)),
                    None => None,
                }
            }

            pub const fn to_index(self) -> $index {
                $index(self.0.get() - 1)
            }

            pub const fn to_usize(self) -> usize {
                self.0.get() as usize
            }

            pub const fn to_u32(self) -> u32 {
                self.0.get()
            }
        }

        impl Default for $number {
            fn default() -> Self {
                Self(NonZeroU32::MIN)
            }
        }

        impl From<NonZeroU32> for $number {
            fn from(value: NonZeroU32) -> Self {
                Self(value)
            }
        }

        impl TryFrom<$index> for $number {
            type Error = ();

            fn try_from(value: $index) -> Result<Self, Self::Error> {
                value.number().ok_or(())
            }
        }

        impl fmt::Display for $number {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, formatter)
            }
        }

        impl Serializable for $number {
            fn write_into<W: ByteWriter>(&self, target: &mut W) {
                target.write_u32(self.to_u32());
            }
        }

        impl Deserializable for $number {
            fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
                let value = source.read_u32()?;
                Self::new(value).ok_or_else(|| {
                    DeserializationError::InvalidValue(
                        concat!($label, " coordinate cannot be zero").into(),
                    )
                })
            }
        }

        #[cfg(feature = "arbitrary")]
        impl Arbitrary for $number {
            type Parameters = ();
            type Strategy = BoxedStrategy<Self>;

            fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
                (1..=u32::MAX).prop_map(|value| Self::new(value).unwrap()).boxed()
            }
        }
    };
}

declare_coordinate_types!(LineIndex, LineNumber, "line");
declare_coordinate_types!(ColumnIndex, ColumnNumber, "column");
