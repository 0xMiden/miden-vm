use alloc::string::{String, ToString};
use core::{fmt, str::FromStr};

/// This represents the way in which a dependent will link against a dependency during assembly.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum Linkage {
    /// Link against the target package dynamically, i.e. it is expected that the package will be
    /// provided to the VM at runtime so that it is available for the dependent.
    #[default]
    Dynamic = 0,
    /// Link the contents of the target package into the dependent package, as if they were defined
    /// as part of the dependent.
    ///
    /// This linkage mode ensures that the dependency does not have to be provided to the VM
    /// separately in order to execute code from the dependent.
    Static,
}

impl Linkage {
    /// Returns true if this represents static linkage
    #[inline]
    pub const fn is_static(&self) -> bool {
        matches!(self, Self::Static)
    }

    /// Returns true if this represents dynamic linkage
    #[inline]
    pub const fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic)
    }

    /// Get the string representation of this linkage
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Dynamic => "dynamic",
            Self::Static => "static",
        }
    }
}

impl fmt::Display for Linkage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::ops::BitOr for Linkage {
    type Output = Linkage;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == rhs {
            return self;
        }
        // If the linkages aren't equal, one must be static and we always prefer static linkage
        // in this case
        Self::Static
    }
}

impl core::ops::BitOrAssign for Linkage {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

/// The error produced when parsing [Linkage] from a string value
#[derive(Debug, thiserror::Error)]
#[error("unknown linkage '{0}': expected either 'dynamic' or 'static'")]
pub struct UnknownLinkageError(String);

impl FromStr for Linkage {
    type Err = UnknownLinkageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "default" | "dynamic" => Ok(Self::Dynamic),
            "static" => Ok(Self::Static),
            other => Err(UnknownLinkageError(other.to_string())),
        }
    }
}

mod serialization {
    use alloc::format;

    use miden_core::serde::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
    };

    use super::Linkage;

    #[cfg(feature = "serde")]
    impl serde::Serialize for Linkage {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            if serializer.is_human_readable() {
                self.as_str().serialize(serializer)
            } else {
                (*self as u8).serialize(serializer)
            }
        }
    }

    #[cfg(feature = "serde")]
    impl<'de> serde::Deserialize<'de> for Linkage {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                <&'de str>::deserialize(deserializer)?
                    .parse::<Linkage>()
                    .map_err(serde::de::Error::custom)
            } else {
                match u8::deserialize(deserializer)? {
                    0 => Ok(Self::Dynamic),
                    1 => Ok(Self::Static),
                    other => {
                        Err(serde::de::Error::custom(format!("invalid Linkage tag '{other}'")))
                    },
                }
            }
        }
    }

    impl Serializable for Linkage {
        fn write_into<W: ByteWriter>(&self, target: &mut W) {
            target.write_u8(*self as u8);
        }
    }

    impl Deserializable for Linkage {
        fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
            match source.read_u8()? {
                0 => Ok(Self::Dynamic),
                1 => Ok(Self::Static),
                other => Err(DeserializationError::InvalidValue(format!(
                    "unknown Linkage tag '{other}'"
                ))),
            }
        }
    }
}

#[cfg(feature = "arbitrary")]
mod arbitrary {
    use proptest::prelude::*;

    use super::Linkage;

    impl proptest::arbitrary::Arbitrary for Linkage {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![Just(Linkage::Dynamic), Just(Linkage::Static),].boxed()
        }
    }
}
