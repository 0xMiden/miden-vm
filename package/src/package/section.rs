use alloc::{borrow::Cow, string::ToString};
use core::{fmt, str::FromStr};

use miden_assembly_syntax::DisplayHex;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A unique identifier/tag for optional sections of the Miden package format
///
/// The following tag ranges are reserved for specific categories of use:
///
/// * `0` - unused
/// * `1..10` - reserved for non-rollup use cases, e.g. debug information
/// * `10..100` - reserved for rollup use cases, e.g. account component metadata
/// * `100..254` - reserved for TBD use cases
/// * `255` - assigned to custom user-defined sections, which must also be uniquely named
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum SectionId {
    //--- CORE SECTIONS
    /// The section containing debug information (source locations, spans)
    DebugInfo = 1,

    //--- ROLLUP SECTIONS
    /// This section provides the encoded metadata for a compiled account component
    ///
    /// Currently, this corresponds to the serialized representation of
    /// `miden-objects::account::AccountComponentMetadata`, i.e. name, descrioption, storage, that
    /// is associated with this package.
    AccountComponentMetadata = 10,

    //--- USER-DEFINED SECTIONS
    Custom(Cow<'static, str>) = 255,
}

impl TryFrom<u8> for SectionId {
    type Error = InvalidSectionIdError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DebugInfo),
            10 => Ok(Self::AccountComponentMetadata),
            _ => Err(InvalidSectionIdError::Tag(value)),
        }
    }
}

impl SectionId {
    pub fn custom(name: impl AsRef<str>) -> Result<Self, InvalidSectionIdError> {
        let name = name.as_ref();
        if !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
            return Err(InvalidSectionIdError::InvalidStart);
        }
        if name.contains(|c: char| !c.is_ascii_alphanumeric() && !matches!(c, '.' | '_' | '-')) {
            return Err(InvalidSectionIdError::InvalidCharacter);
        }
        Ok(Self::Custom(name.to_string().into()))
    }

    pub const fn tag(&self) -> u8 {
        // SAFETY: This is safe because we have given this enum a
        // primitive representation with #[repr(u8)], with the first
        // field of the underlying union-of-structs the discriminant
        //
        // See the section on "accessing the numeric value of the discriminant"
        // here: https://doc.rust-lang.org/std/mem/fn.discriminant.html
        unsafe { *(self as *const Self).cast::<u8>() }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidSectionIdError {
    #[error("invalid section id: cannot be empty")]
    Empty,
    #[error(
        "invalid section id: contains invalid characters, only the set [a-z0-9._-] are allowed"
    )]
    InvalidCharacter,
    #[error("invalid section id: must start with a character in the set [a-z_]")]
    InvalidStart,
    #[error("invalid section id: {0} is not recognized or is incomplete")]
    Tag(u8),
}

impl FromStr for SectionId {
    type Err = InvalidSectionIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "debug_info" => Ok(Self::DebugInfo),
            "account_component_metadata" => Ok(Self::AccountComponentMetadata),
            custom => Self::custom(custom),
        }
    }
}

impl fmt::Display for SectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DebugInfo => f.write_str("debug_info"),
            Self::AccountComponentMetadata => f.write_str("account_component_metadata"),
            Self::Custom(custom) => f.write_str(custom.as_ref()),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Section {
    pub id: SectionId,
    pub data: Cow<'static, [u8]>,
}

impl fmt::Debug for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verbose = f.alternate();
        let mut builder = f.debug_struct("Section");
        builder.field("id", &format_args!("{}", &self.id));
        if verbose {
            builder.field("data", &format_args!("{}", DisplayHex(&self.data))).finish()
        } else {
            builder.field("data", &format_args!("{} bytes", self.data.len())).finish()
        }
    }
}

impl Section {
    pub fn new<B>(id: SectionId, data: B) -> Self
    where
        B: Into<Cow<'static, [u8]>>,
    {
        Self { id, data: data.into() }
    }

    /// Returns true if this section is empty, i.e. has no data
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the size in bytes of this section's data
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SectionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{SeqAccess, Unexpected};

        const DEBUG_INFO: u8 = SectionId::DebugInfo.tag();
        const ACCOUNT_COMPONENT_METADATA: u8 = SectionId::AccountComponentMetadata.tag();
        const CUSTOM: u8 = SectionId::Custom(Cow::Borrowed("")).tag();

        serde_untagged::UntaggedEnumVisitor::new()
            .expecting("a valid section id")
            .string(|s| Self::from_str(s).map_err(serde::de::Error::custom))
            .u8(|tag| match tag {
                DEBUG_INFO => Ok(Self::DebugInfo),
                ACCOUNT_COMPONENT_METADATA => Ok(Self::AccountComponentMetadata),
                CUSTOM => Err(serde::de::Error::custom("expected a custom section name")),
                other => Err(serde::de::Error::invalid_value(
                    Unexpected::Unsigned(other as u64),
                    &"a valid section id tag",
                )),
            })
            .seq(|mut seq| {
                let tag = seq
                    .next_element::<u8>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &"a section id tag"))?;
                match tag {
                    DEBUG_INFO => Ok(Self::DebugInfo),
                    ACCOUNT_COMPONENT_METADATA => Ok(Self::AccountComponentMetadata),
                    CUSTOM => seq
                        .next_element::<&str>()?
                        .ok_or_else(|| {
                            serde::de::Error::invalid_length(1, &"a custom section name")
                        })
                        .and_then(|s| Self::custom(s).map_err(serde::de::Error::custom)),
                    other => Err(serde::de::Error::invalid_value(
                        Unexpected::Unsigned(other as u64),
                        &"a valid section id tag",
                    )),
                }
            })
            .deserialize(deserializer)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SectionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTupleVariant;
        let tag = self.tag() as u32;
        match self {
            Self::DebugInfo => serializer.serialize_unit_variant("SectionId", tag, "DebugInfo"),
            Self::AccountComponentMetadata => {
                serializer.serialize_unit_variant("SectionId", tag, "AccountComponentMetadata")
            },
            Self::Custom(custom) => {
                let mut tuple =
                    serializer.serialize_tuple_variant("SectionId", tag, "Custom", 1)?;
                tuple.serialize_field(&custom.as_ref())?;
                tuple.end()
            },
        }
    }
}
