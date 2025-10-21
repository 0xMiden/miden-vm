use alloc::{
    borrow::{Cow, ToOwned},
    format,
    string::ToString,
};
use core::{fmt, str::FromStr};

use miden_assembly_syntax::DisplayHex;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A unique identifier for optional sections of the Miden package format
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[repr(transparent)]
pub struct SectionId(Cow<'static, str>);

impl SectionId {
    /// The section containing debug information (source locations, spans)
    pub const DEBUG_INFO: Self = Self(Cow::Borrowed("debug_info"));
    /// This section provides the encoded metadata for a compiled account component
    ///
    /// Currently, this corresponds to the serialized representation of
    /// `miden-objects::account::AccountComponentMetadata`, i.e. name, descrioption, storage, that
    /// is associated with this package.
    pub const ACCOUNT_COMPONENT_METADATA: Self = Self(Cow::Borrowed("account_component_metadata"));

    /// Construct a user-defined (i.e. "custom") section identifier
    ///
    /// Section identifiers must be either an ASCII alphanumeric, or one of the following
    /// characters: `.`, `_`, `-`. Additionally, the identifier must start with an ASCII alphabetic
    /// character or `_`.
    pub fn custom(name: impl AsRef<str>) -> Result<Self, InvalidSectionIdError> {
        let name = name.as_ref();
        if !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
            return Err(InvalidSectionIdError::InvalidStart);
        }
        if name.contains(|c: char| !c.is_ascii_alphanumeric() && !matches!(c, '.' | '_' | '-')) {
            return Err(InvalidSectionIdError::InvalidCharacter);
        }
        Ok(Self(name.to_string().into()))
    }

    /// Get this section identifier as a string
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
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
}

impl FromStr for SectionId {
    type Err = InvalidSectionIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "debug_info" => Ok(Self::DEBUG_INFO),
            "account_component_metadata" => Ok(Self::ACCOUNT_COMPONENT_METADATA),
            custom => Self::custom(custom),
        }
    }
}

impl fmt::Display for SectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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

impl miden_core::utils::Serializable for Section {
    fn write_into<W: miden_core::utils::ByteWriter>(&self, target: &mut W) {
        let id = self.id.as_str();
        target.write_usize(id.len());
        target.write_bytes(id.as_bytes());
        target.write_usize(self.len());
        target.write_bytes(&self.data);
    }
}

impl miden_core::utils::Deserializable for Section {
    fn read_from<R: miden_core::utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, miden_core::utils::DeserializationError> {
        let id_len = source.read_usize()?;
        let id_bytes = source.read_slice(id_len)?;
        let id_str = core::str::from_utf8(id_bytes).map_err(|err| {
            miden_core::utils::DeserializationError::InvalidValue(format!(
                "invalid utf-8 in section name: {err}"
            ))
        })?;
        let id = SectionId(Cow::Owned(id_str.to_owned()));

        let len = source.read_usize()?;
        let bytes = source.read_slice(len)?;
        Ok(Section { id, data: Cow::Owned(bytes.to_owned()) })
    }
}
