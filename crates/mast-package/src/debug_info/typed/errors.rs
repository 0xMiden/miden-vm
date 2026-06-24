use alloc::string::String;

use thiserror::Error;

use super::super::DebugPrimitiveType;

/// Errors from resolving, encoding, or decoding values against a [`Package`](crate::Package)'s
/// debug sections.
#[derive(Debug, Error)]
pub enum TypedDebugInfoError {
    /// A token failed to parse as a WIT scalar handled by a [`WitScalarCodec`].
    ///
    /// [`WitScalarCodec`]: super::WitScalarCodec
    #[error("invalid {wit_name} '{token}': {reason}")]
    InvalidScalar {
        wit_name: String,
        token: String,
        reason: String,
    },

    #[error("invalid bool '{0}' (expected true/false/0/1)")]
    InvalidBool(String),

    #[error("invalid u64 '{0}'")]
    InvalidU64(String),

    #[error("invalid integer '{0}'")]
    InvalidInt(String),

    #[error("invalid float '{0}'")]
    InvalidFloat(String),

    #[error("invalid hex '{0}'")]
    InvalidHex(String),

    #[error("value '{0}' is out of range for a field element")]
    FeltOutOfRange(String),

    #[error("value '{token}' is out of range for {ty:?}")]
    IntOutOfRange { token: String, ty: DebugPrimitiveType },

    #[error("not enough arguments")]
    NotEnoughArgs,

    #[error("missing type at index {0} in the debug type table")]
    MissingType(u32),

    #[error("type with shape '{0}' cannot be encoded as an argument")]
    UnsupportedType(&'static str),

    #[error("type nesting is too deep or cyclic")]
    RecursionLimit,
}
