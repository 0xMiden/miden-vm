use alloc::string::String;

use thiserror::Error;

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

    #[error("invalid hex '{0}'")]
    InvalidHex(String),

    #[error("value '{0}' is out of range for a field element")]
    FeltOutOfRange(String),

    #[error("not enough arguments")]
    NotEnoughArgs,

    #[error("missing type at index {0} in DebugTypesSection")]
    MissingType(u32),

    #[error("type with shape '{0}' cannot be encoded as an argument")]
    UnsupportedType(&'static str),

    #[error("type nesting is too deep or cyclic")]
    RecursionLimit,
}
