use alloc::string::String;

use thiserror::Error;

/// Errors from turning argument tokens into felts, or result felts into text, for a procedure
/// signature.
#[derive(Debug, Error)]
pub enum TypedError {
    /// We could not read a token for a WIT type that has a [`WitScalarCodec`].
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

    #[error("invalid felt '{0}'")]
    InvalidFelt(String),

    /// We could not read a token as the number type the signature asks for.
    #[error("invalid {ty} value '{token}'")]
    InvalidNumber { token: String, ty: String },

    #[error("value '{0}' is out of range for a field element")]
    FeltOutOfRange(String),

    #[error("value '{token}' is out of range for {ty}")]
    IntOutOfRange { token: String, ty: String },

    #[error("procedure '{procedure}' expects {expected} argument(s), got {actual}")]
    ArgumentCount {
        procedure: String,
        expected: usize,
        actual: usize,
    },

    #[error("procedure '{procedure}' takes a parameter that cannot be given as an argument")]
    UnsupportedParameter { procedure: String },

    #[error("procedure '{procedure}' returns a value that cannot be decoded")]
    UnsupportedResult { procedure: String },

    #[error("procedure '{procedure}' returns {expected} felt(s), but the stack holds {actual}")]
    ResultStackTooShort {
        procedure: String,
        expected: usize,
        actual: usize,
    },

    /// The felts we got back are not a valid value of the type in the signature. If we printed
    /// them, a bad result would look like a good one.
    #[error("{ty} result is malformed: {reason}")]
    MalformedResult { ty: String, reason: &'static str },

    /// `ty` names the type the problem is in. A signature shows a named struct as its name only,
    /// so a bad struct nested in one never appears there, and this is the only place it is named.
    #[error("type information for {ty} is invalid: {reason}")]
    InvalidTypeInfo { ty: String, reason: &'static str },

    /// The token count and the encoder do not agree on how many tokens a signature needs. Both
    /// walk the same types, so this is our bug, not bad input.
    #[error("internal error: the encoder did not consume exactly the expected arguments")]
    TokenCountMismatch,

    /// The felt count and the decoder do not agree on how many felts a signature returns. Same
    /// idea as [`Self::TokenCountMismatch`], and also our bug.
    #[error("internal error: the decoder did not consume exactly the expected result felts")]
    FeltCountMismatch,

    /// A codec made a different number of felts than its type takes on the stack. We stop here
    /// and do not put a value of the wrong width on the stack.
    #[error("codec for '{wit_name}' produced {actual} felt(s), but the type occupies {expected}")]
    CodecWidthMismatch {
        wit_name: String,
        expected: usize,
        actual: usize,
    },

    /// The calling convention says how a value is laid out in felts. We support one layout: the
    /// canonical one, with one stack slot per leaf field.
    #[error("procedure '{procedure}' uses convention '{abi}', only 'component-model' is supported")]
    UnsupportedCallConv { procedure: String, abi: String },

    /// An array whose elements take no felts. It reads nothing from the stack, so its length comes
    /// only from the type: `[empty; 1_000_000]` would be a million lines that say nothing.
    #[error("{ty} is not decoded: its elements take no felts, so there is nothing to print")]
    ZeroWidthArray { ty: String },

    #[error("no typed representation for a value of shape '{0}'")]
    UnsupportedType(&'static str),
}
