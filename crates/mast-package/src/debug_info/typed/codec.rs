//! Pluggable codecs for WIT scalar types that encode from a single token and occupy a fixed
//! number of stack felts, overriding the generic field-by-field struct handling.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use miden_core::Word;

use super::{Felt, errors::TypedDebugInfoError};

/// Encoding and rendering of one WIT scalar type.
///
/// Debug type names are full WIT paths (e.g. `miden:base/core-types@1.0.0/account-id`); a codec
/// is matched against the bare type name — the last `/`-segment — regardless of package and
/// version. When a struct's name matches a registered codec, the codec replaces the generic
/// struct handling: one token in, [`felt_count`](Self::felt_count) felts out, and the reverse
/// when rendering results.
///
/// [`TypedProcInfo`](super::TypedProcInfo) registers the [`WordCodec`] by default. Codecs for
/// types defined outside this crate (e.g. `account-id`, which is validated with protocol-level
/// rules) are registered by the consumer via
/// [`TypedProcInfo::with_scalar_codec`](super::TypedProcInfo::with_scalar_codec).
pub trait WitScalarCodec {
    /// Bare WIT type name this codec handles (e.g. `account-id`).
    fn wit_name(&self) -> &str;

    /// Number of felts a value of this type occupies on the stack.
    fn felt_count(&self) -> usize;

    /// Encodes a single token into exactly [`felt_count`](Self::felt_count) felts.
    fn encode(&self, token: &str) -> Result<Vec<Felt>, TypedDebugInfoError>;

    /// Renders exactly [`felt_count`](Self::felt_count) felts as a display string (e.g.
    /// `word(0x..)`), or `None` if the felts are not a valid value of this type. On `None` the
    /// caller falls back to generic field-by-field rendering.
    fn decode(&self, felts: &[Felt]) -> Option<String>;
}

/// Codec for the WIT `word` struct: one hex token, four felts.
///
/// The compiler lowers WIT `word` (a record of 4 felts) to a named struct and never emits
/// `DebugPrimitiveType::Word`, so result and argument handling for compiler-built packages goes
/// through this codec, not the `Word` primitive arm.
pub struct WordCodec;

impl WitScalarCodec for WordCodec {
    fn wit_name(&self) -> &str {
        "word"
    }

    fn felt_count(&self) -> usize {
        4
    }

    fn encode(&self, token: &str) -> Result<Vec<Felt>, TypedDebugInfoError> {
        let word = Word::try_from(token).map_err(|err| TypedDebugInfoError::InvalidScalar {
            wit_name: self.wit_name().to_string(),
            token: token.to_string(),
            reason: err.to_string(),
        })?;
        Ok(word.to_vec())
    }

    fn decode(&self, felts: &[Felt]) -> Option<String> {
        if felts.len() < 4 {
            return None;
        }
        let word = Word::from([felts[0], felts[1], felts[2], felts[3]]);
        Some(format!("word({})", word.to_hex()))
    }
}
