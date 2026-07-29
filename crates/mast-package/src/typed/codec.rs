//! Codecs for WIT types that take one token. They replace the normal field by field way.

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};

use miden_assembly_syntax::ast::types::StructType;
use miden_core::{Felt, Word};

use super::errors::TypedError;

/// The WIT interface of the core types. The built-in codecs belong to it.
///
/// A type name has a version, like `miden:base/core-types@1.0.0/word`. We do not match the
/// version, so a codec still works when the core types get a new version.
pub const MIDEN_CORE_TYPES: &str = "miden:base/core-types";

/// How to encode and print one WIT type.
///
/// A type name in a signature is a full WIT path, like `miden:base/core-types@1.0.0/word`.
/// We match a codec on two parts: the plain name from [`Self::wit_name`] and the interface from
/// [`Self::wit_interface`]. If both match, the codec does the work: one token in, the felts of the
/// type out, and the other way around for results.
///
/// The type says how many felts a value takes, not the codec. So a codec cannot disagree with the
/// signature.
///
/// [`TypedProcInfo`](super::TypedProcInfo) adds [`WordCodec`] and [`FeltCodec`] for you. Types
/// with rules from outside this crate need a codec from the user. See
/// [`TypedProcInfo::with_scalar_codec`](super::TypedProcInfo::with_scalar_codec).
pub trait WitScalarCodec {
    /// The plain WIT type name this codec handles, like `word`.
    fn wit_name(&self) -> &str;

    /// The WIT interface this codec belongs to, without the version. For example
    /// [`MIDEN_CORE_TYPES`] for the core types, or `miden:shapes/points` for your own types.
    ///
    /// This stops a codec from taking a type that only has the same plain name. Some other
    /// `miden:shapes/points/word` is not the core `word`. If the two have the same width, we would
    /// read a hex token and get a wrong value, and nobody would see the problem.
    ///
    /// `None` means we match on the plain name only, from any interface. This also covers a plain
    /// type name that is not WIT, because it has no interface.
    ///
    /// There is no default on purpose. Both answers are wrong in some case, and neither one gives
    /// an error. With a default interface, a codec for your own type would never match, and we
    /// would read its arguments field by field. With no default, a codec could take a type that is
    /// not its own. So you must choose.
    fn wit_interface(&self) -> Option<&str>;

    /// Turns one token into the felts of this type.
    fn encode(&self, token: &str) -> Result<Vec<Felt>, TypedError>;

    /// Turns the felts of one value into text, like `word(0x..)`. Returns an error if the felts
    /// are not a valid value of this type.
    ///
    /// The error goes to the caller. We do not fall back to the field by field way. If we printed
    /// the fields of a value the codec just called bad, a bad value would look good. And if we
    /// dropped the error, the caller could not tell a bad result from a procedure that returns
    /// nothing.
    fn decode(&self, felts: &[Felt]) -> Result<String, TypedError>;
}

/// Codec for the WIT `word` type: one hex token, four felts.
///
/// The compiler turns WIT `word` (four felts) into a named struct. So `word` goes through this
/// codec, not through a primitive branch.
pub struct WordCodec;

impl WitScalarCodec for WordCodec {
    fn wit_name(&self) -> &str {
        "word"
    }

    fn wit_interface(&self) -> Option<&str> {
        Some(MIDEN_CORE_TYPES)
    }

    fn encode(&self, token: &str) -> Result<Vec<Felt>, TypedError> {
        let word = Word::try_from(token).map_err(|err| TypedError::InvalidScalar {
            wit_name: self.wit_name().to_string(),
            token: token.to_string(),
            reason: err.to_string(),
        })?;
        Ok(word.to_vec())
    }

    fn decode(&self, felts: &[Felt]) -> Result<String, TypedError> {
        // The caller gives us as many felts as the *type* takes, so any other count means the
        // type and this codec do not agree. Printing the first four would pass a part of the
        // value off as the whole.
        let [a, b, c, d] = felts else {
            return Err(TypedError::MalformedResult {
                ty: self.wit_name().to_string(),
                reason: "a word occupies exactly four felts",
            });
        };
        Ok(format!("word({})", Word::from([*a, *b, *c, *d]).to_hex()))
    }
}

/// Codec for the WIT `felt` type: one decimal token, one felt.
///
/// The compiler turns `felt` into a named struct with one `inner` field. `felt` is a core type,
/// so only the value is interesting. This codec drops the struct and shows the value.
pub struct FeltCodec;

impl WitScalarCodec for FeltCodec {
    fn wit_name(&self) -> &str {
        "felt"
    }

    fn wit_interface(&self) -> Option<&str> {
        Some(MIDEN_CORE_TYPES)
    }

    fn encode(&self, token: &str) -> Result<Vec<Felt>, TypedError> {
        Ok(alloc::vec![parse_felt_token(token)?])
    }

    fn decode(&self, felts: &[Felt]) -> Result<String, TypedError> {
        // One felt, no more, for the same reason as [`WordCodec::decode`].
        let [value] = felts else {
            return Err(TypedError::MalformedResult {
                ty: self.wit_name().to_string(),
                reason: "a felt occupies exactly one felt",
            });
        };
        Ok(value.to_string())
    }
}

/// The codec for `struct_ty`. We match the plain type name *and* the WIT interface it comes from.
/// See [`WitScalarCodec::wit_interface`] for why we also match the interface.
pub(super) fn codec_for_struct<'a>(
    codecs: &'a [Box<dyn WitScalarCodec>],
    struct_ty: &StructType,
) -> Option<&'a dyn WitScalarCodec> {
    // `felt_count` walks types with no codecs, so stop before we read the name.
    if codecs.is_empty() {
        return None;
    }
    // We keep `name` here, because `leaf` and `interface` point into it.
    let name = struct_ty.name()?;
    let leaf = type_leaf_name(&name)?;
    // The interface without the version, so `miden:base/core-types@1.0.0/word` gives
    // `miden:base/core-types`. A plain name like `point` has none.
    let interface = name.trim_matches('"').rsplit_once('/').map(|(interface, _leaf)| {
        interface.rsplit_once('@').map_or(interface, |(base, _version)| base)
    });

    codecs
        .iter()
        .find(|codec| {
            codec.wit_name() == leaf
                && match codec.wit_interface() {
                    // A codec with an interface only takes types from that interface.
                    Some(expected) => interface == Some(expected),
                    // A codec with no interface takes any type with this name.
                    None => true,
                }
        })
        .map(AsRef::as_ref)
}

/// The last part of a type name. We use it so a type matches with any package or version in front
/// of it.
///
/// A type name has two shapes: a WIT path with `/` and a version, like
/// `miden:shapes/points@0.1.0/point`, or a plain name, like `point`. `/` is the only separator we
/// split on because it is the only one the compiler writes: it joins the WIT interface export name
/// and the type name, and stores the result as it is. See
/// `register_component_instance_export_type_names` in
/// `frontend/wasm/src/component/types/mod.rs` of the compiler.
///
/// Returns `None` if the name says nothing: it is empty, or it ends with a separator. A struct
/// with no name has no name here either, so it never reaches this function.
pub(super) fn type_leaf_name(name: &str) -> Option<&str> {
    let leaf = name.rsplit('/').next().unwrap_or(name).trim_matches('"');
    (!leaf.is_empty()).then_some(leaf)
}

/// Reads a decimal `felt` token. A Goldilocks felt is a value from `0` to `p`, where
/// `p = 2^64 - 2^32 + 1`. `p` is smaller than `2^64`, so every felt fits in a `u64`. Then
/// `Felt::try_from` drops the values from `p` to `2^64`: they fit a `u64`, but they are not
/// felts.
pub(super) fn parse_felt_token(s: &str) -> Result<Felt, TypedError> {
    let v: u64 = s.parse().map_err(|_| TypedError::InvalidFelt(s.to_string()))?;
    Felt::try_from(v).map_err(|_| TypedError::FeltOutOfRange(s.to_string()))
}
