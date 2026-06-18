//! Encodes argument tokens into felts using debug type info.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use super::{
    super::{DebugPrimitiveType, DebugTypeIdx, DebugTypeInfo},
    Felt, MAX_TYPE_DEPTH, TypedDebugInfoError, TypedView, WitScalarCodec, WordCodec,
    count::count_units,
    introspect::{type_name_raw, wit_type_name},
};

/// Encodes the tokens for a value of type `idx` into its stack felts.
/// Consumes exactly `arg_token_count(idx)` tokens and produces `stack_felt_count(idx)` felts.
pub(super) fn encode_tokens<I: Iterator<Item = String>>(
    tokens: &mut I,
    view: &TypedView<'_>,
    idx: DebugTypeIdx,
) -> Result<Vec<Felt>, TypedDebugInfoError> {
    encode_tokens_at(tokens, view, idx, 0)
}

fn encode_tokens_at<I: Iterator<Item = String>>(
    tokens: &mut I,
    view: &TypedView<'_>,
    idx: DebugTypeIdx,
    depth: usize,
) -> Result<Vec<Felt>, TypedDebugInfoError> {
    if depth > MAX_TYPE_DEPTH {
        return Err(TypedDebugInfoError::RecursionLimit);
    }
    let ty = view
        .types
        .types
        .get(idx.as_u32() as usize)
        .ok_or(TypedDebugInfoError::MissingType(idx.as_u32()))?;
    match ty {
        DebugTypeInfo::Primitive(DebugPrimitiveType::Void) => Ok(Vec::new()),
        DebugTypeInfo::Primitive(p) => encode_primitive(next_token(tokens)?, *p),
        DebugTypeInfo::Struct { name_idx, fields, .. } => {
            let name = type_name_raw(view.types, *name_idx);
            if let Some(codec) = view.codec_for(wit_type_name(name)) {
                return codec.encode(&next_token(tokens)?);
            }
            let mut felts = Vec::new();
            for f in fields {
                felts.extend(encode_tokens_at(tokens, view, f.type_idx, depth + 1)?);
            }
            Ok(felts)
        },
        DebugTypeInfo::Array { element_type_idx, count: Some(n) } => {
            let mut felts = Vec::new();
            for _ in 0..*n {
                let chunk = encode_tokens_at(tokens, view, *element_type_idx, depth + 1)?;
                // An array of a zero-width element type (e.g. `void`) consumes no tokens and
                // produces no felts, so a huge `count` would otherwise spin without progress.
                let empty = chunk.is_empty();
                felts.extend(chunk);
                if empty {
                    break;
                }
            }
            Ok(felts)
        },
        DebugTypeInfo::Array { count: None, .. } => {
            Err(TypedDebugInfoError::UnsupportedType("array"))
        },
        // No defined encoding for the below type shapes as arguments.
        DebugTypeInfo::Pointer { .. } => Err(TypedDebugInfoError::UnsupportedType("pointer")),
        DebugTypeInfo::Function { .. } => Err(TypedDebugInfoError::UnsupportedType("function")),
        DebugTypeInfo::Unknown => Err(TypedDebugInfoError::UnsupportedType("unknown")),
    }
}

/// Number of tokens `encode_tokens` reads for `idx`; must match it exactly. One token per
/// primitive, `void` none, a codec-handled scalar struct (e.g. `word`) one, other structs and
/// fixed arrays the sum of their leaves. `None` when the count isn't static (dynamic array,
/// pointer, function, unknown), the type graph is cyclic/deeper than [`MAX_TYPE_DEPTH`], or the
/// count overflows; the caller then skips the upfront count check.
pub(super) fn arg_token_count(view: &TypedView<'_>, idx: DebugTypeIdx) -> Option<usize> {
    // One token per primitive leaf (`void` none); a codec-handled scalar is a single token.
    count_units(
        view,
        idx,
        |p| match p {
            DebugPrimitiveType::Void => 0,
            _ => 1,
        },
        |_| 1,
    )
}

fn encode_primitive(
    token: String,
    p: DebugPrimitiveType,
) -> Result<Vec<Felt>, TypedDebugInfoError> {
    match p {
        // Compiler-built packages emit `word` as a struct handled by `WordCodec`; this arm fires
        // only for a core `Word` primitive.
        DebugPrimitiveType::Word => WordCodec.encode(&token),
        DebugPrimitiveType::Bool => {
            let v = match token.to_ascii_lowercase().as_str() {
                "true" | "1" => 1u64,
                "false" | "0" => 0,
                _ => return Err(TypedDebugInfoError::InvalidBool(token)),
            };
            Felt::try_from(v)
                .map(|f| alloc::vec![f])
                .map_err(|_| TypedDebugInfoError::FeltOutOfRange(token))
        },
        DebugPrimitiveType::Void => Ok(Vec::new()),
        _ => Ok(alloc::vec![parse_felt_token(&token)?]),
    }
}

/// Decimal or `0x..` hex token to a `Felt`. Shared between the typed and raw arg parsers.
pub fn parse_felt_token(s: &str) -> Result<Felt, TypedDebugInfoError> {
    let v: u64 = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| TypedDebugInfoError::InvalidHex(s.to_string()))?
    } else {
        s.parse::<u64>().map_err(|_| TypedDebugInfoError::InvalidU64(s.to_string()))?
    };
    Felt::try_from(v).map_err(|_| TypedDebugInfoError::FeltOutOfRange(s.to_string()))
}

fn next_token<I: Iterator<Item = String>>(tokens: &mut I) -> Result<String, TypedDebugInfoError> {
    tokens.next().ok_or(TypedDebugInfoError::NotEnoughArgs)
}
