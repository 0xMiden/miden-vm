//! Encodes argument tokens into felts using debug type info.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use super::{
    super::{DebugPrimitiveType, DebugTypeIdx, DebugTypeInfo},
    Felt, MAX_TYPE_DEPTH, TypedDebugInfoError, TypedView, WitScalarCodec, WordCodec,
    lookup::{type_name_raw, wit_type_name},
    max_for_bits,
    sizing::count_units,
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
    let ty = view.types.get_type(idx).ok_or(TypedDebugInfoError::MissingType(idx.as_u32()))?;
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
        DebugTypeInfo::Enum { .. } => Err(TypedDebugInfoError::UnsupportedType("enum")),
        DebugTypeInfo::Unknown => Err(TypedDebugInfoError::UnsupportedType("unknown")),
    }
}

/// Number of tokens `encode_tokens` reads for `idx`; must match it exactly. One token per
/// primitive, `void` none, a codec-handled scalar struct (e.g. `word`) one, other structs and
/// fixed arrays the sum of their leaves. `None` when the count isn't static (dynamic array,
/// pointer, function, unknown), the type graph is cyclic/deeper than [`MAX_TYPE_DEPTH`], or the
/// count overflows; the caller then skips the upfront count check.
pub(super) fn arg_token_count(view: &TypedView<'_>, idx: DebugTypeIdx) -> Option<usize> {
    // One token per primitive value (`void` takes none). `count_units` sums structs and arrays.
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
    let n = p.size_in_felts() as usize;
    match p {
        // Compiler-built packages emit `word` as a struct handled by `WordCodec`; this arm fires
        // only for a core `Word` primitive.
        DebugPrimitiveType::Word => WordCodec.encode(&token),
        DebugPrimitiveType::Void => Ok(Vec::new()),
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
        DebugPrimitiveType::Felt => Ok(alloc::vec![parse_felt_token(&token)?]),
        // Signed ints: check the range, then store as two's-complement 32-bit limbs (low first).
        DebugPrimitiveType::I8
        | DebugPrimitiveType::I16
        | DebugPrimitiveType::I32
        | DebugPrimitiveType::I64
        | DebugPrimitiveType::I128 => {
            let value = parse_signed(&token, p.size_in_bytes() * 8, p)?;
            Ok(limbs_to_felts(value, n))
        },
        DebugPrimitiveType::U8
        | DebugPrimitiveType::U16
        | DebugPrimitiveType::U32
        | DebugPrimitiveType::U64
        | DebugPrimitiveType::U128 => {
            let value = parse_unsigned(&token, p.size_in_bytes() * 8, p)?;
            Ok(limbs_to_felts(value, n))
        },
        DebugPrimitiveType::F32 => {
            let v: f32 =
                token.parse().map_err(|_| TypedDebugInfoError::InvalidFloat { token, ty: p })?;
            Ok(limbs_to_felts(v.to_bits() as u128, n))
        },
        DebugPrimitiveType::F64 => {
            let v: f64 =
                token.parse().map_err(|_| TypedDebugInfoError::InvalidFloat { token, ty: p })?;
            Ok(limbs_to_felts(v.to_bits() as u128, n))
        },
        // 256-bit values exceed the `u128` limb path; no typed encoding is defined for them yet.
        DebugPrimitiveType::U256 => Err(TypedDebugInfoError::UnsupportedType("u256")),
    }
}

/// Cuts `value` into `n` 32-bit limbs (low first), one felt each. Each limb is a `u32`, so
/// [`Felt::from_u32`] never fails.
fn limbs_to_felts(value: u128, n: usize) -> Vec<Felt> {
    (0..n).map(|i| Felt::from_u32((value >> (32 * i)) as u32)).collect()
}

/// Reads an unsigned int (decimal or `0x..` hex) and checks it fits in `bits` bits.
fn parse_unsigned(
    token: &str,
    bits: u32,
    p: DebugPrimitiveType,
) -> Result<u128, TypedDebugInfoError> {
    let value = if let Some(hex) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16)
            .map_err(|_| TypedDebugInfoError::InvalidHex(token.to_string()))?
    } else {
        token
            .parse::<u128>()
            .map_err(|_| TypedDebugInfoError::InvalidInt { token: token.to_string(), ty: p })?
    };
    if value > max_for_bits(bits) {
        return Err(int_out_of_range(token, p));
    }
    Ok(value)
}

/// Reads a signed int and returns its two's-complement bits. A `0x..` token is raw bits (must fit
/// in `bits`); a decimal token is checked against the signed range.
fn parse_signed(
    token: &str,
    bits: u32,
    p: DebugPrimitiveType,
) -> Result<u128, TypedDebugInfoError> {
    if let Some(hex) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
        let raw = u128::from_str_radix(hex, 16)
            .map_err(|_| TypedDebugInfoError::InvalidHex(token.to_string()))?;
        if raw > max_for_bits(bits) {
            return Err(int_out_of_range(token, p));
        }
        return Ok(raw);
    }
    let signed = token
        .parse::<i128>()
        .map_err(|_| TypedDebugInfoError::InvalidInt { token: token.to_string(), ty: p })?;
    // Shift `i128::MIN`/`MAX` down to this width to get the range. At 128 bits the shift is 0.
    let min = i128::MIN >> (128 - bits);
    let max = i128::MAX >> (128 - bits);
    if signed < min || signed > max {
        return Err(int_out_of_range(token, p));
    }
    Ok((signed as u128) & max_for_bits(bits))
}

fn int_out_of_range(token: &str, p: DebugPrimitiveType) -> TypedDebugInfoError {
    TypedDebugInfoError::IntOutOfRange { token: token.to_string(), ty: p }
}

/// Reads a decimal or `0x..` hex token into a `Felt` (full field range). Used by the `Felt` arm.
fn parse_felt_token(s: &str) -> Result<Felt, TypedDebugInfoError> {
    let v: u64 = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| TypedDebugInfoError::InvalidHex(s.to_string()))?
    } else {
        s.parse::<u64>().map_err(|_| TypedDebugInfoError::InvalidFelt(s.to_string()))?
    };
    Felt::try_from(v).map_err(|_| TypedDebugInfoError::FeltOutOfRange(s.to_string()))
}

fn next_token<I: Iterator<Item = String>>(tokens: &mut I) -> Result<String, TypedDebugInfoError> {
    tokens.next().ok_or(TypedDebugInfoError::NotEnoughArgs)
}
