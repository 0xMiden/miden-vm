//! Decodes felts into a structured string using debug type info.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use miden_core::Word;

use super::{
    super::{DebugPrimitiveType, DebugTypeIdx, DebugTypeInfo},
    Felt, MAX_TYPE_DEPTH, TypedView, WitScalarCodec,
    lookup::{field_name, is_anonymous, type_name_raw, wit_type_name},
    max_for_bits,
    sizing::count_units,
};

/// How many felts a value of type `idx` takes on the stack. The decoder reads exactly this many
/// to render the result. `None` when the count isn't known statically (dynamic arrays, `Unknown`),
/// the type graph is cyclic/deeper than [`MAX_TYPE_DEPTH`], or a count computation overflows.
pub(super) fn stack_felt_count(view: &TypedView<'_>, idx: DebugTypeIdx) -> Option<usize> {
    count_units(view, idx, |p| p.size_in_felts() as usize, |c| c.felt_count())
}

/// Returns `(body, leftover)`. The body for primitives omits the outer type tag.
pub(super) fn decode_value<'a>(
    felts: &'a [Felt],
    view: &TypedView<'_>,
    idx: DebugTypeIdx,
) -> Option<(String, &'a [Felt])> {
    decode_value_at(felts, view, idx, 0)
}

fn decode_value_at<'a>(
    felts: &'a [Felt],
    view: &TypedView<'_>,
    idx: DebugTypeIdx,
    depth: usize,
) -> Option<(String, &'a [Felt])> {
    if depth > MAX_TYPE_DEPTH {
        return None;
    }
    let ty = view.types.get_type(idx)?;
    match ty {
        DebugTypeInfo::Primitive(p) => decode_primitive(felts, *p),
        DebugTypeInfo::Struct { name_idx, fields, .. } => {
            let full = type_name_raw(view.types, *name_idx);
            let short = wit_type_name(full);
            // A codec that fails to render (invalid value) falls through to the generic
            // field-by-field rendering below.
            if let Some(codec) = view.codec_for(short)
                && let Some((rendered, rest)) = decode_scalar(felts, codec)
            {
                return Some((rendered, rest));
            }
            if let [only] = fields.as_slice() {
                let (inner, rest) = decode_value_at(felts, view, only.type_idx, depth + 1)?;
                return Some((wrap_struct(short, &inner), rest));
            }
            let mut cursor = felts;
            let mut rendered = Vec::with_capacity(fields.len());
            for f in fields {
                let fname = field_name(view.types, f.name_idx);
                let (fv, rest) = decode_value_at(cursor, view, f.type_idx, depth + 1)?;
                rendered.push(format!("{fname}={fv}"));
                cursor = rest;
            }
            Some((wrap_struct(short, &rendered.join(", ")), cursor))
        },
        DebugTypeInfo::Array { element_type_idx, count: Some(n) } => {
            // Don't pre-size from the (untrusted) `count`: an array of a zero-width element type
            // (e.g. `void`) can carry a huge `count` while occupying no felts, which would
            // otherwise pre-allocate / spin billions of entries. Stop as soon as an element
            // consumes no felts.
            let mut cursor = felts;
            let mut rendered = Vec::new();
            for _ in 0..*n {
                let before = cursor.len();
                let (v, rest) = decode_value_at(cursor, view, *element_type_idx, depth + 1)?;
                rendered.push(v);
                cursor = rest;
                if cursor.len() == before {
                    break;
                }
            }
            Some((format!("[{}]", rendered.join(", ")), cursor))
        },
        DebugTypeInfo::Array { count: None, .. }
        | DebugTypeInfo::Pointer { .. }
        | DebugTypeInfo::Function { .. }
        | DebugTypeInfo::Enum { .. }
        | DebugTypeInfo::Unknown => None,
    }
}

/// Renders a codec-handled scalar from the front of `felts`, returning the leftover felts.
fn decode_scalar<'a>(
    felts: &'a [Felt],
    codec: &dyn WitScalarCodec,
) -> Option<(String, &'a [Felt])> {
    let n = codec.felt_count();
    if felts.len() < n {
        return None;
    }
    let (chunk, rest) = felts.split_at(n);
    let rendered = codec.decode(chunk)?;
    Some((rendered, rest))
}

fn decode_primitive(felts: &[Felt], p: DebugPrimitiveType) -> Option<(String, &[Felt])> {
    match p {
        DebugPrimitiveType::Void => Some((String::from("()"), felts)),
        // Compiler-built packages emit `word` as a struct handled by `WordCodec`; this arm fires
        // only for a core `Word` primitive. It renders the bare hex, since `decode_result` adds
        // the primitive type tag itself.
        DebugPrimitiveType::Word => {
            if felts.len() < 4 {
                return None;
            }
            let (chunk, rest) = felts.split_at(4);
            let word = Word::from([chunk[0], chunk[1], chunk[2], chunk[3]]);
            Some((word.to_hex(), rest))
        },
        DebugPrimitiveType::Felt => {
            let (head, rest) = felts.split_first()?;
            Some((head.to_string(), rest))
        },
        DebugPrimitiveType::Bool => {
            let (head, rest) = felts.split_first()?;
            let v = head.as_canonical_u64();
            Some((if v == 0 { "false".into() } else { "true".into() }, rest))
        },
        // Signed ints: read the limbs, then read the low `bits` bits as two's complement.
        DebugPrimitiveType::I8
        | DebugPrimitiveType::I16
        | DebugPrimitiveType::I32
        | DebugPrimitiveType::I64
        | DebugPrimitiveType::I128 => {
            let (value, rest) = read_limbs(felts, p.size_in_felts() as usize)?;
            Some((render_signed(value, p.size_in_bytes() * 8), rest))
        },
        // Unsigned ints: read the limbs and print the packed value.
        DebugPrimitiveType::U8
        | DebugPrimitiveType::U16
        | DebugPrimitiveType::U32
        | DebugPrimitiveType::U64
        | DebugPrimitiveType::U128 => {
            let (value, rest) = read_limbs(felts, p.size_in_felts() as usize)?;
            Some((render_unsigned(value, p.size_in_bytes() * 8), rest))
        },
        DebugPrimitiveType::F32 => {
            let (value, rest) = read_limbs(felts, p.size_in_felts() as usize)?;
            Some((f32::from_bits(value as u32).to_string(), rest))
        },
        DebugPrimitiveType::F64 => {
            let (value, rest) = read_limbs(felts, p.size_in_felts() as usize)?;
            Some((f64::from_bits(value as u64).to_string(), rest))
        },
        // 256-bit values exceed the `u128` limb path; no typed decoding is defined for them yet.
        DebugPrimitiveType::U256 => None,
    }
}

/// Reads `n` 32-bit limbs (low first) from the front of `felts` and packs them into a `u128`
/// (`n` is at most 4, so 128 bits fit). This is the inverse of the encoder's `limbs_to_felts`.
/// Returns the value and the leftover felts, or `None` if there are too few felts or a felt is
/// bigger than 32 bits (not a valid limb).
fn read_limbs(felts: &[Felt], n: usize) -> Option<(u128, &[Felt])> {
    if felts.len() < n {
        return None;
    }
    let (chunk, rest) = felts.split_at(n);
    let mut value: u128 = 0;
    for (i, f) in chunk.iter().enumerate() {
        let limb = f.as_canonical_u64();
        if limb > u32::MAX as u64 {
            return None;
        }
        value |= (limb as u128) << (32 * i);
    }
    Some((value, rest))
}

/// Prints the low `bits` bits of `value` as an unsigned decimal.
fn render_unsigned(value: u128, bits: u32) -> String {
    (value & max_for_bits(bits)).to_string()
}

/// Prints the low `bits` bits of `value` as a signed decimal (two's complement). We move the sign
/// bit to the top, then shift back down to copy the sign. This also drops higher bits and works up
/// to 128 bits (shift of 0).
fn render_signed(value: u128, bits: u32) -> String {
    let shift = 128 - bits;
    (((value << shift) as i128) >> shift).to_string()
}

/// `name(body)` for named structs; `{body}` for anonymous or unnamed ones.
fn wrap_struct(short: &str, body: &str) -> String {
    if is_anonymous(short) {
        format!("{{{body}}}")
    } else {
        format!("{short}({body})")
    }
}
