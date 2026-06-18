//! Decodes felts into a structured string using debug type info.

use alloc::{format, string::String, vec::Vec};

use miden_core::Word;

use super::{
    super::{DebugPrimitiveType, DebugTypeIdx, DebugTypeInfo},
    Felt, MAX_TYPE_DEPTH, TypedView, WitScalarCodec,
    count::count_units,
    introspect::{field_name, is_anonymous, type_name_raw, wit_type_name},
};

/// How many felts a value of type `idx` takes on the stack. The decoder reads exactly this many
/// to render the result. `None` when the count isn't known statically (dynamic arrays, `Unknown`),
/// the type graph is cyclic/deeper than [`MAX_TYPE_DEPTH`], or a count computation overflows.
pub(super) fn stack_felt_count(view: &TypedView<'_>, idx: DebugTypeIdx) -> Option<usize> {
    count_units(view, idx, primitive_felt_count, |c| c.felt_count())
}

/// Stack felts a primitive leaf occupies.
fn primitive_felt_count(p: DebugPrimitiveType) -> usize {
    match p {
        DebugPrimitiveType::Word => 4,
        DebugPrimitiveType::Void => 0,
        _ => 1,
    }
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
    let ty = view.types.types.get(idx.as_u32() as usize)?;
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
            Some((format!("{head}"), rest))
        },
        DebugPrimitiveType::Bool => {
            let (head, rest) = felts.split_first()?;
            let v = head.as_canonical_u64();
            Some((if v == 0 { "false".into() } else { "true".into() }, rest))
        },
        DebugPrimitiveType::I8
        | DebugPrimitiveType::I16
        | DebugPrimitiveType::I32
        | DebugPrimitiveType::I64
        | DebugPrimitiveType::U8
        | DebugPrimitiveType::U16
        | DebugPrimitiveType::U32
        | DebugPrimitiveType::U64 => {
            let (head, rest) = felts.split_first()?;
            Some((format!("{}", head.as_canonical_u64()), rest))
        },
        DebugPrimitiveType::I128
        | DebugPrimitiveType::U128
        | DebugPrimitiveType::F32
        | DebugPrimitiveType::F64 => {
            let (head, rest) = felts.split_first()?;
            Some((format!("{} (as {p:?})", head.as_canonical_u64()), rest))
        },
    }
}

/// `name(body)` for named structs; `{body}` for anonymous or unnamed ones.
fn wrap_struct(short: &str, body: &str) -> String {
    if is_anonymous(short) {
        format!("{{{body}}}")
    } else {
        format!("{short}({body})")
    }
}
