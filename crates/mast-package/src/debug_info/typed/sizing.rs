//! Shared type-graph traversal that sizes a value by summing a per-leaf weight. Two callers use
//! it: [`stack_felt_count`](super::decode::stack_felt_count) (felts a value occupies) and
//! [`arg_token_count`](super::encode::arg_token_count) (tokens a value consumes). Keeping the
//! recursion here means the depth guard, overflow checks, and array/struct/codec handling can't
//! drift between the two — only the leaf weights differ.

use super::{
    super::{DebugPrimitiveType, DebugTypeIdx, DebugTypeInfo},
    MAX_TYPE_DEPTH, TypedView, WitScalarCodec,
    lookup::{type_leaf_name, type_name_raw},
};

/// Sums a per-leaf unit count over `idx`. `primitive` weights a primitive leaf; `codec` weights a
/// codec-handled scalar struct, which is treated as one opaque leaf regardless of its fields.
///
/// `None` for shapes with no static size (dynamic array, pointer, function, unknown), a cyclic or
/// deeper-than-[`MAX_TYPE_DEPTH`] graph, or a count that overflows `usize`.
pub(super) fn count_units(
    view: &TypedView<'_>,
    idx: DebugTypeIdx,
    primitive: fn(DebugPrimitiveType) -> usize,
    codec: fn(&dyn WitScalarCodec) -> usize,
) -> Option<usize> {
    count_units_at(view, idx, 0, primitive, codec)
}

fn count_units_at(
    view: &TypedView<'_>,
    idx: DebugTypeIdx,
    depth: usize,
    primitive: fn(DebugPrimitiveType) -> usize,
    codec: fn(&dyn WitScalarCodec) -> usize,
) -> Option<usize> {
    if depth > MAX_TYPE_DEPTH {
        return None;
    }
    let ty = view.types.get_type(idx)?;
    match ty {
        DebugTypeInfo::Primitive(p) => Some(primitive(*p)),
        DebugTypeInfo::Array { element_type_idx, count } => {
            let element = count_units_at(view, *element_type_idx, depth + 1, primitive, codec)?;
            // `checked_mul` so a hostile `count` can't overflow (trivially so where `usize` is
            // 32-bit, e.g. wasm32) and report a bogus small size.
            count.and_then(|n| element.checked_mul(n as usize))
        },
        DebugTypeInfo::Struct { name_idx, fields, .. } => {
            // A codec-handled scalar (e.g. `account-id`) is one opaque leaf, so weight it with
            // `codec` regardless of its fields.
            let name = type_name_raw(view.types, *name_idx);
            if let Some(c) = view.codec_for(type_leaf_name(name)) {
                return Some(codec(c));
            }
            let mut total = 0usize;
            for f in fields {
                total = total.checked_add(count_units_at(
                    view,
                    f.type_idx,
                    depth + 1,
                    primitive,
                    codec,
                )?)?;
            }
            Some(total)
        },
        DebugTypeInfo::Pointer { .. }
        | DebugTypeInfo::Function { .. }
        | DebugTypeInfo::Enum { .. }
        | DebugTypeInfo::Unknown => None,
    }
}
