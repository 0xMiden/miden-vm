//! Renders `DebugTypeInfo` as a human-readable type signature.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use super::{
    super::{DebugFieldInfo, DebugTypeIdx, DebugTypeInfo, DebugTypesSection},
    lookup::{field_name, is_anonymous, type_name_raw, wit_type_name},
};

// Stops infinite recursion if a type refers back to itself.
const MAX_DEPTH: usize = 8;

pub(super) fn format_type(types: &DebugTypesSection, idx: DebugTypeIdx, depth: usize) -> String {
    if depth > MAX_DEPTH {
        return "...".into();
    }
    let Some(ty) = types.get_type(idx) else {
        return format!("?#{}", idx.as_u32());
    };
    match ty {
        DebugTypeInfo::Primitive(p) => format!("{p:?}"),
        DebugTypeInfo::Pointer { pointee_type_idx } => {
            format!("*{}", format_type(types, *pointee_type_idx, depth + 1))
        },
        DebugTypeInfo::Array { element_type_idx, count } => {
            format_array(types, *element_type_idx, *count, depth)
        },
        DebugTypeInfo::Struct { name_idx, fields, .. } => {
            format_struct(types, *name_idx, fields, depth)
        },
        DebugTypeInfo::Function { return_type_idx, param_type_indices } => {
            format_function(types, *return_type_idx, param_type_indices, depth)
        },
        DebugTypeInfo::Enum { name_idx, .. } => {
            wit_type_name(type_name_raw(types, *name_idx)).to_string()
        },
        DebugTypeInfo::Unknown => "?".into(),
    }
}

fn format_array(
    types: &DebugTypesSection,
    element: DebugTypeIdx,
    count: Option<u32>,
    depth: usize,
) -> String {
    let inner = format_type(types, element, depth + 1);
    match count {
        Some(n) => format!("[{inner}; {n}]"),
        None => format!("[{inner}]"),
    }
}

fn format_struct(
    types: &DebugTypesSection,
    name_idx: u32,
    fields: &[DebugFieldInfo],
    depth: usize,
) -> String {
    let full = type_name_raw(types, name_idx);
    let short = wit_type_name(full);
    if is_anonymous(short) {
        let fields_str = fields
            .iter()
            .map(|f| {
                let fname = field_name(types, f.name_idx);
                let fty = format_type(types, f.type_idx, depth + 1);
                format!("{fname}: {fty}")
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("{{{fields_str}}}")
    } else {
        short.to_string()
    }
}

fn format_function(
    types: &DebugTypesSection,
    return_idx: Option<DebugTypeIdx>,
    param_indices: &[DebugTypeIdx],
    depth: usize,
) -> String {
    let params = param_indices
        .iter()
        .map(|t| format_type(types, *t, depth + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let ret = return_idx.map_or_else(|| "()".into(), |t| format_type(types, t, depth + 1));
    format!("fn({params}) -> {ret}")
}
