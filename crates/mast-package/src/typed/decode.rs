//! Turns the felts a procedure returns into text.

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};

use miden_assembly_syntax::ast::types::Type;
use miden_core::Felt;

use super::{
    WitScalarCodec,
    arity::{felt_count, max_for_bits, signed_from_bits, signed_range, slot_bits},
    codec::{codec_for_struct, type_leaf_name},
    errors::TypedError,
};

/// What we say when a result needs more felts than the stack holds.
const STACK_TOO_SHORT: &str = "the stack ran out of result felts";

/// Reads one value of `ty` from the start of `felts`. Returns the text and the felts that are
/// left. A primitive has no type name after it here.
pub(super) fn decode_type<'a>(
    felts: &'a [Felt],
    ty: &Type,
    codecs: &[Box<dyn WitScalarCodec>],
) -> Result<(String, &'a [Felt]), TypedError> {
    match ty {
        Type::Struct(struct_ty) => {
            // A codec decides the output for its own type. If it says the value is bad, the
            // error goes to the caller. We do not try the field by field way below, because that
            // would make a bad value look good.
            if let Some(codec) = codec_for_struct(codecs, struct_ty) {
                let n = felt_count(ty).ok_or(TypedError::UnsupportedType("struct"))?;
                let (chunk, rest) = take_felts(felts, n, ty)?;
                return Ok((codec.decode(chunk)?, rest));
            }

            // Field names give us the shape. No names at all means a tuple, like `(a, b)`. All
            // names means a record, like `{ x: a, y: b }`. The compiler never mixes the two, so a
            // mix means the type info is bad. We do not guess.
            // For a tuple field the compiler writes no name at all, or the position as the name,
            // like `"0"`. A real field name is never just its own index.
            let fields = struct_ty.fields();
            let unnamed = fields
                .iter()
                .enumerate()
                .filter(|(i, field)| match field.name.as_deref() {
                    None => true,
                    Some(name) => name.is_empty() || name.parse::<usize>() == Ok(*i),
                })
                .count();
            if unnamed != 0 && unnamed != fields.len() {
                return Err(TypedError::InvalidTypeInfo("a struct mixes named and unnamed fields"));
            }
            // A struct with no fields has no names, so we print it as a tuple, like `name()`,
            // and not as an empty record, like `name {  }`.
            let tuple = unnamed != 0 || fields.is_empty();

            let mut cursor = felts;
            let mut rendered = Vec::with_capacity(fields.len());
            for field in fields {
                let (value, rest) = decode_type(cursor, &field.ty, codecs)?;
                if tuple {
                    rendered.push(value);
                } else {
                    // After the check above, every field here has a real name.
                    let name = field.name.as_deref().unwrap_or_default();
                    rendered.push(format!("{name}: {value}"));
                }
                cursor = rest;
            }

            let body = rendered.join(", ");
            // `name` outlives the borrow `type_leaf_name` returns.
            let name = struct_ty.name();
            let out = match (name.as_deref().and_then(type_leaf_name), tuple) {
                (Some(name), true) => format!("{name}({body})"),
                (Some(name), false) => format!("{name} {{ {body} }}"),
                (None, true) => format!("({body})"),
                (None, false) => format!("{{ {body} }}"),
            };
            Ok((out, cursor))
        },
        Type::Array(array_ty) => {
            let mut cursor = felts;
            let mut rendered = Vec::new();
            for _ in 0..array_ty.len {
                let before = cursor.len();
                let (value, rest) = decode_type(cursor, &array_ty.ty, codecs)?;
                rendered.push(value);
                cursor = rest;
                // An element of width zero reads nothing. Without this check, a big `len` would
                // loop and never move forward.
                if cursor.len() == before {
                    break;
                }
            }
            Ok((format!("[{}]", rendered.join(", ")), cursor))
        },
        Type::List(_) => Err(TypedError::UnsupportedType("list")),
        Type::Ptr(_) => Err(TypedError::UnsupportedType("pointer")),
        Type::Function(_) => Err(TypedError::UnsupportedType("function")),
        Type::Enum(_) => Err(TypedError::UnsupportedType("enum")),
        Type::Unknown => Err(TypedError::UnsupportedType("unknown")),
        Type::Never => Err(TypedError::UnsupportedType("never")),
        primitive => decode_primitive(felts, primitive),
    }
}

fn decode_primitive<'a>(felts: &'a [Felt], ty: &Type) -> Result<(String, &'a [Felt]), TypedError> {
    let n = ty.size_in_felts();
    let bits = ty.size_in_bits() as u32;

    match ty {
        Type::Felt => {
            let (head, rest) = take_one_felt(felts, ty)?;
            Ok((head.to_string(), rest))
        },
        Type::I1 => {
            let (head, rest) = take_one_felt(felts, ty)?;
            let rendered = match head.as_canonical_u64() {
                0 => "false".into(),
                1 => "true".into(),
                _ => {
                    return Err(malformed(ty, "a bool is either 0 or 1"));
                },
            };
            Ok((rendered, rest))
        },
        // A signed value fills its whole slot, sign-extended, so it is read at the slot's width
        // and only then checked against the range of its type.
        Type::I8 | Type::I16 | Type::I32 | Type::I64 | Type::I128 => {
            let (value, rest) = read_limbs(felts, n, ty)?;
            let signed = signed_from_bits(value, slot_bits(n));
            let (min, max) = signed_range(bits);
            if signed < min || signed > max {
                return Err(malformed(ty, "the value is outside the range of the type"));
            }
            Ok((signed.to_string(), rest))
        },
        // An unsigned value is masked to its own width, not extended, so anything wider is bad
        // output. Without this check a `u8` result of 300 would read as 44.
        Type::U8 | Type::U16 | Type::U32 | Type::U64 | Type::U128 => {
            let (value, rest) = read_limbs(felts, n, ty)?;
            if value > max_for_bits(bits) {
                return Err(malformed(ty, "the value is wider than the type"));
            }
            Ok((value.to_string(), rest))
        },
        Type::F64 => {
            let (value, rest) = read_limbs(felts, n, ty)?;
            Ok((f64::from_bits(value as u64).to_string(), rest))
        },
        // 256 bits do not fit our `u128` path. We cannot decode them yet.
        Type::U256 => Err(TypedError::UnsupportedType("u256")),
        _ => Err(TypedError::UnsupportedType("unsupported primitive")),
    }
}

/// Reads `n` limbs of 32 bits from the start of `felts`, low limb first, and joins them into a
/// `u128`. `n` is 4 or less, so 128 bits are enough. The opposite of `limbs_to_felts`.
///
/// Whether the value belongs to the type is up to the caller: the answer differs for a signed and
/// an unsigned type.
fn read_limbs<'a>(
    felts: &'a [Felt],
    n: usize,
    ty: &Type,
) -> Result<(u128, &'a [Felt]), TypedError> {
    let (chunk, rest) = take_felts(felts, n, ty)?;
    let mut value: u128 = 0;
    for (i, f) in chunk.iter().enumerate() {
        let limb = f.as_canonical_u64();
        if limb > u32::MAX as u64 {
            return Err(malformed(ty, "a felt is wider than the 32-bit limb it stands for"));
        }
        value |= (limb as u128) << (32 * i);
    }
    Ok((value, rest))
}

fn take_one_felt<'a>(felts: &'a [Felt], ty: &Type) -> Result<(&'a Felt, &'a [Felt]), TypedError> {
    felts.split_first().ok_or_else(|| malformed(ty, STACK_TOO_SHORT))
}

fn take_felts<'a>(
    felts: &'a [Felt],
    n: usize,
    ty: &Type,
) -> Result<(&'a [Felt], &'a [Felt]), TypedError> {
    felts.split_at_checked(n).ok_or_else(|| malformed(ty, STACK_TOO_SHORT))
}

fn malformed(ty: &Type, reason: &'static str) -> TypedError {
    TypedError::MalformedResult { ty: ty.to_string(), reason }
}
