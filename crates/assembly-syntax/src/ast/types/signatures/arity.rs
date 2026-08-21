//! How much room a value takes, and what fits in it.
//!
//! [`felt_count`] and [`token_count`] are one walk over a type that adds up a number for each
//! leaf: the felts a value takes on the stack, and the argument tokens it needs. The walk lives
//! here, so arrays and structs always work the same way for both. Only the number for a leaf is
//! different.
//!
//! The rest is arithmetic on the width of a stack slot, which encode and decode both need to tell
//! a value that fits from one that does not.

use alloc::boxed::Box;

use midenc_hir_type::Type;

use super::{WitScalarCodec, codec::codec_for_struct};

/// How many felts a value of `ty` takes on the stack. `None` if the type has no place on the
/// stack.
///
/// For a struct we add up the fields. We do not use the byte size of the struct, because the ABI
/// puts every field in its own stack slot, so the padding between fields never reaches the
/// stack.
pub(super) fn felt_count(ty: &Type) -> Option<usize> {
    count_units(ty, &[], Unit::Felts)
}

/// How many argument tokens a value of `ty` needs. One for each primitive leaf. One for a type
/// with a codec, whatever number of fields it has. For a struct or a fixed array, the sum of its
/// parts.
///
/// `None` if the count is not fixed: lists, pointers, functions, enums and unknown types. Encoding
/// would fail for those anyway.
pub(super) fn token_count(ty: &Type, codecs: &[Box<dyn WitScalarCodec>]) -> Option<usize> {
    count_units(ty, codecs, Unit::Tokens)
}

/// What [`count_units`] counts. This is the only difference between the two walks at a leaf.
#[derive(Clone, Copy)]
enum Unit {
    /// The felts a leaf takes on the stack.
    Felts,
    /// The argument tokens a leaf needs: always one.
    Tokens,
}

/// Adds up the number for each leaf of `ty`. A type with a codec counts as one unit. The felt
/// walk passes no codecs, so that branch only runs for the token walk.
fn count_units(ty: &Type, codecs: &[Box<dyn WitScalarCodec>], unit: Unit) -> Option<usize> {
    match ty {
        Type::Struct(struct_ty) => {
            if codec_for_struct(codecs, struct_ty).is_some() {
                return Some(1);
            }
            let mut total = 0usize;
            for field in struct_ty.fields() {
                total = total.checked_add(count_units(&field.ty, codecs, unit)?)?;
            }
            Some(total)
        },
        Type::Array(array_ty) => {
            let element = count_units(&array_ty.ty, codecs, unit)?;
            element.checked_mul(array_ty.len)
        },
        // Types we do not take from the user. Most of them do have a place on the stack: `Ptr`
        // and `Function` are `u32` values in one felt, and an enum is its tag or a blob as big as
        // its biggest variant. But none of them has a text form a user could type. If we gave
        // them a size here, we would promise something the encoder cannot do. `U256` has a place
        // on the stack too, but it is wider than the `u128` path we use everywhere. Only `Never`
        // and `Unknown` really hold no value; their size is zero, so we say no here instead of
        // counting them as nothing.
        Type::List(_)
        | Type::Ptr(_)
        | Type::Function(_)
        | Type::Enum(_)
        | Type::U256
        | Type::Unknown
        | Type::Never => None,
        primitive => Some(match unit {
            Unit::Felts => primitive.size_in_felts(),
            Unit::Tokens => 1,
        }),
    }
}

/// The biggest unsigned value for `bits` bits. We also use it as a mask for the low `bits` bits.
/// Both encode and decode need it.
pub(super) fn max_for_bits(bits: u32) -> u128 {
    if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 }
}

/// The lowest and highest value a signed integer of `bits` bits can hold.
pub(super) fn signed_range(bits: u32) -> (i128, i128) {
    let shift = 128 - bits;
    (i128::MIN >> shift, i128::MAX >> shift)
}

/// Reads `value` as a signed integer that fills `bits` bits, copying the sign and dropping
/// anything above it.
pub(super) fn signed_from_bits(value: u128, bits: u32) -> i128 {
    let shift = 128 - bits;
    ((value << shift) as i128) >> shift
}

/// The bits a value occupies on the stack, which is not the width of its type: the canonical ABI
/// gives every integer a whole number of 32-bit slots, so an `i8` travels in 32 bits.
pub(super) fn slot_bits(felts: usize) -> u32 {
    felts as u32 * 32
}
