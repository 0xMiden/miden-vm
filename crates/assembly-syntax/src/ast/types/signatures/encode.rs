//! Turns argument tokens into the felts a procedure needs on the stack.

use alloc::{boxed::Box, string::ToString, vec::Vec};
use core::str::FromStr;

use miden_core::Felt;
use midenc_hir_type::Type;

use super::{
    WitScalarCodec,
    arity::{felt_count, max_for_bits, signed_range, slot_bits, token_count},
    codec::{codec_for_struct, parse_felt_token},
    errors::TypedError,
};

/// Encodes one value of `ty`. It reads exactly as many tokens as
/// [`token_count`](super::arity::token_count) says, and makes as many felts as the value takes on
/// the stack.
pub(super) fn encode_type<I>(
    tokens: &mut I,
    ty: &Type,
    codecs: &[Box<dyn WitScalarCodec>],
) -> Result<Vec<Felt>, TypedError>
where
    I: Iterator,
    I::Item: AsRef<str>,
{
    match ty {
        Type::Struct(struct_ty) => {
            let struct_ty = struct_ty.get();
            if let Some(codec) = codec_for_struct(codecs, &struct_ty) {
                let token = tokens.next().ok_or(TypedError::TokenCountMismatch)?;
                let felts = codec.encode(token.as_ref())?;
                // A codec chooses the text form of its type, but not the width. A wrong width
                // would put a value on the stack that the procedure cannot read. A type with no
                // width on the stack gives us nothing to check against, so it stops here too,
                // the same way it does when we decode.
                let expected = felt_count(ty).ok_or(TypedError::UnsupportedType("struct"))?;
                if felts.len() != expected {
                    return Err(TypedError::CodecWidthMismatch {
                        wit_name: codec.wit_name().to_string(),
                        expected,
                        actual: felts.len(),
                    });
                }
                return Ok(felts);
            }
            let mut felts = Vec::new();
            for field in struct_ty.fields() {
                felts.extend(encode_type(tokens, &field.ty, codecs)?);
            }
            Ok(felts)
        },
        Type::Array(array_ty) => {
            if token_count(&array_ty.ty, codecs) == Some(0) {
                return Ok(Vec::new());
            }
            let mut felts = Vec::new();
            for _ in 0..array_ty.len {
                felts.extend(encode_type(tokens, &array_ty.ty, codecs)?);
            }
            Ok(felts)
        },
        Type::List(_) => Err(TypedError::UnsupportedType("list")),
        Type::Ptr(_) => Err(TypedError::UnsupportedType("pointer")),
        Type::Function(_) => Err(TypedError::UnsupportedType("function")),
        Type::Enum(_) => Err(TypedError::UnsupportedType("enum")),
        Type::Unknown => Err(TypedError::UnsupportedType("unknown")),
        Type::Never => Err(TypedError::UnsupportedType("never")),
        primitive => {
            let token = tokens.next().ok_or(TypedError::TokenCountMismatch)?;
            encode_primitive(token.as_ref(), primitive)
        },
    }
}

fn encode_primitive(token: &str, ty: &Type) -> Result<Vec<Felt>, TypedError> {
    let felts = ty.size_in_felts();
    let bits = ty.size_in_bits() as u32;

    match ty {
        // The compiler turns WIT `felt` into a named struct, and `FeltCodec` handles that. This
        // branch is for a plain field element in the signature. Both read the token the same way,
        // but here we do not go through the codec.
        Type::Felt => Ok(alloc::vec![parse_felt_token(token)?]),
        Type::I1 => {
            let v = match token.to_ascii_lowercase().as_str() {
                "true" | "1" => 1,
                "false" | "0" => 0,
                _ => return Err(TypedError::InvalidBool(token.to_string())),
            };
            Ok(alloc::vec![Felt::from_u32(v)])
        },
        Type::I8 | Type::I16 | Type::I32 | Type::I64 | Type::I128 => {
            let value = parse_signed(token, bits, slot_bits(felts), ty)?;
            Ok(limbs_to_felts(value, felts))
        },
        Type::U8 | Type::U16 | Type::U32 | Type::U64 | Type::U128 => {
            let value = parse_unsigned(token, bits, ty)?;
            Ok(limbs_to_felts(value, felts))
        },
        Type::F64 => {
            let value = parse_number::<f64>(token, ty)?;
            Ok(limbs_to_felts(value.to_bits() as u128, felts))
        },
        // 256 bits do not fit our `u128` path. We cannot encode them yet.
        Type::U256 => Err(TypedError::UnsupportedType("u256")),
        _ => Err(TypedError::UnsupportedType("unsupported primitive")),
    }
}

/// Cuts `value` into `n` limbs of 32 bits, one felt each. The low limb comes first, so `felts[0]`
/// holds bits `0..32`. Every limb is a `u32`, so [`Felt::from_u32`] always works.
fn limbs_to_felts(value: u128, n: usize) -> Vec<Felt> {
    debug_assert!(n <= 4, "a value of more than four limbs does not fit the u128 path");
    (0..n).map(|i| Felt::from_u32((value >> (32 * i)) as u32)).collect()
}

/// Reads `token` as `T`, naming the type from the signature in the error.
fn parse_number<T: FromStr>(token: &str, ty: &Type) -> Result<T, TypedError> {
    token.parse::<T>().map_err(|_| TypedError::InvalidNumber {
        token: token.to_string(),
        ty: ty.to_string(),
    })
}

/// Reads an unsigned decimal number and checks that it fits in `bits` bits.
fn parse_unsigned(token: &str, bits: u32, ty: &Type) -> Result<u128, TypedError> {
    let value = parse_number::<u128>(token, ty)?;
    if value > max_for_bits(bits) {
        return Err(int_out_of_range(token, ty));
    }
    Ok(value)
}

/// Reads a signed decimal number and returns the bits that go on the stack. The value has to fit
/// the `bits` of its type, but it is written sign-extended across the whole `slot`: `-1i8` is the
/// 32-bit pattern of `-1`, not the byte `0xff`.
fn parse_signed(token: &str, bits: u32, slot: u32, ty: &Type) -> Result<u128, TypedError> {
    let signed = parse_number::<i128>(token, ty)?;
    let (min, max) = signed_range(bits);
    if signed < min || signed > max {
        return Err(int_out_of_range(token, ty));
    }
    Ok((signed as u128) & max_for_bits(slot))
}

fn int_out_of_range(token: &str, ty: &Type) -> TypedError {
    TypedError::IntOutOfRange {
        token: token.to_string(),
        ty: ty.to_string(),
    }
}
