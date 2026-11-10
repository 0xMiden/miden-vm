//! Test-only utilities shared across unit tests.

use alloc::string::String;

use miden_assembly_syntax::ast::types::Type;

use crate::debug::FormatType;

/// Formats a scalar value that has already been read from memory as little-endian bytes.
pub(crate) fn write_scalar_bytes(
    output: &mut String,
    ty: &'static str,
    format: FormatType,
    bytes: &[u8],
) -> Result<(), String> {
    use core::fmt::Write;

    let ty = match ty {
        "i1" => Type::I1,
        "i8" => Type::I8,
        "u8" => Type::U8,
        "i16" => Type::I16,
        "u16" => Type::U16,
        "i32" => Type::I32,
        "u32" => Type::U32,
        "i64" => Type::I64,
        "u64" => Type::U64,
        other => return Err(format!("unsupported scalar test type '{other}'")),
    };

    macro_rules! write_with_format_type {
        ($value:expr) => {
            match format {
                FormatType::Decimal => write!(output, "{}", $value).unwrap(),
                FormatType::Hex => write!(output, "{:0x}", $value).unwrap(),
                FormatType::Binary => write!(output, "{:0b}", $value).unwrap(),
            }
        };
    }

    match ty {
        Type::I1 => match format {
            FormatType::Decimal => write!(output, "{}", bytes[0] != 0).unwrap(),
            FormatType::Hex => write!(output, "{:#0x}", (bytes[0] != 0) as u8).unwrap(),
            FormatType::Binary => write!(output, "{:#0b}", (bytes[0] != 0) as u8).unwrap(),
        },
        Type::I8 => write_with_format_type!(bytes[0] as i8),
        Type::U8 => write_with_format_type!(bytes[0]),
        Type::I16 => write_with_format_type!(i16::from_le_bytes([bytes[0], bytes[1]])),
        Type::U16 => write_with_format_type!(u16::from_le_bytes([bytes[0], bytes[1]])),
        Type::I32 => {
            write_with_format_type!(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }
        Type::U32 => {
            write_with_format_type!(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }
        Type::I64 => write_with_format_type!(i64::from_le_bytes(bytes[..8].try_into().unwrap())),
        Type::U64 => write_with_format_type!(u64::from_le_bytes(bytes[..8].try_into().unwrap())),
        _ => return Err(format!("support for reads of type '{ty}' are not implemented yet")),
    }

    Ok(())
}
