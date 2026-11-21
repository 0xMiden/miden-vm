use alloc::string::{String, ToString};

use super::FormatType;
#[cfg(feature = "std")]
use super::{MemoryMode, ReadMemoryExpr};
use crate::test_utils::write_scalar_bytes;

#[test]
fn write_scalar_bytes_reads_little_endian_u64() {
    let mut output = String::new();

    write_scalar_bytes(&mut output, "u64", FormatType::Decimal, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();

    assert_eq!(output, u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]).to_string());
}

#[test]
fn write_scalar_bytes_reads_little_endian_u16_hex() {
    let mut output = String::new();

    write_scalar_bytes(&mut output, "u16", FormatType::Hex, &[0x34, 0x12]).unwrap();

    assert_eq!(output, "1234");
}

#[test]
#[cfg(feature = "std")]
fn parses_word_and_byte_memory_reads() {
    let word: ReadMemoryExpr = "0x10".parse().unwrap();
    assert_eq!(word.addr.addr, 0x10);
    assert_eq!(word.addr.offset, 0);
    assert_eq!(word.mode, MemoryMode::Word);
    assert_eq!(word.count, 1);
    assert_eq!(word.to_string(), "16 -t word");

    let bytes: ReadMemoryExpr = "17 -t u64 -c 2 -m bytes -f hex".parse().unwrap();
    assert_eq!(bytes.addr.addr, 4);
    assert_eq!(bytes.addr.offset, 1);
    assert_eq!(bytes.mode, MemoryMode::Byte);
    assert_eq!(bytes.count, 2);
    assert_eq!(bytes.to_string(), "17 -t u64 -c 2 -m byte -f hex");
}

#[test]
#[cfg(feature = "std")]
fn parses_all_memory_types_and_aliases() {
    for ty in [
        "i1", "i8", "i16", "i32", "i64", "i128", "u8", "u16", "u32", "u64", "u128", "felt", "word",
        "ptr",
    ] {
        let expr = format!("0 -t {ty}");
        assert!(expr.parse::<ReadMemoryExpr>().is_ok(), "failed to parse {ty}");
    }
    for mode in ["w", "word", "words", "miden"] {
        assert_eq!(mode.parse::<MemoryMode>().unwrap(), MemoryMode::Word);
    }
    for mode in ["b", "byte", "bytes", "rust"] {
        assert_eq!(mode.parse::<MemoryMode>().unwrap(), MemoryMode::Byte);
    }
    for format in ["d", "decimal"] {
        assert_eq!(format.parse::<FormatType>().unwrap(), FormatType::Decimal);
    }
    for format in ["x", "hex", "hexadecimal"] {
        assert_eq!(format.parse::<FormatType>().unwrap(), FormatType::Hex);
    }
    for format in ["b", "bin", "binary", "bits"] {
        assert_eq!(format.parse::<FormatType>().unwrap(), FormatType::Binary);
    }
}

#[test]
#[cfg(feature = "std")]
fn rejects_invalid_memory_read_arguments() {
    for input in ["", "-1", "0xnot-an-address", "0 -t nope", "0 -m nope", "0 -f nope"] {
        assert!(input.parse::<ReadMemoryExpr>().is_err(), "accepted {input:?}");
    }
    assert!("invalid".parse::<MemoryMode>().is_err());
    assert!("invalid".parse::<FormatType>().is_err());
}
