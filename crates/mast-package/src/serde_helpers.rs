//! Deserialization helpers that the package sections and the debug information share.
//!
//! The helpers hold the rules that every untrusted decode applies: a length-prefixed string
//! keeps a byte cap, and a section payload decodes under a byte budget and accepts no trailing
//! bytes.

use miden_core::serde::{
    BudgetedReader, ByteReader, Deserializable, DeserializationError, SliceReader, read_bounded_len,
};

// CAPPED STRING
// ================================================================================================

/// Reads a length-prefixed UTF-8 string whose byte length must stay at or below `max_size`.
///
/// `label` names the string in the length and encoding errors. `over_cap` builds the error for a
/// length over `max_size`, so each caller keeps the message of its own format.
///
/// The declared length passes the reader budget check before the bytes are read, so a short
/// payload cannot make the decode allocate.
///
/// # Errors
/// Returns an error when the length is over the reader budget or over `max_size`, when the bytes
/// are missing, or when the bytes are not UTF-8.
pub(crate) fn read_capped_str<'a, R: ByteReader>(
    source: &'a mut R,
    label: &str,
    max_size: usize,
    over_cap: impl FnOnce(usize) -> DeserializationError,
) -> Result<&'a str, DeserializationError> {
    let len = read_bounded_len(source, label, 1)?;
    if len > max_size {
        return Err(over_cap(len));
    }
    let bytes = source.read_slice(len)?;
    core::str::from_utf8(bytes).map_err(|err| {
        DeserializationError::InvalidValue(format!("invalid utf-8 in {label}: {err}"))
    })
}

// BUDGETED PAYLOAD
// ================================================================================================

/// The failure of a budgeted payload decode.
pub(crate) enum PayloadError {
    /// The payload failed to decode.
    Decode(DeserializationError),
    /// Bytes follow the encoded value.
    TrailingBytes,
}

/// Decodes a value from the payload of a package section.
///
/// The payload is untrusted input, so the reader gets a budget of the payload size: no length
/// prefix can make the decode allocate more than the payload holds. Bytes after the encoded
/// value are refused, because a section payload holds one value and nothing else.
///
/// # Errors
/// Returns [`PayloadError::Decode`] when the payload fails to decode, and
/// [`PayloadError::TrailingBytes`] when bytes follow the encoded value.
pub(crate) fn read_payload_with_budget<T: Deserializable>(bytes: &[u8]) -> Result<T, PayloadError> {
    let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
    let value = T::read_from(&mut reader).map_err(PayloadError::Decode)?;
    if reader.has_more_bytes() {
        return Err(PayloadError::TrailingBytes);
    }
    Ok(value)
}
