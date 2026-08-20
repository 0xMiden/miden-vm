//! The `event_handlers` package section: a Wasm module with custom event handlers.
//!
//! The section carries one untrusted core Wasm module plus a manifest that maps event names to
//! the exports that handle them. Hosts hand the section to the `miden-wasm-event-handlers` crate,
//! which validates the module and registers one handler per manifest entry.
//!
//! The section is semantic package content: handler code decides the advice a program receives,
//! so the section is part of [`Package::dependency_commitment`](crate::Package::dependency_commitment). The
//! manifest order inside the section is canonical — reordering entries changes the package
//! identity.
//!
//! Decoding applies explicit size caps ([`MAX_MODULE_BYTES`], [`MAX_HANDLERS`],
//! [`MAX_NAME_BYTES`]) and rejects oversized payloads before allocation, since the section is
//! untrusted input.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use miden_core::{
    events::EventName,
    serde::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        validate_bounded_len,
    },
};

// CONSTANTS
// ================================================================================================

/// The maximum size of the embedded Wasm module, in bytes (16 MiB).
pub const MAX_MODULE_BYTES: usize = 16 * 1024 * 1024;

/// The maximum number of handler manifest entries.
pub const MAX_HANDLERS: usize = 256;

/// The maximum length of an event name or an export name, in bytes.
pub const MAX_NAME_BYTES: usize = 255;

/// The smallest serialized size of one manifest entry: two empty length-prefixed names.
const MIN_ENTRY_BYTES: usize = 2;

// EVENT HANDLER SECTION
// ================================================================================================

/// The decoded content of the `event_handlers` package section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventHandlerSection {
    /// The version of the host/guest ABI contract the module was built against.
    pub abi_version: u32,
    /// The Wasm binary of the handler module.
    pub module: Vec<u8>,
    /// The manifest: one entry per handler the module provides. The order is canonical.
    pub handlers: Vec<EventHandlerManifestEntry>,
}

/// One manifest entry: the event and the Wasm export that handles it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventHandlerManifestEntry {
    /// The name of the event.
    pub event: EventName,
    /// The name of the Wasm export that handles the event.
    pub export: String,
}

impl EventHandlerManifestEntry {
    /// Creates a manifest entry.
    pub fn new(event: EventName, export: impl Into<String>) -> Self {
        Self { event, export: export.into() }
    }
}

// ERRORS
// ================================================================================================

/// An error raised while attaching or extracting an [`EventHandlerSection`].
#[derive(Debug, thiserror::Error)]
pub enum EventHandlerSectionError {
    /// The package contains more than one `event_handlers` section.
    #[error("package contains more than one 'event_handlers' section")]
    DuplicateSection,

    /// The package already has an `event_handlers` section, so another one cannot be attached.
    #[error("package already has an 'event_handlers' section")]
    AlreadyPresent,

    /// The section payload failed to decode.
    #[error("failed to decode 'event_handlers' section: {0}")]
    Decode(#[from] DeserializationError),

    /// The section payload has bytes after the encoded section.
    #[error("'event_handlers' section has trailing bytes")]
    TrailingBytes,

    /// A field of the section goes over its size cap.
    #[error("'event_handlers' section {field} length {actual} goes over the cap of {max}")]
    OverSizeCap {
        /// The offending field.
        field: &'static str,
        /// The declared or actual length.
        actual: usize,
        /// The cap for the field.
        max: usize,
    },
}

// SERIALIZATION
// ================================================================================================

/// Checks a declared length against its cap and returns a deserialization error over the cap.
fn check_cap(field: &'static str, actual: usize, max: usize) -> Result<(), DeserializationError> {
    if actual > max {
        return Err(DeserializationError::InvalidValue(alloc::format!(
            "'event_handlers' section {field} length {actual} goes over the cap of {max}"
        )));
    }
    Ok(())
}

/// Reads a length prefix, checks it against `max`, and checks that the source still holds the
/// bytes the length claims.
///
/// `min_element_size` is the smallest serialized size of one of the elements the length counts.
fn read_capped_len<R: ByteReader>(
    source: &mut R,
    field: &'static str,
    max: usize,
    min_element_size: usize,
) -> Result<usize, DeserializationError> {
    let len = source.read_usize()?;
    check_cap(field, len, max)?;
    validate_bounded_len(source, field, len, min_element_size)?;
    Ok(len)
}

/// Reads a length-prefixed string with `field` capped at [`MAX_NAME_BYTES`].
///
/// The [`Deserializable`] impl of `String` reads the same bytes, but it applies no cap before it
/// allocates, so the untrusted decode keeps this reader.
fn read_str<R: ByteReader>(
    source: &mut R,
    field: &'static str,
) -> Result<String, DeserializationError> {
    let len = read_capped_len(source, field, MAX_NAME_BYTES, 1)?;
    let bytes = source.read_slice(len)?;
    let value = core::str::from_utf8(bytes).map_err(|err| {
        DeserializationError::InvalidValue(alloc::format!("invalid utf-8 in {field}: {err}"))
    })?;
    Ok(value.to_string())
}

impl Serializable for EventHandlerSection {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.abi_version);
        target.write_usize(self.module.len());
        target.write_bytes(&self.module);
        target.write_usize(self.handlers.len());
        for entry in &self.handlers {
            entry.event.write_into(target);
            entry.export.write_into(target);
        }
    }
}

impl Deserializable for EventHandlerSection {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let abi_version = source.read_u32()?;

        let module_len = read_capped_len(source, "module", MAX_MODULE_BYTES, 1)?;
        let module = source.read_slice(module_len)?.to_vec();

        let handler_count =
            read_capped_len(source, "handler count", MAX_HANDLERS, MIN_ENTRY_BYTES)?;
        let mut handlers = Vec::with_capacity(handler_count);
        for _ in 0..handler_count {
            let event = EventName::from_string(read_str(source, "event name")?);
            let export = read_str(source, "export name")?;
            handlers.push(EventHandlerManifestEntry { event, export });
        }

        Ok(Self { abi_version, module, handlers })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_core::serde::SliceReader;

    use super::*;

    fn sample() -> EventHandlerSection {
        EventHandlerSection {
            abi_version: 1,
            module: vec![0, 97, 115, 109, 1, 0, 0, 0],
            handlers: vec![
                EventHandlerManifestEntry::new(EventName::new("test::wasm::a"), "a"),
                EventHandlerManifestEntry::new(EventName::new("test::wasm::b"), "b"),
            ],
        }
    }

    #[test]
    fn section_roundtrip() {
        let section = sample();
        let bytes = section.to_bytes();
        let decoded = EventHandlerSection::read_from(&mut SliceReader::new(&bytes)).unwrap();
        assert_eq!(decoded, section);
    }

    #[test]
    fn oversized_module_is_rejected_before_allocation() {
        let mut bytes = Vec::new();
        bytes.write_u32(1);
        // A module length far over the cap; no module bytes follow.
        bytes.write_usize(MAX_MODULE_BYTES + 1);
        let err = EventHandlerSection::read_from(&mut SliceReader::new(&bytes)).unwrap_err();
        assert!(err.to_string().contains("cap"), "unexpected error: {err}");
    }

    #[test]
    fn oversized_handler_count_is_rejected() {
        let mut bytes = Vec::new();
        bytes.write_u32(1);
        bytes.write_usize(0);
        bytes.write_usize(MAX_HANDLERS + 1);
        let err = EventHandlerSection::read_from(&mut SliceReader::new(&bytes)).unwrap_err();
        assert!(err.to_string().contains("cap"), "unexpected error: {err}");
    }

    #[test]
    fn oversized_event_name_is_rejected() {
        let mut bytes = Vec::new();
        bytes.write_u32(1);
        bytes.write_usize(0);
        bytes.write_usize(1);
        bytes.write_usize(MAX_NAME_BYTES + 1);
        let err = EventHandlerSection::read_from(&mut SliceReader::new(&bytes)).unwrap_err();
        assert!(err.to_string().contains("cap"), "unexpected error: {err}");
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let bytes = sample().to_bytes();
        for cut in [0, 4, 8, bytes.len() - 1] {
            let result = EventHandlerSection::read_from(&mut SliceReader::new(&bytes[..cut]));
            assert!(result.is_err(), "truncation at {cut} must fail");
        }
    }
}
