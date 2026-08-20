//! The `event_handlers` package section: a Wasm module with custom event handlers.
//!
//! The section carries one untrusted core Wasm module plus a manifest that maps event names to
//! the exports that handle them. Hosts hand the section to the `miden-wasm-event-handlers` crate,
//! which validates the module and registers one handler per manifest entry.
//!
//! The section is semantic package content: handler code decides the advice a program receives,
//! so the section is part of [`Package::dependency_commitment`](crate::Package::dependency_commitment). The
//! manifest order inside the section is canonical — reordering entries changes the package
//! identity. Tooling that derives the manifest from a guest module sorts the entries by event
//! name, so link order does not change the identity.
//!
//! [`EventHandlerSection::validate`] holds the rules that all paths share. Attaching, decoding,
//! and deriving a section apply the same check, so every host sees the same set of accepted
//! sections.
//!
//! Decoding applies explicit size caps ([`MAX_MODULE_BYTES`], [`MAX_HANDLERS`],
//! [`MAX_NAME_BYTES`]), rejects oversized payloads before allocation, and rejects empty event
//! and export names, since the section is untrusted input.

use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};

use miden_core::{
    events::EventName,
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader, validate_bounded_len,
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

/// The lowest ABI version a section can declare. Version 0 names no host/guest contract.
const MIN_ABI_VERSION: u32 = 1;

/// A lower bound on the serialized size of one manifest entry: the two name length prefixes.
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
    /// The manifest: one entry per handler the module provides.
    ///
    /// The order is canonical: it is part of the package identity. Derivation from a guest
    /// module canonicalizes the order by event name, because the record order in the module is
    /// link order and changes with the toolchain.
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

// VALIDATION
// ================================================================================================

impl EventHandlerSection {
    /// Checks the section against the rules that every path shares.
    ///
    /// The rules are: the ABI version is at least 1; the module, the handler count, and each
    /// name stay inside their caps; each name is not empty; no two entries name the same event;
    /// and no entry names an event in
    /// [`EventName::RESERVED_NAMESPACE`](miden_core::events::EventName::RESERVED_NAMESPACE).
    ///
    /// Attaching, decoding, and deriving a section apply this check. The format decode does not:
    /// it applies only the caps it needs before it allocates.
    ///
    /// # Errors
    /// Returns an error when the section breaks one of the rules above.
    pub fn validate(&self) -> Result<(), EventHandlerSectionError> {
        if self.abi_version < MIN_ABI_VERSION {
            return Err(EventHandlerSectionError::UnsupportedAbiVersion {
                version: self.abi_version,
            });
        }
        check_size_cap("module", self.module.len(), MAX_MODULE_BYTES)?;
        check_size_cap("handler count", self.handlers.len(), MAX_HANDLERS)?;

        let mut seen = BTreeSet::new();
        for entry in &self.handlers {
            for (field, name) in
                [("event name", entry.event.as_str()), ("export name", entry.export.as_str())]
            {
                if name.is_empty() {
                    return Err(EventHandlerSectionError::EmptyName { field });
                }
                check_size_cap(field, name.len(), MAX_NAME_BYTES)?;
            }
            if entry.event.is_reserved() {
                return Err(EventHandlerSectionError::ReservedEventName {
                    event: entry.event.clone(),
                });
            }
            // A host registers handlers by event ID, so two entries with the same ID cannot both
            // register.
            if !seen.insert(entry.event.to_event_id()) {
                return Err(EventHandlerSectionError::DuplicateEvent {
                    event: entry.event.clone(),
                });
            }
        }
        Ok(())
    }
}

/// Checks a length against its cap.
fn check_size_cap(
    field: &'static str,
    actual: usize,
    max: usize,
) -> Result<(), EventHandlerSectionError> {
    if actual > max {
        return Err(EventHandlerSectionError::OverSizeCap { field, actual, max });
    }
    Ok(())
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

    /// The section declares an ABI version that no host/guest contract uses.
    #[error("'event_handlers' section declares unsupported abi version {version}")]
    UnsupportedAbiVersion {
        /// The declared version.
        version: u32,
    },

    /// A name of a manifest entry is empty.
    #[error("'event_handlers' section {field} is empty")]
    EmptyName {
        /// The offending field.
        field: &'static str,
    },

    /// More than one manifest entry names the same event.
    #[error("'event_handlers' section has more than one handler for event '{event}'")]
    DuplicateEvent {
        /// The event with more than one handler.
        event: EventName,
    },

    /// A manifest entry names an event in the reserved namespace, which only the VM can handle.
    #[error(
        "'event_handlers' section handles event '{event}' in the reserved '{namespace}' namespace",
        namespace = EventName::RESERVED_NAMESPACE
    )]
    ReservedEventName {
        /// The reserved event name.
        event: EventName,
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
/// allocates, so the untrusted decode keeps this reader. An empty name is refused: it names no
/// event and no export.
fn read_str<R: ByteReader>(
    source: &mut R,
    field: &'static str,
) -> Result<String, DeserializationError> {
    let len = read_capped_len(source, field, MAX_NAME_BYTES, 1)?;
    if len == 0 {
        return Err(DeserializationError::InvalidValue(alloc::format!(
            "'event_handlers' section {field} is empty"
        )));
    }
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

impl EventHandlerSection {
    /// Decodes the payload of an `event_handlers` package section.
    ///
    /// The payload is untrusted input, so the reader gets a budget of the payload size, bytes
    /// after the encoded section are refused, and the decoded section must pass
    /// [`Self::validate`]. This is the full decode path:
    /// [`Package::event_handlers`](crate::Package::event_handlers) and the fuzz target both call
    /// it, so neither can drift from the other.
    ///
    /// # Errors
    /// Returns an error when the payload fails to decode (including size-cap violations), when
    /// bytes follow the encoded section, or when the section breaks a rule of [`Self::validate`].
    pub fn from_payload(bytes: &[u8]) -> Result<Self, EventHandlerSectionError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        let section = Self::read_from(&mut reader)?;
        if reader.has_more_bytes() {
            return Err(EventHandlerSectionError::TrailingBytes);
        }
        section.validate()?;
        Ok(section)
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
    fn empty_event_name_is_rejected() {
        let mut bytes = Vec::new();
        bytes.write_u32(1);
        bytes.write_usize(0);
        bytes.write_usize(1);
        // An empty event name, followed by a valid export name.
        bytes.write_usize(0);
        "handler".to_string().write_into(&mut bytes);
        let err = EventHandlerSection::read_from(&mut SliceReader::new(&bytes)).unwrap_err();
        assert!(err.to_string().contains("event name is empty"), "unexpected error: {err}");
    }

    #[test]
    fn empty_export_name_is_rejected() {
        let mut bytes = Vec::new();
        bytes.write_u32(1);
        bytes.write_usize(0);
        bytes.write_usize(1);
        EventName::new("test::wasm::a").write_into(&mut bytes);
        // An empty export name.
        bytes.write_usize(0);
        let err = EventHandlerSection::read_from(&mut SliceReader::new(&bytes)).unwrap_err();
        assert!(err.to_string().contains("export name is empty"), "unexpected error: {err}");
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
