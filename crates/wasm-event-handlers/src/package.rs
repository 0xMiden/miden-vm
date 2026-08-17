//! Loading Wasm event handlers out of a Miden package, and deriving the handler manifest from
//! a compiled guest module.

use alloc::{format, string::ToString, sync::Arc, vec::Vec};

use miden_event_handler_abi::{ABI_VERSION, MANIFEST_SECTION_NAME};
use miden_mast_package::{EventHandlerManifestEntry, EventHandlerSection, Package};
use miden_processor::{
    HostLibrary,
    event::{EventHandler, EventName},
};

use crate::{
    WasmHandlerLimits, WasmHandlerLoadError, WasmHandlerModule,
    module::{read_leb_u32, walk_wasm_sections},
};

/// Loads the package's `event_handlers` section, validates the Wasm module, and returns one
/// registered-handler pair per manifest entry.
///
/// Returns an empty vector when the package has no `event_handlers` section.
///
/// # Errors
/// Returns an error when the section is malformed (see
/// [`EventHandlerSectionError`](miden_mast_package::EventHandlerSectionError)) or when the
/// handler module fails validation (see [`WasmHandlerLoadError`]).
pub fn handlers_from_package(
    package: &Package,
    limits: WasmHandlerLimits,
) -> Result<Vec<(EventName, Arc<dyn EventHandler>)>, WasmHandlerLoadError> {
    let Some(section) = package.event_handlers()? else {
        return Ok(Vec::new());
    };
    let manifest = section.handlers.into_iter().map(|entry| (entry.event, entry.export)).collect();
    let module =
        Arc::new(WasmHandlerModule::new(&section.module, section.abi_version, manifest, limits)?);
    Ok(module.handlers())
}

/// Builds a [`HostLibrary`] from a package: its MAST forest, its debug info, and the Wasm event
/// handlers of its `event_handlers` section, if any.
///
/// Load the result into a host with
/// [`DefaultHost::load_library`](miden_processor::DefaultHost::load_library), which registers
/// the handlers next to the MAST forest.
///
/// # Errors
/// Same failure conditions as [`handlers_from_package`].
pub fn host_library_from_package(
    package: &Arc<Package>,
    limits: WasmHandlerLimits,
) -> Result<HostLibrary, WasmHandlerLoadError> {
    let handlers = handlers_from_package(package, limits)?;
    let mut library = HostLibrary::from(package.clone());
    library.handlers = handlers;
    Ok(library)
}

// MANIFEST DERIVATION
// ================================================================================================

/// The version byte of one `miden:event-manifest` record. Kept in sync with the record format
/// the `miden-event-handler-macros` crate emits.
const MANIFEST_RECORD_VERSION: u8 = 1;

/// Reads the handler manifest embedded in a compiled guest module.
///
/// The guest SDK macro writes one record per handler into the `miden:event-manifest` custom
/// section. This function collects the records so package tooling can construct the
/// `event_handlers` section without a hand-written manifest.
///
/// # Errors
/// Returns [`WasmHandlerLoadError::InvalidModule`] when the section layout or a manifest record
/// is malformed.
pub fn manifest_from_module(
    wasm: &[u8],
) -> Result<Vec<EventHandlerManifestEntry>, WasmHandlerLoadError> {
    let mut payloads = Vec::new();
    walk_wasm_sections(wasm, |id, payload| {
        // Custom sections have ID 0; their payload starts with a LEB128-prefixed name.
        if id == 0 {
            payloads.push(payload);
        }
    })
    .ok_or_else(|| WasmHandlerLoadError::InvalidModule("malformed section layout".to_string()))?;

    let mut entries = Vec::new();
    for payload in payloads {
        let Some((name, records)) = split_custom_section(payload) else {
            return Err(WasmHandlerLoadError::InvalidModule(
                "malformed custom section".to_string(),
            ));
        };
        if name == MANIFEST_SECTION_NAME.as_bytes() {
            parse_manifest_records(records, &mut entries)?;
        }
    }
    Ok(entries)
}

/// Builds an [`EventHandlerSection`] for a compiled guest module, deriving the manifest from
/// the module's embedded `miden:event-manifest` records.
///
/// # Errors
/// Same failure conditions as [`manifest_from_module`].
pub fn section_from_module(wasm: Vec<u8>) -> Result<EventHandlerSection, WasmHandlerLoadError> {
    let handlers = manifest_from_module(&wasm)?;
    Ok(EventHandlerSection {
        abi_version: ABI_VERSION,
        module: wasm,
        handlers,
    })
}

/// Fuzzing support: returns `true` when the top-level section walk of `wasm` succeeds and every
/// custom section splits into a name and content.
///
/// Differential fuzzing checks this against wasmi's validator: the load path conservatively
/// rejects modules whose walk fails, so any module wasmi validates must also walk. Not part of
/// the public API.
#[doc(hidden)]
pub fn fuzz_walk_sections(wasm: &[u8]) -> bool {
    let mut custom_sections_ok = true;
    let walked = walk_wasm_sections(wasm, |id, payload| {
        if id == 0 {
            custom_sections_ok &= split_custom_section(payload).is_some();
        }
    });
    walked.is_some() && custom_sections_ok
}

/// Splits a custom-section payload into its name and its content.
fn split_custom_section(payload: &[u8]) -> Option<(&[u8], &[u8])> {
    let (name_len, name_start) = read_leb_u32(payload, 0)?;
    let content_start = name_start.checked_add(name_len as usize)?;
    let name = payload.get(name_start..content_start)?;
    Some((name, payload.get(content_start..)?))
}

/// Parses concatenated manifest records: one version byte, then the event name and the export
/// name, each as a little-endian `u32` length followed by the bytes.
fn parse_manifest_records(
    mut records: &[u8],
    entries: &mut Vec<EventHandlerManifestEntry>,
) -> Result<(), WasmHandlerLoadError> {
    fn read_name(records: &[u8]) -> Option<(&str, &[u8])> {
        let len_bytes: [u8; 4] = records.get(..4)?.try_into().ok()?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        let end = 4usize.checked_add(len)?;
        let name = core::str::from_utf8(records.get(4..end)?).ok()?;
        Some((name, &records[end..]))
    }

    while !records.is_empty() {
        let malformed =
            || WasmHandlerLoadError::InvalidModule("malformed manifest record".to_string());
        let (&version, rest) = records.split_first().ok_or_else(malformed)?;
        if version != MANIFEST_RECORD_VERSION {
            return Err(WasmHandlerLoadError::InvalidModule(format!(
                "unsupported manifest record version {version}"
            )));
        }
        let (event, rest) = read_name(rest).ok_or_else(malformed)?;
        let (export, rest) = read_name(rest).ok_or_else(malformed)?;
        entries.push(EventHandlerManifestEntry::new(
            EventName::from_string(event.to_string()),
            export,
        ));
        records = rest;
    }
    Ok(())
}
