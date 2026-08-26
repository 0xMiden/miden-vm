//! Loading Wasm event handlers out of a Miden package, and deriving the handler manifest from
//! a compiled guest module.

use alloc::{format, string::ToString, sync::Arc, vec::Vec};

use miden_event_handler_abi::{ABI_VERSION, MANIFEST_RECORD_VERSION, MANIFEST_SECTION_NAME};
use miden_mast_package::{
    EventHandlerManifestEntry, EventHandlerSection, EventHandlerSectionError, MAX_HANDLERS,
    MAX_MODULE_BYTES, MAX_NAME_BYTES, Package,
};
use miden_processor::{
    HostLibrary,
    event::{EventHandler, EventName},
};

use crate::{
    WasmHandlerLimits, WasmHandlerLoadError, WasmHandlerModule,
    module::{HEADER_LEN, module_statics, read_leb_u32, walk_wasm_sections},
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
    Ok(HostLibrary::from(package.clone()).set_handlers(handlers))
}

// MANIFEST DERIVATION
// ================================================================================================

/// Reads the handler manifest embedded in a compiled guest module.
///
/// The guest SDK macro writes one record per handler into the `miden:event-manifest` custom
/// section. This function collects the records so package tooling can construct the
/// `event_handlers` section without a hand-written manifest.
///
/// The module is untrusted input, so the derivation stays inside the section caps of the package
/// format: a module over [`MAX_MODULE_BYTES`] is refused before the walk, and the record loop
/// stops at [`MAX_HANDLERS`] entries and at names over [`MAX_NAME_BYTES`].
///
/// # Errors
/// Returns [`WasmHandlerLoadError::ModuleTooLarge`] when the module is over the size cap,
/// [`WasmHandlerLoadError::InvalidModule`] when the section layout or a manifest record is
/// malformed, and [`WasmHandlerLoadError::InvalidManifest`] when the records break a manifest
/// rule of the package format.
pub fn manifest_from_module(
    wasm: &[u8],
) -> Result<Vec<EventHandlerManifestEntry>, WasmHandlerLoadError> {
    check_module_size(wasm)?;

    // Only the manifest sections are collected, so the other custom sections of the module cost
    // no allocation here.
    let mut manifests = Vec::new();
    let mut malformed = false;
    walk_wasm_sections(wasm, |id, payload, _| {
        // Custom sections have ID 0; their payload starts with a LEB128-prefixed name.
        if id != 0 {
            return;
        }
        match split_custom_section(payload) {
            Some((name, records)) if name == MANIFEST_SECTION_NAME.as_bytes() => {
                manifests.push(records);
            },
            Some(_) => {},
            None => malformed = true,
        }
    })
    .ok_or_else(|| WasmHandlerLoadError::InvalidModule("malformed section layout".to_string()))?;
    if malformed {
        return Err(WasmHandlerLoadError::InvalidModule("malformed custom section".to_string()));
    }

    let mut entries = Vec::new();
    for records in manifests {
        parse_manifest_records(records, &mut entries)?;
    }
    Ok(entries)
}

/// Builds an [`EventHandlerSection`] for a compiled guest module, deriving the manifest from
/// the module's embedded `miden:event-manifest` records.
///
/// The entries are sorted by event name, and the manifest custom sections are removed from the
/// module bytes: the records are link-ordered duplicates of the manifest the section carries.
/// This makes the manifest order and the record order independent of the toolchain, but it does
/// not make the module bytes independent of link order — the code and data sections also move
/// when the linker changes their order.
///
/// The derived section is also dry-loaded with [`WasmHandlerModule::new`] under `limits`, so
/// producer tooling cannot ship a package that every consumer refuses at load. Pass
/// [`WasmHandlerLimits::default`] for the default host policy, or the limits of the target hosts
/// when they are looser: a module that needs more fuel or memory than the default is a valid
/// package for a host that grants it. Limits stay host policy in both directions, so a consumer
/// with stricter limits can still refuse a section this function accepts.
///
/// # Errors
/// Same failure conditions as [`manifest_from_module`], plus the section rules of
/// [`EventHandlerSection::validate`] and the load rules of [`WasmHandlerModule::new`].
pub fn section_from_module(
    wasm: Vec<u8>,
    limits: WasmHandlerLimits,
) -> Result<EventHandlerSection, WasmHandlerLoadError> {
    let mut handlers = manifest_from_module(&wasm)?;
    handlers.sort_by(|a, b| a.event.as_str().cmp(b.event.as_str()));
    let module = strip_manifest_sections(&wasm).ok_or_else(|| {
        WasmHandlerLoadError::InvalidModule("malformed section layout".to_string())
    })?;
    let section = EventHandlerSection {
        // While only ABI v1 exists, the module cannot need more than the current version. Once
        // ABI v2 exists, derivation must compute the lowest version the module's imports need.
        abi_version: ABI_VERSION,
        module,
        handlers,
    };
    section.validate()?;

    // The section rules say nothing about the module itself, so a section that passes them can
    // still fail every consumer's load (no `memory` export, an import outside the host function
    // set, a bad export signature). Move that failure to the producer's build.
    let manifest = section
        .handlers
        .iter()
        .map(|entry| (entry.event.clone(), entry.export.clone()))
        .collect();
    WasmHandlerModule::new(&section.module, section.abi_version, manifest, limits)?;
    Ok(section)
}

/// Returns `wasm` without its `miden:event-manifest` custom sections.
///
/// The result keeps the 8-byte header and every other top-level section, with their bytes
/// unchanged. Returns `None` when the section layout is malformed.
fn strip_manifest_sections(wasm: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(wasm.len());
    out.extend_from_slice(wasm.get(..HEADER_LEN)?);

    let mut malformed = false;
    walk_wasm_sections(wasm, |id, payload, section| {
        // Custom sections have ID 0; their payload starts with a LEB128-prefixed name.
        let is_manifest = if id == 0 {
            match split_custom_section(payload) {
                Some((name, _)) => name == MANIFEST_SECTION_NAME.as_bytes(),
                None => {
                    malformed = true;
                    false
                },
            }
        } else {
            false
        };
        if !is_manifest {
            // The copy holds the section ID and the size prefix as they were encoded.
            out.extend_from_slice(&wasm[section]);
        }
    })?;
    if malformed {
        return None;
    }
    Some(out)
}

/// Checks the size of an untrusted module against the section cap.
fn check_module_size(wasm: &[u8]) -> Result<(), WasmHandlerLoadError> {
    if wasm.len() > MAX_MODULE_BYTES {
        return Err(WasmHandlerLoadError::ModuleTooLarge {
            size: wasm.len(),
            max: MAX_MODULE_BYTES,
        });
    }
    Ok(())
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
    let walked = walk_wasm_sections(wasm, |id, payload, _| {
        if id == 0 {
            custom_sections_ok &= split_custom_section(payload).is_some();
        }
    });
    walked.is_some() && custom_sections_ok
}

/// Fuzzing support: returns `true` when the loader's static analysis of `wasm` accepts the
/// section layout (the memory, table, element, data, and start sections).
///
/// Differential fuzzing checks this against wasmi's validator: the load path conservatively
/// rejects a module whose static analysis fails, so any module wasmi validates must also pass
/// it. Not part of the public API.
#[doc(hidden)]
pub fn fuzz_module_statics(wasm: &[u8]) -> bool {
    module_statics(wasm).is_some()
}

/// Test support: appends a `miden:event-manifest` custom section to `wasm` that holds one record
/// per `(event, export)` pair, in the given order.
///
/// The section carries the layout the guest SDK macro writes, so a test or a fuzz target builds a
/// manifest-carrying module without a Rust toolchain. Not part of the public API.
#[doc(hidden)]
pub fn test_append_manifest_section(mut wasm: Vec<u8>, handlers: &[(&str, &str)]) -> Vec<u8> {
    let mut payload = leb_u32(MANIFEST_SECTION_NAME.len() as u32);
    payload.extend_from_slice(MANIFEST_SECTION_NAME.as_bytes());
    for (event, export) in handlers {
        payload.push(MANIFEST_RECORD_VERSION);
        for name in [event, export] {
            payload.extend_from_slice(&(name.len() as u32).to_le_bytes());
            payload.extend_from_slice(name.as_bytes());
        }
    }

    // A custom section: ID 0, then the LEB128 payload size.
    wasm.push(0x00);
    wasm.extend_from_slice(&leb_u32(payload.len() as u32));
    wasm.extend_from_slice(&payload);
    wasm
}

/// Encodes `value` as LEB128.
fn leb_u32(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
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
///
/// The records come from an untrusted module, so the caps of the package format apply here,
/// before the manifest reaches [`WasmHandlerModule::new`]: `entries` holds at most
/// [`MAX_HANDLERS`] entries, each name is not empty and holds at most [`MAX_NAME_BYTES`] bytes.
/// The caps bound the memory the records can make this function allocate.
fn parse_manifest_records(
    mut records: &[u8],
    entries: &mut Vec<EventHandlerManifestEntry>,
) -> Result<(), WasmHandlerLoadError> {
    /// Reports a manifest rule of the package format as a load error.
    fn manifest_error(err: EventHandlerSectionError) -> WasmHandlerLoadError {
        WasmHandlerLoadError::InvalidManifest(err)
    }

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
        // The names are still borrowed from the module here, so the per-entry rules apply
        // before the entry allocates. The rules and their messages come from the package
        // format, so this early check cannot drift from `validate_manifest_entries`, which
        // sees the same manifest later.
        for (field, name) in [("event name", event), ("export name", export)] {
            if name.is_empty() {
                return Err(manifest_error(EventHandlerSectionError::EmptyName { field }));
            }
            if name.len() > MAX_NAME_BYTES {
                return Err(manifest_error(EventHandlerSectionError::OverSizeCap {
                    field,
                    actual: name.len(),
                    max: MAX_NAME_BYTES,
                }));
            }
        }
        if entries.len() >= MAX_HANDLERS {
            return Err(manifest_error(EventHandlerSectionError::TooManyHandlers {
                max: MAX_HANDLERS,
            }));
        }
        entries.push(EventHandlerManifestEntry::new(
            EventName::from_string(event.to_string()),
            export,
        ));
        records = rest;
    }
    Ok(())
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec};

    use super::*;

    /// Builds a loadable handler module: the exported linear memory plus one `() -> ()` export
    /// per distinct name. Derivation dry-loads the section it builds, so the fixtures must pass
    /// the load rules as well as the section rules.
    fn base_module(exports: &[&str]) -> Vec<u8> {
        let mut declared: Vec<&str> = Vec::new();
        let mut funcs = String::new();
        for export in exports {
            if !declared.contains(export) {
                declared.push(export);
                funcs.push_str(&format!("(func (export \"{export}\"))"));
            }
        }
        wat::parse_str(format!("(module (memory (export \"memory\") 1) {funcs})"))
            .expect("the fixture WAT parses")
    }

    /// Encodes one custom section that is not a manifest: ID 0, the payload size, the name length,
    /// the name, the content. Both lengths stay under 128, so each one is a single LEB128 byte.
    fn other_custom_section(name: &str, content: &[u8]) -> Vec<u8> {
        let payload_len = 1 + name.len() + content.len();
        assert!(payload_len < 128, "the fixture section must fit a one-byte length");

        let mut section = vec![0x00, payload_len as u8, name.len() as u8];
        section.extend_from_slice(name.as_bytes());
        section.extend_from_slice(content);
        section
    }

    /// Builds a loadable Wasm binary that carries a `miden:event-manifest` custom section with
    /// one record per `(event, export)` pair, in the given order.
    fn module_with_manifest(handlers: &[(&str, &str)]) -> Vec<u8> {
        let exports: Vec<&str> = handlers.iter().map(|(_, export)| *export).collect();
        test_append_manifest_section(base_module(&exports), handlers)
    }

    #[test]
    fn derived_manifest_is_sorted_by_event_name() {
        let wasm = module_with_manifest(&[("test::wasm::b", "b"), ("test::wasm::a", "a")]);

        // The raw records keep the link order of the module.
        let entries = manifest_from_module(&wasm).expect("the manifest parses");
        assert_eq!(entries[0].event.as_str(), "test::wasm::b");

        // Derivation canonicalizes the order, so the link order cannot change the identity of
        // the package.
        let section =
            section_from_module(wasm, WasmHandlerLimits::default()).expect("the section derives");
        let events: Vec<_> = section.handlers.iter().map(|entry| entry.event.as_str()).collect();
        assert_eq!(events, vec!["test::wasm::a", "test::wasm::b"]);
    }

    #[test]
    fn derived_section_applies_the_section_rules() {
        // Two handlers for one event.
        let wasm = module_with_manifest(&[("test::wasm::a", "a"), ("test::wasm::a", "b")]);
        assert!(matches!(
            section_from_module(wasm, WasmHandlerLimits::default()),
            Err(WasmHandlerLoadError::Section(_))
        ));

        // An event in the reserved namespace.
        let wasm = module_with_manifest(&[("sys::a", "a")]);
        assert!(matches!(
            section_from_module(wasm, WasmHandlerLimits::default()),
            Err(WasmHandlerLoadError::Section(_))
        ));
    }

    #[test]
    fn derivation_strips_the_manifest_sections() {
        let other = other_custom_section("extra", b"keep me");
        let base = base_module(&["a", "b"]);
        let mut wasm = test_append_manifest_section(base.clone(), &[("test::wasm::a", "a")]);
        wasm.extend_from_slice(&other);
        let wasm = test_append_manifest_section(wasm, &[("test::wasm::b", "b")]);

        let section =
            section_from_module(wasm, WasmHandlerLimits::default()).expect("the section derives");
        let events: Vec<_> = section.handlers.iter().map(|entry| entry.event.as_str()).collect();
        assert_eq!(events, vec!["test::wasm::a", "test::wasm::b"]);

        // The shipped module keeps every other section and carries no manifest records.
        let mut expected = base;
        expected.extend_from_slice(&other);
        assert_eq!(section.module, expected);
        assert!(
            manifest_from_module(&section.module)
                .expect("the stripped module still parses")
                .is_empty()
        );
    }

    #[test]
    fn derived_section_must_load() {
        // The manifest records break no section rule, but the module exports no linear memory,
        // so every host would refuse it at load. Derivation refuses it at the producer instead.
        let wasm = test_append_manifest_section(
            wat::parse_str("(module (func (export \"a\")))").expect("the WAT parses"),
            &[("test::wasm::a", "a")],
        );

        // The records themselves parse; only the load rules refuse the module.
        assert_eq!(manifest_from_module(&wasm).expect("the manifest parses").len(), 1);
        assert!(matches!(
            section_from_module(wasm, WasmHandlerLimits::default()),
            Err(WasmHandlerLoadError::MissingMemoryExport)
        ));
    }

    #[test]
    fn derivation_dry_loads_under_the_given_limits() {
        // The table declares more elements than the default cap grants, so the default limits
        // refuse a module that a host with a larger cap accepts. The producer must be able to
        // build the section for that host.
        let wasm = test_append_manifest_section(
            wat::parse_str(
                "(module (memory (export \"memory\") 1) (table 5000 funcref) (func (export \"a\")))",
            )
            .expect("the WAT parses"),
            &[("test::wasm::a", "a")],
        );

        assert!(section_from_module(wasm.clone(), WasmHandlerLimits::default()).is_err());
        let looser = WasmHandlerLimits {
            max_table_elements: 8192,
            ..WasmHandlerLimits::default()
        };
        section_from_module(wasm, looser).expect("the looser table cap accepts the module");
    }

    #[test]
    fn derivation_bounds_the_manifest_records() {
        // One record more than the manifest cap.
        let events: Vec<String> =
            (0..=MAX_HANDLERS).map(|index| format!("test::wasm::h{index}")).collect();
        let handlers: Vec<(&str, &str)> =
            events.iter().map(|event| (event.as_str(), "h")).collect();
        let err = manifest_from_module(&module_with_manifest(&handlers)).unwrap_err();
        assert!(err.to_string().contains("handlers"), "unexpected error: {err}");

        // A name over the name cap.
        let long_name = "e".repeat(MAX_NAME_BYTES + 1);
        let wasm = module_with_manifest(&[(long_name.as_str(), "a")]);
        let err = manifest_from_module(&wasm).unwrap_err();
        assert!(err.to_string().contains("cap"), "unexpected error: {err}");

        // A module over the module cap: refused before the section walk.
        let mut wasm = module_with_manifest(&[("test::wasm::a", "a")]);
        wasm.resize(MAX_MODULE_BYTES + 1, 0);
        let err = manifest_from_module(&wasm).unwrap_err();
        assert!(
            matches!(err, WasmHandlerLoadError::ModuleTooLarge { max: MAX_MODULE_BYTES, .. }),
            "unexpected error: {err}"
        );
    }
}
