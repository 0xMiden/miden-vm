//! Loading, validation, and execution of Wasm handler modules.

use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_event_handler_abi::{ABI_VERSION, IMPORT_MODULE};
use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventHandler, EventName},
};
use wasmi::{Config, EnforcedLimits, Engine, Linker, Module, Store};

use crate::{
    error::{HostTrap, HostTrapKind, WasmHandlerLoadError, WasmHandlerRunError},
    host::{FUEL_PER_FELT, HostCtx, build_linker},
};

// LIMITS
// ================================================================================================

/// Resource limits for one handler call.
///
/// Handler modules are untrusted, so every call runs under these limits. Going over any of them
/// traps the handler, which discards all buffered mutations.
#[derive(Debug, Clone)]
pub struct WasmHandlerLimits {
    /// The fuel budget for one call. Roughly one unit per executed Wasm instruction; host calls
    /// charge additional fuel in proportion to the field elements they move and to the hashes
    /// they compute, so the budget bounds the total work a handler causes.
    pub fuel: u64,
    /// The maximum size of the guest linear memory, in bytes.
    pub max_memory_bytes: usize,
    /// The maximum total number of table elements. Tables are allocated eagerly, so without
    /// this cap a tiny module could demand a multi-gigabyte allocation before any fuel applies.
    pub max_table_elements: usize,
    /// The maximum size of the Wasm binary, in bytes.
    pub max_module_bytes: usize,
    /// The maximum total number of field elements across all mutations one call buffers.
    pub max_mutation_felts: usize,
    /// Permits float instructions in the handler module. Off by default: handler output must be
    /// deterministic across hosts, and handlers have no use for floats.
    pub allow_floats: bool,
}

impl Default for WasmHandlerLimits {
    fn default() -> Self {
        Self {
            fuel: 10_000_000,
            max_memory_bytes: 16 * 1024 * 1024,
            max_table_elements: 4096,
            max_module_bytes: 16 * 1024 * 1024,
            max_mutation_felts: 1 << 16,
            allow_floats: false,
        }
    }
}

// WASM HANDLER MODULE
// ================================================================================================

/// A validated Wasm handler module together with its manifest.
///
/// The module is parsed, validated, and compiled once. Each event call then runs in a fresh
/// store and instance, so handlers keep no state between calls.
pub struct WasmHandlerModule {
    engine: Engine,
    module: Module,
    linker: Linker<HostCtx>,
    limits: WasmHandlerLimits,
    manifest: Vec<(EventName, String)>,
    /// The fuel charge for one instantiation, deducted from the budget of every call.
    instantiation_fuel: u64,
}

impl WasmHandlerModule {
    /// Parses, validates, and compiles a handler module.
    ///
    /// `manifest` maps each event name to the export that handles it.
    ///
    /// # Errors
    /// Returns an error when:
    /// - `abi_version` is not the version this crate implements;
    /// - the Wasm binary is larger than `limits.max_module_bytes`;
    /// - the Wasm binary does not parse or validate, or oversteps the structural compilation limits
    ///   ([`EnforcedLimits::strict`]);
    /// - the module imports from a namespace other than `miden:event/v1`, or an import has a
    ///   signature the host function set does not provide;
    /// - the module has a start section;
    /// - a manifest export is missing or does not have the `() -> ()` signature;
    /// - a manifest entry has an empty event name or an empty export name;
    /// - the manifest contains a duplicate event or a reserved `sys::` event name.
    pub fn new(
        wasm: &[u8],
        abi_version: u32,
        manifest: Vec<(EventName, String)>,
        limits: WasmHandlerLimits,
    ) -> Result<Self, WasmHandlerLoadError> {
        // ABI version bumps are additive only, so every version from 1 up to the version this
        // crate implements is acceptable. See `miden_event_handler_abi::ABI_VERSION`.
        if abi_version == 0 || abi_version > ABI_VERSION {
            return Err(WasmHandlerLoadError::AbiVersionMismatch {
                declared: abi_version,
                supported: ABI_VERSION,
            });
        }

        // The package decode path has its own module-size cap, but this constructor is public,
        // so it enforces the limit itself before handing the bytes to the compiler.
        if wasm.len() > limits.max_module_bytes {
            return Err(WasmHandlerLoadError::ModuleTooLarge {
                size: wasm.len(),
                max: limits.max_module_bytes,
            });
        }

        // Validate the manifest before touching the Wasm binary.
        let mut seen = BTreeSet::new();
        for (event, export) in &manifest {
            if event.as_str().is_empty() || export.is_empty() {
                return Err(WasmHandlerLoadError::EmptyManifestName);
            }
            if event.is_reserved() {
                return Err(WasmHandlerLoadError::ReservedEvent { event: event.clone() });
            }
            if !seen.insert(event.to_event_id()) {
                return Err(WasmHandlerLoadError::DuplicateEvent { event: event.clone() });
            }
        }

        let mut config = Config::default();
        config.consume_fuel(true);
        config.floats(limits.allow_floats);
        // Structural compilation limits (function/global/segment counts, signature sizes)
        // defend `Module::new` itself against compilation bombs in untrusted binaries.
        config.enforced_limits(EnforcedLimits::strict());
        let engine = Engine::new(&config);

        let module = Module::new(&engine, wasm)
            .map_err(|err| WasmHandlerLoadError::InvalidModule(err.to_string()))?;

        // The import allowlist closes the sandbox: no WASI, no other namespaces.
        for import in module.imports() {
            if import.module() != IMPORT_MODULE {
                return Err(WasmHandlerLoadError::ForbiddenImport {
                    module: import.module().to_string(),
                    name: import.name().to_string(),
                });
            }
        }

        // No guest code may run before the fuel budget and the limits are installed, and a start
        // function would also re-run on every instantiate-per-call. wasmi's instantiation always
        // runs the start function, so modules with a start section are rejected here instead.
        if has_start_section(wasm) {
            return Err(WasmHandlerLoadError::StartSection);
        }

        // wasmi meters no instantiation work (memory zeroing, segment copies), so the static
        // cost is computed once here and deducted from the fuel budget of every call. A module
        // whose instantiation alone eats the whole budget can never run; refuse it now.
        let instantiation_fuel = instantiation_fuel(wasm).ok_or_else(|| {
            WasmHandlerLoadError::InvalidModule("malformed section layout".to_string())
        })?;
        if instantiation_fuel >= limits.fuel {
            return Err(WasmHandlerLoadError::InstantiationOverBudget {
                cost: instantiation_fuel,
                fuel: limits.fuel,
            });
        }

        let linker = build_linker(&engine);
        let this = Self {
            engine,
            module,
            linker,
            limits,
            manifest,
            instantiation_fuel,
        };
        this.validate_instantiation()?;
        Ok(this)
    }

    /// Returns the validated `(event, export)` manifest.
    pub fn manifest(&self) -> &[(EventName, String)] {
        &self.manifest
    }

    /// Returns one registered-handler pair per manifest entry, ready for host registration.
    pub fn handlers(self: &Arc<Self>) -> Vec<(EventName, Arc<dyn EventHandler>)> {
        self.manifest
            .iter()
            .map(|(event, export)| {
                let handler = WasmEventHandler {
                    module: Arc::clone(self),
                    export: export.clone(),
                };
                (event.clone(), Arc::new(handler) as Arc<dyn EventHandler>)
            })
            .collect()
    }

    /// Dry-run instantiation at load time: resolves every import against the host function set
    /// (this catches signature mismatches) and checks that every manifest export exists with
    /// the `() -> ()` signature. No guest code runs: start sections were rejected before.
    fn validate_instantiation(&self) -> Result<(), WasmHandlerLoadError> {
        let mut store = self.new_store(core::ptr::null());
        let instance = self
            .linker
            .instantiate_and_start(&mut store, &self.module)
            .map_err(|err| WasmHandlerLoadError::Instantiation(err.to_string()))?;
        for (_, export) in &self.manifest {
            instance.get_typed_func::<(), ()>(&store, export).map_err(|err| {
                WasmHandlerLoadError::BadExport {
                    export: export.clone(),
                    reason: err.to_string(),
                }
            })?;
        }
        Ok(())
    }

    /// Creates a fresh store for one call, with the resource limiter installed and the fuel
    /// budget set.
    fn new_store(&self, state: *const ProcessorState<'static>) -> Store<HostCtx> {
        let mut store = Store::new(&self.engine, HostCtx::new(state, &self.limits));
        store.limiter(|ctx| &mut ctx.limits);
        // The static instantiation cost is charged up front; the load-time check keeps it
        // under the budget.
        store
            .set_fuel(self.limits.fuel.saturating_sub(self.instantiation_fuel))
            .expect("fuel metering is enabled in the engine config");
        store
    }

    /// Runs one handler export against the given processor state and returns the mutations it
    /// buffered.
    fn call(
        &self,
        process: &ProcessorState<'_>,
        export: &str,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        // Erase the lifetime for storage in the store data. The pointer stays valid for this
        // whole function, which outlives the store; see `host::StatePtr` for the safety
        // contract.
        let state_ptr = core::ptr::from_ref(process).cast::<ProcessorState<'static>>();
        let mut store = self.new_store(state_ptr);

        // `instantiate_and_start` runs no guest code here: modules with a start section are
        // rejected at load time.
        let instance = self
            .linker
            .instantiate_and_start(&mut store, &self.module)
            .map_err(|err| WasmHandlerRunError::Instantiation(err.to_string()))?;
        let func = instance
            .get_typed_func::<(), ()>(&store, export)
            .map_err(|err| WasmHandlerRunError::Instantiation(err.to_string()))?;

        match func.call(&mut store, ()) {
            Ok(()) => Ok(store.into_data().mutations),
            Err(err) => {
                let data = store.into_data();
                let run_err = if let Some(msg) = data.error_msg {
                    WasmHandlerRunError::Failed(msg)
                } else {
                    classify_trap(&err, self.limits.fuel)
                };
                Err(run_err.into())
            },
        }
    }
}

/// Maps a wasmi error to the run-error variant, so resource-limit violations are
/// distinguishable from handler defects.
///
/// Fuel can run out in two places: wasmi's own metering of guest instructions (a
/// [`wasmi::TrapCode`]) and [`HostTrap`]s raised by the host-call fuel charges. Both map to
/// [`WasmHandlerRunError::OutOfFuel`].
fn classify_trap(err: &wasmi::Error, fuel: u64) -> WasmHandlerRunError {
    if let Some(trap) = err.downcast_ref::<HostTrap>() {
        return match trap.kind {
            HostTrapKind::OutOfFuel => WasmHandlerRunError::OutOfFuel(fuel),
            HostTrapKind::MutationLimit => WasmHandlerRunError::LimitExceeded(trap.msg.clone()),
            HostTrapKind::Defect => WasmHandlerRunError::Trapped(err.to_string()),
        };
    }
    match err.as_trap_code() {
        Some(wasmi::TrapCode::OutOfFuel) => WasmHandlerRunError::OutOfFuel(fuel),
        // The store limits refused a memory or table growth (`trap_on_grow_failure`).
        Some(wasmi::TrapCode::GrowthOperationLimited) => {
            WasmHandlerRunError::LimitExceeded(err.to_string())
        },
        _ => WasmHandlerRunError::Trapped(err.to_string()),
    }
}

/// Decodes a LEB128-encoded `u32` from `data` at `pos`; returns the value and the next
/// position.
pub(crate) fn read_leb_u32(data: &[u8], mut pos: usize) -> Option<(u32, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(pos)?;
        pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 35 {
            return None;
        }
    }
    u32::try_from(value).ok().map(|value| (value, pos))
}

/// Walks the top-level sections of a Wasm binary, calling `visit` with each section ID and
/// payload. Returns `None` when the walk meets a malformed layout.
pub(crate) fn walk_wasm_sections<'a>(
    wasm: &'a [u8],
    mut visit: impl FnMut(u8, &'a [u8]),
) -> Option<()> {
    /// The length of the Wasm binary header (magic + version).
    const HEADER_LEN: usize = 8;

    if wasm.len() < HEADER_LEN {
        return None;
    }
    let mut pos = HEADER_LEN;
    while pos < wasm.len() {
        let id = wasm[pos];
        let (size, payload_start) = read_leb_u32(wasm, pos + 1)?;
        let payload_end = payload_start.checked_add(size as usize)?;
        visit(id, wasm.get(payload_start..payload_end)?);
        pos = payload_end;
    }
    Some(())
}

/// Decodes a LEB128-encoded `u64` from `data` at `pos`; returns the value and the next
/// position.
fn read_leb_u64(data: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(pos)?;
        pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 70 {
            return None;
        }
    }
    Some((value, pos))
}

/// Computes the fuel charge for one instantiation of the module.
///
/// wasmi meters no instantiation work: it allocates and zeroes the declared initial memory,
/// allocates the initial tables, and copies the data and element segments before any guest
/// code runs. The sizes are static, so the charge is computed once at load time. The rate is
/// one fuel unit per 8 bytes, the same as [`FUEL_PER_FELT`] for host-moved data; the byte
/// count is an upper bound that counts passive segments as if they were copied.
///
/// Returns `None` when a section does not parse, which `WasmHandlerModule::new` reports as an
/// invalid module.
fn instantiation_fuel(wasm: &[u8]) -> Option<u64> {
    /// The section IDs whose contents instantiation materializes.
    const TABLE_SECTION_ID: u8 = 4;
    const MEMORY_SECTION_ID: u8 = 5;
    const ELEMENT_SECTION_ID: u8 = 9;
    const DATA_SECTION_ID: u8 = 11;
    /// The size of one Wasm linear-memory page.
    const PAGE_BYTES: u64 = 65536;
    /// The size of one table element (a reference) on a 64-bit host.
    const TABLE_ELEMENT_BYTES: u64 = 8;

    let mut bytes: u64 = 0;
    let mut malformed = false;
    walk_wasm_sections(wasm, |id, payload| match id {
        MEMORY_SECTION_ID => match limits_min_total(payload, false) {
            Some(pages) => bytes = bytes.saturating_add(pages.saturating_mul(PAGE_BYTES)),
            None => malformed = true,
        },
        TABLE_SECTION_ID => match limits_min_total(payload, true) {
            Some(elems) => {
                bytes = bytes.saturating_add(elems.saturating_mul(TABLE_ELEMENT_BYTES))
            },
            None => malformed = true,
        },
        DATA_SECTION_ID | ELEMENT_SECTION_ID => {
            bytes = bytes.saturating_add(payload.len() as u64);
        },
        _ => {},
    })?;
    if malformed {
        return None;
    }
    Some(bytes.div_ceil(8).saturating_mul(FUEL_PER_FELT))
}

/// Sums the limit minimums of a memory or table section payload: the pages (memory) or
/// elements (table) allocated at instantiation. `skip_reftype` skips the reference-type byte
/// that leads each table entry.
fn limits_min_total(payload: &[u8], skip_reftype: bool) -> Option<u64> {
    let (count, mut pos) = read_leb_u32(payload, 0)?;
    let mut total: u64 = 0;
    for _ in 0..count {
        if skip_reftype {
            payload.get(pos)?;
            pos += 1;
        }
        let flags = *payload.get(pos)?;
        pos += 1;
        // Valid limit flags: bit 0 = maximum present, bit 1 = shared, bit 2 = 64-bit.
        if flags > 0b111 {
            return None;
        }
        let (min, next) = read_leb_u64(payload, pos)?;
        pos = next;
        if flags & 1 != 0 {
            let (_, next) = read_leb_u64(payload, pos)?;
            pos = next;
        }
        total = total.saturating_add(min);
    }
    Some(total)
}

/// Returns `true` when the Wasm binary has a start section (section ID 8).
///
/// The walk runs after wasmi validated the binary, so the section layout is well formed. Out of
/// caution, a malformed walk is also reported as a start section.
fn has_start_section(wasm: &[u8]) -> bool {
    /// The section ID of the start section.
    const START_SECTION_ID: u8 = 8;

    let mut found = false;
    let walked = walk_wasm_sections(wasm, |id, _| found |= id == START_SECTION_ID);
    walked.is_none() || found
}

impl core::fmt::Debug for WasmHandlerModule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WasmHandlerModule")
            .field("limits", &self.limits)
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

// WASM EVENT HANDLER
// ================================================================================================

/// An [`EventHandler`] that runs one export of a [`WasmHandlerModule`].
///
/// Each call instantiates the module afresh, so the handler keeps no state between events.
pub struct WasmEventHandler {
    module: Arc<WasmHandlerModule>,
    export: String,
}

impl EventHandler for WasmEventHandler {
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        self.module.call(process, &self.export)
    }
}
