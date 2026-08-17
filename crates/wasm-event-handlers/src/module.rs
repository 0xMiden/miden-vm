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
use wasmi::{Config, Engine, Linker, Module, Store};

use crate::{
    error::{WasmHandlerLoadError, WasmHandlerRunError},
    host::{HostCtx, build_linker},
};

// LIMITS
// ================================================================================================

/// Resource limits for one handler call.
///
/// Handler modules are untrusted, so every call runs under these limits. Going over any of them
/// traps the handler, which discards all buffered mutations.
#[derive(Debug, Clone)]
pub struct WasmHandlerLimits {
    /// The fuel budget for one call. Roughly one unit per executed Wasm instruction.
    pub fuel: u64,
    /// The maximum size of the guest linear memory, in bytes.
    pub max_memory_bytes: usize,
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
}

impl WasmHandlerModule {
    /// Parses, validates, and compiles a handler module.
    ///
    /// `manifest` maps each event name to the export that handles it.
    ///
    /// # Errors
    /// Returns an error when:
    /// - `abi_version` is not the version this crate implements;
    /// - the Wasm binary does not parse or validate;
    /// - the module imports from a namespace other than `miden:event/v1`, or an import has a
    ///   signature the host function set does not provide;
    /// - the module has a start section;
    /// - a manifest export is missing or does not have the `() -> ()` signature;
    /// - the manifest contains a duplicate event or a reserved `sys::` event name.
    pub fn new(
        wasm: &[u8],
        abi_version: u32,
        manifest: Vec<(EventName, String)>,
        limits: WasmHandlerLimits,
    ) -> Result<Self, WasmHandlerLoadError> {
        if abi_version != ABI_VERSION {
            return Err(WasmHandlerLoadError::AbiVersionMismatch {
                declared: abi_version,
                supported: ABI_VERSION,
            });
        }

        // Validate the manifest before touching the Wasm binary.
        let mut seen = BTreeSet::new();
        for (event, _) in &manifest {
            if event.as_str().starts_with("sys::") {
                return Err(WasmHandlerLoadError::ReservedEvent { event: event.clone() });
            }
            if !seen.insert(event.to_event_id()) {
                return Err(WasmHandlerLoadError::DuplicateEvent { event: event.clone() });
            }
        }

        let mut config = Config::default();
        config.consume_fuel(true);
        config.floats(limits.allow_floats);
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

        let linker = build_linker(&engine);
        let this = Self { engine, module, linker, limits, manifest };
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
        store
            .set_fuel(self.limits.fuel)
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
                let out_of_fuel = matches!(err.as_trap_code(), Some(wasmi::TrapCode::OutOfFuel));
                let data = store.into_data();
                let run_err = if let Some(msg) = data.error_msg {
                    WasmHandlerRunError::Failed(msg)
                } else if out_of_fuel {
                    WasmHandlerRunError::OutOfFuel(self.limits.fuel)
                } else {
                    WasmHandlerRunError::Trapped(err.to_string())
                };
                Err(run_err.into())
            },
        }
    }
}

/// Returns `true` when the Wasm binary has a start section (section ID 8).
///
/// The walk runs after wasmi validated the binary, so the section layout is well formed. Out of
/// caution, any inconsistency the walk still meets is reported as a start section.
fn has_start_section(wasm: &[u8]) -> bool {
    /// The length of the Wasm binary header (magic + version).
    const HEADER_LEN: usize = 8;
    /// The section ID of the start section.
    const START_SECTION_ID: u8 = 8;

    let mut pos = HEADER_LEN;
    while pos < wasm.len() {
        let id = wasm[pos];
        pos += 1;

        // Decode the LEB128-encoded section size.
        let mut size: u64 = 0;
        let mut shift = 0u32;
        loop {
            let Some(&byte) = wasm.get(pos) else { return true };
            pos += 1;
            size |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 35 {
                return true;
            }
        }

        if id == START_SECTION_ID {
            return true;
        }
        pos = match pos.checked_add(size as usize) {
            Some(next) => next,
            None => return true,
        };
    }
    false
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
