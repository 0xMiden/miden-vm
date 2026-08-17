//! Loading Wasm event handlers out of a Miden package.

use alloc::{sync::Arc, vec::Vec};

use miden_mast_package::Package;
use miden_processor::{
    HostLibrary,
    event::{EventHandler, EventName},
};

use crate::{WasmHandlerLimits, WasmHandlerLoadError, WasmHandlerModule};

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
