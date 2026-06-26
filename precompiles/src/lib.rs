#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::path::PathBuf;

use miden_core::{deferred::PrecompileRegistry, mast::MastForest, serde::Deserializable};
use miden_mast_package::Package;
use miden_processor::HostLibrary;
use miden_utils_sync::LazyLock;

#[cfg(feature = "std")]
#[doc(hidden)]
pub fn asm_source_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("asm")
}

// PRECOMPILES LIBRARY
// ================================================================================================

/// The Miden precompiles library, wrapping the compiled `miden-precompiles` [`Package`].
///
/// This scaffold package reserves the `miden::precompiles` MASM namespace. Concrete deferred
/// precompile wrappers and event handlers are added in later commits.
///
/// The crate's deferred [`PrecompileRegistry`] is exposed separately via [`registry`].
///
/// [`Package`]: miden_mast_package::Package
#[derive(Clone)]
pub struct PrecompilesLibrary(Arc<Package>);

impl PrecompilesLibrary {
    /// Serialized representation of the `miden-precompiles` package.
    pub const SERIALIZED: &'static [u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/miden-precompiles.masp"));

    /// Returns a reference to the [`MastForest`] underlying the precompiles library.
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        self.0.mast_forest()
    }

    /// Returns a reference to the underlying [`Arc<Package>`].
    pub fn package(&self) -> Arc<Package> {
        self.0.clone()
    }
}

impl AsRef<Package> for PrecompilesLibrary {
    fn as_ref(&self) -> &Package {
        &self.0
    }
}

impl From<&PrecompilesLibrary> for HostLibrary {
    fn from(precompiles_lib: &PrecompilesLibrary) -> Self {
        let mut library = HostLibrary::from(precompiles_lib.package());
        library.handlers = event_handlers::default_event_handlers();
        library
    }
}

impl Default for PrecompilesLibrary {
    fn default() -> Self {
        static PRECOMPILES: LazyLock<PrecompilesLibrary> = LazyLock::new(|| {
            let contents = Package::read_from_bytes(PrecompilesLibrary::SERIALIZED)
                .expect("failed to read miden-precompiles package!");
            PrecompilesLibrary(Arc::new(contents))
        });
        PRECOMPILES.clone()
    }
}

// EVENT HANDLERS
// ================================================================================================

pub mod event_handlers {
    use alloc::{sync::Arc, vec::Vec};

    use miden_core::events::EventName;
    use miden_processor::event::EventHandler;

    /// Returns the default host event handlers required by this precompiles package.
    pub fn default_event_handlers() -> Vec<(EventName, Arc<dyn EventHandler>)> {
        Vec::new()
    }
}

// REGISTRY
// ================================================================================================

/// Returns a [`PrecompileRegistry`] containing the deferred precompiles provided by this crate.
pub fn registry() -> PrecompileRegistry {
    PrecompileRegistry::new()
}
