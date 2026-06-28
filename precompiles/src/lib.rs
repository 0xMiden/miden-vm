#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::path::PathBuf;

use miden_core::{deferred::PrecompileRegistry, serde::Deserializable};
use miden_mast_package::Package;
use miden_processor::HostLibrary;
use miden_utils_sync::LazyLock;

mod codec;
#[cfg(feature = "codegen-tools")]
#[doc(hidden)]
pub mod codegen;
mod dsa;
mod hash;
mod math;

pub use hash::{
    HashFunction, HashPrecompile, keccak256::Keccak256Precompile, sha512::Sha512Precompile,
};
pub use math::{
    curve::{
        CurveId, CurvePoint, CurvePrecompile, CurveSpec, ShortWeierstrassSpec, TwistedEdwardsSpec,
    },
    ed25519_base::Ed25519Base,
    ed25519_scalar::Ed25519Scalar,
    k1_base::K1Base,
    k1_scalar::K1Scalar,
    r1_base::R1Base,
    r1_scalar::R1Scalar,
    u256::U256,
    uint::{Limbs, UintDomain, UintPrecompile, UintSpec},
};

#[cfg(feature = "std")]
#[doc(hidden)]
pub fn asm_source_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("asm")
}

// PRECOMPILES LIBRARY
// ================================================================================================

/// The Miden precompiles library, wrapping the compiled `miden-precompiles` [`Package`].
///
/// The package bundles the MASM procedures exported under the `miden::precompiles` namespace,
/// including hash wrappers, arithmetic wrappers, signature wrappers, and deferred-DAG helper
/// procedures. When the package is dynamically linked during assembly, these procedures can be
/// called from any Miden program and are serialized as 32 bytes.
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

    /// Returns a reference to the underlying [`Arc<Package>`].
    pub fn package(&self) -> Arc<Package> {
        self.0.clone()
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
    use alloc::{sync::Arc, vec, vec::Vec};

    use miden_core::events::EventName;
    use miden_processor::event::EventHandler;

    use crate::{hash::handlers as hash_handlers, math::uint::handlers as uint_handlers};

    /// Event used by generated field uint wrappers to request an inverse witness from the host.
    pub const UINT_FIELD_INV_EVENT_NAME: EventName = uint_handlers::UINT_FIELD_INV_EVENT_NAME;

    /// Returns the default host event handlers required by this precompiles package.
    pub fn default_event_handlers() -> Vec<(EventName, Arc<dyn EventHandler>)> {
        vec![
            hash_handlers::keccak256_digest_event_handler(),
            hash_handlers::sha512_digest_event_handler(),
            uint_handlers::field_inv_event_handler(),
        ]
    }
}

// REGISTRY
// ================================================================================================

/// Returns a [`PrecompileRegistry`] containing the deferred precompiles provided by this crate.
pub fn registry() -> PrecompileRegistry {
    PrecompileRegistry::new()
        .with_precompile(Keccak256Precompile::default())
        .with_precompile(Sha512Precompile::default())
        .with_precompile(UintPrecompile)
        .with_precompile(CurvePrecompile)
}
