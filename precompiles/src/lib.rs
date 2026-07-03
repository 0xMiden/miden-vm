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
mod hash;
mod math;

pub use codec::{chunks_to_bytes_exact, n_chunks};
pub use hash::{HashAssertNode, HashFunction, HashPrecompile, keccak256::Keccak256Precompile};
pub use math::{
    curve::{
        CurveCoefficient, CurveId, CurveNodeRef, CurvePoint, CurvePrecompile, CurveSpec,
        ED25519_SW_A_PTR, ED25519_SW_B_PTR, ED25519_SW_GROUP_PTR, K1_A_PTR, K1_B_PTR, K1_GROUP_PTR,
        R1_A_PTR, R1_B_PTR, R1_GROUP_PTR, ShortWeierstrassSpec, curve_coefficients,
    },
    ed25519_base::Ed25519Base,
    ed25519_scalar::Ed25519Scalar,
    k1_base::K1Base,
    k1_scalar::K1Scalar,
    r1_base::R1Base,
    r1_scalar::R1Scalar,
    u256::U256,
    uint::{
        ED25519_BASE_BOUND_PTR, ED25519_SCALAR_BOUND_PTR, K1_BASE_BOUND_PTR, K1_SCALAR_BOUND_PTR,
        Limbs, R1_BASE_BOUND_PTR, R1_SCALAR_BOUND_PTR, U256_BOUND_PTR, UintDomain, UintNodeRef,
        UintPrecompile, UintSpec,
    },
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
/// The package bundles MASM support procedures for hash wrappers, arithmetic wrappers, signature
/// wrappers, and deferred-DAG helpers. These MASM modules are currently internal implementation
/// detail for core-library facades and precompile tests, while the crate's
/// [`PrecompileRegistry`] for deferred evaluation is provided separately via [`registry`].
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
            uint_handlers::field_inv_event_handler(),
        ]
    }
}

// REGISTRY
// ================================================================================================

/// Returns a [`PrecompileRegistry`] containing the precompiles provided by this crate.
pub fn registry() -> PrecompileRegistry {
    PrecompileRegistry::new()
        .with_precompile(Keccak256Precompile::default())
        .with_precompile(UintPrecompile)
        .with_precompile(CurvePrecompile)
}
