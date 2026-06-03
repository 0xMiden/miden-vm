#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{sync::Arc, vec};

use miden_core::{deferred::PrecompileRegistry, mast::MastForest, serde::Deserializable};
use miden_mast_package::Package;
use miden_processor::HostLibrary;
use miden_utils_sync::LazyLock;

mod codec;
mod dsa;
mod hash;

pub use dsa::{
    ecdsa_k256_keccak::EcdsaK256KeccakPrecompile, eddsa_ed25519::EddsaEd25519Precompile,
};
pub use hash::{
    HashFunction, HashPrecompile, keccak256::Keccak256Precompile, sha512::Sha512Precompile,
};

// PRECOMPILES LIBRARY
// ================================================================================================

/// The Miden precompiles library, wrapping the compiled `miden-precompiles` [`Package`].
///
/// The package bundles the MASM procedures exported under the `miden::precompiles` namespace: the
/// `keccak256` wrappers under `miden::precompiles::crypto::hashes::keccak256` and the deferred-DAG
/// helper procedures under `miden::precompiles::sys`. When the package is dynamically linked during
/// assembly, these procedures can be called from any Miden program and are serialized as 32 bytes.
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
        Self {
            mast_forest: precompiles_lib.mast_forest().clone(),
            handlers: vec![],
        }
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

// REGISTRY
// ================================================================================================

/// Returns a [`PrecompileRegistry`] containing the deferred precompiles provided by this crate.
pub fn registry() -> PrecompileRegistry {
    PrecompileRegistry::new()
        .with_precompile(Keccak256Precompile::default())
        .with_precompile(Sha512Precompile::default())
        .with_precompile(EcdsaK256KeccakPrecompile)
        .with_precompile(EddsaEd25519Precompile)
}
