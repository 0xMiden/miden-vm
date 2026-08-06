#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(any(feature = "constraints-tools", all(test, feature = "std")))]
pub mod constraints_regen;
pub mod dsa;
#[cfg(feature = "constraints-tools")]
pub mod evaluator_regen;
pub mod handlers;

extern crate alloc;

use alloc::{sync::Arc, vec, vec::Vec};

use miden_core::{Word, events::EventName, mast::MastForest};
use miden_mast_package::Package;
use miden_processor::{HostLibrary, event::EventHandler};
use miden_utils_sync::LazyLock;

use crate::handlers::{
    aead_decrypt::{AEAD_DECRYPT_EVENT_NAME, handle_aead_decrypt},
    debug::default_debug_handlers,
    falcon_div::{FALCON_DIV_EVENT_NAME, handle_falcon_div},
    precompiles::{
        keccak256::{KECCAK256_DIGEST_EVENT_NAME, handle_keccak256_digest},
        uint_field_inv::{UINT_FIELD_INV_EVENT_NAME, handle_uint_field_inv},
    },
    readonly::readonly_noop_handlers,
    smt_peek::{SMT_PEEK_EVENT_NAME, handle_smt_peek},
    sorted_array::{
        LOWERBOUND_ARRAY_EVENT_NAME, LOWERBOUND_KEY_VALUE_EVENT_NAME, handle_lowerbound_array,
        handle_lowerbound_key_value,
    },
    u64_div::{U64_DIV_EVENT_NAME, handle_u64_div},
    u128_div::{U128_DIV_EVENT_NAME, handle_u128_div},
    u256_div::{U256_DIV_EVENT_NAME, handle_u256_div},
};

// CORE LIBRARY
// ================================================================================================

/// The Miden core library, providing a set of optimized procedures for Miden programs.
///
/// This library wraps the `miden-core` [`Package`] and its `miden-precompiles` runtime dependency.
/// When the core library is dynamically linked during assembly time, procedures can be called from
/// any Miden program and are serialized as 32 bytes, reducing the amount of code that needs to be
/// shared between parties for proving and verifying program execution.
///
/// # Contents
///
/// The core library provides several categories of functionality:
///
/// - **Cryptographic primitives**: Poseidon2, Blake3, SHA-256, Falcon signature verification,
///   authenticated encryption (AEAD decryption), and stable core facades for bundled deferred
///   precompiles under `::miden::core::*`.
/// - **Mathematical operations**: Division operations for u64, u128, and u256.
/// - **Data structures**: Sparse Merkle Tree operations, Merkle Mountain Range (MMR), and sorted
///   array utilities with lower-bound search capabilities.
/// - **Memory operations**: Efficient hashing and "un-hashing" of large amounts of data.
///
/// # Usage
///
/// The core library is typically used with the assembler to enable core library procedures
/// in compiled programs:
///
/// ```rust,ignore
/// use miden_assembly::{Assembler, Linkage};
/// use miden_core_lib::CoreLibrary;
///
/// let core_lib = CoreLibrary::default();
/// let mut assembler = Assembler::new(source_manager);
/// for package in core_lib.packages() {
///     assembler.link_package(package, Linkage::Dynamic).unwrap();
/// }
/// ```
///
/// For program execution, you'll also need to register the event handlers:
///
/// ```rust,ignore
/// # let core_lib = CoreLibrary::default();
/// let handlers = core_lib.handlers();
/// // Register handlers with your host...
/// ```
///
/// Stack and memory print-style debug handlers are registered with stdout writers by default.
/// These handlers can print private values if a program moves witness data onto the operand stack
/// or into memory. Privacy-sensitive hosts should replace or unregister these handlers. Advice
/// debug handlers can expose witness data directly, so hosts must opt into those explicitly.
///
/// [`Package`]: miden_mast_package::Package
#[derive(Clone)]
pub struct CoreLibrary {
    core_package: Arc<Package>,
    precompiles_package: Arc<Package>,
    mast_forest: Arc<MastForest>,
}

impl AsRef<Package> for CoreLibrary {
    fn as_ref(&self) -> &Package {
        &self.core_package
    }
}

impl From<&CoreLibrary> for HostLibrary {
    fn from(core_lib: &CoreLibrary) -> Self {
        Self {
            mast_forest: Arc::clone(core_lib.mast_forest()),
            package_debug_info: Ok(None),
            handlers: core_lib.handlers(),
        }
    }
}

impl CoreLibrary {
    /// Serialized representation of the Miden `core` package.
    pub const SERIALIZED: &'static [u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/miden-core.masp"));

    /// Serialized representation of the `miden-precompiles` package used by the core library.
    pub const PRECOMPILES_SERIALIZED: &'static [u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/miden-precompiles.masp"));

    /// Returns a reference to the merged [MastForest] used to execute the core library and its
    /// precompiles dependency.
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        &self.mast_forest
    }

    /// Returns the `miden-core` package.
    pub fn package(&self) -> Arc<Package> {
        Arc::clone(&self.core_package)
    }

    /// Returns the `miden-precompiles` package required by `miden-core`.
    pub fn precompiles_package(&self) -> Arc<Package> {
        Arc::clone(&self.precompiles_package)
    }

    /// Returns the core package followed by its precompiles dependency.
    pub fn packages(&self) -> [Arc<Package>; 2] {
        [self.package(), self.precompiles_package()]
    }

    /// Returns the MAST root of `sys::vm::verify_vm_proof` — the verifier identity under
    /// which recursive proofs are content-addressed.
    ///
    /// Operators pass this root when registering a proof package in the advice map
    /// (`RecursiveVerifierInputs::for_request`). A consumer derives the identical value
    /// in-VM with `procref` — a procedure's root is intrinsic to its own MAST — so the two sides
    /// agree without a shared constant; consumers key their proof fetches by this root.
    pub fn recursive_verifier_root(&self) -> Word {
        self.core_package
            .get_procedure_root_by_path("::miden::core::sys::vm::verify_vm_proof")
            .expect("verify_vm_proof is exported from the core library")
    }

    /// Returns the default event handlers required by the core library.
    ///
    /// Stack and memory print-style debug handlers write to stdout by default. These handlers can
    /// print private values if a program moves witness data onto the operand stack or into memory.
    /// Hosts can replace those handlers to route output to a UI, log, no-op handler, or other sink.
    /// Advice debug handlers can expose witness data directly, so hosts must opt into those
    /// explicitly by extending this handler set with
    /// [`crate::handlers::debug::advice_debug_handlers`].
    pub fn handlers(&self) -> Vec<(EventName, Arc<dyn EventHandler>)> {
        let mut handlers: Vec<(EventName, Arc<dyn EventHandler>)> = vec![
            (SMT_PEEK_EVENT_NAME, Arc::new(handle_smt_peek)),
            (U64_DIV_EVENT_NAME, Arc::new(handle_u64_div)),
            (U128_DIV_EVENT_NAME, Arc::new(handle_u128_div)),
            (U256_DIV_EVENT_NAME, Arc::new(handle_u256_div)),
            (FALCON_DIV_EVENT_NAME, Arc::new(handle_falcon_div)),
            (LOWERBOUND_ARRAY_EVENT_NAME, Arc::new(handle_lowerbound_array)),
            (LOWERBOUND_KEY_VALUE_EVENT_NAME, Arc::new(handle_lowerbound_key_value)),
            (AEAD_DECRYPT_EVENT_NAME, Arc::new(handle_aead_decrypt)),
            (KECCAK256_DIGEST_EVENT_NAME, Arc::new(handle_keccak256_digest)),
            (UINT_FIELD_INV_EVENT_NAME, Arc::new(handle_uint_field_inv)),
        ];
        handlers.extend(default_debug_handlers());
        handlers.extend(readonly_noop_handlers());
        handlers
    }
}

impl Default for CoreLibrary {
    fn default() -> Self {
        static CORELIB: LazyLock<CoreLibrary> = LazyLock::new(|| {
            let core_package = Arc::new(
                Package::read_from_bytes_trusted(CoreLibrary::SERIALIZED)
                    .expect("failed to read core package!"),
            );
            let precompiles_package = Arc::new(
                Package::read_from_bytes_trusted(CoreLibrary::PRECOMPILES_SERIALIZED)
                    .expect("failed to read precompiles package!"),
            );
            let (mast_forest, _) = MastForest::merge([
                core_package.mast_forest().as_ref(),
                precompiles_package.mast_forest().as_ref(),
            ])
            .expect("failed to merge core and precompiles MAST forests");

            CoreLibrary {
                core_package,
                precompiles_package,
                mast_forest: Arc::new(mast_forest),
            }
        });
        CORELIB.clone()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_package_version_matches_crate_version() {
        let core_lib = CoreLibrary::default();
        let crate_version = env!("CARGO_PKG_VERSION")
            .parse::<miden_mast_package::Version>()
            .expect("crate version should be a valid package version");

        for package in core_lib.packages() {
            assert_eq!(
                &package.version, &crate_version,
                "embedded package {} should track the miden-core-lib crate version",
                package.name,
            );
        }
    }

    #[test]
    fn test_compile() {
        let core_lib = CoreLibrary::default();
        let exists = core_lib
            .core_package
            .get_procedure_root_by_path("::miden::core::math::u64::overflowing_add")
            .is_some();

        assert!(exists);
    }
}
