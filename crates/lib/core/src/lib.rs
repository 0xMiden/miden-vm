#![no_std]

pub mod dsa;
pub mod handlers;

extern crate alloc;

use alloc::{sync::Arc, vec, vec::Vec};

use miden_assembly::{Library, mast::MastForest, utils::Deserializable};
use miden_core::{EventName, precompile::PrecompileVerifierRegistry};
use miden_processor::{EventHandler, HostLibrary};
use miden_utils_sync::LazyLock;

use crate::handlers::{
    aead_decrypt::{AEAD_DECRYPT_EVENT_NAME, handle_aead_decrypt},
    ecdsa::{ECDSA_VERIFY_EVENT_NAME, EcdsaPrecompile},
    eddsa_ed25519::{EDDSA25519_VERIFY_EVENT_NAME, EddsaPrecompile},
    falcon_div::{FALCON_DIV_EVENT_NAME, handle_falcon_div},
    keccak256::{KECCAK_HASH_BYTES_EVENT_NAME, KeccakPrecompile},
    sha512::{SHA512_HASH_BYTES_EVENT_NAME, Sha512Precompile},
    smt_peek::{SMT_PEEK_EVENT_NAME, handle_smt_peek},
    sorted_array::{
        LOWERBOUND_ARRAY_EVENT_NAME, LOWERBOUND_KEY_VALUE_EVENT_NAME, handle_lowerbound_array,
        handle_lowerbound_key_value,
    },
    u64_div::{U64_DIV_EVENT_NAME, handle_u64_div},
};

// STANDARD LIBRARY
// ================================================================================================

/// TODO: add docs
#[derive(Clone)]
pub struct CoreLibrary(Library);

impl AsRef<Library> for CoreLibrary {
    fn as_ref(&self) -> &Library {
        &self.0
    }
}

impl From<CoreLibrary> for Library {
    fn from(value: CoreLibrary) -> Self {
        value.0
    }
}

impl From<&CoreLibrary> for HostLibrary {
    fn from(core_lib: &CoreLibrary) -> Self {
        Self {
            mast_forest: core_lib.mast_forest().clone(),
            handlers: core_lib.handlers(),
        }
    }
}

impl CoreLibrary {
    /// Serialized representation of the Miden core library.
    pub const SERIALIZED: &'static [u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/core.masl"));

    /// Returns a reference to the [MastForest] underlying the Miden core library.
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        self.0.mast_forest()
    }

    /// Returns a reference to the underlying [`Library`].
    pub fn library(&self) -> &Library {
        &self.0
    }

    /// List of all `EventHandlers` required to run all of the core library.
    pub fn handlers(&self) -> Vec<(EventName, Arc<dyn EventHandler>)> {
        vec![
            (KECCAK_HASH_BYTES_EVENT_NAME, Arc::new(KeccakPrecompile)),
            (SHA512_HASH_BYTES_EVENT_NAME, Arc::new(Sha512Precompile)),
            (ECDSA_VERIFY_EVENT_NAME, Arc::new(EcdsaPrecompile)),
            (EDDSA25519_VERIFY_EVENT_NAME, Arc::new(EddsaPrecompile)),
            (SMT_PEEK_EVENT_NAME, Arc::new(handle_smt_peek)),
            (U64_DIV_EVENT_NAME, Arc::new(handle_u64_div)),
            (FALCON_DIV_EVENT_NAME, Arc::new(handle_falcon_div)),
            (LOWERBOUND_ARRAY_EVENT_NAME, Arc::new(handle_lowerbound_array)),
            (LOWERBOUND_KEY_VALUE_EVENT_NAME, Arc::new(handle_lowerbound_key_value)),
            (AEAD_DECRYPT_EVENT_NAME, Arc::new(handle_aead_decrypt)),
        ]
    }

    /// Returns a [`PrecompileVerifierRegistry`] containing all verifiers required to validate
    /// core library precompile requests.
    pub fn verifier_registry(&self) -> PrecompileVerifierRegistry {
        PrecompileVerifierRegistry::new()
            .with_verifier(&KECCAK_HASH_BYTES_EVENT_NAME, Arc::new(KeccakPrecompile))
            .with_verifier(&SHA512_HASH_BYTES_EVENT_NAME, Arc::new(Sha512Precompile))
            .with_verifier(&ECDSA_VERIFY_EVENT_NAME, Arc::new(EcdsaPrecompile))
            .with_verifier(&EDDSA25519_VERIFY_EVENT_NAME, Arc::new(EddsaPrecompile))
    }
}

impl Default for CoreLibrary {
    fn default() -> Self {
        static STDLIB: LazyLock<CoreLibrary> = LazyLock::new(|| {
            let contents = Library::read_from_bytes(CoreLibrary::SERIALIZED)
                .expect("failed to read std masl!");
            CoreLibrary(contents)
        });
        STDLIB.clone()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_assembly::Path;

    use super::*;

    #[test]
    fn test_compile() {
        let path = Path::new("::miden::core::math::u64::overflowing_add");
        let core_lib = CoreLibrary::default();
        let exists = core_lib.0.module_infos().any(|module| {
            module.procedures().any(|(_, proc)| &module.path().join(&proc.name) == path)
        });

        assert!(exists);
    }
}
