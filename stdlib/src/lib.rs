#![no_std]

pub mod handlers;

extern crate alloc;

use alloc::{sync::Arc, vec, vec::Vec};

use miden_assembly::{Library, mast::MastForest, utils::Deserializable};
use miden_core::{EventId, Felt, Word};
use miden_processor::{EventHandler, HostLibrary};
use miden_utils_sync::LazyLock;

use crate::handlers::keccak256::{KECCAK_HASH_MEMORY_EVENT_ID, handle_keccak_hash_memory};

// STANDARD LIBRARY
// ================================================================================================

/// TODO: add docs
#[derive(Clone)]
pub struct StdLibrary(Library);

impl AsRef<Library> for StdLibrary {
    fn as_ref(&self) -> &Library {
        &self.0
    }
}

impl From<StdLibrary> for Library {
    fn from(value: StdLibrary) -> Self {
        value.0
    }
}

impl From<&StdLibrary> for HostLibrary {
    fn from(stdlib: &StdLibrary) -> Self {
        Self {
            mast_forest: stdlib.mast_forest().clone(),
            handlers: stdlib.handlers(),
        }
    }
}

impl StdLibrary {
    /// Serialized representation of the Miden standard library.
    pub const SERIALIZED: &'static [u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/std.masl"));

    /// Returns a reference to the [MastForest] underlying the Miden standard library.
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        self.0.mast_forest()
    }

    /// Returns a reference to the underlying [`Library`].
    pub fn library(&self) -> &Library {
        &self.0
    }

    /// List of all `EventHandlers` required to run all of the standard library.
    pub fn handlers(&self) -> Vec<(EventId, Arc<dyn EventHandler>)> {
        vec![(KECCAK_HASH_MEMORY_EVENT_ID, Arc::new(handle_keccak_hash_memory))]
    }
}

impl Default for StdLibrary {
    fn default() -> Self {
        static STDLIB: LazyLock<StdLibrary> = LazyLock::new(|| {
            let contents =
                Library::read_from_bytes(StdLibrary::SERIALIZED).expect("failed to read std masl!");
            StdLibrary(contents)
        });
        STDLIB.clone()
    }
}

// FALCON SIGNATURE
// ================================================================================================

/// Signs the provided message with the provided secret key and returns the resulting signature
/// encoded in the format required by the rpo_faclcon512::verify procedure, or `None` if the secret
/// key is malformed due to either incorrect length or failed decoding.
///
/// The values are the ones required for a Falcon signature verification inside the VM and they are:
///
/// 1. The challenge point, a tuple of elements representing an element in the quadratic extension
///    field, at which we evaluate the polynomials in the subsequent three points to check the
///    product relationship.
/// 2. The expanded public key represented as the coefficients of a polynomial of degree < 512.
/// 3. The signature represented as the coefficients of a polynomial of degree < 512.
/// 4. The product of the above two polynomials in the ring of polynomials with coefficients in the
///    Miden field.
/// 5. The nonce represented as 8 field elements.
#[cfg(feature = "std")]
pub fn falcon_sign(sk: &[Felt], msg: Word) -> Option<Vec<Felt>> {
    use alloc::vec;

    use miden_core::{
        Felt,
        crypto::{
            dsa::rpo_falcon512::{Polynomial, SecretKey},
            hash::Rpo256,
        },
        utils::Deserializable,
    };

    // Create the corresponding secret key
    let mut sk_bytes = Vec::with_capacity(sk.len());
    for element in sk {
        let value = element.as_int();
        if value > u8::MAX as u64 {
            return None;
        }
        sk_bytes.push(value as u8);
    }

    let sk = SecretKey::read_from_bytes(&sk_bytes).ok()?;

    // We can now generate the signature
    let sig = sk.sign(msg);

    // The signature is composed of a nonce and a polynomial s2

    // The nonce is represented as 8 field elements.
    let nonce = sig.nonce();

    // We convert the signature to a polynomial
    let s2 = sig.sig_poly();

    // We also need in the VM the expanded key corresponding to the public key the was provided
    // via the operand stack
    let h = sk.public_key();

    // Lastly, for the probabilistic product routine that is part of the verification procedure,
    // we need to compute the product of the expanded key and the signature polynomial in
    // the ring of polynomials with coefficients in the Miden field.
    let pi = Polynomial::mul_modulo_p(&h, s2);

    // We now push the expanded key, the signature polynomial, and the product of the
    // expanded key and the signature polynomial to the advice stack. We also push
    // the challenge point at which the previous polynomials will be evaluated.
    // Finally, we push the nonce needed for the hash-to-point algorithm.

    let mut polynomials: Vec<Felt> =
        h.coefficients.iter().map(|a| Felt::from(a.value() as u32)).collect();
    polynomials.extend(s2.coefficients.iter().map(|a| Felt::from(a.value() as u32)));
    polynomials.extend(pi.iter().map(|a| Felt::new(*a)));

    let digest_polynomials = Rpo256::hash_elements(&polynomials);
    let challenge = (digest_polynomials[0], digest_polynomials[1]);

    let mut result: Vec<Felt> = vec![challenge.0, challenge.1];
    result.extend_from_slice(&polynomials);
    result.extend_from_slice(&nonce.to_elements());

    result.reverse();
    Some(result)
}

#[cfg(not(feature = "std"))]
pub fn falcon_sign(_pk_sk: &[Felt], _msg: Word) -> Option<Vec<Felt>> {
    None
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_assembly::LibraryPath;

    use super::*;

    #[test]
    fn test_compile() {
        let path = "std::math::u64::overflowing_add".parse::<LibraryPath>().unwrap();
        let stdlib = StdLibrary::default();
        let exists = stdlib.0.module_infos().any(|module| {
            module
                .procedures()
                .any(|(_, proc)| module.path().clone().append(&proc.name).unwrap() == path)
        });

        assert!(exists);
    }
}
