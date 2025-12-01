#![no_std]

pub mod handlers;

extern crate alloc;

use alloc::{sync::Arc, vec, vec::Vec};

use miden_assembly::{Library, mast::MastForest, utils::Deserializable};
use miden_core::{
    EventName, Felt, Word, precompile::PrecompileVerifierRegistry, utils::Serializable,
};
use miden_crypto::dsa::ecdsa_k256_keccak;
use miden_processor::{EventHandler, HostLibrary};
use miden_utils_sync::LazyLock;

use crate::handlers::{
    bytes_to_packed_u32_felts,
    ecdsa::{ECDSA_VERIFY_EVENT_NAME, EcdsaPrecompile},
    falcon_div::{FALCON_DIV_EVENT_NAME, handle_falcon_div},
    keccak256::{KECCAK_HASH_BYTES_EVENT_NAME, KeccakPrecompile},
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
    pub fn handlers(&self) -> Vec<(EventName, Arc<dyn EventHandler>)> {
        vec![
            (KECCAK_HASH_BYTES_EVENT_NAME, Arc::new(KeccakPrecompile)),
            (ECDSA_VERIFY_EVENT_NAME, Arc::new(EcdsaPrecompile)),
            (SMT_PEEK_EVENT_NAME, Arc::new(handle_smt_peek)),
            (U64_DIV_EVENT_NAME, Arc::new(handle_u64_div)),
            (FALCON_DIV_EVENT_NAME, Arc::new(handle_falcon_div)),
            (LOWERBOUND_ARRAY_EVENT_NAME, Arc::new(handle_lowerbound_array)),
            (LOWERBOUND_KEY_VALUE_EVENT_NAME, Arc::new(handle_lowerbound_key_value)),
        ]
    }

    /// Returns a [`PrecompileVerifierRegistry`] containing all verifiers required to validate
    /// standard library precompile requests.
    pub fn verifier_registry(&self) -> PrecompileVerifierRegistry {
        PrecompileVerifierRegistry::new()
            .with_verifier(&KECCAK_HASH_BYTES_EVENT_NAME, Arc::new(KeccakPrecompile))
            .with_verifier(&ECDSA_VERIFY_EVENT_NAME, Arc::new(EcdsaPrecompile))
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

// ECDSA SIGNATURE
// ================================================================================================

/// Signs the provided message with the supplied secret key and encodes this signature and the
/// associated public key into a vector of field elements in the format expected by
/// `stdlib::crypto::dsa::ecdsa::secp256k1::verify_ecdsa_k256_keccak` procedure.
///
/// See [encode_ecdsa_signature()] for more info.
pub fn ecdsa_sign(sk: &ecdsa_k256_keccak::SecretKey, msg: Word) -> Vec<Felt> {
    let pk = sk.public_key();
    let sig = sk.sign(msg);
    encode_ecdsa_signature(&pk, &sig)
}

/// Infers the pubic key from the provided signature and message, and encodes this public key and
/// signature into a vector of field elements in the format expected by
/// `stdlib::crypto::dsa::ecdsa::secp256k1::verify_ecdsa_k256_keccak` procedure.
///
/// See [encode_ecdsa_signature()] for more info.
///
/// # Errors
/// Returns an error if key recovery from signature and message fails.
pub fn prepare_ecdsa_signature(
    msg: Word,
    sig: &ecdsa_k256_keccak::Signature,
) -> Result<Vec<Felt>, ecdsa_k256_keccak::PublicKeyError> {
    let pk = ecdsa_k256_keccak::PublicKey::recover_from(msg, sig)?;
    Ok(encode_ecdsa_signature(&pk, sig))
}

/// Encodes the provided public key and signature into a vector of field elements in the format
/// expected by `stdlib::crypto::dsa::ecdsa::secp256k1::verify_ecdsa_k256_keccak` procedure.
///
/// 1. The compressed secp256k1 public key encoded as 9 packed-u32 felts (33 bytes total).
/// 2. The ECDSA signature encoded as 17 packed-u32 felts (66 bytes total).
///
/// The two chunks are concatenated as `[PK[9] || SIG[17]]` so they can be streamed straight to
/// the advice provider before invoking `secp256k1::verify_ecdsa_k256_keccak`.
pub fn encode_ecdsa_signature(
    pk: &ecdsa_k256_keccak::PublicKey,
    sig: &ecdsa_k256_keccak::Signature,
) -> Vec<Felt> {
    let mut out = Vec::new();
    let pk_bytes = pk.to_bytes();
    out.extend(bytes_to_packed_u32_felts(&pk_bytes));
    let sig_bytes = sig.to_bytes();
    out.extend(bytes_to_packed_u32_felts(&sig_bytes));
    out
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
    use miden_assembly::Path;

    use super::*;

    #[test]
    fn test_compile() {
        let path = Path::new("::std::math::u64::overflowing_add");
        let stdlib = StdLibrary::default();
        let exists = stdlib.0.module_infos().any(|module| {
            module.procedures().any(|(_, proc)| &module.path().join(&proc.name) == path)
        });

        assert!(exists);
    }
}
