//! Digital signature schemes provided by this crate.

pub mod ecdsa_k256_keccak;
pub mod eddsa_25519_sha512;
mod falcon512_common;
// Kept private while Poseidon2 remains the protocol Falcon variant.
#[allow(dead_code)]
mod falcon512_eidos;
pub mod falcon512_poseidon2;
