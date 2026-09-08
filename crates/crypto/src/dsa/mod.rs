//! Digital signature schemes provided by this crate.

pub mod ecdsa_k256_keccak;
pub mod eddsa_25519_sha512;
mod falcon512_common;
// Falcon512-Eidos is internal; Falcon512-Poseidon2 is the public protocol variant.
#[allow(dead_code)]
mod falcon512_eidos;
pub mod falcon512_poseidon2;
