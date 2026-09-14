//! Digital signature schemes supported by default in the Miden VM.

pub mod ecdsa_k256_keccak;
pub mod eddsa_25519_sha512;
mod falcon512_common;
pub mod falcon512_eidos;
