#[cfg(feature = "std")]
mod falcon;

mod aead;
mod blake3;
mod circuit_evaluation;
mod ecdsa_k256_keccak;
mod eddsa_ed25519;
mod keccak256;
mod keccak256_native;
mod keccak256_native_masm;
mod poseidon2;
mod sha256;
mod sha512;
