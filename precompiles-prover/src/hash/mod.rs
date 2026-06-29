//! Hashers and shared hasher infrastructure.
//!
//! Houses the [`memory64`] bus (the shared 64-bit memory namespace
//! hashers read state and input from), the [`chunk`] chiplet (input
//! chunking + Poseidon2 content commitment, shared across hashers),
//! and the [`keccak`] hasher. Future hashers (SHA-2, …) join as
//! siblings of [`keccak`], reusing [`chunk`] and [`memory64`] in
//! their own address sub-namespaces.

pub mod chunk;
pub mod keccak;
pub mod memory64;
