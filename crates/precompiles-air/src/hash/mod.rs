//! Hashers and shared hasher infrastructure.
//!
//! Houses the [`memory64`] bus (the shared 64-bit memory namespace
//! hashers read state and input from), the [`chunk`] chiplet (input
//! chunking + Eidos content commitment, shared across hashers),
//! and the [`keccak`] hasher.

pub mod chunk;
pub mod chunk_node;
pub mod chunk_node_sponge;
pub mod keccak;
pub mod memory64;
