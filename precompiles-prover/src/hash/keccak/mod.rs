//! Keccak hasher.
//!
//! The [`round`] chiplet (TAM-style miniVM running one Keccak-f[1600]
//! round), the [`sponge`] chiplet that absorbs / squeezes around it,
//! the [`node`] chiplet that ties chunks + sponge into a Keccak
//! transcript-DAG node, and the [`reference`] implementation used as a
//! trace-gen oracle. Connects to the shared
//! [`memory64`](super::memory64) bus and consumes input chunks from the
//! [`chunk`](super::chunk) chiplet.
//!
//! See `docs/chiplets/keccak.md`, `docs/chiplets/keccak-sponge.md`, and
//! `docs/chiplets/keccak-node.md` for the design rationale.

pub mod digest;
pub mod node;
pub mod reference;
pub mod round;
pub mod sponge;

pub use digest::KeccakDigest;
