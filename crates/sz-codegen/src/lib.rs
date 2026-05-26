//! Emits Miden MASM procs for u16-limb modular-multiplication verifiers checked with a
//! Schwartz-Zippel identity at a Fiat-Shamir-derived point in the quadratic extension of the
//! Miden base field.
//!
//! The checked-in verifiers prove identities of the form
//!
//!   `a(x) * b(x) - q(x) * m(x) - c(x)
//!       - (W - x) * (e_shifted(x) - offset(x))  =  0`
//!
//! where the signed carry is shifted by `2^31` per coefficient (so every landed felt is a valid
//! u32) and `offset` is the fixed `[2^31; 32]` polynomial that undoes the shift inside the
//! identity. Both `m` and `offset` are absorbed as the fixed-statement prefix and pinned under a
//! single Poseidon2 digest. A [`spec::LinearRelation`] describes one such identity plus its
//! witness layout and auxiliary checks; [`emit_masm`] turns one into a fully-specialized MASM
//! proc.
//!
//! Emitted artifacts (`modmul_k1_base`, `modmul_k1_scalar`) are checked into source control.
//! The `regen` binary regenerates them; CI runs it in `--check` mode and fails if the working
//! tree drifts from the spec.
//!
//! The emitter is straight-line by design: per-modulus differences produce per-spec differences
//! in the emitted MASM, and optimization happens by enriching the spec rather than branching
//! inside the emitter.

#![no_std]

extern crate alloc;

pub mod emit;
pub mod spec;
pub mod specs;

pub use emit::{emit_masm, emit_module, fixed_prefix_seeded_initial_state};
