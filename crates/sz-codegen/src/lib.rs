//! Emits Miden MASM procs for u16-limb modular-multiplication verifiers checked with a
//! Schwartz-Zippel identity at a Fiat-Shamir-derived point in the quadratic extension of the
//! Miden base field.
//!
//! The checked-in verifiers prove identities of the form
//!
//!   `a(x) * b(x) - q(x) * m(x) - c(x)
//!       - (W - x) * (e_pos(x) - e_neg(x))  =  0`
//!
//! where the signed carry polynomial `e = e_pos - e_neg` is provided as two non-negative
//! halves (each component is u32-bounded). A [`spec::LinearRelation`] is the small internal IR
//! used to describe that identity, witness layout, and auxiliary checks; [`emit_masm`] turns one
//! into a fully-specialized MASM proc.
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

pub use emit::{emit_masm, emit_module, modulus_seeded_initial_state};
