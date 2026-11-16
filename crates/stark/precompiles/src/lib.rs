#![no_std]

//! Native proving, verification, setup, and recursive advice for the precompile relation.
//!
//! Authored AIRs live in [`miden_air_definitions::precompiles`]. Production evaluators, geometry,
//! embedded ACE instructions, and the identity pins consumed by the recursive verifier come from
//! [`miden_air::precompiles`]. Native verification and recursive advice consume these compiled
//! artifacts without symbolically capturing AIRs at runtime.
//!
//! # Features
//!
//! Native verification supports `no_std` with `alloc` when default features are disabled and
//! requires no prover implementation dependencies. The default `std` feature exposes
//! `recursive::PvmRecursiveVerifierInputs`, which adapts Eidos proofs for the in-VM PVM verifier.
//!
//! Enable `prover` for `prover::prove_precompiles` and its variants accepting explicit work limits
//! and memory budgets. Witnesses are prepared and admitted independently, then combined in a
//! proving session that shares repeated computations. Root order and repetitions are preserved;
//! empty batches and batches above [`miden_core::deferred::MAX_PRECOMPILE_ROOTS`] are rejected.
//! The memory budget bounds conservative reservations for preparation and session construction,
//! then the modelled proving peak before trace allocation. Proving uses the shared
//! [`miden_stark::memory`] estimator. The `concurrent` feature enables parallel computation.
//!
//! # Verification and setup
//!
//! [`verifier::verify_deferred`] verifies a serialized STARK against an explicit aggregate root and
//! returns authenticated security parameters. The caller enforces execution-root coverage and
//! minimum-security requirements. [`setup`] supplies configuration factories, preprocessing caches,
//! native setup commitments, and PVM security parameters.
//!
//! Generic configuration factories and transcript observation come from [`miden_stark::config`].
//! The accepted PVM PCS preset comes from [`miden_air::precompiles::policy`];
//! [`setup::config::eidos_config`] supplies the PVM transcript domain.
//!
//! # Generation tools
//!
//! The `fixture-tools` feature enables `pvm-proof-fixture` for regenerating and checking the pinned
//! Eidos proof fixture. The `constants-tools` feature enables `pvm-constants-regen` for the PVM
//! MASM parameters and generated verifier artifacts in `crates/lib/core/asm/sys/pvm`:
//!
//! ```text
//! cargo run --release -p miden-precompiles-stark --features fixture-tools --bin pvm-proof-fixture -- --check
//! cargo run --release -p miden-precompiles-stark --features constants-tools --bin pvm-constants-regen -- --check
//! ```
//!
//! Replace `--check` with `--write` to regenerate the corresponding artifacts. The constants tool
//! checks the compiled circuit's digest, relation digest, and shape against the pins in
//! [`miden_air::precompiles::protocol`] before comparing or writing generated MASM. Its
//! implementation is exposed as `recursive::ace_constants_regen` with `constants-tools` enabled.
//!
//! For breaking API changes and replacement imports, see [`miden_ace::migration`].

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "prover")]
pub mod prover;
#[cfg(feature = "std")]
pub mod recursive;
pub mod setup;
pub mod verifier;
