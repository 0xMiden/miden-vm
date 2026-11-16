#![no_std]

//! Production VM and precompile AIRs and build-generated artifacts.
//!
//! [`vm`] and [`precompiles`] expose the production AIRs and own their PCS presets, protocol
//! versions, and identity pins consumed by the recursive verifiers. Handwritten constraints, trace
//! schemas, and shared Eidos equations live in [`miden_air_definitions`]; its
//! [`miden_air_definitions::vm`] module describes the VM's four-AIR statement.
//!
//! [`vm::MidenAir`] and [`precompiles::ChipletAir`] wrap their authored AIRs, delegating metadata
//! and auxiliary-trace construction while dispatching constraint evaluation and degrees to
//! generated code. This crate defines the concrete [`miden_stark::air::MultiAir`] adapters;
//! `miden-air-definitions` supplies statement validation, VM claim observation, and the VM/PVM
//! external assertions. The native engine and recursive verifier derive proof order from trace
//! heights.
//!
//! Cargo generates native evaluators, security metadata, and canonical ACE streams into `OUT_DIR`.
//! The source crate exposes optional capture and circuit construction through `compiler::vm` and
//! `compiler::precompiles`. Compiler tooling is a build dependency; runtime consumers use the
//! generated artifacts. The core library's recursive-verifier MASM imports parameters generated
//! from the same captures; see [Maintaining recursive-verifier MASM].
//!
//! Relation setup and transcript-domain adapters live in `miden-vm-stark` and
//! `miden-precompiles-stark`. Shared AIR contracts, transcript channels, lookup mechanisms,
//! configuration factories, and security estimators live in [`miden_stark`]. Breaking API changes
//! and replacement imports are documented in `miden_ace::migration`.
//!
//! # About AIR
//!
//! An algebraic intermediate representation (AIR) describes a computation as low-degree polynomial
//! constraints. The prover evaluates them over the processor's execution trace and includes the
//! results in the proof; the verifier checks the constraints against the committed trace. The VM
//! [design documentation] describes its constraints in detail. StarkWare's [Arithmetization I],
//! [Arithmetization II], and [STARK Core Engine] articles provide further background.
//!
//! [Maintaining recursive-verifier MASM]: https://github.com/0xMiden/miden-vm/blob/next/crates/lib/core/RECURSIVE_VERIFIER.md
//! [design documentation]: https://docs.miden.xyz/miden-vm/design
//! [Arithmetization I]: https://medium.com/starkware/arithmetization-i-15c046390862
//! [Arithmetization II]: https://medium.com/starkware/arithmetization-ii-403c3b3f4355
//! [STARK Core Engine]: https://medium.com/starkware/starkdex-deep-dive-the-stark-core-engine-497942d0f0ab

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod precompiles;
pub mod vm;
