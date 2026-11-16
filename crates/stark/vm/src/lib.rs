//! Miden VM relation proving, native verification, and recursive advice.
//!
//! This crate implements STARK proving and verification for the VM relation, concrete setup and
//! configuration, security reporting, and recursive-verifier inputs. Execution and trace
//! construction live in `miden-processor`. Both crates use [`miden_air_definitions::vm::VmTrace`];
//! this backend has no normal dependency on the processor.
//!
//! Authored constraints and statement semantics live in [`miden_air_definitions::vm`]. This backend
//! consumes production evaluators and embedded ACE instructions from [`miden_air::vm`] without
//! compiling AIRs at runtime.
//!
//! # Features
//!
//! Native verification supports `no_std` with `alloc` when default features are disabled. The
//! default `std` feature enables shared setup and circuit caches, `prover` enables proving, and
//! `concurrent` enables parallel computation.
//!
//! # Traces and verification
//!
//! Low-level processor callers supply a [`memory`] budget before constructing a trace. Use
//! [`debug::check_constraints`] to evaluate production constraints over a completed trace, and
//! [`miden_air_definitions::vm::VmTrace`] for trace inspection and buffer access.
//!
//! [`verifier::verify`] authenticates the VM STARK against an execution claim. The proof's deferred
//! computations require separate verification. The `miden-prover` and `miden-verifier` entrypoints
//! coordinate execution proofs, precompile obligations, and application acceptance policy.
//!
//! # Configuration and security
//!
//! [`miden_air::vm::config`] defines PCS presets and accepted relation, circuit, and setup digests.
//! [`setup::config::eidos_config`] supplies the VM transcript domain. Generated security geometry
//! and constants live in [`miden_air::vm::security`]; this crate's [`security`] module constructs
//! the VM-specific inputs to the shared estimator. Generic configuration factories and security
//! estimators live in [`miden_stark::config`] and [`miden_stark::security`].
//!
//! For breaking API changes and replacement imports, see [`miden_ace::migration`].
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod debug;
pub mod memory;
#[cfg(feature = "prover")]
pub mod prover;
pub mod recursive;
pub mod security;
pub mod setup;
pub mod verifier;
