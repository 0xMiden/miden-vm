//! Shared scaffolding for the deferred-DAG precompile integration tests.
//!
//! Houses the reference precompile implementations (`Uint`, `Group`, `Hash`, `Sig`) that
//! exercise `miden_core::deferred`'s public surface. These are not production precompiles
//! (those live in `miden-core-lib::precompiles`); they are deliberately minimal vehicles for
//! testing the framework itself. Each `core/tests/precompile_*.rs` integration test pulls
//! this in via `mod common;` and uses only the slice it needs.
#![allow(dead_code, unused_imports)]

pub mod precompile;
