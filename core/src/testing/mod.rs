//! Test-support surface, gated behind the `testing` feature (and always available under
//! `cfg(test)`).
//!
//! Reusable across crates: enable `miden-core/testing` in a consumer's dev-dependencies to pull
//! these in.

pub mod precompile;
