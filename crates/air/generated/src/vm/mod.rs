//! Production AIR evaluators and proof protocol for the Miden VM.
//!
//! Authored constraints and trace layouts live in [`miden_air_definitions::vm`]. This module
//! combines their metadata and lookup construction with build-generated native evaluators.

pub mod ace;
mod airs;
pub mod config;
#[allow(clippy::eq_op)]
mod generated;
mod proof_order;
pub mod security;
mod statement;

pub use airs::MidenAir;
pub use miden_air_definitions::vm::NUM_PUBLIC_VALUES;
pub use proof_order::{AIRS, MIDEN_AIR_COUNT};
pub use statement::MidenMultiAir;
