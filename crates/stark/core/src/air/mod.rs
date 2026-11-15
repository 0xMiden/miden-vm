//! Authored relations, prepared execution, and validated statements.
//!
//! [`native`] owns source specifications, fallible witnesses, checked descriptors, kernels and
//! borrowed evaluation sessions. [`MultiAir`] defines the trusted collection and cross-AIR hooks;
//! [`Statement`] and [`ProverStatement`] validate each proof's caller inputs and main traces.

mod contracts;
pub mod debug;
mod encoding;
pub mod native;
mod statement;
mod util;

pub use contracts::{MultiAir, ReductionError};
pub use encoding::StatementEncoding;
pub use statement::{InstanceError, ProverStatement, Statement};
pub use util::{log2_ceil_u8, log2_strict_u8};
