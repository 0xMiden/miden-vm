//! Authored AIR relations with immutable expression inputs and a separate assertion sink.
//!
//! A [`LiftedAir`] defines mathematics and shape. [`ProverAir`] additionally constructs a
//! concrete auxiliary witness; evaluating or inspecting a relation does not need that capability.
//! Fixed matrices are constructed by setup, not by expression evaluation.

mod builder;
mod contracts;
mod frame;
#[doc(hidden)]
pub mod migration;
mod spec;

pub use builder::{ConstraintMeta, ConstraintPath, Filtered, LiftedAirBuilder, Named};
pub use contracts::{AuxTrace, AuxTraceInputs, LiftedAir, ProverAir};
pub use frame::{AirFrame, Frame, Inputs, Rows, Selectors, UniformInputs};
pub use spec::{AirSpec, PreprocessedSpec, SpecError};
