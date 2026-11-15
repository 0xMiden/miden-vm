//! Authored AIR relations with immutable expression inputs and a separate assertion sink.
//!
//! A [`LiftedAir`] defines mathematics and shape. [`ProverAir`] additionally constructs a
//! concrete auxiliary witness; evaluating or inspecting a relation does not need that capability.
//! Fixed matrices are constructed by setup, not by expression evaluation.

mod analysis;
mod builder;
mod capture;
mod contracts;
mod descriptor;
mod frame;
mod identity;
#[doc(hidden)]
pub mod migration;
mod spec;
pub mod symbolic;

pub use analysis::{
    AirAnalysis, AnalysisError, ConstraintCounts, ConstraintDegrees, ConstraintLayout, DegreeBound,
    DegreeOp, DegreeProfile,
};
pub use builder::{ConstraintMeta, ConstraintPath, Filtered, LiftedAirBuilder, Named};
pub use capture::Assertion;
pub use contracts::{AuxTrace, AuxTraceInputs, LiftedAir, ProverAir};
pub use descriptor::{
    AirDescriptor, Capture, DescriptorError, DescriptorParts, capture, capture_with,
};
pub use frame::{AirFrame, Frame, Inputs, Rows, Selectors, UniformInputs};
pub use spec::{AirSpec, PreprocessedSpec, SpecError};
