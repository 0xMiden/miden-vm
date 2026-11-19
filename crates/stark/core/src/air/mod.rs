//! Authored relations, prepared execution, and validated statements.
//!
//! A [`LiftedAir`] defines equations and shape; [`ProverAir`] additionally constructs concrete
//! auxiliary witnesses. Checked descriptors and [`AirKernel`] bind prepared evaluation to its
//! inputs. [`MultiAir`] defines the trusted collection and cross-AIR hooks; [`Statement`] and
//! [`ProverStatement`] validate each proof's caller inputs and main traces. Fixed matrices are
//! constructed by setup, not by source capture or row evaluation.

mod analysis;
mod builder;
mod capture;
mod contracts;
pub mod debug;
mod descriptor;
mod encoding;
mod frame;
mod identity;
mod kernel;
mod spec;
mod statement;
pub mod symbolic;
mod util;

pub use analysis::{
    AirAnalysis, AnalysisError, ConstraintCounts, ConstraintDegrees, ConstraintLayout, DegreeBound,
    DegreeOp, DegreeProfile,
};
pub use builder::{ConstraintMeta, ConstraintPath, Filtered, LiftedAirBuilder, Named};
pub use capture::{Assertion, SymbolicSink};
pub use contracts::{AuxTrace, AuxTraceInputs, LiftedAir, MultiAir, ProverAir, ReductionError};
pub use descriptor::{
    AirDescriptor, Capture, DescriptorError, DescriptorParts, capture, capture_from_spec,
    capture_with,
};
pub use encoding::StatementEncoding;
pub use frame::{AirFrame, Frame, Inputs, Rows, Selectors, UniformInputs};
pub use kernel::{
    AirKernel, BindError, DirectKernel, EvaluationSession, KernelGeometry, QuotientAllocationError,
    resolve_quotient_chunks,
};
pub use spec::{AirSpec, PreprocessedSpec, SpecError};
pub use statement::{InstanceError, ProverStatement, Statement};
pub use util::{log2_ceil_u8, log2_strict_u8};
