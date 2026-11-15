//! Native LogUp declarations, shared scoped callbacks, and witness arithmetic.

pub mod aux_builder;
pub mod builder;
pub mod challenges;
pub mod constraint;
#[cfg(feature = "std")]
pub mod debug;
pub mod message;
pub mod native;
pub mod prover;

pub use aux_builder::{LookupFractions, accumulate, accumulate_slow};
pub use builder::{BoundaryBuilder, Deg, LookupBatch, LookupColumn, LookupGroup};
pub use challenges::Challenges;
pub use message::LookupMessage;
pub use native::{
    ConstraintLookupBuilder, LookupAir, LookupBuilder, build_logup_aux_trace,
    build_lookup_fractions,
};
pub use prover::ProverLookupBuilder;
