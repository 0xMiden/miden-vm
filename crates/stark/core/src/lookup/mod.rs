//! LogUp declarations, shared scoped callbacks, and witness arithmetic.

pub mod aux_builder;
pub mod builder;
pub mod challenges;
pub mod constraint;
mod contracts;
#[cfg(feature = "std")]
pub mod debug;
pub mod message;
pub mod prover;

pub use aux_builder::{LookupFractions, accumulate, accumulate_slow};
pub use builder::{BoundaryBuilder, Deg, LookupBatch, LookupColumn, LookupGroup};
pub use challenges::Challenges;
pub use constraint::{ConstraintLookupBuilder, eval_lookup};
pub use contracts::{LookupAir, LookupBuilder, LookupFrame};
#[cfg(feature = "std")]
pub use debug::validation::{NativeValidationBuilder, validate_native};
pub use message::LookupMessage;
pub use prover::{LookupError, ProverLookupBuilder, build_logup_aux_trace, build_lookup_fractions};
