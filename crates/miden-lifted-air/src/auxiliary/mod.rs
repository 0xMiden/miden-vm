//! Auxiliary trace types: builder and cross-AIR identity checking.
//!
//! # Protocol Overview
//!
//! The auxiliary trace enables cross-AIR buses (multiset / logup) in the lifted STARK.
//!
//! ## Prover
//!
//! 1. [`AuxBuilder::build_aux_trace`] constructs the aux trace and returns aux values
//!    (extension-field elements whose meaning is AIR-defined).
//! 2. The aux trace is committed (Merkle commitment).
//! 3. Aux values are sent via the Fiat-Shamir transcript.
//!
//! ## AIR constraints ([`eval`](crate::LiftedAir::eval))
//!
//! 4. The AIR defines how aux values relate to the committed aux trace. A common pattern is to
//!    constrain them to equal the aux trace's last row, but the protocol does not impose this — the
//!    AIR is free to define whatever relationship it needs.
//! 5. Transition constraints enforce the aux trace's internal logic (e.g. running product
//!    accumulation).
//!
//! ## Verifier
//!
//! 6. The verifier receives aux values from the transcript.
//! 7. Constraint evaluation (steps 4–5) is checked at a random point.
//! 8. [`reduced_aux_values`](crate::LiftedAir::reduced_aux_values) computes each AIR's bus
//!    contribution from the aux values, challenges, and public inputs.
//! 9. Global check: all contributions combine to identity (prod=1, sum=0).

mod builder;
mod values;

pub use builder::AuxBuilder;
pub use values::ReducedAuxValues;

/// Variable-length public inputs for an AIR instance.
///
/// A list of *reducible inputs*: each `&[F]` is a slice of base-field elements
/// that [`LiftedAir::reduced_aux_values`](crate::LiftedAir::reduced_aux_values)
/// reduces to a single extension-field value. The AIR defines how to group and
/// interpret them (e.g. which inputs belong to which bus).
///
/// The number of slices must equal
/// [`LiftedAir::num_var_len_public_inputs`](crate::LiftedAir::num_var_len_public_inputs).
///
/// **Commitment:** callers **must** bind these inputs to the Fiat-Shamir
/// challenger state, just like [`public_values`](crate::AirInstance::public_values).
pub type VarLenPublicInputs<'a, F> = &'a [&'a [F]];

/// Boxed error returned by
/// [`LiftedAir::reduced_aux_values`](crate::LiftedAir::reduced_aux_values).
///
/// Each AIR defines its own concrete error type and boxes it into this alias.
pub type ReductionError = alloc::boxed::Box<dyn core::error::Error + Send + Sync>;
