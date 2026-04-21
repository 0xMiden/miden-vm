//! Single AIR self-validation entry point.
//!
//! Exposes one free function, [`validate`], and one extension trait,
//! [`ValidateLookupAir`], so any qualifying [`LookupAir`](super::super::LookupAir)
//! can be checked with `air.validate(layout)`. Collapses what was previously a
//! six-file surface (per-pass inventory walk, structure report, symbolic degree
//! budget, …) into one short-circuit [`Result<(), ValidationError>`] that covers:
//!
//! - `num_columns` declared vs observed (symbolic walker counts `next_column` calls).
//! - Per-group and per-column `Deg { n, d }` declared vs observed (symbolic walker measures
//!   `SymbolicExpression::degree_multiple` on the running `(U, V)`).
//! - Cached-encoding canonical vs encoded `(U, V)` equivalence on a random row pair.
//! - Simple-group scope: no illegal `insert_encoded` outside the `encoded` closure.
//!
//! The global max-degree budget is **not** checked here — the STARK prover's quotient
//! validation already enforces it and duplicating that check muddies this module's
//! purpose.

use alloc::vec::Vec;
use core::fmt;

use miden_core::field::QuadFelt;
use miden_crypto::{
    rand::random_felt,
    stark::air::{RowWindow, symbolic::SymbolicAirBuilder},
};

use super::super::{Challenges, Deg, LookupAir};
use crate::Felt;

pub mod builder;
pub mod degree;

pub use builder::EncodingCheckBuilder;
pub use degree::DegreeCheckBuilder;

// VALIDATION ERROR
// ================================================================================================

/// First problem [`validate`] observed. See the module docstring for the per-check
/// semantics; each variant corresponds to one of the four checks.
#[derive(Clone, Debug)]
pub enum ValidationError {
    /// [`LookupAir::num_columns`] disagreed with the number of `next_column` calls
    /// issued by `eval`.
    NumColumnsMismatch { declared: usize, observed: usize },
    /// A column's declared `Deg` was tighter than the observed symbolic degree of
    /// its accumulated `(U, V)`.
    ColumnDegreeMismatch {
        column_idx: usize,
        declared: Deg,
        observed: Deg,
    },
    /// A group's declared `Deg` was tighter than the observed symbolic degree of
    /// the group's `(U, V)` fold.
    GroupDegreeMismatch {
        column_idx: usize,
        group_idx: usize,
        name: &'static str,
        declared: Deg,
        observed: Deg,
    },
    /// A cached-encoding group's canonical and encoded closures produced different
    /// `(U, V)` pairs on the sampled row.
    EncodingMismatch {
        column_idx: usize,
        group_idx: usize,
        name: &'static str,
        u_canonical: QuadFelt,
        v_canonical: QuadFelt,
        u_encoded: QuadFelt,
        v_encoded: QuadFelt,
    },
    /// A simple-mode group called `insert_encoded`, which is only legal inside the
    /// `encoded` closure of `group_with_cached_encoding`.
    ScopeViolation {
        column_idx: usize,
        group_idx: usize,
        name: &'static str,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NumColumnsMismatch { declared, observed } => {
                write!(f, "num_columns mismatch: declared {declared}, observed {observed}",)
            },
            Self::ColumnDegreeMismatch { column_idx, declared, observed } => write!(
                f,
                "column[{column_idx}] degree mismatch: declared (n={}, d={}), observed (n={}, d={})",
                declared.n, declared.d, observed.n, observed.d,
            ),
            Self::GroupDegreeMismatch {
                column_idx,
                group_idx,
                name,
                declared,
                observed,
            } => write!(
                f,
                "column[{column_idx}] group[{group_idx}] {name:?} degree mismatch: declared (n={}, d={}), observed (n={}, d={})",
                declared.n, declared.d, observed.n, observed.d,
            ),
            Self::EncodingMismatch {
                column_idx,
                group_idx,
                name,
                u_canonical,
                v_canonical,
                u_encoded,
                v_encoded,
            } => write!(
                f,
                "column[{column_idx}] group[{group_idx}] {name:?} cached-encoding mismatch: canonical=({u_canonical:?}, {v_canonical:?}) encoded=({u_encoded:?}, {v_encoded:?})",
            ),
            Self::ScopeViolation { column_idx, group_idx, name } => write!(
                f,
                "column[{column_idx}] group[{group_idx}] {name:?} simple group called insert_encoded",
            ),
        }
    }
}

// LAYOUT
// ================================================================================================

/// Subset of the full `AirLayout` struct that [`validate`] actually consumes. Kept
/// local so callers don't need to thread prover-only fields (permutation width,
/// committed final count) through just to run the self-check.
#[derive(Clone, Copy, Debug)]
pub struct ValidateLayout {
    pub trace_width: usize,
    pub num_public_values: usize,
    pub num_periodic_columns: usize,
    pub permutation_width: usize,
    pub num_permutation_challenges: usize,
    pub num_permutation_values: usize,
}

impl ValidateLayout {
    fn to_symbolic(self) -> miden_crypto::stark::air::symbolic::AirLayout {
        miden_crypto::stark::air::symbolic::AirLayout {
            preprocessed_width: 0,
            main_width: self.trace_width,
            num_public_values: self.num_public_values,
            permutation_width: self.permutation_width,
            num_permutation_challenges: self.num_permutation_challenges,
            num_permutation_values: self.num_permutation_values,
            num_periodic_columns: self.num_periodic_columns,
        }
    }
}

// VALIDATE
// ================================================================================================

/// Run every AIR self-check in one pass.
///
/// Short-circuits on the first problem. See [`ValidationError`] for the variants.
pub fn validate<A>(air: &A, layout: ValidateLayout) -> Result<(), ValidationError>
where
    for<'a> A: LookupAir<EncodingCheckBuilder<'a>>,
    for<'ab> A: LookupAir<DegreeCheckBuilder<'ab>>,
{
    // Walk 1: symbolic. Catches num_columns mismatch + any tighter-than-observed
    // Deg annotation. Cheap and deterministic.
    {
        let mut sym = SymbolicAirBuilder::<Felt, QuadFelt>::new(layout.to_symbolic());
        let builder = DegreeCheckBuilder::new(&mut sym, air);
        let error = {
            let mut builder = builder;
            air.eval(&mut builder);
            builder.take_error()
        };
        if let Some(err) = error {
            return Err(err);
        }
    }

    // Walk 2: concrete single random row pair. Catches cached-encoding divergence
    // and simple-group scope violations.
    {
        let current: Vec<Felt> = (0..layout.trace_width).map(|_| random_felt()).collect();
        let next: Vec<Felt> = (0..layout.trace_width).map(|_| random_felt()).collect();
        let periodic: Vec<Felt> = (0..layout.num_periodic_columns).map(|_| random_felt()).collect();
        let alpha = QuadFelt::new([random_felt(), random_felt()]);
        let beta = QuadFelt::new([random_felt(), random_felt()]);
        let challenges = Challenges::<QuadFelt>::new(
            alpha,
            beta,
            <A as LookupAir<EncodingCheckBuilder<'_>>>::max_message_width(air),
            <A as LookupAir<EncodingCheckBuilder<'_>>>::num_bus_ids(air),
        );

        let main = RowWindow::from_two_rows(&current, &next);
        let mut builder = EncodingCheckBuilder::new(main, &periodic, &challenges);
        air.eval(&mut builder);
        if let Some(err) = builder.take_error() {
            return Err(err);
        }
    }

    Ok(())
}

// EXTENSION TRAIT
// ================================================================================================

/// Extension trait that adapts [`validate`] into a method on any qualifying
/// [`LookupAir`](super::super::LookupAir). Call sites write
/// `MyLookupAir.validate(layout)` instead of `validate(&MyLookupAir, layout)`.
pub trait ValidateLookupAir {
    fn validate(&self, layout: ValidateLayout) -> Result<(), ValidationError>;
}

impl<A> ValidateLookupAir for A
where
    for<'a> A: LookupAir<EncodingCheckBuilder<'a>>,
    for<'ab> A: LookupAir<DegreeCheckBuilder<'ab>>,
{
    fn validate(&self, layout: ValidateLayout) -> Result<(), ValidationError> {
        validate(self, layout)
    }
}
