//! Symbolic degree-budget pass.
//!
//! Thin free function that runs the production [`ConstraintLookupBuilder`] through a
//! [`SymbolicAirBuilder`] and asserts every emitted extension/base constraint stays within
//! [`DEGREE_BUDGET`]. Lives inside the [`super`] validation module because the degree
//! check is a structural invariant of the AIR — not a runtime trace check. The sibling
//! [`super::builder`] module (the `ValidationBuilder`) covers every other structural
//! invariant (inventory, canonical-vs-encoded equivalence, scope).

use alloc::{format, string::String, vec::Vec};

use miden_core::field::QuadFelt;
use miden_crypto::stark::air::{
    LiftedAir,
    symbolic::{AirLayout, SymbolicAirBuilder},
};

use super::super::super::{ConstraintLookupBuilder, LookupAir};
use crate::{
    Felt, NUM_PUBLIC_VALUES, ProcessorAir,
    trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, TRACE_WIDTH},
};

/// Maximum allowed constraint degree (transition degree budget).
pub const DEGREE_BUDGET: usize = 9;

/// Per-constraint degree mismatch record.
#[derive(Debug, Clone)]
pub struct DegreeMismatch {
    pub kind: &'static str, // "extension" or "base"
    pub index: usize,
    pub degree: usize,
}

/// Report returned by [`check_symbolic_degrees`].
#[derive(Debug, Default)]
pub struct DegreeReport {
    pub mismatches: Vec<DegreeMismatch>,
    pub info: Vec<String>,
}

/// Run `air` through a fresh [`SymbolicAirBuilder`] sized for [`ProcessorAir`] and assert
/// every resulting constraint degree is within [`DEGREE_BUDGET`].
pub fn check_symbolic_degrees<A>(air: &A) -> Result<DegreeReport, DegreeReport>
where
    for<'ab> A: LookupAir<ConstraintLookupBuilder<'ab, SymbolicAirBuilder<Felt, QuadFelt>>>,
{
    let num_periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir).len();
    let mut builder = SymbolicAirBuilder::<Felt, QuadFelt>::new(AirLayout {
        preprocessed_width: 0,
        main_width: TRACE_WIDTH,
        num_public_values: NUM_PUBLIC_VALUES,
        permutation_width: AUX_TRACE_WIDTH,
        num_permutation_challenges: AUX_TRACE_RAND_CHALLENGES,
        num_permutation_values: AUX_TRACE_WIDTH,
        num_periodic_columns: num_periodic,
    });

    {
        let mut lb = ConstraintLookupBuilder::new(&mut builder, air);
        air.eval(&mut lb);
    }

    let mut report = DegreeReport::default();
    let ext = builder.extension_constraints();
    report.info.push(format!("extension constraints: {}", ext.len()));
    for (i, c) in ext.iter().enumerate() {
        let deg = c.degree_multiple();
        if deg > DEGREE_BUDGET {
            report
                .mismatches
                .push(DegreeMismatch { kind: "extension", index: i, degree: deg });
        }
    }
    let base = builder.base_constraints();
    report.info.push(format!("base constraints: {}", base.len()));
    for (i, c) in base.iter().enumerate() {
        let deg = c.degree_multiple();
        if deg > DEGREE_BUDGET {
            report.mismatches.push(DegreeMismatch { kind: "base", index: i, degree: deg });
        }
    }

    if report.mismatches.is_empty() {
        Ok(report)
    } else {
        Err(report)
    }
}
