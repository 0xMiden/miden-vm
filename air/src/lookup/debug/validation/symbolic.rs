//! Symbolic degree-budget pass.
//!
//! Runs the production `ConstraintLookupBuilder` through a [`SymbolicAirBuilder`] sized
//! from a caller-supplied [`AirLayout`] and checks every emitted extension / base
//! constraint against a caller-supplied degree budget. The pass is a structural invariant
//! of the AIR, not a runtime trace check, so it lives in the [`super`] validation module
//! alongside the other `LookupAir` self-checks.

use alloc::{format, string::String, vec::Vec};

use miden_core::field::QuadFelt;
use miden_crypto::stark::air::symbolic::{AirLayout, SymbolicAirBuilder};

use crate::{
    Felt,
    lookup::{ConstraintLookupBuilder, LookupAir, RunningSumLookupAir},
};

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

/// Run `air` through a fresh [`SymbolicAirBuilder`] sized by `layout` and assert every
/// resulting constraint degree is `<= degree_budget`.
pub fn check_symbolic_degrees<A>(
    air: &A,
    layout: AirLayout,
    degree_budget: usize,
) -> Result<DegreeReport, DegreeReport>
where
    for<'ab> A: LookupAir<ConstraintLookupBuilder<'ab, SymbolicAirBuilder<Felt, QuadFelt>>>
        + RunningSumLookupAir,
{
    let mut builder = SymbolicAirBuilder::<Felt, QuadFelt>::new(layout);

    {
        let mut lb = ConstraintLookupBuilder::new(&mut builder, air);
        air.eval(&mut lb);
        lb.finalize();
    }

    let mut report = DegreeReport::default();
    let ext = builder.extension_constraints();
    report.info.push(format!("extension constraints: {}", ext.len()));
    for (i, c) in ext.iter().enumerate() {
        let deg = c.degree_multiple();
        if deg > degree_budget {
            report
                .mismatches
                .push(DegreeMismatch { kind: "extension", index: i, degree: deg });
        }
    }
    let base = builder.base_constraints();
    report.info.push(format!("base constraints: {}", base.len()));
    for (i, c) in base.iter().enumerate() {
        let deg = c.degree_multiple();
        if deg > degree_budget {
            report.mismatches.push(DegreeMismatch { kind: "base", index: i, degree: deg });
        }
    }

    if report.mismatches.is_empty() {
        Ok(report)
    } else {
        Err(report)
    }
}
