//! Miden-side AIR self-validation wrapper.
//!
//! Layers the Miden-specific symbolic degree-budget pass
//! ([`check_symbolic_degrees`]) on top of the generic
//! [`validate_structure_only`](crate::lookup::debug::validation::validate_structure_only)
//! entry point in [`crate::lookup::debug::validation`].
//!
//! See [`crate::lookup::debug::validation`] for the generic record types
//! ([`StructureReport`], [`GroupMismatch`], [`ScopeReport`], …) and structure checks.

use alloc::{string::String, vec::Vec};
use core::fmt;

pub mod symbolic;

pub use symbolic::{DEGREE_BUDGET, DegreeMismatch, DegreeReport, check_symbolic_degrees};

use crate::lookup::{
    LookupAir,
    debug::validation::{
        DebugStructureBuilder, GroupMismatch, NumColumnsCheck, StructureReport,
        validate_structure_only,
    },
};

// VALIDATION REPORT
// ================================================================================================

/// Bundled outcome of [`validate`].
///
/// Composes a [`StructureReport`] (from the generic structural checks) with the Miden-side
/// symbolic degree-budget pass.
#[derive(Debug)]
pub struct ValidationReport {
    pub air_name: &'static str,
    pub num_columns: NumColumnsCheck,
    /// Empty on success. One entry per cached-encoding group whose canonical and encoded
    /// closures produced different `(U_g, V_g)` pairs on the sampled row.
    pub encoding_mismatches: Vec<GroupMismatch>,
    /// Empty on success. One string per simple-mode group that illegally called
    /// `insert_encoded`.
    pub scope_violations: Vec<String>,
    /// Empty on success. One entry per constraint that exceeded [`DEGREE_BUDGET`].
    pub degree_mismatches: Vec<DegreeMismatch>,
}

impl ValidationReport {
    /// `true` iff every check passed.
    pub fn is_ok(&self) -> bool {
        matches!(self.num_columns, NumColumnsCheck::Matches(_))
            && self.encoding_mismatches.is_empty()
            && self.scope_violations.is_empty()
            && self.degree_mismatches.is_empty()
    }
}

impl fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ValidationReport for {}", self.air_name)?;
        match &self.num_columns {
            NumColumnsCheck::Matches(n) => writeln!(f, "  num_columns: OK ({n})")?,
            NumColumnsCheck::Mismatch { declared, observed } => {
                writeln!(f, "  num_columns: MISMATCH declared={declared} observed={observed}",)?
            },
        }
        if self.encoding_mismatches.is_empty() {
            writeln!(f, "  encoding_equivalence: OK")?;
        } else {
            writeln!(f, "  encoding_equivalence: {} mismatches", self.encoding_mismatches.len())?;
            for m in &self.encoding_mismatches {
                writeln!(
                    f,
                    "    column[{}] group[{}]: canonical=({:?}, {:?}) encoded=({:?}, {:?})",
                    m.column_idx,
                    m.group_idx,
                    m.u_canonical,
                    m.v_canonical,
                    m.u_encoded,
                    m.v_encoded,
                )?;
            }
        }
        if self.scope_violations.is_empty() {
            writeln!(f, "  scope: OK")?;
        } else {
            writeln!(f, "  scope: {} violations", self.scope_violations.len())?;
            for v in &self.scope_violations {
                writeln!(f, "    {v}")?;
            }
        }
        if self.degree_mismatches.is_empty() {
            writeln!(f, "  degree_budget: OK")?;
        } else {
            writeln!(f, "  degree_budget: {} over budget", self.degree_mismatches.len())?;
            for d in &self.degree_mismatches {
                writeln!(f, "    {} constraint[{}] degree={}", d.kind, d.index, d.degree)?;
            }
        }
        Ok(())
    }
}

/// Run every AIR self-check and return a single [`ValidationReport`].
///
/// Bundles:
/// 1. Canonical-vs-encoded fold equivalence (via an inventory walk on a random row pair).
/// 2. Scope violations (simple groups that touched `insert_encoded`).
/// 3. Symbolic degree-budget pass over the production `ConstraintLookupBuilder`.
/// 4. `num_columns` consistency (declared vs observed).
pub fn validate<A>(
    air: &A,
    air_name: &'static str,
    trace_width: usize,
    num_periodic: usize,
    num_public_values: usize,
) -> ValidationReport
where
    for<'a> A: LookupAir<DebugStructureBuilder<'a>>,
    for<'ab> A: LookupAir<
        crate::lookup::ConstraintLookupBuilder<
            'ab,
            miden_crypto::stark::air::symbolic::SymbolicAirBuilder<
                crate::Felt,
                miden_core::field::QuadFelt,
            >,
        >,
    >,
{
    let StructureReport {
        air_name,
        num_columns,
        encoding_mismatches,
        scope_violations,
    } = validate_structure_only(air, air_name, trace_width, num_periodic, num_public_values);

    let degree_mismatches = match check_symbolic_degrees(air) {
        Ok(_) => Vec::new(),
        Err(report) => report.mismatches,
    };

    ValidationReport {
        air_name,
        num_columns,
        encoding_mismatches,
        scope_violations,
        degree_mismatches,
    }
}
