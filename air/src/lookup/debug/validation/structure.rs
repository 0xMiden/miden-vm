//! Structure-only AIR self-check ([`validate_structure_only`]).
//!
//! Runs an inventory walk on a random row pair and packages the results plus a
//! `num_columns` consistency check into a [`StructureReport`]. The composed
//! [`super::validate()`] layers a symbolic degree-budget pass on top.

use alloc::{string::String, vec::Vec};
use core::fmt;

use miden_core::field::QuadFelt;

use super::{
    super::super::{Challenges, LookupAir},
    DebugStructureBuilder, GroupMismatch, inspect_structure,
};
use crate::Felt;

/// Outcome of the `num_columns` consistency check.
#[derive(Clone, Debug)]
pub enum NumColumnsCheck {
    Matches(usize),
    Mismatch { declared: usize, observed: usize },
}

/// Bundled outcome of [`validate_structure_only`]. Covers every check that runs against
/// the `LookupAir` itself — no degree-budget pass (that's
/// [`check_symbolic_degrees`](super::check_symbolic_degrees), which [`super::validate()`]
/// layers on top).
#[derive(Debug)]
pub struct StructureReport {
    pub air_name: &'static str,
    pub num_columns: NumColumnsCheck,
    /// Empty on success. One entry per cached-encoding group whose canonical and encoded
    /// closures produced different `(U_g, V_g)` pairs on the sampled row.
    pub encoding_mismatches: Vec<GroupMismatch>,
    /// Empty on success. One string per simple-mode group that illegally called
    /// `insert_encoded`.
    pub scope_violations: Vec<String>,
}

impl StructureReport {
    /// `true` iff every structural check passed.
    pub fn is_ok(&self) -> bool {
        matches!(self.num_columns, NumColumnsCheck::Matches(_))
            && self.encoding_mismatches.is_empty()
            && self.scope_violations.is_empty()
    }
}

impl fmt::Display for StructureReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "StructureReport for {}", self.air_name)?;
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
        Ok(())
    }
}

/// Run the structure-only AIR self-checks (no symbolic degree pass) and return a
/// [`StructureReport`].
///
/// Bundles:
/// 1. Canonical-vs-encoded fold equivalence (via an inventory walk on a random row pair).
/// 2. Scope violations (simple groups that touched `insert_encoded`).
/// 3. `num_columns` consistency (declared vs observed).
///
/// [`super::validate()`] layers a symbolic degree-budget pass on top.
pub fn validate_structure_only<A>(
    air: &A,
    air_name: &'static str,
    trace_width: usize,
    num_periodic: usize,
    num_public_values: usize,
) -> StructureReport
where
    for<'a> A: LookupAir<DebugStructureBuilder<'a>>,
{
    use miden_crypto::rand::random_felt;

    let current: Vec<Felt> = (0..trace_width).map(|_| random_felt()).collect();
    let next: Vec<Felt> = (0..trace_width).map(|_| random_felt()).collect();
    let periodic: Vec<Felt> = (0..num_periodic).map(|_| random_felt()).collect();
    let publics: Vec<Felt> = (0..num_public_values).map(|_| random_felt()).collect();
    let alpha = QuadFelt::new([random_felt(), random_felt()]);
    let beta = QuadFelt::new([random_felt(), random_felt()]);
    let challenges = Challenges::<QuadFelt>::new(
        alpha,
        beta,
        <A as LookupAir<DebugStructureBuilder<'_>>>::max_message_width(air),
        <A as LookupAir<DebugStructureBuilder<'_>>>::num_bus_ids(air),
    );

    let inventory =
        inspect_structure(air, air_name, &current, &next, &periodic, &publics, &challenges);

    let encoding_mismatches: Vec<GroupMismatch> = inventory
        .equivalence_mismatches()
        .map(|g| {
            let can = g.canonical.fold.expect("CachedEncoding group must carry a canonical fold");
            let enc = g.encoded.fold.expect("CachedEncoding group must carry an encoded fold");
            GroupMismatch {
                column_idx: g.column_idx,
                group_idx: g.group_idx,
                u_canonical: can.0,
                v_canonical: can.1,
                u_encoded: enc.0,
                v_encoded: enc.1,
            }
        })
        .collect();

    let scope_violations = inventory.scope_violations();

    let declared_columns = air.num_columns();
    let observed_columns = inventory.columns.len();
    let num_columns = if declared_columns == observed_columns {
        NumColumnsCheck::Matches(declared_columns)
    } else {
        NumColumnsCheck::Mismatch {
            declared: declared_columns,
            observed: observed_columns,
        }
    };

    StructureReport {
        air_name,
        num_columns,
        encoding_mismatches,
        scope_violations,
    }
}
