//! AIR self-validation surface.
//!
//! The `validation` module holds every check that operates on the `LookupAir` itself —
//! as opposed to the sibling [`super::trace`] module, which debugs a concrete
//! execution trace.
//!
//! The top-level entry point is [`validate`], a single free function that bundles:
//! 1. Canonical-vs-encoded fold equivalence (from a random-row inventory walk).
//! 2. Scope violations (simple groups that touch encoding primitives).
//! 3. Symbolic degree budget (via [`symbolic::check_symbolic_degrees`]).
//! 4. Constants consistency — currently [`LookupAir::num_columns`] matches the observed number of
//!    `next_column` calls. Further checks (`column_shape`, `max_message_width`, `num_bus_ids`) are
//!    planned follow-ups.
//!
//! Layout:
//!
//! - [`builder`] — [`DebugStructureBuilder`] (+ column / group / batch) that drives the inventory
//!   walk.
//! - This file — records ([`DebugStructure`], [`GroupRecord`], …), and the check wrappers
//!   ([`inspect_structure`], [`collect_inventory`], [`check_encoding_equivalence`],
//!   [`check_challenge_scoping`]).
//!
//! The Miden-side degree-budget pass (`check_symbolic_degrees` /
//! [`DEGREE_BUDGET`](crate::constraints::lookup::debug::validation::DEGREE_BUDGET)) lives at
//! `air/src/constraints/lookup/debug/validation/symbolic.rs`.

use alloc::{format, string::String, vec, vec::Vec};
use core::fmt;

use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
use miden_crypto::stark::air::RowWindow;

use super::super::{Challenges, Deg, LookupAir};
use crate::Felt;

pub mod builder;

pub use builder::{
    DebugStructureBatch, DebugStructureBuilder, DebugStructureColumn, DebugStructureGroup,
};

// RECORDS
// ================================================================================================

/// Sign / shape of an interaction's multiplicity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultSign {
    /// `add(...)` — multiplicity = +1.
    Add,
    /// `remove(...)` — multiplicity = -1.
    Remove,
    /// `insert(...)` — signed multiplicity from a caller-provided expression.
    Insert,
    /// `insert_encoded(...)` — signed multiplicity against a pre-encoded denominator.
    InsertEncoded,
}

/// How a group was opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodingMode {
    /// Opened via `LookupColumn::group` — challenge-free simple path.
    Simple,
    /// Opened via `LookupColumn::group_with_cached_encoding` — dual-closure path.
    CachedEncoding,
}

/// One interaction record — a single `add` / `remove` / `insert` / `insert_encoded` emit.
#[derive(Clone, Debug)]
pub struct InteractionRecord {
    pub name: &'static str,
    /// `core::any::type_name::<M>()` captured on the message type at the emit site.
    /// `None` for `insert_encoded` (no `LookupMessage` instance exists).
    pub kind: Option<&'static str>,
    pub sign: MultSign,
    pub claimed_degree: Deg,
    pub inside_batch: bool,
}

/// Per-pass interactions + `(U_g, V_g)` fold. A `Simple` group populates only
/// `canonical`; a `CachedEncoding` group populates both.
#[derive(Clone, Debug, Default)]
pub struct PassRecord {
    pub interactions: Vec<InteractionRecord>,
    pub fold: Option<(QuadFelt, QuadFelt)>,
}

/// One group record. The two sub-records are split so the column can reborrow disjoint
/// fields sequentially (`rec.canonical` in the canonical pass, `rec.encoded` in the
/// encoded pass) without tripping the GAT's `'g`-pinned mutable borrow.
#[derive(Clone, Debug)]
pub struct GroupRecord {
    pub name: &'static str,
    pub column_idx: usize,
    pub group_idx: usize,
    pub encoding_mode: EncodingMode,
    pub claimed_degree: Deg,
    /// Interactions + fold from `LookupColumn::group` or the canonical closure of
    /// `LookupColumn::group_with_cached_encoding`.
    pub canonical: PassRecord,
    /// Interactions + fold from the encoded closure of
    /// `LookupColumn::group_with_cached_encoding`. Empty for `Simple` groups.
    pub encoded: PassRecord,
}

/// One column record.
#[derive(Clone, Debug)]
pub struct ColumnRecord {
    pub column_idx: usize,
    pub claimed_column_degree: Deg,
    pub groups: Vec<GroupRecord>,
}

/// Full structural snapshot for one [`LookupAir`].
#[derive(Clone, Debug)]
pub struct DebugStructure {
    pub air_name: &'static str,
    pub columns: Vec<ColumnRecord>,
}

/// Backwards-compatible alias so staged callers that name `Inventory` keep compiling.
pub type Inventory = DebugStructure;

/// Canonical-vs-encoded mismatch projection exposed by [`check_encoding_equivalence`].
#[derive(Clone, Debug)]
pub struct GroupMismatch {
    pub column_idx: usize,
    pub group_idx: usize,
    pub u_canonical: QuadFelt,
    pub v_canonical: QuadFelt,
    pub u_encoded: QuadFelt,
    pub v_encoded: QuadFelt,
}

/// Scope-check projection returned by [`check_challenge_scoping`].
#[derive(Debug, Default)]
pub struct ScopeReport {
    pub violations: Vec<String>,
}

// VIEWS
// ================================================================================================

impl DebugStructure {
    /// Total number of interactions across every column, group, and pass.
    pub fn total_interactions(&self) -> usize {
        self.columns
            .iter()
            .flat_map(|c| c.groups.iter())
            .map(|g| g.canonical.interactions.len() + g.encoded.interactions.len())
            .sum()
    }

    /// Simple-mode groups that contain an `InsertEncoded` interaction in their canonical
    /// pass — a contract violation, since encoding primitives are only legal inside the
    /// `encoded` closure of `group_with_cached_encoding`.
    pub fn scope_violations(&self) -> Vec<String> {
        self.columns
            .iter()
            .flat_map(|c| c.groups.iter())
            .filter(|g| {
                g.encoding_mode == EncodingMode::Simple
                    && g.canonical.interactions.iter().any(|ix| ix.sign == MultSign::InsertEncoded)
            })
            .map(|g| {
                format!("simple group {:?} in column {} used insert_encoded", g.name, g.column_idx,)
            })
            .collect()
    }

    /// Cached-encoding groups whose canonical and encoded folds disagree.
    pub fn equivalence_mismatches(&self) -> impl Iterator<Item = &GroupRecord> {
        self.columns.iter().flat_map(|c| c.groups.iter()).filter(|g| {
            g.encoding_mode == EncodingMode::CachedEncoding && g.canonical.fold != g.encoded.fold
        })
    }
}

impl fmt::Display for DebugStructure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "DebugStructure for {} ({} columns)", self.air_name, self.columns.len())?;
        for col in &self.columns {
            writeln!(
                f,
                "  column[{}] claimed=(n={}, d={})",
                col.column_idx, col.claimed_column_degree.n, col.claimed_column_degree.d,
            )?;
            for g in &col.groups {
                writeln!(
                    f,
                    "    group[{}] {:?} name={:?} claimed=(n={}, d={})",
                    g.group_idx, g.encoding_mode, g.name, g.claimed_degree.n, g.claimed_degree.d,
                )?;
                if let (Some(can), Some(enc)) = (g.canonical.fold, g.encoded.fold) {
                    writeln!(
                        f,
                        "      canonical_fold=({:?}, {:?}) encoded_fold=({:?}, {:?})",
                        can.0, can.1, enc.0, enc.1,
                    )?;
                } else if let Some(can) = g.canonical.fold {
                    writeln!(f, "      canonical_fold=({:?}, {:?})", can.0, can.1)?;
                }
                write_pass(f, "canonical", &g.canonical.interactions)?;
                if !g.encoded.interactions.is_empty() || g.encoded.fold.is_some() {
                    write_pass(f, "encoded", &g.encoded.interactions)?;
                }
            }
        }
        Ok(())
    }
}

fn write_pass(
    f: &mut fmt::Formatter<'_>,
    label: &str,
    interactions: &[InteractionRecord],
) -> fmt::Result {
    if interactions.is_empty() {
        return Ok(());
    }
    writeln!(f, "      [{}]", label)?;
    for ix in interactions {
        writeln!(
            f,
            "        {:?} {:?} kind={:?} claimed=(n={}, d={}) inside_batch={}",
            ix.sign, ix.name, ix.kind, ix.claimed_degree.n, ix.claimed_degree.d, ix.inside_batch,
        )?;
    }
    Ok(())
}

// ENTRY POINTS
// ================================================================================================

/// Walk `air` on one row pair and return a full [`DebugStructure`].
///
/// `current_row` / `next_row` feed the per-group fold algebra; zero rows are fine for
/// pure-inventory or scope walks (the fold comparison passes trivially), random rows
/// exercise encoding equivalence.
pub fn inspect_structure<A>(
    air: &A,
    air_name: &'static str,
    current_row: &[Felt],
    next_row: &[Felt],
    periodic_values: &[Felt],
    public_values: &[Felt],
    challenges: &Challenges<QuadFelt>,
) -> DebugStructure
where
    for<'a> A: LookupAir<DebugStructureBuilder<'a>>,
{
    let main = RowWindow::from_two_rows(current_row, next_row);
    let mut out = DebugStructure { air_name, columns: Vec::new() };
    {
        let mut ib =
            DebugStructureBuilder::new(main, periodic_values, public_values, challenges, &mut out);
        air.eval(&mut ib);
    }
    out
}

/// Walk `air` with zero rows and return the populated inventory.
pub fn collect_inventory<A>(
    air: &A,
    air_name: &'static str,
    trace_width: usize,
    num_periodic: usize,
    num_public_values: usize,
) -> Inventory
where
    for<'a> A: LookupAir<DebugStructureBuilder<'a>>,
{
    let current = vec![Felt::ZERO; trace_width];
    let next = vec![Felt::ZERO; trace_width];
    let periodic = vec![Felt::ZERO; num_periodic];
    let publics = vec![Felt::ZERO; num_public_values];
    let challenges = Challenges::<QuadFelt>::new(
        QuadFelt::ONE,
        QuadFelt::ONE,
        air.max_message_width(),
        air.num_bus_ids(),
    );
    inspect_structure(air, air_name, &current, &next, &periodic, &publics, &challenges)
}

/// Run canonical-vs-encoded fold comparison on the given row pair and return any
/// mismatches.
pub fn check_encoding_equivalence<A>(
    air: &A,
    current_row: &[Felt],
    next_row: &[Felt],
    periodic_values: &[Felt],
    public_values: &[Felt],
    challenges: &Challenges<QuadFelt>,
) -> Vec<GroupMismatch>
where
    for<'a> A: LookupAir<DebugStructureBuilder<'a>>,
{
    let structure = inspect_structure(
        air,
        "",
        current_row,
        next_row,
        periodic_values,
        public_values,
        challenges,
    );
    structure
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
        .collect()
}

/// Walk `air` with zero rows and flag any simple group that touched the encoding
/// primitives.
pub fn check_challenge_scoping<A>(
    air: &A,
    air_name: &'static str,
    trace_width: usize,
    num_periodic: usize,
    num_public_values: usize,
) -> Result<(), ScopeReport>
where
    for<'a> A: LookupAir<DebugStructureBuilder<'a>>,
{
    let structure = collect_inventory(air, air_name, trace_width, num_periodic, num_public_values);
    let violations = structure.scope_violations();
    if violations.is_empty() {
        Ok(())
    } else {
        Err(ScopeReport { violations })
    }
}

// STRUCTURE REPORT
// ================================================================================================

/// Outcome of the `num_columns` consistency check.
#[derive(Clone, Debug)]
pub enum NumColumnsCheck {
    Matches(usize),
    Mismatch { declared: usize, observed: usize },
}

/// Bundled outcome of [`validate_structure_only`]. Covers every check that runs against
/// the `LookupAir` itself — no degree-budget pass (that's
/// [`check_symbolic_degrees`](crate::constraints::lookup::debug::validation::check_symbolic_degrees),
/// layered on top by the Miden-side
/// [`validate`](crate::constraints::lookup::debug::validation::validate) wrapper).
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
/// The Miden-side
/// [`validate`](crate::constraints::lookup::debug::validation::validate) wrapper layers
/// a symbolic degree-budget pass on top.
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
