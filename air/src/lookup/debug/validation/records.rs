//! Inventory records produced by the AIR walk.
//!
//! [`DebugStructureBuilder`](super::DebugStructureBuilder) populates a [`DebugStructure`]
//! — the structural snapshot of one `LookupAir::eval` — whose leaves are
//! [`InteractionRecord`]s grouped under [`GroupRecord`]/[`ColumnRecord`]. The `Display`
//! impl here is what the `-p miden-air -- --nocapture` inventory tests print.
//!
//! The per-check projections ([`GroupMismatch`], [`ScopeReport`]) live here too since they
//! are projections out of `DebugStructure`.

use alloc::{format, string::String, vec::Vec};
use core::fmt;

use miden_core::field::QuadFelt;

use super::super::super::Deg;

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

/// Full structural snapshot for one [`LookupAir`](super::super::super::LookupAir).
#[derive(Clone, Debug)]
pub struct DebugStructure {
    pub air_name: &'static str,
    pub columns: Vec<ColumnRecord>,
}

/// Backwards-compatible alias so staged callers that name `Inventory` keep compiling.
pub type Inventory = DebugStructure;

/// Canonical-vs-encoded mismatch projection exposed by
/// [`check_encoding_equivalence`](super::check_encoding_equivalence).
#[derive(Clone, Debug)]
pub struct GroupMismatch {
    pub column_idx: usize,
    pub group_idx: usize,
    pub u_canonical: QuadFelt,
    pub v_canonical: QuadFelt,
    pub u_encoded: QuadFelt,
    pub v_encoded: QuadFelt,
}

/// Scope-check projection returned by
/// [`check_challenge_scoping`](super::check_challenge_scoping).
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
    writeln!(f, "      [{label}]")?;
    for ix in interactions {
        writeln!(
            f,
            "        {:?} {:?} kind={:?} claimed=(n={}, d={}) inside_batch={}",
            ix.sign, ix.name, ix.kind, ix.claimed_degree.n, ix.claimed_degree.d, ix.inside_batch,
        )?;
    }
    Ok(())
}
