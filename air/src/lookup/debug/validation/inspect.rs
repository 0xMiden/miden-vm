//! Entry points that walk the AIR to collect a [`DebugStructure`].
//!
//! The three check wrappers ([`collect_inventory`], [`check_encoding_equivalence`],
//! [`check_challenge_scoping`]) all sit on top of [`inspect_structure`]. The composed
//! [`super::validate_structure_only`] also reuses this module rather than duplicating
//! walker setup.

use alloc::{vec, vec::Vec};

use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
use miden_crypto::stark::air::RowWindow;

use super::{
    super::super::{Challenges, LookupAir},
    DebugStructure, DebugStructureBuilder, GroupMismatch, Inventory, ScopeReport,
};
use crate::Felt;

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
