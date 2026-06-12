//! Poseidon2-permutation LogUp lookup AIR.
//!
//! This AIR owns the compute side of the hasher controller/permutation link. The
//! controller rows remain in `ChipletsAir`; row 0 and row 15 of each Poseidon2 cycle
//! receive the matching perm-link messages here, weighted by the cycle multiplicity.

use core::{array, borrow::Borrow};

use miden_core::field::PrimeCharacteristicRing;

use super::messages::HasherPermLinkMsg;
use crate::{
    Felt,
    constraints::poseidon2_permutation::columns::{
        Poseidon2PermutationCols, Poseidon2PermutationPeriodicCols,
    },
    lookup::{Deg, LookupBuilder, LookupColumn, LookupGroup},
};

// POSEIDON2 PERMUTATION LOOKUP BUILDER
// ================================================================================================

/// Extension trait required by the Poseidon2-permutation [`LookupAir`](crate::lookup::LookupAir).
pub(crate) trait Poseidon2PermutationLookupBuilder: LookupBuilder<F = Felt> {}

// POSEIDON2 PERMUTATION LOOKUP COLUMNS
// ================================================================================================

/// Per-column fraction stride for the standalone Poseidon2-permutation AIR.
pub(crate) const POSEIDON2_PERMUTATION_COLUMN_SHAPE: [usize; 1] = [1];

/// Emit the perm-link receiver column for the Poseidon2-permutation AIR.
pub(crate) fn emit_poseidon2_permutation_lookup_columns<LB>(
    builder: &mut LB,
    local: &Poseidon2PermutationCols<LB::Var>,
) where
    LB: Poseidon2PermutationLookupBuilder,
{
    let periodic: &Poseidon2PermutationPeriodicCols<LB::PeriodicVar> =
        builder.periodic_values().borrow();

    let is_init_ext: LB::Expr = periodic.is_init_ext.into();
    let not_cycle_end: LB::Expr = periodic.not_cycle_end();

    let f_row0 = is_init_ext;
    let f_row15 = LB::Expr::ONE - not_cycle_end;
    // This AIR receives the perm-link messages emitted by the hasher controller.
    let multiplicity: LB::Expr = LB::Expr::ZERO - local.multiplicity.into();
    let input_state: [LB::Var; 12] = array::from_fn(|i| local.state[i]);
    let output_state = input_state;

    builder.next_column(
        |col| {
            col.group(
                "poseidon2_perm_link",
                |g| {
                    g.insert(
                        "perm_row0",
                        f_row0,
                        multiplicity.clone(),
                        move || {
                            let state: [LB::Expr; 12] = input_state.map(Into::into);
                            HasherPermLinkMsg::Input { state }
                        },
                        Deg { v: 2, u: 2 },
                    );

                    g.insert(
                        "perm_row15",
                        f_row15,
                        multiplicity,
                        move || {
                            let state: [LB::Expr; 12] = output_state.map(Into::into);
                            HasherPermLinkMsg::Output { state }
                        },
                        Deg { v: 2, u: 2 },
                    );
                },
                Deg { v: 2, u: 2 },
            );
        },
        Deg { v: 2, u: 2 },
    );
}
