//! Poseidon2 permutation LogUp lookup AIR.

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

/// Extension trait required by the Poseidon2 permutation lookup AIR.
pub(crate) trait Poseidon2PermutationLookupBuilder: LookupBuilder<F = Felt> {}

/// Per-column fraction stride for the Poseidon2 permutation AIR.
pub(crate) const POSEIDON2_PERMUTATION_COLUMN_SHAPE: [usize; 1] = [1];

/// Emits the Poseidon2 side of the perm-link bus.
///
/// Row 0 removes the controller input request and row 15 removes the controller output
/// request, both with the cycle multiplicity. Padding cycles have multiplicity 0.
pub(crate) fn emit_poseidon2_permutation_lookup_columns<LB>(
    builder: &mut LB,
    local: &Poseidon2PermutationCols<LB::Var>,
) where
    LB: Poseidon2PermutationLookupBuilder,
{
    let periodic: &Poseidon2PermutationPeriodicCols<LB::PeriodicVar> =
        builder.periodic_values().borrow();

    let f_row0: LB::Expr = periodic.is_init_ext.into();
    let f_row15 = LB::Expr::ONE - periodic.not_cycle_end();
    let multiplicity: LB::Expr = LB::Expr::ZERO - local.multiplicity.into();
    let state: [LB::Var; 12] = array::from_fn(|i| local.state[i]);

    builder.next_column(
        |col| {
            col.group(
                "poseidon2_perm_link",
                |g| {
                    g.insert(
                        "perm_row0",
                        f_row0,
                        multiplicity.clone(),
                        || {
                            let state = state.map(Into::into);
                            HasherPermLinkMsg::Input { state }
                        },
                        Deg { v: 2, u: 2 },
                    );

                    g.insert(
                        "perm_row15",
                        f_row15,
                        multiplicity,
                        || {
                            let state = state.map(Into::into);
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
