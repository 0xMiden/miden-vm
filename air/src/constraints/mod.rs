//! Miden VM Constraints
//!
//! This module contains the constraint functions for the Miden VM processor.
//!
//! ## Organization
//!
//! Constraints are separated into two categories:
//!
//! ### Main Trace Constraints
//! - system: clock, ctx, fn_hash transitions
//! - range: range checker V column transitions
//! - stack: general stack constraints
//!
//! ### Bus Constraints (Auxiliary Trace)
//! - range::bus
//!
//! Bus constraints access the auxiliary trace via `builder.permutation()` and use
//! random challenges from `builder.permutation_randomness()` for multiset/LogUp verification.
//!
//! Additional components (decoder, chiplets) are introduced in later constraint chunks.

use chiplets::selectors::ChipletSelectors;
use miden_crypto::stark::air::{ExtensionBuilder, WindowAccess};

use crate::{MainCols, MidenAirBuilder, trace::Challenges};

pub mod bus;
pub mod chiplets;
pub mod columns;
pub mod constants;
pub mod decoder;
mod degree_audit;
pub mod ext_field;
pub mod logup;
pub mod logup_msg;
pub mod lookup;
pub(crate) mod op_flags;
pub mod public_inputs;
pub mod range;
pub mod stack;
pub mod system;
pub mod utils;

// ENTRY POINTS
// ================================================================================================

/// Enforces all main trace constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    selectors: &ChipletSelectors<AB::Expr>,
    op_flags: &op_flags::OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    system::enforce_main(builder, local, next, op_flags);
    range::enforce_main(builder, local, next);
    stack::enforce_main(builder, local, next, op_flags);
    decoder::enforce_main(builder, local, next, op_flags);
    chiplets::enforce_main(builder, local, next, selectors);
}

/// Enforces all auxiliary (bus) constraints: boundary + transition.
///
/// Bus soundness relies on three mechanisms:
///   1. **Boundary** -- aux columns start at identity (1 or 0)
///   2. **Transition** -- row-to-row update rules determine all subsequent values
///   3. **`reduced_aux_values`** -- final values satisfy bus identities
pub fn enforce_bus<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    selectors: &ChipletSelectors<AB::Expr>,
    op_flags: &op_flags::OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let r = builder.permutation_randomness();
    let challenges = Challenges::<AB::ExprEF>::new(r[0].into(), r[1].into());

    // First row: running products = 1, LogUp sums = 0.
    enforce_bus_first_row(builder);

    // Last row: bind aux trace to committed finals checked by `reduced_aux_values`,
    // preventing a malicious prover from committing arbitrary finals.
    enforce_bus_last_row(builder);

    range::bus::enforce_bus(builder, local, &challenges, selectors);
    stack::bus::enforce_bus(builder, local, next, op_flags, &challenges);
    decoder::bus::enforce_bus(builder, local, next, op_flags, &challenges);
    chiplets::bus::enforce_bus(builder, local, next, op_flags, &challenges, selectors);
}

fn enforce_bus_first_row<AB>(builder: &mut AB)
where
    AB: MidenAirBuilder,
{
    use bus::indices::*;

    let aux = builder.permutation();
    let aux_local = aux.current_slice();

    let p1 = aux_local[P1_BLOCK_STACK];
    let p2 = aux_local[P2_BLOCK_HASH];
    let p3 = aux_local[P3_OP_GROUP];
    let s_aux = aux_local[P1_STACK];
    let b_hk = aux_local[B_HASH_KERNEL];
    let b_ch = aux_local[B_CHIPLETS];
    let b_rng = aux_local[B_RANGE];
    let v_wir = aux_local[V_WIRING];

    let mut first = builder.when_first_row();
    first.assert_one_ext(p1);
    first.assert_one_ext(p2);
    first.assert_one_ext(p3);
    first.assert_one_ext(s_aux);
    first.assert_one_ext(b_hk);
    first.assert_one_ext(b_ch);
    first.assert_zero_ext(b_rng);
    first.assert_zero_ext(v_wir);
}

fn enforce_bus_last_row<AB>(builder: &mut AB)
where
    AB: MidenAirBuilder,
{
    use crate::trace::AUX_TRACE_WIDTH;

    const N: usize = AUX_TRACE_WIDTH;

    let cols: [AB::VarEF; N] = {
        let aux = builder.permutation();
        let s = aux.current_slice();
        core::array::from_fn(|i| s[i])
    };
    let finals: [AB::ExprEF; N] = {
        let f = builder.permutation_values();
        core::array::from_fn(|i| f[i].clone().into())
    };

    let mut last = builder.when_last_row();
    for (col, expected) in cols.into_iter().zip(finals) {
        last.assert_eq_ext(col, expected);
    }
}
