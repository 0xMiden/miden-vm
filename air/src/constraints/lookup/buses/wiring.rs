//! ACE wiring bus (C3 / `BUS_ACE_WIRING`).
//!
//! Two READ/EVAL wire interactions gated by the ACE chiplet selector + its per-row block
//! selector.
//!
//! The two batches are folded into a single `ace_flag`-gated batch with
//! `sblock`-muxed multiplicities: `wire_0` fires with the same multiplicity `m_0`
//! on both READ and EVAL rows, so it factors out; `wire_1` and `wire_2` get
//! `sblock`-parameterized multiplicities that recover the original rational at
//! every row. This drops the outer selector from degree 5 (`is_read`/`is_eval`)
//! to degree 4 (`ace_flag`), bringing the column transition from 9 to 8.
//!
//! Algebraic equivalence:
//!
//! ```text
//!   is_read · (m_0/wire_0 + m_1/wire_1)
//! + is_eval · (m_0/wire_0 − 1/wire_1 − 1/wire_2)
//!   = ace_flag · [ m_0/wire_0
//!                + ((1 − sblock)·m_1 − sblock)/wire_1
//!                + (−sblock)/wire_2 ]
//! ```

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    Felt, MainCols,
    constraints::{
        logup_msg::AceWireMsg,
        lookup::{LookupBatch, LookupBuilder, LookupColumn, LookupGroup},
    },
    trace::chiplets::ace::{
        CLK_IDX, CTX_IDX, ID_0_IDX, ID_1_IDX, ID_2_IDX, M_0_IDX, M_1_IDX, SELECTOR_BLOCK_IDX,
        V_0_0_IDX, V_0_1_IDX, V_1_0_IDX, V_1_1_IDX, V_2_0_IDX, V_2_1_IDX,
    },
};

/// ACE chiplet column offset within `MainCols::chiplets` (s_ctrl + s1..s3 = 4 selector slots
/// before the ACE data starts; s4 overlaps the first ACE column).
const ACE_OFFSET: usize = 4;

/// Emit the ACE wiring bus (C3).
pub(in crate::constraints::lookup) fn emit_ace_wiring<LB>(
    builder: &mut LB,
    local: &MainCols<LB::Var>,
    _next: &MainCols<LB::Var>,
) where
    LB: LookupBuilder<F = Felt>,
{
    // Old layout: ace_flag = s0*s1*s2*(1-s3) where chiplets[0..4] = [s0, s1, s2, s3].
    // New layout: virtual s0 = 1 - s_ctrl - s_perm; s1..s4 live in chiplets[1..5].
    // ACE flag formula `s0*s1*s2*(1-s3)` is preserved (matches `is_ace = s012 - s0123`
    // in `chiplets::selectors::build_chiplet_selectors`).
    let s_ctrl: LB::Expr = local.chiplets[0].into();
    let s_perm: LB::Expr = local.perm_seg.into();
    let virtual_s0: LB::Expr = LB::Expr::ONE - s_ctrl - s_perm;
    let s1: LB::Expr = local.chiplets[1].into();
    let s2: LB::Expr = local.chiplets[2].into();
    let s3: LB::Expr = local.chiplets[3].into();

    let ace_flag: LB::Expr = virtual_s0 * s1 * s2 * (LB::Expr::ONE - s3);
    let sblock: LB::Expr = local.chiplets[ACE_OFFSET + SELECTOR_BLOCK_IDX].into();

    let clk: LB::Expr = local.chiplets[ACE_OFFSET + CLK_IDX].into();
    let ctx: LB::Expr = local.chiplets[ACE_OFFSET + CTX_IDX].into();
    let m0: LB::Expr = local.chiplets[ACE_OFFSET + M_0_IDX].into();
    let m1: LB::Expr = local.chiplets[ACE_OFFSET + M_1_IDX].into();

    let wire_0 = AceWireMsg {
        clk: clk.clone(),
        ctx: ctx.clone(),
        id: local.chiplets[ACE_OFFSET + ID_0_IDX].into(),
        v0: local.chiplets[ACE_OFFSET + V_0_0_IDX].into(),
        v1: local.chiplets[ACE_OFFSET + V_0_1_IDX].into(),
    };
    let wire_1 = AceWireMsg {
        clk: clk.clone(),
        ctx: ctx.clone(),
        id: local.chiplets[ACE_OFFSET + ID_1_IDX].into(),
        v0: local.chiplets[ACE_OFFSET + V_1_0_IDX].into(),
        v1: local.chiplets[ACE_OFFSET + V_1_1_IDX].into(),
    };
    let wire_2 = AceWireMsg {
        clk,
        ctx,
        id: local.chiplets[ACE_OFFSET + ID_2_IDX].into(),
        v0: local.chiplets[ACE_OFFSET + V_2_0_IDX].into(),
        v1: local.chiplets[ACE_OFFSET + V_2_1_IDX].into(),
    };

    builder.column(|col| {
        col.group(|g| {
            // Single `ace_flag`-gated batch with `sblock`-muxed multiplicities
            // for wire_1 and wire_2. `wire_0`'s `m_0` is invariant across the
            // READ/EVAL split, so it lives in the batch as a plain trace-column
            // multiplicity.
            let wire_1_mult = (LB::Expr::ONE - sblock.clone()) * m1 - sblock.clone();
            let wire_2_mult = LB::Expr::ZERO - sblock;
            g.batch(ace_flag, move |b| {
                b.insert(m0, wire_0);
                b.insert(wire_1_mult, wire_1);
                b.insert(wire_2_mult, wire_2);
            });
        });
    });
}
