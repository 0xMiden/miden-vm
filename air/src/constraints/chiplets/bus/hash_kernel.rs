//! Hash kernel virtual table bus constraint (`b_hash_kernel`).
//!
//! This module enforces a single running-product column (aux index 5) which aggregates three
//! logically separate tables:
//!
//! 1. **Sibling table** for Merkle root updates (hasher chiplet).
//! 2. **ACE memory reads** (ACE chiplet requests; memory chiplet responses on `b_chiplets`).
//! 3. **Log-precompile transcript** (capacity state transitions for LOGPRECOMPILE).
//!
//! Rows contribute either a request term, a response term, or the identity (when no flag is set).
//! The request/response values use the standard message format:
//! `alpha + sum_i beta^i * element[i]`.

use core::borrow::Borrow;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::{ExtensionBuilder, WindowAccess};

use crate::{
    Felt, MainTraceRow, MidenAirBuilder,
    constraints::{
        bus::indices::B_HASH_KERNEL,
        chiplets::{columns::PeriodicCols, hasher::flags, selectors::ChipletSelectors},
        op_flags::OpFlags,
        utils::BoolNot,
    },
    trace::{
        Challenges, LOG_PRECOMPILE_LABEL,
        bus_types::{CHIPLETS_BUS, LOG_PRECOMPILE_TRANSCRIPT, SIBLING_TABLE},
        chiplets::{
            ace::{ACE_INSTRUCTION_ID1_OFFSET, ACE_INSTRUCTION_ID2_OFFSET},
            memory::{MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL},
        },
        log_precompile::{HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE},
    },
};

// ENTRY POINTS
// ================================================================================================

/// Enforces the hash kernel virtual table (b_hash_kernel) bus constraint.
///
/// This constraint combines:
/// 1. Sibling table for Merkle root updates
/// 2. ACE memory read requests
/// 3. Log precompile transcript tracking
pub fn enforce_hash_kernel_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    challenges: &Challenges<AB::ExprEF>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // =========================================================================
    // AUXILIARY TRACE ACCESS
    // =========================================================================

    let (p_local, p_next) = {
        let aux = builder.permutation();
        let aux_local = aux.current_slice();
        let aux_next = aux.next_slice();
        (aux_local[B_HASH_KERNEL], aux_next[B_HASH_KERNEL])
    };

    // =========================================================================
    // PERIODIC VALUES
    // =========================================================================

    let periodic: &PeriodicCols<_> = builder.periodic_values().borrow();
    let cycle_row_0 = periodic.hasher.cycle_row_0.into();
    let cycle_row_31 = periodic.hasher.cycle_row_31.into();

    // =========================================================================
    // COMMON VALUES
    // =========================================================================

    let is_hasher = selectors.hasher.is_active.clone();

    let hasher = local.hasher();
    let hasher_next = next.hasher();

    // Hasher operation selectors (only meaningful within hasher chiplet)
    let s0 = hasher.selectors[0];
    let s1 = hasher.selectors[1];
    let s2 = hasher.selectors[2];

    // Node index for sibling table
    let node_index = hasher.node_index;
    let node_index_next = hasher_next.node_index;

    // Hasher state for sibling values (kept as Var; converted to Expr on demand)
    let h = &hasher.state;
    let h_next = &hasher_next.state;

    // =========================================================================
    // SIBLING TABLE FLAGS AND VALUES
    // =========================================================================

    // MU/MUA flags (requests - remove siblings during new path).
    let f_mu: AB::Expr =
        is_hasher.clone() * flags::f_mu(cycle_row_0.clone(), s0.into(), s1.into(), s2.into());
    let f_mua: AB::Expr =
        is_hasher.clone() * flags::f_mua(cycle_row_31.clone(), s0.into(), s1.into(), s2.into());

    // MV/MVA flags (responses - add siblings during old path).
    let f_mv: AB::Expr =
        is_hasher.clone() * flags::f_mv(cycle_row_0.clone(), s0.into(), s1.into(), s2.into());
    let f_mva: AB::Expr =
        is_hasher.clone() * flags::f_mva(cycle_row_31.clone(), s0.into(), s1.into(), s2.into());

    // Compute sibling values based on bit b (LSB of node index).
    // The hasher constraints enforce that b is binary on shift rows.
    let b: AB::Expr = node_index - node_index_next.into().double();
    let is_b_zero = b.not();
    let is_b_one = b;

    // Sibling value for current row (uses current hasher state).
    // b selects which half of the rate holds the sibling.
    let v_sibling_curr = compute_sibling_b0::<AB>(challenges, node_index, h) * is_b_zero.clone()
        + compute_sibling_b1::<AB>(challenges, node_index, h) * is_b_one.clone();

    // Sibling value for next row (used by MVA/MUA on the transition row).
    let v_sibling_next = compute_sibling_b0::<AB>(challenges, node_index, h_next) * is_b_zero
        + compute_sibling_b1::<AB>(challenges, node_index, h_next) * is_b_one;

    // =========================================================================
    // ACE MEMORY FLAGS AND VALUES
    // =========================================================================

    let is_ace_row: AB::Expr = selectors.ace.is_active.clone();

    let ace = local.ace();

    // Block selector determines read (0) vs eval (1).
    let f_ace_read: AB::Expr = is_ace_row.clone() * ace.s_block.into().not();
    let f_ace_eval: AB::Expr = is_ace_row * ace.s_block;

    // Word read value: label + ctx + ptr + clk + 4-lane value.
    let v_ace_word = {
        let label: AB::Expr = Felt::from_u8(MEMORY_READ_WORD_LABEL).into();
        challenges.encode(
            CHIPLETS_BUS,
            [
                label,
                ace.ctx.into(),
                ace.ptr.into(),
                ace.clk.into(),
                ace.v_0.0.into(), // v_0_0
                ace.v_0.1.into(), // v_0_1
                ace.v_1.0.into(), // v_1_0
                ace.v_1.1.into(), // v_1_1
            ],
        )
    };

    // Element read value: label + ctx + ptr + clk + element.
    let v_ace_element = {
        let label: AB::Expr = Felt::from_u8(MEMORY_READ_ELEMENT_LABEL).into();
        let id_1 = ace.id_1; // ID_1
        let id_2 = ace.eval().id_2; // ID_2
        let eval_op = ace.eval_op;

        let offset1: AB::Expr = ACE_INSTRUCTION_ID1_OFFSET.into();
        let offset2: AB::Expr = ACE_INSTRUCTION_ID2_OFFSET.into();
        let element = id_1 + id_2 * offset1 + (eval_op + AB::Expr::ONE) * offset2;
        challenges
            .encode(CHIPLETS_BUS, [label, ace.ctx.into(), ace.ptr.into(), ace.clk.into(), element])
    };

    // =========================================================================
    // LOG PRECOMPILE FLAGS AND VALUES
    // =========================================================================

    let f_logprecompile: AB::Expr = op_flags.log_precompile();

    // CAP_PREV from helper registers (provided and constrained by the decoder logic).
    let helpers = local.decoder.user_op_helpers();
    let cap_prev = &helpers[HELPER_CAP_PREV_RANGE];

    // CAP_NEXT from next-row stack.
    let cap_next = &next.stack.top[STACK_CAP_NEXT_RANGE];

    let log_label: AB::Expr = Felt::from_u8(LOG_PRECOMPILE_LABEL).into();

    // CAP_PREV value (request - removed).
    let v_cap_prev = challenges.encode(
        LOG_PRECOMPILE_TRANSCRIPT,
        [
            log_label.clone(),
            cap_prev[0].into(),
            cap_prev[1].into(),
            cap_prev[2].into(),
            cap_prev[3].into(),
        ],
    );

    // CAP_NEXT value (response - inserted).
    let v_cap_next = challenges.encode(
        LOG_PRECOMPILE_TRANSCRIPT,
        [
            log_label,
            cap_next[0].into(),
            cap_next[1].into(),
            cap_next[2].into(),
            cap_next[3].into(),
        ],
    );

    // =========================================================================
    // RUNNING PRODUCT CONSTRAINT
    // =========================================================================

    // Include the identity term when no request/response flag is set on a row.
    // Flags are mutually exclusive by construction (chiplet selectors + op flags).
    let request_flag_sum = f_mu.clone()
        + f_mua.clone()
        + f_ace_read.clone()
        + f_ace_eval.clone()
        + f_logprecompile.clone();
    let requests: AB::ExprEF = v_sibling_curr.clone() * f_mu.clone()
        + v_sibling_next.clone() * f_mua.clone()
        + v_ace_word * f_ace_read
        + v_ace_element * f_ace_eval
        + v_cap_prev * f_logprecompile.clone()
        + request_flag_sum.not();

    let response_flag_sum = f_mv.clone() + f_mva.clone() + f_logprecompile.clone();
    let responses: AB::ExprEF = v_sibling_curr * f_mv
        + v_sibling_next * f_mva
        + v_cap_next * f_logprecompile
        + response_flag_sum.not();

    // Running product constraint: p' * requests = p * responses
    let p_local_ef: AB::ExprEF = p_local.into();
    let p_next_ef: AB::ExprEF = p_next.into();

    builder
        .when_transition()
        .assert_eq_ext(p_next_ef * requests, p_local_ef * responses);
}

// INTERNAL HELPERS
// ================================================================================================

/// Sibling at h[4..7]: positions [2, 7, 8, 9, 10].
const SIBLING_B0_LAYOUT: [usize; 5] = [2, 7, 8, 9, 10];
/// Sibling at h[0..3]: positions [2, 3, 4, 5, 6].
const SIBLING_B1_LAYOUT: [usize; 5] = [2, 3, 4, 5, 6];

fn compute_sibling_b0<AB>(
    challenges: &Challenges<AB::ExprEF>,
    node_index: AB::Var,
    h: &[AB::Var; 12],
) -> AB::ExprEF
where
    AB: MidenAirBuilder,
{
    challenges.encode_sparse(
        SIBLING_TABLE,
        SIBLING_B0_LAYOUT,
        [node_index.into(), h[4].into(), h[5].into(), h[6].into(), h[7].into()],
    )
}

/// Compute sibling value when b=1 (sibling at h[0..3]).
///
/// Message layout: alpha[0] (constant) + alpha[3] * node_index + alpha[4..7] * h[0..3].
fn compute_sibling_b1<AB>(
    challenges: &Challenges<AB::ExprEF>,
    node_index: AB::Var,
    h: &[AB::Var; 12],
) -> AB::ExprEF
where
    AB: MidenAirBuilder,
{
    challenges.encode_sparse(
        SIBLING_TABLE,
        SIBLING_B1_LAYOUT,
        [node_index.into(), h[0].into(), h[1].into(), h[2].into(), h[3].into()],
    )
}
