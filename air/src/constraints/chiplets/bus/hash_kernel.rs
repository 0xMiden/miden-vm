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

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::{ExtensionBuilder, WindowAccess};

use crate::{
    Felt, MainTraceRow, MidenAirBuilder,
    constraints::{
        bus::indices::B_HASH_KERNEL,
        chiplets::{
            hasher::{flags, periodic},
            selectors::ChipletSelectors,
        },
        op_flags::OpFlags,
        utils::BoolNot,
    },
    trace::{
        CHIPLETS_OFFSET, Challenges, LOG_PRECOMPILE_LABEL,
        chiplets::{
            HASHER_NODE_INDEX_COL_IDX, HASHER_SELECTOR_COL_RANGE, HASHER_STATE_COL_RANGE,
            NUM_ACE_SELECTORS,
            ace::{
                ACE_INSTRUCTION_ID1_OFFSET, ACE_INSTRUCTION_ID2_OFFSET, CLK_IDX, CTX_IDX,
                EVAL_OP_IDX, ID_1_IDX, ID_2_IDX, PTR_IDX, SELECTOR_BLOCK_IDX, V_0_0_IDX, V_0_1_IDX,
                V_1_0_IDX, V_1_1_IDX,
            },
            memory::{MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL},
        },
        decoder::USER_OP_HELPERS_OFFSET,
        log_precompile::{HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE},
    },
};

// CONSTANTS
// ================================================================================================

// Column offsets relative to chiplets array.
const S_START: usize = HASHER_SELECTOR_COL_RANGE.start - CHIPLETS_OFFSET;
const H_START: usize = HASHER_STATE_COL_RANGE.start - CHIPLETS_OFFSET;
const IDX_COL: usize = HASHER_NODE_INDEX_COL_IDX - CHIPLETS_OFFSET;

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

    let (cycle_row_0, cycle_row_31) = {
        // Clone only the periodic values we need (avoids per-eval `to_vec()` allocation).
        let p = builder.periodic_values();
        let cycle_row_0: AB::Expr = p[periodic::P_CYCLE_ROW_0].into();
        let cycle_row_31: AB::Expr = p[periodic::P_CYCLE_ROW_31].into();
        (cycle_row_0, cycle_row_31)
    };

    // =========================================================================
    // COMMON VALUES
    // =========================================================================

    let is_hasher = selectors.hasher.is_active.clone();

    // Hasher operation selectors (only meaningful within hasher chiplet)
    let s0 = local.chiplets[S_START];
    let s1 = local.chiplets[S_START + 1];
    let s2 = local.chiplets[S_START + 2];

    // Node index for sibling table
    let node_index = local.chiplets[IDX_COL];
    let node_index_next = next.chiplets[IDX_COL];

    // Hasher state for sibling values
    let h: [AB::Expr; 12] = core::array::from_fn(|i| local.chiplets[H_START + i].into());
    let h_next: [AB::Expr; 12] = core::array::from_fn(|i| next.chiplets[H_START + i].into());

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
    let b: AB::Expr = node_index - AB::Expr::from(node_index_next).double();
    let is_b_zero = b.not();
    let is_b_one = b;

    // Sibling value for current row (uses current hasher state).
    // b selects which half of the rate holds the sibling.
    let node_index_expr: AB::Expr = node_index.into();
    let v_sibling_curr = compute_sibling_b0::<AB>(challenges, &node_index_expr, &h)
        * is_b_zero.clone()
        + compute_sibling_b1::<AB>(challenges, &node_index_expr, &h) * is_b_one.clone();

    // Sibling value for next row (used by MVA/MUA on the transition row).
    let v_sibling_next = compute_sibling_b0::<AB>(challenges, &node_index_expr, &h_next)
        * is_b_zero
        + compute_sibling_b1::<AB>(challenges, &node_index_expr, &h_next) * is_b_one;

    // =========================================================================
    // ACE MEMORY FLAGS AND VALUES
    // =========================================================================

    let is_ace_row: AB::Expr = selectors.ace.is_active.clone();

    // Block selector determines read (0) vs eval (1)
    let block_selector = local.chiplets[NUM_ACE_SELECTORS + SELECTOR_BLOCK_IDX];

    let f_ace_read: AB::Expr = is_ace_row.clone() * AB::Expr::from(block_selector).not();
    let f_ace_eval: AB::Expr = is_ace_row * block_selector;

    // ACE columns for memory messages
    let ace_clk = local.chiplets[NUM_ACE_SELECTORS + CLK_IDX];
    let ace_ctx = local.chiplets[NUM_ACE_SELECTORS + CTX_IDX];
    let ace_ptr = local.chiplets[NUM_ACE_SELECTORS + PTR_IDX];

    // Word read value: label + ctx + ptr + clk + 4-lane value.
    let v_ace_word = {
        let v0_0 = local.chiplets[NUM_ACE_SELECTORS + V_0_0_IDX];
        let v0_1 = local.chiplets[NUM_ACE_SELECTORS + V_0_1_IDX];
        let v1_0 = local.chiplets[NUM_ACE_SELECTORS + V_1_0_IDX];
        let v1_1 = local.chiplets[NUM_ACE_SELECTORS + V_1_1_IDX];
        let label: AB::Expr = Felt::from_u8(MEMORY_READ_WORD_LABEL).into();

        challenges.encode([
            label,
            ace_ctx.into(),
            ace_ptr.into(),
            ace_clk.into(),
            v0_0.into(),
            v0_1.into(),
            v1_0.into(),
            v1_1.into(),
        ])
    };

    // Element read value: label + ctx + ptr + clk + element.
    let v_ace_element = {
        let id_1 = local.chiplets[NUM_ACE_SELECTORS + ID_1_IDX];
        let id_2 = local.chiplets[NUM_ACE_SELECTORS + ID_2_IDX];
        let eval_op = local.chiplets[NUM_ACE_SELECTORS + EVAL_OP_IDX];

        let offset1: AB::Expr = ACE_INSTRUCTION_ID1_OFFSET.into();
        let offset2: AB::Expr = ACE_INSTRUCTION_ID2_OFFSET.into();
        let element = id_1 + id_2 * offset1 + (eval_op + AB::Expr::ONE) * offset2;
        let label: AB::Expr = Felt::from_u8(MEMORY_READ_ELEMENT_LABEL).into();

        challenges.encode([label, ace_ctx.into(), ace_ptr.into(), ace_clk.into(), element])
    };

    // =========================================================================
    // LOG PRECOMPILE FLAGS AND VALUES
    // =========================================================================

    let f_logprecompile: AB::Expr = op_flags.log_precompile();

    // CAP_PREV from helper registers (provided and constrained by the decoder logic).
    let cap_prev: [AB::Expr; 4] = core::array::from_fn(|i| {
        local.decoder[USER_OP_HELPERS_OFFSET + HELPER_CAP_PREV_RANGE.start + i].into()
    });

    // CAP_NEXT from next-row stack.
    let cap_next: [AB::Expr; 4] =
        core::array::from_fn(|i| next.stack[STACK_CAP_NEXT_RANGE.start + i].into());

    let log_label: AB::Expr = Felt::from_u8(LOG_PRECOMPILE_LABEL).into();

    // CAP_PREV value (request - removed).
    let v_cap_prev = challenges.encode([
        log_label.clone(),
        cap_prev[0].clone(),
        cap_prev[1].clone(),
        cap_prev[2].clone(),
        cap_prev[3].clone(),
    ]);

    // CAP_NEXT value (response - inserted).
    let v_cap_next = challenges.encode([
        log_label,
        cap_next[0].clone(),
        cap_next[1].clone(),
        cap_next[2].clone(),
        cap_next[3].clone(),
    ]);

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
    node_index: &AB::Expr,
    h: &[AB::Expr; 12],
) -> AB::ExprEF
where
    AB: MidenAirBuilder,
{
    challenges.encode_sparse(
        SIBLING_B0_LAYOUT,
        [node_index.clone(), h[4].clone(), h[5].clone(), h[6].clone(), h[7].clone()],
    )
}

/// Compute sibling value when b=1 (sibling at h[0..3]).
///
/// Message layout: alpha[0] (constant) + alpha[3] * node_index + alpha[4..7] * h[0..3].
fn compute_sibling_b1<AB>(
    challenges: &Challenges<AB::ExprEF>,
    node_index: &AB::Expr,
    h: &[AB::Expr; 12],
) -> AB::ExprEF
where
    AB: MidenAirBuilder,
{
    challenges.encode_sparse(
        SIBLING_B1_LAYOUT,
        [node_index.clone(), h[0].clone(), h[1].clone(), h[2].clone(), h[3].clone()],
    )
}
