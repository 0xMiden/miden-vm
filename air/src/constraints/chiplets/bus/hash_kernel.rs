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
//! The request/response values use the standard linear-combination message format based on
//! `alphas` (challenge powers).

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::{air::MidenAirBuilder, matrix::Matrix};

use crate::{
    Felt, MainTraceRow,
    constraints::{
        bus::{alphas_from_challenges, indices::B_HASH_KERNEL},
        chiplets::hasher::{flags, periodic},
        op_flags::OpFlags,
        tagging::{
            TagGroup, TaggingAirBuilderExt, ids::TAG_HASH_KERNEL_BUS_BASE, tagged_assert_zero_ext,
        },
    },
    trace::{
        CHIPLETS_OFFSET, LOG_PRECOMPILE_LABEL,
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

/// Tag ID and namespace for the hash-kernel (virtual table) bus transition constraint.
const HASH_KERNEL_BUS_ID: usize = TAG_HASH_KERNEL_BUS_BASE;
const HASH_KERNEL_BUS_NAMESPACE: &str = "chiplets.bus.hash_kernel.transition";
const HASH_KERNEL_BUS_NAMES: [&str; 1] = [HASH_KERNEL_BUS_NAMESPACE; 1];
const HASH_KERNEL_BUS_TAGS: TagGroup = TagGroup {
    base: HASH_KERNEL_BUS_ID,
    names: &HASH_KERNEL_BUS_NAMES,
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
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // =========================================================================
    // AUXILIARY TRACE ACCESS
    // =========================================================================

    let (p_local, p_next, alphas) = {
        let aux = builder.permutation();
        let aux_local = aux.row_slice(0).expect("Matrix should have at least 1 row");
        let aux_next = aux.row_slice(1).expect("Matrix should have at least 2 rows");
        let p_local = aux_local[B_HASH_KERNEL];
        let p_next = aux_next[B_HASH_KERNEL];

        let challenges = builder.permutation_randomness();
        let alphas: [AB::ExprEF; 16] = alphas_from_challenges::<AB, 16>(challenges);
        (p_local, p_next, alphas)
    };

    let one = AB::Expr::ONE;
    let one_ef = AB::ExprEF::ONE;

    // =========================================================================
    // PERIODIC VALUES
    // =========================================================================

    let (cycle_row_0, cycle_row_31) = {
        // Clone only the periodic values we need (avoids per-eval `to_vec()` allocation).
        let p = builder.periodic_evals();
        let cycle_row_0: AB::Expr = p[periodic::P_CYCLE_ROW_0].into();
        let cycle_row_31: AB::Expr = p[periodic::P_CYCLE_ROW_31].into();
        (cycle_row_0, cycle_row_31)
    };

    // =========================================================================
    // COMMON VALUES
    // =========================================================================

    // Hasher chiplet rows have s0 = 0 (chiplet selector).
    let chiplet_selector: AB::Expr = local.chiplets[0].clone().into();
    let is_hasher: AB::Expr = one.clone() - chiplet_selector.clone();

    // Hasher operation selectors (only meaningful within hasher chiplet)
    let s0: AB::Expr = local.chiplets[S_START].clone().into();
    let s1: AB::Expr = local.chiplets[S_START + 1].clone().into();
    let s2: AB::Expr = local.chiplets[S_START + 2].clone().into();

    // Node index for sibling table
    let node_index: AB::Expr = local.chiplets[IDX_COL].clone().into();
    let node_index_next: AB::Expr = next.chiplets[IDX_COL].clone().into();

    // Hasher state for sibling values
    let h: [AB::Expr; 12] = core::array::from_fn(|i| local.chiplets[H_START + i].clone().into());
    let h_next: [AB::Expr; 12] =
        core::array::from_fn(|i| next.chiplets[H_START + i].clone().into());

    // =========================================================================
    // SIBLING TABLE FLAGS AND VALUES
    // =========================================================================

    // MU/MUA flags (requests - remove siblings during new path).
    let f_mu: AB::Expr =
        is_hasher.clone() * flags::f_mu(cycle_row_0.clone(), s0.clone(), s1.clone(), s2.clone());
    let f_mua: AB::Expr =
        is_hasher.clone() * flags::f_mua(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone());

    // MV/MVA flags (responses - add siblings during old path).
    let f_mv: AB::Expr =
        is_hasher.clone() * flags::f_mv(cycle_row_0.clone(), s0.clone(), s1.clone(), s2.clone());
    let f_mva: AB::Expr = is_hasher.clone() * flags::f_mva(cycle_row_31.clone(), s0, s1, s2);

    // Compute sibling values based on bit b (LSB of node index).
    // The hasher constraints enforce that b is binary on shift rows.
    let two = AB::Expr::from_u16(2);
    let b: AB::Expr = node_index.clone() - two * node_index_next.clone();
    let is_b_zero = one.clone() - b.clone();
    let is_b_one = b;

    // Sibling value for current row (uses current hasher state).
    // b selects which half of the rate holds the sibling.
    let v_sibling_curr = compute_sibling_b0::<AB>(&alphas, &node_index, &h) * is_b_zero.clone()
        + compute_sibling_b1::<AB>(&alphas, &node_index, &h) * is_b_one.clone();

    // Sibling value for next row (used by MVA/MUA on the transition row).
    let v_sibling_next = compute_sibling_b0::<AB>(&alphas, &node_index, &h_next) * is_b_zero
        + compute_sibling_b1::<AB>(&alphas, &node_index, &h_next) * is_b_one;

    // =========================================================================
    // ACE MEMORY FLAGS AND VALUES
    // =========================================================================

    // ACE chiplet selector: s0=1, s1=1, s2=1, s3=0
    let s3: AB::Expr = local.chiplets[3].clone().into();
    let chiplet_s1: AB::Expr = local.chiplets[1].clone().into();
    let chiplet_s2: AB::Expr = local.chiplets[2].clone().into();

    let is_ace_row: AB::Expr =
        chiplet_selector.clone() * chiplet_s1.clone() * chiplet_s2.clone() * (one.clone() - s3);

    // Block selector determines read (0) vs eval (1)
    let block_selector: AB::Expr =
        local.chiplets[NUM_ACE_SELECTORS + SELECTOR_BLOCK_IDX].clone().into();

    let f_ace_read: AB::Expr = is_ace_row.clone() * (one.clone() - block_selector.clone());
    let f_ace_eval: AB::Expr = is_ace_row * block_selector;

    // ACE columns for memory messages
    let ace_clk: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + CLK_IDX].clone().into();
    let ace_ctx: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + CTX_IDX].clone().into();
    let ace_ptr: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + PTR_IDX].clone().into();

    // Word read value: label + ctx + ptr + clk + 4-lane value.
    let v_ace_word = {
        let v0_0: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + V_0_0_IDX].clone().into();
        let v0_1: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + V_0_1_IDX].clone().into();
        let v1_0: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + V_1_0_IDX].clone().into();
        let v1_1: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + V_1_1_IDX].clone().into();
        let label: AB::Expr = AB::Expr::from(Felt::from_u8(MEMORY_READ_WORD_LABEL));

        message_with_label::<AB>(
            &alphas,
            label,
            &[ace_ctx.clone(), ace_ptr.clone(), ace_clk.clone(), v0_0, v0_1, v1_0, v1_1],
        )
    };

    // Element read value: label + ctx + ptr + clk + element.
    let v_ace_element = {
        let id_1: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + ID_1_IDX].clone().into();
        let id_2: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + ID_2_IDX].clone().into();
        let eval_op: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + EVAL_OP_IDX].clone().into();

        let offset1: AB::Expr = AB::Expr::from(ACE_INSTRUCTION_ID1_OFFSET);
        let offset2: AB::Expr = AB::Expr::from(ACE_INSTRUCTION_ID2_OFFSET);
        let element = id_1 + id_2 * offset1 + (eval_op + one.clone()) * offset2;
        let label: AB::Expr = AB::Expr::from(Felt::from_u8(MEMORY_READ_ELEMENT_LABEL));

        message_with_label::<AB>(&alphas, label, &[ace_ctx, ace_ptr, ace_clk, element])
    };

    // =========================================================================
    // LOG PRECOMPILE FLAGS AND VALUES
    // =========================================================================

    let f_logprecompile: AB::Expr = op_flags.log_precompile();

    // CAP_PREV from helper registers (provided and constrained by the decoder logic).
    let cap_prev: [AB::Expr; 4] = core::array::from_fn(|i| {
        local.decoder[USER_OP_HELPERS_OFFSET + HELPER_CAP_PREV_RANGE.start + i]
            .clone()
            .into()
    });

    // CAP_NEXT from next-row stack.
    let cap_next: [AB::Expr; 4] =
        core::array::from_fn(|i| next.stack[STACK_CAP_NEXT_RANGE.start + i].clone().into());

    let log_label: AB::Expr = AB::Expr::from(Felt::from_u8(LOG_PRECOMPILE_LABEL));

    // CAP_PREV value (request - removed).
    let v_cap_prev = message_with_label::<AB>(&alphas, log_label.clone(), &cap_prev);

    // CAP_NEXT value (response - inserted).
    let v_cap_next = message_with_label::<AB>(&alphas, log_label, &cap_next);

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
        + (one_ef.clone() - request_flag_sum);

    let response_flag_sum = f_mv.clone() + f_mva.clone() + f_logprecompile.clone();
    let responses: AB::ExprEF = v_sibling_curr * f_mv
        + v_sibling_next * f_mva
        + v_cap_next * f_logprecompile
        + (one_ef - response_flag_sum);

    // Running product constraint: p' * requests = p * responses
    let p_local_ef: AB::ExprEF = p_local.into();
    let p_next_ef: AB::ExprEF = p_next.into();

    let mut idx = 0;
    tagged_assert_zero_ext(
        builder,
        &HASH_KERNEL_BUS_TAGS,
        &mut idx,
        p_next_ef * requests - p_local_ef * responses,
    );
}

// INTERNAL HELPERS
// ================================================================================================

/// Compute sibling value when b=0 (sibling at h[4..7]).
///
/// Message layout: alpha[0] (constant) + alpha[3] * node_index + alpha[8..11] * h[4..7].
fn compute_sibling_b0<AB>(
    alphas: &[AB::ExprEF; 16],
    node_index: &AB::Expr,
    h: &[AB::Expr; 12],
) -> AB::ExprEF
where
    AB: MidenAirBuilder<F = Felt>,
{
    alphas[0].clone()
        + alphas[3].clone() * node_index.clone()
        + alphas[8].clone() * h[4].clone()
        + alphas[9].clone() * h[5].clone()
        + alphas[10].clone() * h[6].clone()
        + alphas[11].clone() * h[7].clone()
}

/// Compute sibling value when b=1 (sibling at h[0..3]).
///
/// Message layout: alpha[0] (constant) + alpha[3] * node_index + alpha[4..7] * h[0..3].
fn compute_sibling_b1<AB>(
    alphas: &[AB::ExprEF; 16],
    node_index: &AB::Expr,
    h: &[AB::Expr; 12],
) -> AB::ExprEF
where
    AB: MidenAirBuilder<F = Felt>,
{
    alphas[0].clone()
        + alphas[3].clone() * node_index.clone()
        + alphas[4].clone() * h[0].clone()
        + alphas[5].clone() * h[1].clone()
        + alphas[6].clone() * h[2].clone()
        + alphas[7].clone() * h[3].clone()
}

/// Build a linear-combination message with a label and a variable number of fields.
///
/// Message layout:
/// - alpha[0] is the constant term
/// - alpha[1] multiplies the label
/// - alpha[2..] multiply the provided fields in order
fn message_with_label<AB>(
    alphas: &[AB::ExprEF; 16],
    label: AB::Expr,
    fields: &[AB::Expr],
) -> AB::ExprEF
where
    AB: MidenAirBuilder<F = Felt>,
{
    debug_assert!(fields.len() <= 14);
    let mut acc = alphas[0].clone() + alphas[1].clone() * label;
    for (idx, field) in fields.iter().enumerate() {
        acc += alphas[idx + 2].clone() * field.clone();
    }
    acc
}
