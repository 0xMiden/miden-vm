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
use miden_crypto::stark::air::{ExtensionBuilder, LiftedAirBuilder, WindowAccess};

use crate::{
    Felt, MainCols, MidenAirBuilder,
    constraints::{
        bus::indices::B_HASH_KERNEL,
        chiplets::{hasher::flags, selectors::ChipletSelectors},
        op_flags::OpFlags,
    },
    trace::{
        CHIPLETS_OFFSET, Challenges, LOG_PRECOMPILE_LABEL, bus_types,
        chiplets::{
            HASHER_MRUPDATE_ID_COL_IDX, HASHER_NODE_INDEX_COL_IDX, HASHER_PERM_SEG_COL_IDX,
            HASHER_SELECTOR_COL_RANGE, HASHER_STATE_COL_RANGE, NUM_ACE_SELECTORS,
            ace::{
                ACE_INSTRUCTION_ID1_OFFSET, ACE_INSTRUCTION_ID2_OFFSET, CLK_IDX, CTX_IDX,
                EVAL_OP_IDX, ID_1_IDX, ID_2_IDX, PTR_IDX, SELECTOR_BLOCK_IDX, V_0_0_IDX, V_0_1_IDX,
                V_1_0_IDX, V_1_1_IDX,
            },
            memory::{MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL},
        },
        log_precompile::{HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE},
    },
};

// CONSTANTS
// ================================================================================================

// Column offsets relative to chiplets array.
const S_START: usize = HASHER_SELECTOR_COL_RANGE.start - CHIPLETS_OFFSET;
const H_START: usize = HASHER_STATE_COL_RANGE.start - CHIPLETS_OFFSET;
const IDX_COL: usize = HASHER_NODE_INDEX_COL_IDX - CHIPLETS_OFFSET;
const MRUPDATE_ID_COL: usize = HASHER_MRUPDATE_ID_COL_IDX - CHIPLETS_OFFSET;
const PERM_SEG_COL: usize = HASHER_PERM_SEG_COL_IDX - CHIPLETS_OFFSET;

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
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    challenges: &Challenges<AB::ExprEF>,
    _selectors: &ChipletSelectors<AB::Expr>,
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

    let one = AB::Expr::ONE;
    let one_ef = AB::ExprEF::ONE;

    // =========================================================================
    // COMMON VALUES
    // =========================================================================

    // Hasher chiplet rows have s0 = 0 (chiplet selector).
    let chiplet_selector: AB::Expr = local.chiplet_selectors()[0].into();
    let is_hasher: AB::Expr = one.clone() - chiplet_selector.clone();

    // Hasher controller flag: active on hasher controller rows (perm_seg=0), not on
    // hasher permutation segment rows (perm_seg=1).
    let perm_seg: AB::Expr = local.chiplets[PERM_SEG_COL].into();
    let controller_flag: AB::Expr = is_hasher.clone() * (one.clone() - perm_seg);

    // Hasher operation selectors (only meaningful on hasher controller rows)
    let s0: AB::Expr = local.chiplets[S_START].into();
    let s1: AB::Expr = local.chiplets[S_START + 1].into();
    let s2: AB::Expr = local.chiplets[S_START + 2].into();

    // Node index and mrupdate_id for sibling table
    let node_index: AB::Expr = local.chiplets[IDX_COL].into();
    let node_index_next: AB::Expr = next.chiplets[IDX_COL].into();
    let mrupdate_id: AB::Expr = local.chiplets[MRUPDATE_ID_COL].into();

    // Hasher state for sibling values
    let h: [AB::Expr; 12] = core::array::from_fn(|i| local.chiplets[H_START + i].into());

    // =========================================================================
    // SIBLING TABLE FLAGS AND VALUES
    // =========================================================================

    // In the controller/perm split, sibling table operations happen on controller input rows
    // for MU (new path - requests/removes) and MV (old path - responses/adds).
    // All MU/MV input rows participate (not just is_start=1).
    let f_mu: AB::Expr = controller_flag.clone() * flags::f_mu(s0.clone(), s1.clone(), s2.clone());
    let f_mv: AB::Expr = controller_flag.clone() * flags::f_mv(s0.clone(), s1.clone(), s2.clone());

    // Direction bit b = input_node_index - 2 * output_node_index (next row is the paired output).
    let b: AB::Expr = node_index.clone() - node_index_next.clone().double();
    let is_b_zero = one.clone() - b.clone();
    let is_b_one = b;

    // Sibling value from the current input row's state, including mrupdate_id for domain
    // separation. b selects which half of the rate holds the sibling.
    let v_sibling = compute_sibling_b0::<AB>(challenges, &mrupdate_id, &node_index, &h) * is_b_zero
        + compute_sibling_b1::<AB>(challenges, &mrupdate_id, &node_index, &h) * is_b_one;

    // =========================================================================
    // ACE MEMORY FLAGS AND VALUES
    // =========================================================================

    // ACE chiplet selector: s0=1, s1=1, s2=1, s3=0
    let s3: AB::Expr = local.chiplets[3].into();
    let chiplet_s1: AB::Expr = local.chiplets[1].into();
    let chiplet_s2: AB::Expr = local.chiplets[2].into();

    let is_ace_row: AB::Expr =
        chiplet_selector.clone() * chiplet_s1.clone() * chiplet_s2.clone() * (one.clone() - s3);

    // Block selector determines read (0) vs eval (1)
    let block_selector: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + SELECTOR_BLOCK_IDX].into();

    let f_ace_read: AB::Expr = is_ace_row.clone() * (one.clone() - block_selector.clone());
    let f_ace_eval: AB::Expr = is_ace_row * block_selector;

    // ACE columns for memory messages
    let ace_clk: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + CLK_IDX].into();
    let ace_ctx: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + CTX_IDX].into();
    let ace_ptr: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + PTR_IDX].into();

    // Word read value: label + ctx + ptr + clk + 4-lane value.
    let v_ace_word = {
        let v0_0: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + V_0_0_IDX].into();
        let v0_1: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + V_0_1_IDX].into();
        let v1_0: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + V_1_0_IDX].into();
        let v1_1: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + V_1_1_IDX].into();
        let label: AB::Expr = AB::Expr::from(Felt::from_u8(MEMORY_READ_WORD_LABEL));

        challenges.encode(
            bus_types::CHIPLETS_BUS,
            [label, ace_ctx.clone(), ace_ptr.clone(), ace_clk.clone(), v0_0, v0_1, v1_0, v1_1],
        )
    };

    // Element read value: label + ctx + ptr + clk + element.
    let v_ace_element = {
        let id_1: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + ID_1_IDX].into();
        let id_2: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + ID_2_IDX].into();
        let eval_op: AB::Expr = local.chiplets[NUM_ACE_SELECTORS + EVAL_OP_IDX].into();

        let offset1: AB::Expr = AB::Expr::from(ACE_INSTRUCTION_ID1_OFFSET);
        let offset2: AB::Expr = AB::Expr::from(ACE_INSTRUCTION_ID2_OFFSET);
        let element = id_1 + id_2 * offset1 + (eval_op + one.clone()) * offset2;
        let label: AB::Expr = AB::Expr::from(Felt::from_u8(MEMORY_READ_ELEMENT_LABEL));

        challenges.encode(bus_types::CHIPLETS_BUS, [label, ace_ctx, ace_ptr, ace_clk, element])
    };

    // =========================================================================
    // LOG PRECOMPILE FLAGS AND VALUES
    // =========================================================================

    let f_logprecompile: AB::Expr = op_flags.log_precompile();

    // CAP_PREV from helper registers (provided and constrained by the decoder logic).
    let cap_prev: [AB::Expr; 4] = core::array::from_fn(|i| {
        local.decoder.hasher_state[2 + HELPER_CAP_PREV_RANGE.start + i].into()
    });

    // CAP_NEXT from next-row stack.
    let cap_next: [AB::Expr; 4] =
        core::array::from_fn(|i| next.stack.get(STACK_CAP_NEXT_RANGE.start + i).into());

    let log_label: AB::Expr = AB::Expr::from(Felt::from_u8(LOG_PRECOMPILE_LABEL));

    // CAP_PREV value (request - removed).
    let v_cap_prev = challenges.encode(
        bus_types::LOG_PRECOMPILE_TRANSCRIPT,
        [
            log_label.clone(),
            cap_prev[0].clone(),
            cap_prev[1].clone(),
            cap_prev[2].clone(),
            cap_prev[3].clone(),
        ],
    );

    // CAP_NEXT value (response - inserted).
    let v_cap_next = challenges.encode(
        bus_types::LOG_PRECOMPILE_TRANSCRIPT,
        [
            log_label,
            cap_next[0].clone(),
            cap_next[1].clone(),
            cap_next[2].clone(),
            cap_next[3].clone(),
        ],
    );

    // =========================================================================
    // RUNNING PRODUCT CONSTRAINT
    // =========================================================================

    // Include the identity term when no request/response flag is set on a row.
    // Flags are mutually exclusive by construction (chiplet selectors + op flags).
    let request_flag_sum =
        f_mu.clone() + f_ace_read.clone() + f_ace_eval.clone() + f_logprecompile.clone();
    let requests: AB::ExprEF = v_sibling.clone() * f_mu
        + v_ace_word * f_ace_read
        + v_ace_element * f_ace_eval
        + v_cap_prev * f_logprecompile.clone()
        + (one_ef.clone() - request_flag_sum);

    let response_flag_sum = f_mv.clone() + f_logprecompile.clone();
    let responses: AB::ExprEF =
        v_sibling * f_mv + v_cap_next * f_logprecompile + (one_ef - response_flag_sum);

    // Running product constraint: p' * requests = p * responses
    let p_local_ef: AB::ExprEF = p_local.into();
    let p_next_ef: AB::ExprEF = p_next.into();

    builder
        .when_transition()
        .assert_zero_ext(p_next_ef * requests - p_local_ef * responses);
}

// INTERNAL HELPERS
// ================================================================================================

/// Sibling at h[4..8] (b=0): positions [1, 2, 7, 8, 9, 10].
/// Position 1 = mrupdate_id, position 2 = node_index, positions 7-10 = sibling (rate1).
const SIBLING_B0_LAYOUT: [usize; 6] = [1, 2, 7, 8, 9, 10];

/// Sibling at h[0..4] (b=1): positions [1, 2, 3, 4, 5, 6].
/// Position 1 = mrupdate_id, position 2 = node_index, positions 3-6 = sibling (rate0).
const SIBLING_B1_LAYOUT: [usize; 6] = [1, 2, 3, 4, 5, 6];

/// Compute sibling value when b=0 (sibling at h[4..8], i.e., rate1).
///
/// Message: `alpha + beta[1]*mrupdate_id + beta[2]*node_index + beta[7..11]*h[4..8]`
fn compute_sibling_b0<AB>(
    challenges: &Challenges<AB::ExprEF>,
    mrupdate_id: &AB::Expr,
    node_index: &AB::Expr,
    h: &[AB::Expr; 12],
) -> AB::ExprEF
where
    AB: LiftedAirBuilder<F = Felt>,
{
    challenges.encode_sparse(
        bus_types::SIBLING_TABLE,
        SIBLING_B0_LAYOUT,
        [
            mrupdate_id.clone(),
            node_index.clone(),
            h[4].clone(),
            h[5].clone(),
            h[6].clone(),
            h[7].clone(),
        ],
    )
}

/// Compute sibling value when b=1 (sibling at h[0..4], i.e., rate0).
///
/// Message: `alpha + beta[1]*mrupdate_id + beta[2]*node_index + beta[3..7]*h[0..4]`
fn compute_sibling_b1<AB>(
    challenges: &Challenges<AB::ExprEF>,
    mrupdate_id: &AB::Expr,
    node_index: &AB::Expr,
    h: &[AB::Expr; 12],
) -> AB::ExprEF
where
    AB: LiftedAirBuilder<F = Felt>,
{
    challenges.encode_sparse(
        bus_types::SIBLING_TABLE,
        SIBLING_B1_LAYOUT,
        [
            mrupdate_id.clone(),
            node_index.clone(),
            h[0].clone(),
            h[1].clone(),
            h[2].clone(),
            h[3].clone(),
        ],
    )
}
