//! Wiring bus constraints (v_wiring).
//!
//! This module enforces the running-sum constraints for the shared v_wiring LogUp column.
//! The column carries contributions from three stacked chiplet regions:
//!
//! 1. **ACE wiring**: tracks node definitions and consumptions in the ACE circuit.
//! 2. **Memory range checks**: verifies w0, w1, 4*w1 are 16-bit via LogUp lookups.
//! 3. **Hasher perm-link**: links hasher controller rows to hasher permutation segment.
//!
//! ## Design
//!
//! Since the chiplet regions are stacked (mutually exclusive selectors), three separate
//! additive constraints gate each region's accumulation formula:
//!
//! ```text
//! ace_flag * (delta * D_ace - N_ace) = 0
//! memory_flag * (delta * D_mem + N_mem) = 0
//! hasher_flag * (delta * D_perm - N_perm) + idle_flag * delta = 0
//! ```
//!
//! The `idle_flag * delta` term is important as on bitwise, kernel-ROM, and padding rows, none of
//! the stacked `v_wiring` contributors are active, but the accumulator must still propagate
//! unchanged so its last-row boundary value remains bound to the earlier accumulation.
//!
//! TODO(Al): Revisit the above equations. The three assertions above could also be collapsed
//! into a single assertion later once we rebase and remove tags.

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::{LiftedAirBuilder, WindowAccess};

use crate::{
    Felt, MainTraceRow,
    constraints::{
        bus::indices::V_WIRING,
        chiplets::{
            hasher::periodic::{P_IS_EXT, P_IS_INIT_EXT, P_IS_INT_EXT, P_IS_PACKED_INT},
            selectors::{ace_chiplet_flag, memory_chiplet_flag},
        },
        tagging::{
            TagGroup, TaggingAirBuilderExt, ids::TAG_WIRING_BUS_BASE, tagged_assert_zero_ext,
        },
    },
    trace::{
        CHIPLETS_OFFSET, Challenges,
        chiplets::{
            HASHER_NODE_INDEX_COL_IDX, HASHER_PERM_SEG_COL_IDX, HASHER_STATE_COL_RANGE,
            MEMORY_WORD_ADDR_HI_COL_IDX, MEMORY_WORD_ADDR_LO_COL_IDX,
            ace::{
                CLK_IDX, CTX_IDX, ID_0_IDX, ID_1_IDX, ID_2_IDX, M_0_IDX, M_1_IDX,
                SELECTOR_BLOCK_IDX, V_0_0_IDX, V_0_1_IDX, V_1_0_IDX, V_1_1_IDX, V_2_0_IDX,
                V_2_1_IDX,
            },
        },
    },
};

// CONSTANTS
// ================================================================================================

const ACE_OFFSET: usize = 4;

const WIRING_BUS_ID: usize = TAG_WIRING_BUS_BASE;
const WIRING_BUS_NAME: &str = "chiplets.bus.wiring.transition";
const WIRING_MEM_NAME: &str = "chiplets.bus.wiring.memory_range";
const WIRING_PERM_LINK_NAME: &str = "chiplets.bus.wiring.hasher_perm_link";
const WIRING_BUS_NAMES: [&str; 3] = [WIRING_BUS_NAME, WIRING_MEM_NAME, WIRING_PERM_LINK_NAME];
const WIRING_BUS_TAGS: TagGroup = TagGroup {
    base: WIRING_BUS_ID,
    names: &WIRING_BUS_NAMES,
};

// ENTRY POINT
// ================================================================================================

/// Enforces the wiring bus constraints for all chiplet regions sharing V_WIRING.
///
/// Three separate additive constraints, one per stacked region:
/// ```text
/// ace_flag * (delta * D_ace - N_ace) = 0
/// memory_flag * (delta * D_mem + N_mem) = 0
/// hasher_flag * (delta * D_perm - N_perm) + idle_flag * delta = 0
/// ```
///
/// Each flag selects the correct accumulation formula for its row type. On idle rows
/// (bitwise, kernel-ROM, and padding), all stacked contributors are inactive, so the
/// `idle_flag * delta` term forces the shared accumulator to propagate unchanged.
pub fn enforce_wiring_bus_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    _next: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // --- Auxiliary trace access ---
    let (v_local, v_next) = {
        let aux = builder.permutation();
        let aux_local = aux.current_slice();
        let aux_next = aux.next_slice();
        (aux_local[V_WIRING], aux_next[V_WIRING])
    };

    let v_local_ef: AB::ExprEF = v_local.into();
    let v_next_ef: AB::ExprEF = v_next.into();
    let delta = v_next_ef - v_local_ef;

    // --- Periodic columns for hasher cycle detection ---
    // Row 0 = is_init_ext. Row 15 (boundary) = 1 - selector_sum.
    let (p_cycle_row_0, p_cycle_row_boundary) = {
        let p = builder.periodic_values();
        let row_0: AB::Expr = p[P_IS_INIT_EXT].into();
        let selector_sum: AB::Expr = Into::<AB::Expr>::into(p[P_IS_INIT_EXT])
            + Into::<AB::Expr>::into(p[P_IS_EXT])
            + Into::<AB::Expr>::into(p[P_IS_PACKED_INT])
            + Into::<AB::Expr>::into(p[P_IS_INT_EXT]);
        let row_boundary = AB::Expr::ONE - selector_sum;
        (row_0, row_boundary)
    };

    // --- Chiplet selectors ---
    let s0: AB::Expr = local.chiplets[0].clone().into();
    let s1: AB::Expr = local.chiplets[1].clone().into();
    let s2: AB::Expr = local.chiplets[2].clone().into();
    let s3: AB::Expr = local.chiplets[3].clone().into();

    let ace_flag = ace_chiplet_flag(s0.clone(), s1.clone(), s2.clone(), s3);
    let memory_flag = memory_chiplet_flag(s0.clone(), s1.clone(), s2);
    let hasher_flag = AB::Expr::ONE - s0.clone();
    let idle_flag = AB::Expr::ONE - ace_flag.clone() - memory_flag.clone() - hasher_flag.clone();

    // --- ACE term ---
    let ace_term = compute_ace_term::<AB>(&delta, ace_flag, local, challenges);

    // --- Memory term ---
    let mem_term = compute_memory_term::<AB>(&delta, memory_flag, local, challenges);

    // --- Hasher perm-link + idle propagation term ---
    let perm_link_term = compute_hasher_perm_link_term::<AB>(
        &delta,
        hasher_flag,
        idle_flag,
        local,
        challenges,
        p_cycle_row_0,
        p_cycle_row_boundary,
    );

    // --- Three separate constraints ---
    let mut idx = 0;
    tagged_assert_zero_ext(builder, &WIRING_BUS_TAGS, &mut idx, ace_term);
    tagged_assert_zero_ext(builder, &WIRING_BUS_TAGS, &mut idx, mem_term);
    tagged_assert_zero_ext(builder, &WIRING_BUS_TAGS, &mut idx, perm_link_term);
}

// ACE TERM
// ================================================================================================

/// Computes the ACE wiring contribution:
/// `ace_flag * (delta * D_ace - N_ace)`
fn compute_ace_term<AB>(
    delta: &AB::ExprEF,
    ace_flag: AB::Expr,
    local: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF
where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // Block selector: sblock = 0 for READ, sblock = 1 for EVAL
    let sblock: AB::Expr = load_ace_col::<AB>(local, SELECTOR_BLOCK_IDX);
    let is_read = AB::Expr::ONE - sblock.clone();
    let is_eval = sblock;

    // Load ACE columns
    let clk: AB::Expr = load_ace_col::<AB>(local, CLK_IDX);
    let ctx: AB::Expr = load_ace_col::<AB>(local, CTX_IDX);
    let wire_0 = encode_wire::<AB>(
        challenges,
        &clk,
        &ctx,
        &load_ace_wire::<AB>(local, ID_0_IDX, V_0_0_IDX, V_0_1_IDX),
    );
    let wire_1 = encode_wire::<AB>(
        challenges,
        &clk,
        &ctx,
        &load_ace_wire::<AB>(local, ID_1_IDX, V_1_0_IDX, V_1_1_IDX),
    );
    let wire_2 = encode_wire::<AB>(
        challenges,
        &clk,
        &ctx,
        &load_ace_wire::<AB>(local, ID_2_IDX, V_2_0_IDX, V_2_1_IDX),
    );
    let m0: AB::Expr = load_ace_col::<AB>(local, M_0_IDX);
    let m1: AB::Expr = load_ace_col::<AB>(local, M_1_IDX);

    // Common denominator
    let d_ace = wire_0.clone() * wire_1.clone() * wire_2.clone();

    // Numerator (not gated by ace_flag -- the outer gate handles it)
    // READ: m0 * w1 * w2 + m1 * w0 * w2
    // EVAL: m0 * w1 * w2 - w0 * w2 - w0 * w1
    let read_terms =
        wire_1.clone() * wire_2.clone() * m0.clone() + wire_0.clone() * wire_2.clone() * m1;
    let eval_terms = wire_1.clone() * wire_2.clone() * m0
        - wire_0.clone() * wire_2.clone()
        - wire_0.clone() * wire_1.clone();

    let n_ace = read_terms * is_read + eval_terms * is_eval;

    // ace_flag * (delta * D_ace - N_ace)
    (delta.clone() * d_ace - n_ace) * ace_flag
}

// MEMORY TERM
// ================================================================================================

/// Computes the memory range check contribution.
///
/// This is a SEPARATE constraint from the ACE wiring, using its own delta from the
/// V_WIRING aux column. It subtracts 3 LogUp fractions per memory row:
/// 1/(alpha+w0) + 1/(alpha+w1) + 1/(alpha+4w1).
fn compute_memory_term<AB>(
    delta: &AB::ExprEF,
    memory_flag: AB::Expr,
    local: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
) -> AB::ExprEF
where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let alpha = &challenges.alpha;

    // Load word-index limbs
    let w0: AB::Expr = local.chiplets[MEMORY_WORD_ADDR_LO_COL_IDX - CHIPLETS_OFFSET].clone().into();
    let w1: AB::Expr = local.chiplets[MEMORY_WORD_ADDR_HI_COL_IDX - CHIPLETS_OFFSET].clone().into();
    let w1_mul4: AB::Expr = w1.clone() * AB::Expr::from_u16(4);

    let den0: AB::ExprEF = alpha.clone() + Into::<AB::ExprEF>::into(w0);
    let den1: AB::ExprEF = alpha.clone() + Into::<AB::ExprEF>::into(w1);
    let den2: AB::ExprEF = alpha.clone() + Into::<AB::ExprEF>::into(w1_mul4);

    // Common denominator and numerator
    let common_den = den0.clone() * den1.clone() * den2.clone();
    let rhs = den1.clone() * den2.clone() + den0.clone() * den2 + den0 * den1;

    // memory_flag * (delta * common_den + rhs) = 0
    let memory_flag_ef: AB::ExprEF = memory_flag.into();
    (delta.clone() * common_den + rhs) * memory_flag_ef
}

// HASHER PERM-LINK TERM
// ================================================================================================

/// Computes the hasher perm-link contribution to the wiring bus and enforces idle propagation.
///
/// This links hasher controller rows (dispatch) to hasher permutation segment (compute):
/// - Hasher controller input (perm_seg=0, hs0=1): +1/msg_in
/// - Hasher controller output (perm_seg=0, hs0=0, hs1=0): +1/msg_out
/// - Hasher permutation cycle row 0 (`is_init_ext = 1`): -m/msg_in
/// - Hasher permutation boundary row (cycle row 15, i.e. `perm_seg=1` and all row-type selectors
///   are 0): -m/msg_out
/// - Idle bitwise / kernel-ROM / padding rows: `delta = 0`
///
/// Common-denominator form:
/// ```text
/// hasher_flag * (delta * msg_in * msg_out
///               - msg_out * (f_in - f_p_in * m)
///               - msg_in * (f_out - f_p_out * m))
/// + idle_flag * delta = 0
/// ```
fn compute_hasher_perm_link_term<AB>(
    delta: &AB::ExprEF,
    hasher_flag: AB::Expr,
    idle_flag: AB::Expr,
    local: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    p_cycle_row_0: AB::Expr,
    p_cycle_row_boundary: AB::Expr,
) -> AB::ExprEF
where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // --- Load hasher-internal selectors ---
    // chiplets[1] = hasher s0 (hs0), chiplets[2] = hasher s1 (hs1)
    let hs0: AB::Expr = local.chiplets[1].clone().into();
    let hs1: AB::Expr = local.chiplets[2].clone().into();

    // perm_seg column
    let perm_seg: AB::Expr =
        local.chiplets[HASHER_PERM_SEG_COL_IDX - CHIPLETS_OFFSET].clone().into();

    // node_index (= multiplicity on perm segment rows)
    let m: AB::Expr = local.chiplets[HASHER_NODE_INDEX_COL_IDX - CHIPLETS_OFFSET].clone().into();

    // --- Flags ---
    let one = AB::Expr::ONE;
    let ctrl = one.clone() - perm_seg.clone(); // 1 on controller rows

    // f_in: controller input row (perm_seg=0, hs0=1)
    let f_in = ctrl.clone() * hs0.clone();

    // f_out: controller output row (perm_seg=0, hs0=0, hs1=0)
    let f_out = ctrl * (one.clone() - hs0) * (one - hs1);

    // f_p_in: packed permutation row 0 (`is_init_ext = 1`)
    let f_p_in = perm_seg.clone() * p_cycle_row_0;

    // f_p_out: perm boundary row (perm_seg=1, cycle boundary)
    let f_p_out = perm_seg * p_cycle_row_boundary;

    // --- Messages ---
    // msg = challenges.encode([label, h0, h1, ..., h11]) -- 13 elements
    // TODO: labels 0/1 risk collisions with other v_wiring contributors (see hasher_perm.rs).
    let msg_in = encode_perm_link_message::<AB>(local, challenges, AB::Expr::ZERO);
    let msg_out = encode_perm_link_message::<AB>(local, challenges, AB::Expr::ONE);

    // --- Common-denominator constraint ---
    // hasher_flag * (delta * msg_in * msg_out
    //               - msg_out * (f_in - f_p_in * m)
    //               - msg_in * (f_out - f_p_out * m)) = 0
    let f_in_ef: AB::ExprEF = f_in.into();
    let f_out_ef: AB::ExprEF = f_out.into();
    let f_p_in_m: AB::ExprEF = (f_p_in * m.clone()).into();
    let f_p_out_m: AB::ExprEF = (f_p_out * m).into();

    let perm_link_term = delta.clone() * msg_in.clone() * msg_out.clone()
        - msg_out * (f_in_ef - f_p_in_m)
        - msg_in * (f_out_ef - f_p_out_m);

    let idle_term: AB::ExprEF = delta.clone() * Into::<AB::ExprEF>::into(idle_flag);

    perm_link_term * hasher_flag + idle_term
}

/// Encodes a perm-link message: `challenges.encode([label, h0, h1, ..., h11])`.
fn encode_perm_link_message<AB>(
    local: &MainTraceRow<AB::Var>,
    challenges: &Challenges<AB::ExprEF>,
    label: AB::Expr,
) -> AB::ExprEF
where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let h_start = HASHER_STATE_COL_RANGE.start - CHIPLETS_OFFSET;

    // Build array: [label, h0, h1, ..., h11]
    let label_ef: AB::ExprEF = label.into();
    let mut acc = challenges.alpha.clone() + challenges.beta_powers[0].clone() * label_ef;
    for i in 0..12 {
        let h_i: AB::ExprEF = local.chiplets[h_start + i].clone().into().into();
        acc += challenges.beta_powers[1 + i].clone() * h_i;
    }
    acc
}

// INTERNAL HELPERS
// ================================================================================================

struct AceWire<Expr> {
    id: Expr,
    v0: Expr,
    v1: Expr,
}

fn load_ace_wire<AB>(
    row: &MainTraceRow<AB::Var>,
    id_idx: usize,
    v0_idx: usize,
    v1_idx: usize,
) -> AceWire<AB::Expr>
where
    AB: LiftedAirBuilder<F = Felt>,
{
    AceWire {
        id: load_ace_col::<AB>(row, id_idx),
        v0: load_ace_col::<AB>(row, v0_idx),
        v1: load_ace_col::<AB>(row, v1_idx),
    }
}

fn encode_wire<AB>(
    challenges: &Challenges<AB::ExprEF>,
    clk: &AB::Expr,
    ctx: &AB::Expr,
    wire: &AceWire<AB::Expr>,
) -> AB::ExprEF
where
    AB: LiftedAirBuilder<F = Felt>,
{
    challenges.encode([clk.clone(), ctx.clone(), wire.id.clone(), wire.v0.clone(), wire.v1.clone()])
}

fn load_ace_col<AB>(row: &MainTraceRow<AB::Var>, ace_col_idx: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let local_idx = ACE_OFFSET + ace_col_idx;
    row.chiplets[local_idx].clone().into()
}
