//! UintMul chiplet — the scaled MAC `κₐ·a·b + κ_c·c ≡ r (mod p)` over
//! stored uints.
//!
//! A **relation** AIR over the [UintStore](crate::uint): it mints no
//! value. `a`, `b`, `c`, `r` and the modulus all live in the store —
//! the convolution operands (`a`, `b`, the modulus) are pulled in over
//! the raw 8×16 [`UintLimbs`](crate::relations::BusId::UintLimbs) view,
//! the linear operands (`c`, `r`) over the 4×32
//! [`UintVal`](crate::relations::BusId::UintVal) view — and this chiplet
//! ties their ptrs to the MAC identity, *providing* the
//! [`UintMul`](crate::relations::BusId::UintMul) relation, consumed by the
//! eval chip's mul `UintOp` nodes (the scaled shapes await the ECC gadget).
//!
//! See the design notes for the full design.
//!
//! ## The identity (vertical Schwartz–Zippel)
//!
//! With the store holding `bound = p − 1`, witnessed quotient `q` and
//! carry polynomial `Γ`, the check at the LogUp challenge β is
//!
//! ```text
//! κₐ·a(β)·b(β) + κ_c·C(β²) − q(β)·(bound(β) + 1) − R(β²) + (β − t)·Γ(β) = 0
//! ```
//!
//! at `t = 2¹⁶`: `a`, `b`, `bound`, `q` are 16-bit limb polynomials
//! (`q` runs to 17 limbs — `q ≤ κₐ·p + κ_c` overflows 16 for `κₐ ≥ 2`
//! on a full-size modulus); the linear `c` / `r` enter as their 4×32
//! views at even powers (`C(β²) = Σ Cₖβ²ᵏ`). `E(X)` has degree ≤ 31,
//! so `Γ = −E_pre/(X − t)` has **31 coefficients** `γ₀..γ₃₀`, each
//! committed sign-offset as `γ'ₖ = γₖ + 2³¹ ∈ [0, 2³²)` in two
//! `Range16`-checked 16-bit halves. The offset correction folds into
//! the γ-lo terms, so every block sums to zero and the `id` register
//! closes at the `c` row, exactly like the store's range check.
//!
//! **No-wrap:** limbs are 16-bit (store-checked, inherited through the
//! `UintLimbs` tie — never re-checked here), `κₐ, κ_c < 2¹⁶`
//! (`Range16`-checked locally), carries `< 2³²` ⟹ every coefficient of
//! `E(X)` stays below `≈ 2⁵³ ≪ p_Goldilocks/2`, so `E(β) = 0` at random
//! β forces the integer MAC. Soundness is unconditional; the **small-κ
//! contract** (`κ ≲ 2⁹`) is a completeness condition only — beyond it
//! the honest carries outgrow their `2³²` window and nothing proves.
//!
//! ## Liquid layout (period 8, folded closing)
//!
//! Only lookups impose shape: the bus-facing operands keep their limbs
//! co-resident in a single row (no more lo/hi split), while the local
//! witnesses `q` / `Γ` flow into every remaining cell — each placement
//! is one precomputed-weight term in the `id` accumulator plus one
//! `Range16` fraction. Nineteen cells per row pack the 148 committed
//! values into exactly 8 live rows:
//!
//! | row | role | cells 0–15 / 0–16 | cells past the limbs |
//! |-----|------|--------------------|------------------------|
//! | 0   | `a`  | a's 16-bit limbs (0–15) | γ spill (16–18) |
//! | 1   | `b`  | b's limbs (0–15) | γ spill (16–18) |
//! | 2   | `p`  | bound's limbs (0–15) | γ spill (16–18) |
//! | 3   | `q`  | q₀..q₁₆ (0–16) | γ spill (17–18) |
//! | 4   | `r`  | r's 4×32 halves (0–7) | γ spill (8–18) |
//! | 5   | `g0` | — | γ (0–18, all cells) |
//! | 6   | `g1` | — | γ (0–14; 15–18 spare) |
//! | 7   | `c`  | c's 4×32 halves (0–7) | mult, c_ptr, κ_c, is_sub, κ_c_signed (8–12); γ spill (13–18) |
//!
//! ([`GAMMA_SLOTS`] is the single placement table the AIR, trace-gen
//! and prover all read.) The `c` row folds the old dedicated term row's
//! role: it's both the last operand row of the block *and* the closing
//! row, so its own contribution — not yet folded into `id` by the time
//! its own row is evaluated — is reconstructed locally (mirroring
//! [`UintAdd`](crate::uint::add)'s `p_own` pattern) and asserted
//! directly instead of relying on a dedicated all-metadata successor
//! row to stay at a hard-pinned zero.
//!
//! ## Registers
//!
//! Two ext-field aux registers beyond the LogUp columns (σ-excluded via
//! `num_logup_cols`):
//!
//! - **`S`** (staging): builds `κₐ·a(β)` on the `a` row, holds through the `b` row (whose `id`
//!   contribution `S·b(β)` lands the degree-2 product at constraint degree 3), resets, builds
//!   `bound(β)` on the `p` row, holds through the `q` row (`−(S+1)·q(β)` — the `+1` is `p = bound +
//!   1`), resets. One register serves both products via the periodic keep gate [`S_KEEP`].
//! - **`id`**: accumulates every role's contribution; `when_first_row` pins 0, the `c` row's folded
//!   check asserts the block closes to 0.
//!
//! ## Padding
//!
//! A padding block is all-zero rows with `act = 0`: the boolean
//! cycle-constant `act` gates every consume and `Range16` flag (and the
//! γ offset constant), so padding emits nothing on any bus and every
//! register transition holds over zeros. No sentinel, no demand.

pub mod trace;

use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_crypto::stark::air::ExtensionBuilder;
use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder};

use crate::{
    logup::{
        Challenges, CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder,
        LookupColumn, LookupGroup, LookupMessage, NUM_PUBLIC_VALUES, NUM_RANDOMNESS,
        NUM_SIGMA_VALUES,
    },
    primitives::byte_pair_lut::Range16Msg,
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    uint::{UintLimbsMsg, UintValMsg},
    utils::{current_main, next_main},
};

// MESSAGES
// ================================================================================================

/// LogUp message for the [`UintMul`](BusId::UintMul) relation: the
/// 8-tuple `(κₐ, κ_c, a_ptr, b_ptr, c_ptr, r_ptr, bound_ptr, is_sub)`
/// asserting `κₐ·a·b + κ_c·c ≡ r (mod p)` (or `κₐ·a·b − κ_c·c ≡ r` when
/// `is_sub = 1`) for stored uints sharing the modulus at `bound_ptr`.
/// *Provided* by [`UintMulAir`] at the op's consumer count; consumed by
/// the eval chip's mul `UintOp` nodes in the plain `κₐ = 1, κ_c = 0`
/// arrangement and by the EC group law's fused MAC certificates.
///
/// The κ's ride the tuple so a consumer demands the exact scale it
/// wants — sub-limb constants (2, 3, …) for fused ECC formulas, κ_c = 0
/// to kill the addend (pure mul / div arrangements need no zero uint).
/// `is_sub` is a distinct relation flag, so an additive provide can never
/// satisfy a subtractive consume.
///
/// Encoded as `bus_prefix[UintMul] + β⁰·κₐ + β¹·κ_c + β²·a_ptr +
/// β³·b_ptr + β⁴·c_ptr + β⁵·r_ptr + β⁶·bound_ptr + β⁷·is_sub`.
#[derive(Debug, Clone)]
pub struct UintMulMsg<E> {
    pub kappa_a: E,
    pub kappa_c: E,
    pub a_ptr: E,
    pub b_ptr: E,
    pub c_ptr: E,
    pub r_ptr: E,
    pub bound_ptr: E,
    /// `0` for the additive shape `κₐ·a·b + κ_c·c ≡ r`, `1` for the
    /// subtractive `κₐ·a·b − κ_c·c ≡ r` — a distinct relation the consumer
    /// demands exactly, so an add provide can never satisfy a sub consume.
    pub is_sub: E,
}

impl<E, EF> LookupMessage<E, EF> for UintMulMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::UintMul as usize,
            [
                self.kappa_a.clone(),
                self.kappa_c.clone(),
                self.a_ptr.clone(),
                self.b_ptr.clone(),
                self.c_ptr.clone(),
                self.r_ptr.clone(),
                self.bound_ptr.clone(),
                self.is_sub.clone(),
            ],
        )
    }
}

// COLUMN LAYOUT
// ================================================================================================

/// Limb/witness cells per row — 19 cells host either 16/17 bus-facing
/// limbs plus γ spill, or (on the `r`/`c` rows) 8 bus-facing 32-bit
/// limbs plus γ spill / term metadata.
pub const NUM_CELLS: usize = 19;
/// `a`'s pointer (cycle-constant per block).
pub const COL_A_PTR: usize = NUM_CELLS;
/// `b`'s pointer (cycle-constant).
pub const COL_B_PTR: usize = NUM_CELLS + 1;
/// `r`'s pointer — the witnessed result (cycle-constant).
pub const COL_R_PTR: usize = NUM_CELLS + 2;
/// the shared modulus's pointer = `bound_ptr` (cycle-constant).
pub const COL_BOUND_PTR: usize = NUM_CELLS + 3;
/// the product scale κₐ (cycle-constant; `Range16`-checked on the `c` row).
pub const COL_KAPPA_A: usize = NUM_CELLS + 4;
/// Block-active flag `act ∈ {0, 1}` (cycle-constant): 1 on real op
/// blocks, 0 on padding; gates every bus flag + the γ offset constant.
pub const COL_ACT: usize = NUM_CELLS + 5;
/// Subtractive-underflow borrow `∈ {0, 1, 2}` (cycle-constant): the moduli
/// the canonical reduction adds back when `is_sub` and the product
/// `< κ_c·c` (up to 2 for the `κ_c = 2` doubling `λ² − 2x₁`). Read on the
/// `p` row (where `bound(β)` is live) to contribute `borrow·(bound(β)+1)`
/// to the SZ identity. Pinned to 0 unless `is_sub`.
pub const COL_BORROW: usize = NUM_CELLS + 6;
pub const NUM_MAIN_COLS: usize = NUM_CELLS + 7;

/// Block period: one mul op = 8 rows, all live.
pub const PERIOD: usize = 8;

// Row roles (also the periodic one-hot indices: selector `i` fires on
// row `i`).
pub const ROW_A: usize = 0;
pub const ROW_B: usize = 1;
pub const ROW_P: usize = 2;
pub const ROW_Q: usize = 3;
pub const ROW_R: usize = 4;
pub const ROW_G0: usize = 5;
pub const ROW_G1: usize = 6;
/// The closing row: hosts `c`'s limbs, the term metadata, and the
/// block's folded closing check.
pub const ROW_C: usize = 7;

/// The periodic `S`-keep gate `g`: `S' = g·S + build`. 1 across each
/// build-and-use span (the `a` row into the `b` row, the `p` row into
/// the `q` row), 0 on the resets after `b` / `q` and across the tail.
pub const S_KEEP: [u64; PERIOD] = [1, 0, 1, 0, 0, 0, 0, 0];
const PCOL_S_KEEP: usize = PERIOD;
const NUM_PERIODIC: usize = PERIOD + 1;

// Term-metadata cells, now hosted on the `c` row past its 8 raw limbs
// (the `c` row reads them locally — no more `next`-row access, since
// there's no separate term row anymore).
pub const TERM_CELL_MULT: usize = 8;
pub const TERM_CELL_C_PTR: usize = 9;
pub const TERM_CELL_KAPPA_C: usize = 10;
/// Subtractive-mode flag `is_sub ∈ {0, 1}`, local to the `c` row.
pub const TERM_CELL_IS_SUB: usize = 11;
/// The witnessed signed scale `κ_c_signed = κ_c·(1 − 2·is_sub)`, pinned
/// locally by a degree-2 constraint (`κ_c`, `is_sub` are both `c`-row-local
/// cells). Hoists the `κ_c·(1 − 2·is_sub)` product out of the `id`-register
/// `linear` contribution so that contribution stays a single local
/// multiplication instead of two.
pub const TERM_CELL_KAPPA_C_SIGNED: usize = 12;

/// Quotient limbs: `q ≤ κₐ·p + κ_c < 2²⁷²` needs 17.
pub const NUM_Q_LIMBS: usize = 17;
/// Carry coefficients: `deg E_pre = 31` (the 17-limb `q` times the
/// 16-limb bound) ⟹ `deg Γ = 30`.
pub const NUM_GAMMA: usize = 31;
/// Committed γ cells: each coefficient as offset (lo, hi) 16-bit halves.
pub const NUM_GAMMA_SLOTS: usize = 2 * NUM_GAMMA;

/// The liquid placement table: `GAMMA_SLOTS[s] = (row, cell)` hosting
/// the γ-half `s` — coefficient `s / 2`, lo half for even `s`, hi for
/// odd. Shared verbatim by the AIR (weights), trace-gen (placement) and
/// prover (the `id` mirror), so the three cannot drift.
pub const GAMMA_SLOTS: [(usize, usize); NUM_GAMMA_SLOTS] = gamma_slots();

const fn gamma_slots() -> [(usize, usize); NUM_GAMMA_SLOTS] {
    let mut slots = [(0usize, 0usize); NUM_GAMMA_SLOTS];
    let mut s = 0;
    // g0: every cell.
    let mut cell = 0;
    while cell < NUM_CELLS {
        slots[s] = (ROW_G0, cell);
        s += 1;
        cell += 1;
    }
    // g1: cells 0..15 (15 used, cells 15..19 spare).
    let mut cell = 0;
    while cell < 15 {
        slots[s] = (ROW_G1, cell);
        s += 1;
        cell += 1;
    }
    // a, b, p: each spill 3 cells (16..19) past their 16 raw limbs.
    let solid16 = [ROW_A, ROW_B, ROW_P];
    let mut i = 0;
    while i < solid16.len() {
        let mut cell = 16;
        while cell < NUM_CELLS {
            slots[s] = (solid16[i], cell);
            s += 1;
            cell += 1;
        }
        i += 1;
    }
    // q: spills 2 cells (17..19) past its 17 raw limbs.
    let mut cell = NUM_Q_LIMBS;
    while cell < NUM_CELLS {
        slots[s] = (ROW_Q, cell);
        s += 1;
        cell += 1;
    }
    // r: spills 11 cells (8..19) past its 8 raw (32-bit, unchecked-here) limbs.
    let mut cell = 8;
    while cell < NUM_CELLS {
        slots[s] = (ROW_R, cell);
        s += 1;
        cell += 1;
    }
    // c: spills 6 cells (13..19) past its 8 raw limbs + 5 term-metadata cells.
    let mut cell = TERM_CELL_KAPPA_C_SIGNED + 1;
    while cell < NUM_CELLS {
        slots[s] = (ROW_C, cell);
        s += 1;
        cell += 1;
    }
    slots
}

// Aux layout: col 0 = LogUp running sum (the UintMul provide), the raw
// UintLimbs consumes, Range16 on every cell position, the two κ
// Range16s, and the 4×32 UintVal consumes, then the Schwartz–Zippel
// `id` and staging `S` registers (excluded from σ via num_logup_cols).
// FLATTENED to lqd 1: every fraction is an act-gated degree-2
// multiplicity, paired ≤ 2 per column (col 0 a single fraction; the
// odd cell count leaves one Range16 column a singleton too) → every
// constraint degree ≤ 3.
const NUM_RAW_CONSUMES: usize = 3; // a, b, bound
const NUM_RAW_CONSUME_COLS: usize = NUM_RAW_CONSUMES.div_ceil(2);
const NUM_RANGE16_COLS: usize = NUM_CELLS.div_ceil(2);
/// Exposed so [`UintStoreMulAir`](crate::uint::store_mul::UintStoreMulAir)
/// can concatenate this chiplet's column shape onto the store's own
/// instead of hand-duplicating the derived column count.
pub(crate) const NUM_LOGUP_COLS: usize = 1 // the UintMul provide
    + NUM_RAW_CONSUME_COLS // the three merged raw UintLimbs consumes (a, b, bound)
    + NUM_RANGE16_COLS // Range16 on every cell position
    + 1 // the two κ Range16s
    + 1; // the merged 4×32 UintVal consumes (r, c)
const REG_ID: usize = NUM_LOGUP_COLS;
const REG_S: usize = NUM_LOGUP_COLS + 1;
const AUX_WIDTH: usize = NUM_LOGUP_COLS + 2;

const fn column_shape() -> [usize; NUM_LOGUP_COLS] {
    let mut shape = [2usize; NUM_LOGUP_COLS];
    shape[0] = 1;
    // The raw-consume block (3 messages, ≤ 2 per column) has a singleton
    // tail.
    if NUM_RAW_CONSUMES % 2 == 1 {
        shape[NUM_RAW_CONSUME_COLS] = 1;
    }
    // The Range16 block starts right after; if NUM_CELLS is odd its last
    // column is a singleton too.
    if NUM_CELLS % 2 == 1 {
        shape[1 + NUM_RAW_CONSUME_COLS + NUM_RANGE16_COLS - 1] = 1;
    }
    shape
}
pub(crate) const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = column_shape();

/// The γ sign offset `2³¹` (carries are committed as `γ + 2³¹`).
pub(crate) const GAMMA_OFFSET: u32 = 1 << 31;

// AIR
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
pub struct UintMulAir;

impl BaseAir<Felt> for UintMulAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        // One one-hot per row role, then the S-keep gate.
        (0..PERIOD)
            .map(|row| {
                let mut col = vec![Felt::ZERO; PERIOD];
                col[row] = Felt::ONE;
                col
            })
            .chain(core::iter::once(S_KEEP.iter().map(|&g| Felt::from(g as u32)).collect()))
            .collect()
    }
}

impl LiftedAir<Felt, QuadFelt> for UintMulAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        AUX_WIDTH
    }

    fn num_aux_values(&self) -> usize {
        NUM_SIGMA_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        trace::build_aux(main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

        let sel: [AB::Expr; NUM_PERIODIC] = {
            let p = builder.periodic_values();
            array::from_fn(|i| p[i].into())
        };

        // β⁰..β³¹ (the γ weights reach (β − t)·β³⁰).
        let beta: AB::ExprEF = builder.permutation_randomness()[1].into();
        let mut bp: Vec<AB::ExprEF> = Vec::with_capacity(NUM_GAMMA + 1);
        bp.push(AB::ExprEF::ONE);
        for i in 1..NUM_GAMMA + 1 {
            bp.push(bp[i - 1].clone() * beta.clone());
        }
        let t16: AB::Expr = AB::Expr::from(Felt::from(1u32 << 16));
        let x_minus_t: AB::ExprEF = beta - t16.clone();
        let offset: AB::Expr = AB::Expr::from(Felt::from(GAMMA_OFFSET));

        let kappa_a: AB::Expr = local[COL_KAPPA_A].into();
        let act: AB::Expr = local[COL_ACT].into();
        // κ_c_signed is now local to the `c` row (see
        // `TERM_CELL_KAPPA_C_SIGNED`) — no more `next`-row access, since
        // the `c` row hosts its own term metadata directly.
        let kappa_c_signed_local: AB::Expr = local[TERM_CELL_KAPPA_C_SIGNED].into();

        // Registers.
        let id: AB::ExprEF =
            current_main::<_, AB::VarEF, 1>(builder.permutation(), REG_ID)[0].into();
        let id_next: AB::ExprEF =
            next_main::<_, AB::VarEF, 1>(builder.permutation(), REG_ID)[0].into();
        let s: AB::ExprEF = current_main::<_, AB::VarEF, 1>(builder.permutation(), REG_S)[0].into();
        let s_next: AB::ExprEF =
            next_main::<_, AB::VarEF, 1>(builder.permutation(), REG_S)[0].into();

        // Weighted cell sums: the 16-limb operands (a/b/bound, cells
        // 0–15), the 17-limb quotient (cells 0–16), and the linear r/c
        // operands (4×32 limbs at even powers, cells 0–7).
        let full16_sum: AB::ExprEF =
            (0..16).fold(AB::ExprEF::ZERO, |acc, i| acc + bp[i].clone() * AB::Expr::from(local[i]));
        let full_q_sum: AB::ExprEF = (0..NUM_Q_LIMBS)
            .fold(AB::ExprEF::ZERO, |acc, i| acc + bp[i].clone() * AB::Expr::from(local[i]));
        let val_sum: AB::ExprEF = (0..8)
            .fold(AB::ExprEF::ZERO, |acc, m| acc + bp[2 * m].clone() * AB::Expr::from(local[m]));

        // S: build κₐ·a(β) on the `a` row, bound(β) on the `p` row;
        // hold / reset per the periodic keep gate.
        let build: AB::ExprEF = full16_sum.clone() * (sel[ROW_A].clone() * kappa_a)
            + full16_sum.clone() * sel[ROW_P].clone();
        let keep: AB::Expr = sel[PCOL_S_KEEP].clone();
        builder.when_first_row().assert_zero_ext(s.clone());
        builder.when_transition().assert_zero_ext(s_next - s.clone() * keep - build);

        // id contributions.
        // The product: S = κₐ·a(β) through the `b` row.
        let product = s.clone() * full16_sum.clone() * sel[ROW_B].clone();
        // The quotient: S = bound(β) through the `q` row; q(β)·(bound(β)+1).
        let quotient = (s + AB::ExprEF::ONE) * full_q_sum * sel[ROW_Q].clone();
        // The linear operands: 4×32 limbs at even powers, both halves on
        // one row. κ_c_signed is local to the `c` row.
        let linear = val_sum.clone() * (sel[ROW_C].clone() * kappa_c_signed_local.clone())
            - val_sum.clone() * sel[ROW_R].clone();
        // The carries: per slot, w(s) = (β − t)·β^k (·2¹⁶ for hi halves);
        // the lo halves carry the −2³¹ offset correction, act-gated so
        // all-zero padding blocks contribute nothing.
        let mut carries = AB::ExprEF::ZERO;
        for (slot, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
            let k = slot / 2;
            let mut w = x_minus_t.clone() * bp[k].clone();
            if slot % 2 == 1 {
                w *= t16.clone();
            }
            let mut gated: AB::Expr = sel[row].clone() * AB::Expr::from(local[cell]);
            if slot % 2 == 0 {
                gated -= sel[row].clone() * act.clone() * offset.clone();
            }
            carries += w * gated;
        }

        // The subtractive borrow: when `is_sub` and `κₐ·a·b < κ_c·c`, the
        // canonical reduction wraps up by one p, so the identity carries
        // `+borrow·(bound(β)+1)`. Contributed on the `p` row, where
        // bound(β) is live as the full limb sum; the +1 of `p = bound + 1`
        // rides β⁰.
        let borrow: AB::Expr = local[COL_BORROW].into();
        let borrow_contrib: AB::ExprEF =
            (full16_sum + AB::ExprEF::ONE) * (sel[ROW_P].clone() * borrow.clone());

        let contrib: AB::ExprEF = product - quotient + linear + carries + borrow_contrib;
        builder.when_first_row().assert_zero_ext(id.clone());
        builder.when_transition().assert_zero_ext(id_next - id.clone() - contrib);

        // The closing row (`c`) has a nonzero contribution of its own —
        // its `κ_c_signed · val_sum` linear term plus its share of γ — so
        // the closure check folds it in directly instead of reading it
        // back from `id_next`. That keeps the check local to the block's
        // last row, so it also covers the trace's final block: relying on
        // `id_next` would read the wrap-around first row's pinned zero
        // regardless of whether that last block actually closed. Built
        // from `c`'s own cells only (not the shared `contrib`, whose
        // other-role terms carry their own periodic gates and would
        // needlessly bloat this constraint's degree once multiplied by
        // `sel[ROW_C]`).
        let mut c_own: AB::ExprEF = val_sum * kappa_c_signed_local.clone();
        for (slot, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
            if row == ROW_C {
                let k = slot / 2;
                let mut w = x_minus_t.clone() * bp[k].clone();
                if slot % 2 == 1 {
                    w *= t16.clone();
                }
                let mut gated: AB::Expr = AB::Expr::from(local[cell]);
                if slot % 2 == 0 {
                    gated -= act.clone() * offset.clone();
                }
                c_own += w * gated;
            }
        }
        builder.assert_zero_ext((id + c_own) * sel[ROW_C].clone());

        // act is the boolean block-active flag (cycle-constant).
        builder.assert_zero(act.clone() * (AB::Expr::ONE - act.clone()));

        // `is_sub` (`c`-row cell) is boolean; `borrow` (cycle-constant)
        // ∈ {0, 1, 2} — a `κ_c = 2` double (`λ² − 2x₁`) underflows by up to
        // 2p — and only fires in the subtractive mode (`borrow ⟹ is_sub`),
        // so an additive op cannot smuggle a +p shift onto its quotient.
        let is_sub: AB::Expr = local[TERM_CELL_IS_SUB].into();
        builder.assert_zero(sel[ROW_C].clone() * is_sub.clone() * (AB::Expr::ONE - is_sub.clone()));

        // κ_c_signed = κ_c · (1 − 2·is_sub), pinned `c`-row-local (both
        // operands live on this row), so `linear` above can read it via a
        // single local witness. Degree 2 (`κ_c` × `is_sub`), well under
        // the lqd-1 budget.
        let kappa_c_local: AB::Expr = local[TERM_CELL_KAPPA_C].into();
        let c_sign_local: AB::Expr = AB::Expr::ONE - is_sub.double();
        builder.assert_zero(
            sel[ROW_C].clone() * (kappa_c_signed_local - kappa_c_local * c_sign_local),
        );

        let two = AB::Expr::from(Felt::from(2u32));
        builder.assert_zero(
            borrow.clone() * (borrow.clone() - AB::Expr::ONE) * (borrow.clone() - two),
        );
        builder.assert_zero(sel[ROW_C].clone() * borrow * (AB::Expr::ONE - is_sub));

        // A provide must come from an active block. The `UintMul` provide is
        // gated only by `sel[ROW_C]` (not `act`), and the operand consumes
        // are act-gated — so an `act = 0` block with zeroed limbs (the SZ
        // registers close trivially) and a witnessed `c`-row `mult` would
        // provide a *false* relation onto the bus. Force the mult to 0 when
        // act = 0.
        builder
            .assert_zero(sel[ROW_C].clone() * (AB::Expr::ONE - act) * local[TERM_CELL_MULT].into());

        // Cycle-constancy: ptrs / κₐ / act are constant within a block
        // (every row but the terminal one).
        let not_term: AB::Expr = AB::Expr::ONE - sel[ROW_C].clone();
        for col in
            [COL_A_PTR, COL_B_PTR, COL_R_PTR, COL_BOUND_PTR, COL_KAPPA_A, COL_ACT, COL_BORROW]
        {
            let here: AB::Expr = local[col].into();
            let there: AB::Expr = next[col].into();
            builder.assert_zero(not_term.clone() * (there - here));
        }

        // Phase 2: LogUp — the UintMul provide + Range16 + the
        // operand consumes.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

impl<LB> LookupAir<LB> for UintMulAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        NUM_LOGUP_COLS
    }

    fn column_shape(&self) -> &[usize] {
        &COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, builder: &mut LB) {
        let local: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);

        let sel: [LB::Expr; NUM_PERIODIC] = {
            let p = builder.periodic_values();
            array::from_fn(|i| p[i].into())
        };

        let a_ptr: LB::Expr = local[COL_A_PTR].into();
        let b_ptr: LB::Expr = local[COL_B_PTR].into();
        let r_ptr: LB::Expr = local[COL_R_PTR].into();
        let bound_ptr: LB::Expr = local[COL_BOUND_PTR].into();
        let kappa_a: LB::Expr = local[COL_KAPPA_A].into();
        let act: LB::Expr = local[COL_ACT].into();
        let c_ptr_local: LB::Expr = local[TERM_CELL_C_PTR].into();
        let kappa_c_local: LB::Expr = local[TERM_CELL_KAPPA_C].into();
        let neg_mult: LB::Expr = LB::Expr::ZERO - local[TERM_CELL_MULT].into();

        let provide_deg = Deg { v: 2, u: 1 };
        let consume_deg = Deg { v: 2, u: 1 };
        let rc_deg = Deg { v: 2, u: 1 };
        // Flattened columns hold ≤ 2 degree-2 fractions → constraint degree ≤ 3.
        let pair_deg = Deg { v: 3, u: 2 };

        // The two 8×16 halves of a/b/bound's 16-limb value on this row —
        // reused across whichever of the three raw-limb rows is active.
        let raw_lo: [LB::Expr; 8] = array::from_fn(|i| local[i].into());
        let raw_hi: [LB::Expr; 8] = array::from_fn(|i| local[8 + i].into());
        let val_lo: [LB::Expr; 4] = array::from_fn(|k| local[k].into());
        let val_hi: [LB::Expr; 4] = array::from_fn(|k| local[4 + k].into());

        // Flattened LogUp (lqd 1): every fraction is an act-gated degree-2
        // multiplicity, paired ≤ 2 per column (col 0 a single fraction).

        // col 0 (running sum): the UintMul provide.
        builder.next_column(
            |col| {
                col.group(
                    "uintmul",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "provide-uintmul",
                                    neg_mult.clone() * sel[ROW_C].clone(),
                                    UintMulMsg {
                                        kappa_a: kappa_a.clone(),
                                        kappa_c: kappa_c_local.clone(),
                                        a_ptr: a_ptr.clone(),
                                        b_ptr: b_ptr.clone(),
                                        c_ptr: c_ptr_local.clone(),
                                        r_ptr: r_ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                        is_sub: local[TERM_CELL_IS_SUB].into(),
                                    },
                                    provide_deg,
                                );
                            },
                            provide_deg,
                        );
                    },
                    provide_deg,
                );
            },
            provide_deg,
        );

        // cols 1..: the three merged raw 16×16 consumes (a, b, modulus),
        // two per col — each operand's full 16 limbs already live
        // together on its own row, so one message covers the whole
        // value.
        let raw_consumes: Vec<(LB::Expr, LB::Expr, [LB::Expr; 16])> =
            [(ROW_A, a_ptr.clone()), (ROW_B, b_ptr.clone()), (ROW_P, bound_ptr.clone())]
                .into_iter()
                .map(|(row, ptr)| {
                    let mult = sel[row].clone() * act.clone();
                    let limbs: [LB::Expr; 16] = array::from_fn(|i| {
                        if i < 8 {
                            raw_lo[i].clone()
                        } else {
                            raw_hi[i - 8].clone()
                        }
                    });
                    (mult, ptr, limbs)
                })
                .collect();
        for group in raw_consumes
            .chunks(2)
            .map(
                <[(
                    <LB as LookupBuilder>::Expr,
                    <LB as LookupBuilder>::Expr,
                    [<LB as LookupBuilder>::Expr; 16],
                )]>::to_vec,
            )
            .collect::<Vec<_>>()
        {
            builder.next_column(
                |col| {
                    col.group(
                        "uintlimbs",
                        |g| {
                            g.batch(
                                "f",
                                LB::Expr::ONE,
                                |b| {
                                    for (mult, ptr, limbs) in group {
                                        b.insert(
                                            "consume-uintlimbs",
                                            mult,
                                            UintLimbsMsg {
                                                ptr,
                                                bound_ptr: bound_ptr.clone(),
                                                limbs,
                                            },
                                            consume_deg,
                                        );
                                    }
                                },
                                pair_deg,
                            );
                        },
                        pair_deg,
                    );
                },
                pair_deg,
            );
        }

        // Range16 gates by cell position: a raw-limb gate (only `q`'s
        // limbs — a witness local to this chiplet — need re-checking
        // here; a/b/bound's raw limbs are inherited already-range16'd
        // from the store via the `UintLimbs` bus tie, so re-checking them
        // would demand a Range16 the store side never registers) plus a
        // γ-slot gate (every row that hosts a γ half at this exact cell
        // position, per `GAMMA_SLOTS` — this is what covers a/b/bound's
        // own γ spill on cells 16–18). `r`/`c`'s own 8×32 limbs (cells
        // 0–7) and `c`'s term-metadata cells never appear in either gate,
        // so they're excluded automatically — as are the dead cells on
        // `g1`'s tail.
        let raw16_gate = |cell: usize| -> LB::Expr {
            if cell < NUM_Q_LIMBS {
                sel[ROW_Q].clone()
            } else {
                LB::Expr::ZERO
            }
        };
        let gamma_gate = |cell: usize| -> LB::Expr {
            GAMMA_SLOTS
                .iter()
                .filter(|&&(_, c)| c == cell)
                .fold(LB::Expr::ZERO, |acc, &(row, _)| acc + sel[row].clone())
        };
        let cell_gate = |cell: usize| -> LB::Expr { raw16_gate(cell) + gamma_gate(cell) };

        // cols 4..4+NUM_RANGE16_COLS: Range16 on all nineteen cell
        // positions, two per column (the last column a singleton).
        let cell_specs: Vec<(LB::Expr, usize)> =
            (0..NUM_CELLS).map(|cell| (cell_gate(cell) * act.clone(), cell)).collect();
        for group in cell_specs
            .chunks(2)
            .map(<[(<LB as LookupBuilder>::Expr, usize)]>::to_vec)
            .collect::<Vec<_>>()
        {
            builder.next_column(
                |col| {
                    col.group(
                        "range16-cells",
                        |g| {
                            g.batch(
                                "f",
                                LB::Expr::ONE,
                                |b| {
                                    for (mult, cell) in group {
                                        b.insert(
                                            "range16-cell",
                                            mult,
                                            Range16Msg { w: local[cell].into() },
                                            rc_deg,
                                        );
                                    }
                                },
                                pair_deg,
                            );
                        },
                        pair_deg,
                    );
                },
                pair_deg,
            );
        }

        // col: the two κ Range16s (both on the `c` row).
        builder.next_column(
            |col| {
                col.group(
                    "range16-kappa",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "range16-kappa-a",
                                    sel[ROW_C].clone() * act.clone(),
                                    Range16Msg { w: kappa_a.clone() },
                                    rc_deg,
                                );
                                b.insert(
                                    "range16-kappa-c",
                                    sel[ROW_C].clone() * act.clone(),
                                    Range16Msg { w: kappa_c_local.clone() },
                                    rc_deg,
                                );
                            },
                            pair_deg,
                        );
                    },
                    pair_deg,
                );
            },
            pair_deg,
        );
        // col: the merged 4×32 UintVal consumes (r, then c) — one
        // message per operand now that both halves are local, so both
        // fit in a single column.
        let val_full: [LB::Expr; 8] = array::from_fn(|i| {
            if i < 4 {
                val_lo[i].clone()
            } else {
                val_hi[i - 4].clone()
            }
        });
        let val_consumes: [(usize, LB::Expr); 2] = [(ROW_R, r_ptr.clone()), (ROW_C, c_ptr_local)];
        builder.next_column(
            |col| {
                col.group(
                    "uintval",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                for (row, ptr) in val_consumes {
                                    b.insert(
                                        "consume-uintval",
                                        sel[row].clone() * act.clone(),
                                        UintValMsg {
                                            ptr,
                                            bound_ptr: bound_ptr.clone(),
                                            limbs: val_full.clone(),
                                        },
                                        consume_deg,
                                    );
                                }
                            },
                            pair_deg,
                        );
                    },
                    pair_deg,
                );
            },
            pair_deg,
        );
    }
}
