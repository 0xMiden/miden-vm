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
//! See `docs/chiplets/uint-mul.md` for the full design.
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
//! closes at the term row, exactly like the store's range check.
//!
//! **No-wrap:** limbs are 16-bit (store-checked, inherited through the
//! `UintLimbs` tie — never re-checked here), `κₐ, κ_c < 2¹⁶`
//! (`Range16`-checked locally), carries `< 2³²` ⟹ every coefficient of
//! `E(X)` stays below `≈ 2⁵³ ≪ p_Goldilocks/2`, so `E(β) = 0` at random
//! β forces the integer MAC. Soundness is unconditional; the **small-κ
//! contract** (`κ ≲ 2⁹`) is a completeness condition only — beyond it
//! the honest carries outgrow their `2³²` window and nothing proves.
//!
//! ## Liquid layout (period 16, zero dead rows)
//!
//! Only lookups impose shape: the bus-facing operands keep 8 limbs
//! co-resident per row (cells 0–7), while the local witnesses `q` / `Γ`
//! flow into every remaining cell — each placement is one
//! precomputed-weight term in the `id` accumulator plus one `Range16`
//! fraction. Ten cells per row pack the 146 committed values into
//! exactly 16 live rows:
//!
//! | row | role | cells 0–7 | cells 8–9 |
//! |-----|-------|--------------------------|------------|
//! | 0–1 | `a` lo/hi | a's 16-bit limbs | γ spill |
//! | 2–3 | `b` lo/hi | b's limbs | γ spill |
//! | 4–5 | `p` lo/hi | bound's limbs | γ spill |
//! | 6 | `q` lo | q₀..q₉ (all ten cells) | — |
//! | 7 | `q` hi | q₁₀..q₁₆ | γ spill (7–9) |
//! | 8–12 | `γ₀..γ₄` | nine γ halves each (0–8) | spare (9) |
//! | 13 | `r` | r's 4×32 halves | γ spill |
//! | 14 | `c` | c's 4×32 halves | spare |
//! | 15 | `term` | mult, c_ptr, κ_c (cells 0–2) | spare |
//!
//! ([`GAMMA_SLOTS`] is the single placement table the AIR, trace-gen
//! and prover all read.) The `c` row sits at term − 1 so `c_ptr` / `κ_c`
//! live as term-row cells read via next-row access — consume,
//! contribution and provide all read the *same* cell, so the tuple is
//! consistent by construction, no tie constraints.
//!
//! ## Registers
//!
//! Two ext-field aux registers beyond the LogUp columns (σ-excluded via
//! `num_logup_cols = 3`):
//!
//! - **`S`** (staging): builds `κₐ·a(β)` over the a-rows, holds through the b-rows (whose `id`
//!   contribution `S·Σbⱼβʲ` lands the degree-2 product at constraint degree 3), resets, builds
//!   `bound(β)`, holds through the q-rows (`−(S+1)·Σqᵢβⁱ` — the `+1` is `p = bound + 1`), resets.
//!   One register serves both products via the periodic keep gate [`S_KEEP`].
//! - **`id`**: accumulates every role's contribution; `when_first_row` pins 0, the term row asserts
//!   0.
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
};
use miden_crypto::stark::air::ExtensionBuilder;
use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder};
use p3_matrix::dense::RowMajorMatrix;

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
/// 7-tuple `(κₐ, κ_c, a_ptr, b_ptr, c_ptr, r_ptr, bound_ptr)` asserting
/// `κₐ·a·b + κ_c·c ≡ r (mod p)` for stored uints sharing the modulus at
/// `bound_ptr`. *Provided* by [`UintMulAir`] at the op's consumer count;
/// consumed by the eval chip's mul `UintOp` nodes in the plain
/// `κₐ = 1, κ_c = 0` arrangement (the scaled shapes await the ECC
/// gadget).
///
/// The κ's ride the tuple so a consumer demands the exact scale it
/// wants — sub-limb constants (2, 3, …) for fused ECC formulas, κ_c = 0
/// to kill the addend (pure mul / div arrangements need no zero uint).
///
/// Encoded as `bus_prefix[UintMul] + β⁰·κₐ + β¹·κ_c + β²·a_ptr +
/// β³·b_ptr + β⁴·c_ptr + β⁵·r_ptr + β⁶·bound_ptr`.
#[derive(Debug, Clone)]
pub struct UintMulMsg<E> {
    pub kappa_a: E,
    pub kappa_c: E,
    pub a_ptr: E,
    pub b_ptr: E,
    pub c_ptr: E,
    pub r_ptr: E,
    pub bound_ptr: E,
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
            ],
        )
    }
}

// COLUMN LAYOUT
// ================================================================================================

/// Limb/witness cells per row — 8 bus-facing limbs plus 2 liquid cells.
pub const NUM_CELLS: usize = 10;
/// `a`'s pointer (cycle-constant per block).
pub const COL_A_PTR: usize = 10;
/// `b`'s pointer (cycle-constant).
pub const COL_B_PTR: usize = 11;
/// `r`'s pointer — the witnessed result (cycle-constant).
pub const COL_R_PTR: usize = 12;
/// the shared modulus's pointer = `bound_ptr` (cycle-constant).
pub const COL_BOUND_PTR: usize = 13;
/// the product scale κₐ (cycle-constant; `Range16`-checked on term rows).
pub const COL_KAPPA_A: usize = 14;
/// Block-active flag `act ∈ {0, 1}` (cycle-constant): 1 on real op
/// blocks, 0 on padding; gates every bus flag + the γ offset constant.
pub const COL_ACT: usize = 15;
pub const NUM_MAIN_COLS: usize = 16;

/// Block period: one mul op = 16 rows, all live.
pub const PERIOD: usize = 16;

// Row roles (also the periodic one-hot indices: selector `i` fires on
// row `i`).
pub const ROW_A_LO: usize = 0;
pub const ROW_A_HI: usize = 1;
pub const ROW_B_LO: usize = 2;
pub const ROW_B_HI: usize = 3;
pub const ROW_P_LO: usize = 4;
pub const ROW_P_HI: usize = 5;
pub const ROW_Q_LO: usize = 6;
pub const ROW_Q_HI: usize = 7;
pub const ROW_G0: usize = 8;
pub const ROW_G4: usize = 12;
pub const ROW_R: usize = 13;
pub const ROW_C: usize = 14;
pub const ROW_TERM: usize = 15;

/// The periodic `S`-keep gate `g`: `S' = g·S + build`. 1 across each
/// build-and-use span (a-rows into the b-rows, p-rows into the q-rows),
/// 0 on the resets after `b_hi` / `q_hi` and across the tail.
pub const S_KEEP: [u64; PERIOD] = [1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const PCOL_S_KEEP: usize = PERIOD;
const NUM_PERIODIC: usize = PERIOD + 1;

// Term-row metadata cells (the c row reads them via next-row access;
// the provide reads them locally — same cell, consistent by
// construction).
pub const TERM_CELL_MULT: usize = 0;
pub const TERM_CELL_C_PTR: usize = 1;
pub const TERM_CELL_KAPPA_C: usize = 2;

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
    // The five dedicated γ rows: cells 0–8 (cell 9 spare, keeping the
    // per-row Range16 batch at nine fractions).
    let mut row = ROW_G0;
    while row <= ROW_G4 {
        let mut cell = 0;
        while cell < 9 {
            slots[s] = (row, cell);
            s += 1;
            cell += 1;
        }
        row += 1;
    }
    // The solid rows' liquid cells (8, 9).
    let solid = [ROW_A_LO, ROW_A_HI, ROW_B_LO, ROW_B_HI, ROW_P_LO, ROW_P_HI];
    let mut i = 0;
    while i < solid.len() {
        slots[s] = (solid[i], 8);
        slots[s + 1] = (solid[i], 9);
        s += 2;
        i += 1;
    }
    // q_hi's tail cells past the seven high q limbs.
    let mut cell = 7;
    while cell < 10 {
        slots[s] = (ROW_Q_HI, cell);
        s += 1;
        cell += 1;
    }
    // The r row's liquid cells close the count at 62.
    slots[s] = (ROW_R, 8);
    slots[s + 1] = (ROW_R, 9);
    slots
}

// Aux layout: col 0 = LogUp running sum (the UintMul provide +
// the six raw UintLimbs consumes), col 1 = Range16 on the bus-facing
// cell positions, col 2 = Range16 on the liquid/κ positions + the 4×32
// UintVal consumes, cols 12/13 = the Schwartz–Zippel `id` and staging `S`
// registers (excluded from σ via num_logup_cols = 12). FLATTENED to lqd 1:
// all 23 fractions are act-gated degree-2 multiplicities, so they pair ≤ 2
// per column (col 0 a single fraction) → every constraint degree ≤ 3.
// Width disregarded (research/logup-flatten).
const NUM_LOGUP_COLS: usize = 12;
const REG_ID: usize = 12;
const REG_S: usize = 13;
const AUX_WIDTH: usize = 14;
const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = [1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2];

/// The γ sign offset `2³¹` (carries are committed as `γ + 2³¹`).
const GAMMA_OFFSET: u32 = 1 << 31;

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
        let mut bp: Vec<AB::ExprEF> = Vec::with_capacity(2 * PERIOD);
        bp.push(AB::ExprEF::ONE);
        for i in 1..2 * PERIOD {
            bp.push(bp[i - 1].clone() * beta.clone());
        }
        let t16: AB::Expr = AB::Expr::from(Felt::from(1u32 << 16));
        let x_minus_t: AB::ExprEF = beta - t16.clone();
        let offset: AB::Expr = AB::Expr::from(Felt::from(GAMMA_OFFSET));

        let kappa_a: AB::Expr = local[COL_KAPPA_A].into();
        let act: AB::Expr = local[COL_ACT].into();
        let kappa_c_next: AB::Expr = next[TERM_CELL_KAPPA_C].into();

        // Registers.
        let id: AB::ExprEF =
            current_main::<_, AB::VarEF, 1>(builder.permutation(), REG_ID)[0].into();
        let id_next: AB::ExprEF =
            next_main::<_, AB::VarEF, 1>(builder.permutation(), REG_ID)[0].into();
        let s: AB::ExprEF = current_main::<_, AB::VarEF, 1>(builder.permutation(), REG_S)[0].into();
        let s_next: AB::ExprEF =
            next_main::<_, AB::VarEF, 1>(builder.permutation(), REG_S)[0].into();

        // Weighted cell sums over the 8 bus-facing limbs (cells 0–7).
        let limb_sum = |from: usize| -> AB::ExprEF {
            (0..8).fold(AB::ExprEF::ZERO, |acc, i| {
                acc + bp[from + i].clone() * AB::Expr::from(local[i])
            })
        };
        let lo_sum = limb_sum(0);
        let hi_sum = limb_sum(8);

        // S: build κₐ·a(β) over the a-rows, bound(β) over the p-rows;
        // hold / reset per the periodic keep gate.
        let build: AB::ExprEF = lo_sum.clone() * (sel[ROW_A_LO].clone() * kappa_a.clone())
            + hi_sum.clone() * (sel[ROW_A_HI].clone() * kappa_a)
            + lo_sum.clone() * sel[ROW_P_LO].clone()
            + hi_sum.clone() * sel[ROW_P_HI].clone();
        let keep: AB::Expr = sel[PCOL_S_KEEP].clone();
        builder.when_first_row().assert_zero_ext(s.clone());
        builder.when_transition().assert_zero_ext(s_next - s.clone() * keep - build);

        // id contributions.
        // The product: S = κₐ·a(β) through the b-rows.
        let product =
            s.clone() * lo_sum * sel[ROW_B_LO].clone() + s.clone() * hi_sum * sel[ROW_B_HI].clone();
        // The quotient: S = bound(β) through the q-rows; q(β)·(bound(β)+1)
        // with q₀..q₉ on q_lo (all ten cells) and q₁₀..q₁₆ on q_hi.
        let q_lo_sum: AB::ExprEF = (0..NUM_CELLS)
            .fold(AB::ExprEF::ZERO, |acc, i| acc + bp[i].clone() * AB::Expr::from(local[i]));
        let q_hi_sum: AB::ExprEF = (0..NUM_Q_LIMBS - NUM_CELLS).fold(AB::ExprEF::ZERO, |acc, i| {
            acc + bp[NUM_CELLS + i].clone() * AB::Expr::from(local[i])
        });
        let quotient = (s + AB::ExprEF::ONE)
            * (q_lo_sum * sel[ROW_Q_LO].clone() + q_hi_sum * sel[ROW_Q_HI].clone());
        // The linear operands: 4×32 limbs at even powers, both halves on
        // one row. κ_c is read from the term row (next).
        let val_sum: AB::ExprEF = (0..8)
            .fold(AB::ExprEF::ZERO, |acc, m| acc + bp[2 * m].clone() * AB::Expr::from(local[m]));
        let linear =
            val_sum.clone() * (sel[ROW_C].clone() * kappa_c_next) - val_sum * sel[ROW_R].clone();
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

        let contrib: AB::ExprEF = product - quotient + linear + carries;
        builder.when_first_row().assert_zero_ext(id.clone());
        builder.when_transition().assert_zero_ext(id_next - id.clone() - contrib);
        builder.assert_zero_ext(id * sel[ROW_TERM].clone());

        // act is the boolean block-active flag (cycle-constant).
        builder.assert_zero(act.clone() * (AB::Expr::ONE - act.clone()));

        // A provide must come from an active block. The `UintMul` provide is
        // gated only by `sel[ROW_TERM]` (not `act`), and the operand consumes
        // are act-gated — so an `act = 0` block with zeroed limbs (the SZ
        // registers close trivially) and a witnessed term-row `mult` would
        // provide a *false* relation onto the bus. Force the mult to 0 when
        // act = 0.
        builder.assert_zero(
            sel[ROW_TERM].clone() * (AB::Expr::ONE - act) * local[TERM_CELL_MULT].into(),
        );

        // Cycle-constancy: ptrs / κₐ / act are constant within a block
        // (every row but the terminal one).
        let not_term: AB::Expr = AB::Expr::ONE - sel[ROW_TERM].clone();
        for col in [COL_A_PTR, COL_B_PTR, COL_R_PTR, COL_BOUND_PTR, COL_KAPPA_A, COL_ACT] {
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
        let next: [LB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

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
        let c_ptr_next: LB::Expr = next[TERM_CELL_C_PTR].into();
        let kappa_c_local: LB::Expr = local[TERM_CELL_KAPPA_C].into();
        let neg_mult: LB::Expr = LB::Expr::ZERO - local[TERM_CELL_MULT].into();

        // Column budget: every fraction column must stay inside the
        // degree-9 (lqd-3) envelope — at most 8 fractions with the act-
        // gated degree-2 multiplicities. The provide + the six raw
        // consumes share col 0 (7 fractions); the eight bus-facing cell
        // positions fill col 1; the two liquid positions, the two κ cells
        // and the four 4×32 consumes fill col 2.
        let provide_deg = Deg { v: 2, u: 1 };
        let consume_deg = Deg { v: 2, u: 1 };
        let rc_deg = Deg { v: 2, u: 1 };
        // Flattened columns hold ≤ 2 degree-2 fractions → constraint degree ≤ 3.
        let pair_deg = Deg { v: 3, u: 2 };

        let raw: [LB::Expr; 8] = array::from_fn(|i| local[i].into());
        let val_lo: [LB::Expr; 4] = array::from_fn(|k| local[k].into());
        let val_hi: [LB::Expr; 4] = array::from_fn(|k| local[4 + k].into());

        // Flattened LogUp (lqd 1): all 23 fractions are act-gated degree-2
        // multiplicities, paired ≤ 2 per column (col 0 a single fraction).

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
                                    neg_mult.clone() * sel[ROW_TERM].clone(),
                                    UintMulMsg {
                                        kappa_a: kappa_a.clone(),
                                        kappa_c: kappa_c_local.clone(),
                                        a_ptr: a_ptr.clone(),
                                        b_ptr: b_ptr.clone(),
                                        c_ptr: local[TERM_CELL_C_PTR].into(),
                                        r_ptr: r_ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
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

        // cols 1..3: the six raw 8×16 consumes (a, b, modulus), two per col.
        let raw_consumes: Vec<(LB::Expr, LB::Expr, LB::Expr)> = [
            (ROW_A_LO, a_ptr.clone()),
            (ROW_A_HI, a_ptr.clone()),
            (ROW_B_LO, b_ptr.clone()),
            (ROW_B_HI, b_ptr.clone()),
            (ROW_P_LO, bound_ptr.clone()),
            (ROW_P_HI, bound_ptr.clone()),
        ]
        .into_iter()
        .map(|(row, ptr)| {
            let offset = if row % 2 == 1 { LB::Expr::ONE } else { LB::Expr::ZERO };
            (sel[row].clone() * act.clone(), ptr, offset)
        })
        .collect();
        for group in raw_consumes
            .chunks(2)
            .map(
                <[(
                    <LB as LookupBuilder>::Expr,
                    <LB as LookupBuilder>::Expr,
                    <LB as LookupBuilder>::Expr,
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
                                    for (mult, ptr, offset) in group {
                                        b.insert(
                                            "consume-uintlimbs",
                                            mult,
                                            UintLimbsMsg {
                                                ptr,
                                                bound_ptr: bound_ptr.clone(),
                                                offset,
                                                limbs: raw.clone(),
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

        // Range16 gates by cell position per [`GAMMA_SLOTS`]: cells 0–7
        // host q limbs + the dedicated γ rows; cell 8 adds the solid
        // spills + r; cell 9 the same minus the γ rows (their cell 9 is
        // spare).
        let g_sum: LB::Expr =
            (ROW_G0..=ROW_G4).map(|r| sel[r].clone()).fold(LB::Expr::ZERO, |acc, s| acc + s);
        let solid_sum: LB::Expr = [ROW_A_LO, ROW_A_HI, ROW_B_LO, ROW_B_HI, ROW_P_LO, ROW_P_HI]
            .map(|r| sel[r].clone())
            .into_iter()
            .fold(LB::Expr::ZERO, |acc, s| acc + s);
        let q_sum: LB::Expr = sel[ROW_Q_LO].clone() + sel[ROW_Q_HI].clone();
        let cell_gate = |cell: usize| -> LB::Expr {
            match cell {
                0..=7 => q_sum.clone() + g_sum.clone(),
                8 => q_sum.clone() + g_sum.clone() + solid_sum.clone() + sel[ROW_R].clone(),
                _ => q_sum.clone() + solid_sum.clone() + sel[ROW_R].clone(),
            }
        };

        // cols 4..8: Range16 on all ten cell positions, two per column.
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

        // col 9: the two κ Range16s (both on the term row).
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
                                    sel[ROW_TERM].clone() * act.clone(),
                                    Range16Msg { w: kappa_a.clone() },
                                    rc_deg,
                                );
                                b.insert(
                                    "range16-kappa-c",
                                    sel[ROW_TERM].clone() * act.clone(),
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
        // cols 10..11: the 4×32 UintVal consumes (r, then c), lo+hi per col.
        let val_consumes: [(usize, LB::Expr); 2] = [(ROW_R, r_ptr.clone()), (ROW_C, c_ptr_next)];
        for (row, ptr) in val_consumes {
            builder.next_column(
                |col| {
                    col.group(
                        "uintval",
                        |g| {
                            g.batch(
                                "f",
                                LB::Expr::ONE,
                                |b| {
                                    for (offset, half) in [
                                        (LB::Expr::ZERO, val_lo.clone()),
                                        (LB::Expr::ONE, val_hi.clone()),
                                    ] {
                                        b.insert(
                                            "consume-uintval",
                                            sel[row].clone() * act.clone(),
                                            UintValMsg {
                                                ptr: ptr.clone(),
                                                bound_ptr: bound_ptr.clone(),
                                                offset,
                                                limbs: half,
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
}
