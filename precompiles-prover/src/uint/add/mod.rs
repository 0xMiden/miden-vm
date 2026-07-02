//! UintAdd chiplet — modular addition `a + b ≡ c (mod p)` over stored uints.
//!
//! A **relation** AIR over the [UintStore](crate::uint): it mints no value.
//! `a`, `b`, `c` and the modulus all live in the store and are pulled in
//! over [`UintVal`](crate::relations::BusId::UintVal); this chiplet just ties
//! their ptrs to the modular-sum identity and *provides* the
//! [`UintAdd`](crate::relations::BusId::UintAdd) relation, consumed by the
//! eval chip's add / sub / neg `UintOp` nodes.
//!
//! See `docs/chiplets/uint-add.md` for the full design.
//!
//! ## The identity (vertical Schwartz–Zippel)
//!
//! `a, b < p ⟹ a + b < 2p`, so at most one modulus subtraction:
//!
//! ```text
//! a + b − k·p = c,    k ∈ {0, 1},    p = bound + 1
//! ```
//!
//! With the store holding `bound = p − 1` (so any modulus, incl. 2²⁵⁶, stays
//! representable), the looked-up value is `bound` and the `+1` becomes a `−k`
//! correction at `β⁰`. Verified at the LogUp challenge `β` by a single `id`
//! ext-field register (aux col 7, excluded from σ by `num_logup_cols = 7`):
//!
//! ```text
//! a(β) + b(β) − c(β) − k·bound(β) − k + (β − t)·Γ(β) = 0,    t = 2³²
//! Γ(β) = Σⱼ₌₀⁶ (γⱼ⁺ − γⱼ⁻)·βʲ
//! ```
//!
//! `D(X) = a + b − c − k·bound − k` has `D(t) = 0`, so `(X − t) ∣ D` with a
//! degree-6 quotient → exactly 7 carries `γ₀..γ₆`, **no top-carry slot** (the
//! bit-256 overflow cancels in the difference, since `a + b = c + k·p`). The
//! signed carry is split `γⱼ = γⱼ⁺ − γⱼ⁻` into the **binary carry chain of
//! `a+b`** (`γ⁺ = α`) and the **binary chain of `c+k·p`** (`γ⁻ = δ`) — both
//! `∈ {0, 1}`, checked by booleanity, no `Range16` on carries. Operands
//! inherit the store's 16-bit `Range16` through the `UintVal` tie; no-wrap
//! holds trivially (`|coeff| ≲ 2³⁵ ≪ 2⁶³`).
//!
//! ## Layout (period-4, one value per row)
//!
//! 8×32 per row (a whole 256-bit value): `a`, `b`, `c` and `p` each take a
//! single row, in that fixed order, and the two `UintVal` halves (offsets
//! 0/1) are both consumed from that one row. `p` sits last in the period, so
//! it doubles as the block's closing row — the `UintAdd` provide and the
//! `id == 0` assertion both fire there, with no dedicated term row.
//!
//! Every row's five cells past the limbs (8–12) host that row's own block
//! scalar plus a share of the seven-limb signed carry pair `γ⁺` / `γ⁻`: `a`
//! has no scalar of its own, so all five go to carries; `b` and `c` each
//! spend one on their zero-sentinel flag, `p` spends one on the reduction
//! bit `k` and one on the provide multiplicity — the rest carry `γ⁺` / `γ⁻`.
//! [`GAMMA_POS_SLOTS`] / [`GAMMA_NEG_SLOTS`] are the placement tables the
//! AIR, trace-gen and prover all read, mirroring the pattern
//! [`UintMul`](crate::uint::mul)'s `GAMMA_SLOTS` uses for its own carries:
//! the `id` accumulation is additive across rows, so splitting a carry
//! vector over several rows' spare cells costs nothing beyond the placement
//! table itself.
//!
//! Two zero-sentinel modes, one per operand row: **`is_c_zero`** drops the
//! `c` side (`a + b ≡ 0` — negation with an unstored zero result) and
//! **`is_b_zero`** drops the `b` side (`a + 0 ≡ c` — the stored-value
//! **equality certificate** `a = c`, both canonical under one modulus;
//! consumed e.g. by the EC group law's `x₁ = x₂` / `y₁ = y₂` case ties).
//!
//! | row | role | cells 0–7  | cells 8–12                                   |
//! |-----|------|------------|-----------------------------------------------|
//! | 0   | `a`  | a's limbs  | γ⁺₀..γ⁺₄                                       |
//! | 1   | `b`  | b's limbs  | `is_b_zero`@8, γ⁺₅ γ⁺₆ @9–10, γ⁻₀ γ⁻₁ @11–12    |
//! | 2   | `c`  | c's limbs  | `is_c_zero`@8, γ⁻₂ γ⁻₃ γ⁻₄ γ⁻₅ @9–12            |
//! | 3   | `p`  | p's limbs  | `k`@8, γ⁻₆@9, `mult`@12 (10–11 spare)          |

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
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    uint::UintValMsg,
    utils::{current_main, next_main},
};

// MESSAGES
// ================================================================================================

/// LogUp message for the [`UintAdd`](BusId::UintAdd) relation: the 4-tuple
/// `(bound_ptr, a_ptr, b_ptr, c_ptr)` asserting `a + b ≡ c (mod p)` for the
/// three stored uints sharing modulus `bound_ptr`. *Provided* by
/// [`UintAddAir`] at the op's consumer count; consumed by the eval chip's
/// add (`a + b = c`), sub (the arrangement `b + r = a`) and neg
/// (`c_ptr = 0`, the `is_c_zero` form) `UintOp` nodes, and by the EC
/// group law's certificates (including the `b_ptr = 0` `is_b_zero` form,
/// the equality certificate `a = c`). Address 0 is never stored, so a 0
/// ptr-slot always reads as "the unstored zero", never as a value.
///
/// Encoded as `bus_prefix[UintAdd] + β⁰·bound_ptr + β¹·a_ptr + β²·b_ptr +
/// β³·c_ptr`.
#[derive(Debug, Clone)]
pub struct UintAddMsg<E> {
    pub bound_ptr: E,
    pub a_ptr: E,
    pub b_ptr: E,
    pub c_ptr: E,
}

impl<E, EF> LookupMessage<E, EF> for UintAddMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::UintAdd as usize,
            [
                self.bound_ptr.clone(),
                self.a_ptr.clone(),
                self.b_ptr.clone(),
                self.c_ptr.clone(),
            ],
        )
    }
}

// COLUMN LAYOUT
// ================================================================================================

/// Limb cells per value row: the full 8×32-bit view (both `UintVal` halves)
/// laid on one row.
pub const NUM_LIMBS: usize = 8;
/// Cell columns per row: 8 limbs plus 5 scalar/carry cells (8–12).
pub const NUM_CELLS: usize = 13;
/// Scalar cell past the limbs holding this row's flag: `is_b_zero` on the
/// `b` row, `is_c_zero` on the `c` row, the reduction bit `k` on the `p`
/// row. Read locally by that row's role-gated constraints.
pub const CELL_FLAG: usize = 8;
/// `a`'s pointer (cycle-constant per block).
pub const COL_A_PTR: usize = NUM_CELLS;
/// `b`'s pointer (cycle-constant).
pub const COL_B_PTR: usize = NUM_CELLS + 1;
/// `c`'s pointer — the witnessed result (cycle-constant).
pub const COL_C_PTR: usize = NUM_CELLS + 2;
/// the shared modulus's pointer = `bound_ptr` (cycle-constant).
pub const COL_BOUND_PTR: usize = NUM_CELLS + 3;
/// Block-active flag `act ∈ {0, 1}` (cycle-constant): 1 on real op blocks,
/// 0 on padding. Gates every `UintVal` consume so an all-zero padding
/// block stays off the bus — with the zero sentinel gone, nothing provides
/// the `(0, 0, off, 0…)` tuples bare periodic flags would emit there.
pub const COL_ACT: usize = NUM_CELLS + 4;
pub const NUM_MAIN_COLS: usize = NUM_CELLS + 5;

/// B-row cell holding the `is_b_zero` flag: when set, `b` is the (unstored)
/// zero — the `+b(β)` term and the `b` `UintVal` consumes are dropped, and
/// `b_ptr` is forced to 0. The block then proves `a + 0 ≡ c (mod p)`, and
/// with `a`, `c` both stored canonical under the shared modulus that is
/// exactly the **equality certificate `a = c`** — value-level, ptr-free, no
/// zero pin.
pub const CELL_IS_B_ZERO: usize = CELL_FLAG;
/// C-row cell holding the `is_c_zero` flag: when set, `c` is the (unstored)
/// zero — the `−c(β)` term and the `c` `UintVal` consumes are dropped, and
/// `c_ptr` is forced to 0 (address 0 is never stored, so it reads as "none"
/// on the `UintAdd` bus). Lets `a + b ≡ 0 (mod p)` (negation: `b = −a`)
/// avoid referencing a stored zero, which can't be pinned untyped for an
/// arbitrary modulus.
pub const CELL_IS_C_ZERO: usize = CELL_FLAG;
/// P-row cell holding the boolean reduction bit `k`.
pub const CELL_K: usize = CELL_FLAG;
/// P-row cell holding the `UintAdd` provide multiplicity = consumer count
/// (one per eval `UintOp` node, 0 for bare ptr-space ops) — read only by
/// the closing row's provide.
pub const TERM_CELL_MULT: usize = 12;

/// Block period: one add op = 4 rows, `a` / `b` / `c` / `p` one row each.
pub const PERIOD: usize = 4;

// One-hot periodic role selectors (one column each, period 4): selector `i`
// fires on row `i`, so the role index doubles as the row index.
pub const ROW_A: usize = 0;
pub const ROW_B: usize = 1;
pub const ROW_C: usize = 2;
/// The modulus row, last in the period — it doubles as the block's closing
/// row (the `UintAdd` provide and the `id == 0` assertion both fire here).
pub const ROW_P: usize = 3;
const NUM_PERIODIC: usize = PERIOD;

/// Carry vector length: `deg Γ = 6` (see the module identity), 7 limbs.
pub const NUM_GAMMA: usize = 7;

/// The `γ⁺` (binary carry chain of `a + b`) placement table: slot `j` hosts
/// `γ⁺ⱼ` at `(row, cell)`. `a` has no scalar of its own so it hosts five;
/// `b` the remaining two, in the cells left over past its zero-sentinel
/// flag. Shared verbatim by the AIR (weights), trace-gen (placement) and
/// the aux builder (the `id` mirror), so the three cannot drift.
pub const GAMMA_POS_SLOTS: [(usize, usize); NUM_GAMMA] = [
    (ROW_A, 8),
    (ROW_A, 9),
    (ROW_A, 10),
    (ROW_A, 11),
    (ROW_A, 12),
    (ROW_B, 9),
    (ROW_B, 10),
];
/// The `γ⁻` (binary carry chain of `c + k·p`) placement table, continuing
/// where [`GAMMA_POS_SLOTS`] leaves off: two cells left on `b`, four on `c`
/// past its own flag, and one on `p` past its flag and the provide-mult
/// cell (cells 10–11 on `p` are unused).
pub const GAMMA_NEG_SLOTS: [(usize, usize); NUM_GAMMA] = [
    (ROW_B, 11),
    (ROW_B, 12),
    (ROW_C, 9),
    (ROW_C, 10),
    (ROW_C, 11),
    (ROW_C, 12),
    (ROW_P, 9),
];

// Aux layout (FLATTENED to lqd 1): cols 0..7 = LogUp fraction columns,
// one/two fractions each so every closing constraint is degree ≤ 3; col 7
// = the Schwartz–Zippel `id` register (excluded from σ via
// num_logup_cols = 7). The four gated b/c consumes carry degree-3
// multiplicities (`flag·(1−is_zero)·act`), so each sits alone; the
// degree-2 consumes/provide pair up; col 0 (the running sum) hosts a
// single degree-2 fraction (the gate adds +1, so a degree-3 multiplicity
// there would bust the budget). Width is disregarded — the point is to
// drop every per-AIR quotient coset to ×2 (research/logup-flatten).
const NUM_LOGUP_COLS: usize = 7;
const REGISTER_COL: usize = 7;
const AUX_WIDTH: usize = 8;
const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = [1, 2, 2, 1, 1, 1, 1];

// AIR
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
pub struct UintAddAir;

impl BaseAir<Felt> for UintAddAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        (0..PERIOD)
            .map(|row| {
                let mut col = vec![Felt::ZERO; PERIOD];
                col[row] = Felt::ONE;
                col
            })
            .collect()
    }
}

impl LiftedAir<Felt, QuadFelt> for UintAddAir {
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

        // Role selectors — the role index doubles as the row index.
        let sel: [AB::Expr; NUM_PERIODIC] = {
            let p = builder.periodic_values();
            array::from_fn(|i| p[i].into())
        };
        let a_sel = sel[ROW_A].clone();
        let b_sel = sel[ROW_B].clone();
        let c_sel = sel[ROW_C].clone();
        let p_sel = sel[ROW_P].clone();

        // β^0 .. β^7.
        let beta: AB::ExprEF = builder.permutation_randomness()[1].into();
        let mut bp: Vec<AB::ExprEF> = Vec::with_capacity(8);
        bp.push(AB::ExprEF::ONE);
        for i in 1..8 {
            bp.push(bp[i - 1].clone() * beta.clone());
        }
        let t32: AB::Expr = AB::Expr::from(Felt::new(1u64 << 32).expect("2^32 < Goldilocks p"));

        // `id` register on aux col 7.
        let id: AB::ExprEF =
            current_main::<_, AB::VarEF, 1>(builder.permutation(), REGISTER_COL)[0].into();
        let id_next: AB::ExprEF =
            next_main::<_, AB::VarEF, 1>(builder.permutation(), REGISTER_COL)[0].into();

        // The full 8×32 value on this row: Σⱼ limbⱼ·βʲ (t = 2³² is the limb
        // radix, so the 32-bit limbs recombine to the 256-bit value at β).
        let full_sum: AB::ExprEF =
            (0..8).fold(AB::ExprEF::ZERO, |s, j| s + bp[j].clone() * AB::Expr::from(local[j]));

        // Block scalars, read locally on their own rows.
        let is_b_zero: AB::Expr = local[CELL_IS_B_ZERO].into();
        let is_c_zero: AB::Expr = local[CELL_IS_C_ZERO].into();
        let k: AB::Expr = local[CELL_K].into();
        let b_active: AB::Expr = AB::Expr::ONE - is_b_zero.clone();
        let c_active: AB::Expr = AB::Expr::ONE - is_c_zero.clone();

        // Carry contributions: each slot's weight (β^{j+1} − t·βʲ) times its
        // hosting row's cell, gated by that row's own selector — whichever
        // physical row the placement table puts it on.
        let mut carry_pos: AB::ExprEF = AB::ExprEF::ZERO;
        for (j, &(row, cell)) in GAMMA_POS_SLOTS.iter().enumerate() {
            let w: AB::ExprEF = bp[j + 1].clone() - bp[j].clone() * t32.clone();
            carry_pos += w * sel[row].clone() * AB::Expr::from(local[cell]);
        }
        let mut carry_neg: AB::ExprEF = AB::ExprEF::ZERO;
        for (j, &(row, cell)) in GAMMA_NEG_SLOTS.iter().enumerate() {
            let w: AB::ExprEF = bp[j + 1].clone() - bp[j].clone() * t32.clone();
            carry_neg += w * sel[row].clone() * AB::Expr::from(local[cell]);
        }

        // Per-row `id` contributions (one selector fires per row, so the
        // cross terms vanish): +a, +b·(1−is_b_zero), −c·(1−is_c_zero),
        // −k·(bound(β)+1), ±carries (spread over whichever rows host them).
        let contrib: AB::ExprEF = full_sum.clone() * a_sel
            + full_sum.clone() * (b_sel.clone() * b_active)
            - full_sum.clone() * (c_sel.clone() * c_active)
            - (full_sum.clone() + bp[0].clone()) * (p_sel.clone() * k.clone())
            + carry_pos
            - carry_neg;

        builder.when_first_row().assert_zero_ext(id.clone());
        builder.when_transition().assert_zero_ext(id_next - id.clone() - contrib);

        // The closing row (`p`) has a nonzero contribution of its own — its
        // `−k·(bound(β)+1)` term plus its share of γ⁻ — so the closure check
        // folds it in directly instead of reading it back from `id_next`.
        // That keeps the check local to the block's last row, so it also
        // covers the trace's final block: relying on `id_next` would read
        // the wrap-around first row's pinned zero regardless of whether that
        // last block actually closed. Built from p's own cells only (not the
        // shared `contrib`, whose other-role terms carry their own periodic
        // gates and would needlessly bloat this constraint's degree once
        // multiplied by `p_sel`).
        let mut p_own: AB::ExprEF = -(full_sum + bp[0].clone()) * k.clone();
        for (j, &(row, cell)) in GAMMA_NEG_SLOTS.iter().enumerate() {
            if row == ROW_P {
                let w: AB::ExprEF = bp[j + 1].clone() - bp[j].clone() * t32.clone();
                p_own -= w * AB::Expr::from(local[cell]);
            }
        }
        builder.assert_zero_ext((id + p_own) * p_sel.clone());

        // k is the boolean reduction bit (p-row scalar).
        builder.assert_zero(p_sel.clone() * k.clone() * (AB::Expr::ONE - k));

        // act is the boolean block-active flag (cycle-constant).
        let act: AB::Expr = local[COL_ACT].into();
        builder.assert_zero(act.clone() * (AB::Expr::ONE - act.clone()));

        // A provide must come from an active block. The `UintAdd` provide is
        // gated only by `sel[ROW_P]` (not `act`), and the operand consumes
        // are act-gated — so an `act = 0` block with zeroed limbs (the SZ
        // closes trivially) and a witnessed closing-row `mult` would provide
        // a *false* relation onto the bus. Force the mult to 0 when act = 0.
        builder.assert_zero(
            p_sel.clone() * (AB::Expr::ONE - act.clone()) * local[TERM_CELL_MULT].into(),
        );

        // is_c_zero (a c-row scalar) is boolean, and forces c_ptr = 0 — the
        // zero result has no stored address, and the tuple's c_ptr = 0 reads
        // as "≡ 0" to a consumer.
        builder
            .assert_zero(c_sel.clone() * is_c_zero.clone() * (AB::Expr::ONE - is_c_zero.clone()));
        let c_ptr_local: AB::Expr = local[COL_C_PTR].into();
        builder.assert_zero(c_sel.clone() * is_c_zero.clone() * c_ptr_local);

        // is_b_zero (a b-row scalar) likewise: boolean, and forces b_ptr = 0
        // so the tuple reads as the `a + 0 ≡ c` equality form.
        builder
            .assert_zero(b_sel.clone() * is_b_zero.clone() * (AB::Expr::ONE - is_b_zero.clone()));
        let b_ptr_local: AB::Expr = local[COL_B_PTR].into();
        builder.assert_zero(b_sel.clone() * is_b_zero.clone() * b_ptr_local);

        // Carry booleanity: every γ⁺ / γ⁻ cell, gated by whichever row's
        // selector the placement table assigns it to.
        for &(row, cell) in GAMMA_POS_SLOTS.iter().chain(GAMMA_NEG_SLOTS.iter()) {
            let lj: AB::Expr = local[cell].into();
            builder.assert_zero(sel[row].clone() * lj.clone() * (AB::Expr::ONE - lj));
        }

        // Cycle-constancy: the four ptrs + act are constant within a block
        // (every row but the closing one, which the not_term gate drops at
        // the block boundary — the modulus row sits last in the period).
        let not_term: AB::Expr = AB::Expr::ONE - p_sel;
        for col in [COL_A_PTR, COL_B_PTR, COL_C_PTR, COL_BOUND_PTR, COL_ACT] {
            let here: AB::Expr = local[col].into();
            let there: AB::Expr = next[col].into();
            builder.assert_zero(not_term.clone() * (there - here));
        }

        // Phase 2: LogUp — UintVal consumes + the UintAdd provide.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

/// Emit one flattened LogUp column carrying a small batch of UintVal
/// consumes (multiplicity `flag·act`). With ≤ 2 degree-2 consumes (or one
/// degree-3 gated consume) per column, every closing constraint stays at
/// degree ≤ 3 → lqd 1. `col_deg` is an ignored hint on the constraint path.
fn consume_column<LB>(
    builder: &mut LB,
    bound_ptr: &LB::Expr,
    act: &LB::Expr,
    consumes: Vec<(LB::Expr, LB::Expr, LB::Expr, [LB::Expr; 4], Deg)>,
    col_deg: Deg,
) where
    LB: LookupBuilder<F = Felt>,
{
    builder.next_column(
        |col| {
            col.group(
                "uintadd",
                |g| {
                    g.batch(
                        "frac",
                        LB::Expr::ONE,
                        |b| {
                            for (flag, ptr, offset, msg_limbs, deg) in consumes {
                                b.insert(
                                    "consume-uintval",
                                    flag * act.clone(),
                                    UintValMsg {
                                        ptr,
                                        bound_ptr: bound_ptr.clone(),
                                        offset,
                                        limbs: msg_limbs,
                                    },
                                    deg,
                                );
                            }
                        },
                        col_deg,
                    );
                },
                col_deg,
            );
        },
        col_deg,
    );
}

impl<LB> LookupAir<LB> for UintAddAir
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
        let c_ptr: LB::Expr = local[COL_C_PTR].into();
        let bound_ptr: LB::Expr = local[COL_BOUND_PTR].into();
        let act: LB::Expr = local[COL_ACT].into();
        let neg_mult: LB::Expr = LB::Expr::ZERO - local[TERM_CELL_MULT].into();

        // The two 4×32 `UintVal` halves of the value on this row: the lo
        // half (cells 0..4, offset 0) and the hi half (cells 4..8, offset
        // 1). Both operand halves consume from the same row (a, b, c and p
        // each take one row), so no next-row read is needed.
        let lo: [LB::Expr; 4] = array::from_fn(|k| local[k].into());
        let hi: [LB::Expr; 4] = array::from_fn(|k| local[4 + k].into());

        // When is_c_zero (this row's flag cell), c is the unstored zero:
        // suppress its UintVal consumes (deg-3 multiplicities with the act
        // gate — inside the budget). is_b_zero suppresses the b consumes
        // the same way.
        let c_active: LB::Expr = LB::Expr::ONE - local[CELL_IS_C_ZERO].into();
        let b_active: LB::Expr = LB::Expr::ONE - local[CELL_IS_B_ZERO].into();

        let consume_deg = Deg { v: 2, u: 1 };
        let gated_consume_deg = Deg { v: 3, u: 1 };
        let provide_deg = Deg { v: 2, u: 1 };
        // Flattened columns hold ≤ 2 fractions; the mixed p-hi+provide column
        // is a 2-denominator batch (degree-3 numerator, degree-2 denominator).
        let cp_col_deg = Deg { v: 3, u: 2 };

        // Each operand consumes both `UintVal` halves from its own row. The
        // a/p multiplicities are `sel·act`; the gated b/c halves carry
        // `sel·(1−is_zero)·act` (degree 3). (flag, ptr, offset, limbs, deg).
        let a_lo = (sel[ROW_A].clone(), a_ptr.clone(), LB::Expr::ZERO, lo.clone(), consume_deg);
        let a_hi = (sel[ROW_A].clone(), a_ptr.clone(), LB::Expr::ONE, hi.clone(), consume_deg);
        let b_lo = (
            sel[ROW_B].clone() * b_active.clone(),
            b_ptr.clone(),
            LB::Expr::ZERO,
            lo.clone(),
            gated_consume_deg,
        );
        let b_hi = (
            sel[ROW_B].clone() * b_active,
            b_ptr.clone(),
            LB::Expr::ONE,
            hi.clone(),
            gated_consume_deg,
        );
        let c_lo = (
            sel[ROW_C].clone() * c_active.clone(),
            c_ptr.clone(),
            LB::Expr::ZERO,
            lo.clone(),
            gated_consume_deg,
        );
        let c_hi = (
            sel[ROW_C].clone() * c_active,
            c_ptr.clone(),
            LB::Expr::ONE,
            hi.clone(),
            gated_consume_deg,
        );
        let p_lo = (sel[ROW_P].clone(), bound_ptr.clone(), LB::Expr::ZERO, lo, consume_deg);
        let p_hi = (sel[ROW_P].clone(), bound_ptr.clone(), LB::Expr::ONE, hi, consume_deg);

        // Flattened LogUp (lqd 1), one/two fractions per column. The four
        // gated b/c consumes carry degree-3 multiplicities
        // (`flag·(1−is_zero)·act`) so each sits alone; the degree-2 a/p
        // consumes pair; the UintAdd provide rides with p-hi; col 0 (the
        // running sum) hosts a single degree-2 consume (the +1 gate forbids
        // a degree-3 one there).

        // col 0: a-lo (running sum, one degree-2 consume).
        consume_column(builder, &bound_ptr, &act, vec![a_lo], consume_deg);
        // col 1: a-hi + p-lo (two degree-2 consumes).
        consume_column(builder, &bound_ptr, &act, vec![a_hi, p_lo], consume_deg);
        // col 2: p-hi consume + the UintAdd provide (mixed batch, both deg-2).
        builder.next_column(
            |col| {
                col.group(
                    "uintadd-pp",
                    |g| {
                        g.batch(
                            "pp",
                            LB::Expr::ONE,
                            |b| {
                                let (flag, ptr, offset, msg_limbs, deg) = p_hi;
                                b.insert(
                                    "consume-uintval",
                                    flag * act.clone(),
                                    UintValMsg {
                                        ptr,
                                        bound_ptr: bound_ptr.clone(),
                                        offset,
                                        limbs: msg_limbs,
                                    },
                                    deg,
                                );
                                b.insert(
                                    "provide-uintadd",
                                    neg_mult.clone() * sel[ROW_P].clone(),
                                    UintAddMsg {
                                        bound_ptr: bound_ptr.clone(),
                                        a_ptr: a_ptr.clone(),
                                        b_ptr: b_ptr.clone(),
                                        c_ptr: c_ptr.clone(),
                                    },
                                    provide_deg,
                                );
                            },
                            cp_col_deg,
                        );
                    },
                    cp_col_deg,
                );
            },
            cp_col_deg,
        );
        // cols 3..6: the gated b/c consumes, one per column (degree-3 mult).
        consume_column(builder, &bound_ptr, &act, vec![b_lo], gated_consume_deg);
        consume_column(builder, &bound_ptr, &act, vec![b_hi], gated_consume_deg);
        consume_column(builder, &bound_ptr, &act, vec![c_lo], gated_consume_deg);
        consume_column(builder, &bound_ptr, &act, vec![c_hi], gated_consume_deg);
    }
}
