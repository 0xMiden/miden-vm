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
//! ## Layout (period-8, one value per row)
//!
//! 8×32 per row (a whole 256-bit value), so `a`, `b`, `c` and `p` each take
//! a single row; the two `UintVal` halves (offsets 0/1) are both consumed
//! from that one row. Each operand row hosts its own block scalar in the
//! cell past the limbs — `is_b_zero` on the `b` row, `is_c_zero` on the `c`
//! row, the reduction bit `k` on the `p` row — read locally, so no scalar
//! needs constancy transport. The carries take one row each; a `term` row
//! (hosting the provide mult) closes the SZ.
//!
//! Two zero-sentinel modes, one per operand row: **`is_c_zero`** drops the
//! `c` side (`a + b ≡ 0` — negation with an unstored zero result) and
//! **`is_b_zero`** drops the `b` side (`a + 0 ≡ c` — the stored-value
//! **equality certificate** `a = c`, both canonical under one modulus;
//! consumed e.g. by the EC group law's `x₁ = x₂` / `y₁ = y₂` case ties).
//!
//! | row | role   | cells 0–7 / scalar        | id contributes            |
//! |-----|--------|----------------------------|---------------------------|
//! | 0   | `a`    | a's 8×32 limbs             | `+a(β)`                   |
//! | 1   | `b`    | b's 8×32 limbs; `is_b_zero`@8 | `+b(β)·(1 − is_b_zero)` |
//! | 2   | `c`    | c's 8×32 limbs; `is_c_zero`@8 | `−c(β)·(1 − is_c_zero)` |
//! | 3   | `p`    | bound's 8×32 limbs; `k`@8  | `−k·(bound(β) + 1)`       |
//! | 4   | `cpos` | γ⁺₀..₆ (cells 0–6)         | `+Σ γ⁺ⱼ(β^{j+1} − t·βʲ)`  |
//! | 5   | `cneg` | γ⁻₀..₆ (cells 0–6)         | `−Σ γ⁻ⱼ(β^{j+1} − t·βʲ)`  |
//! | 6   | —      | (spare)                    | 0                         |
//! | 7   | `term` | `mult` (cell 0)            | assert `id = 0`           |

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
/// Scalar cell past the limbs holding this row's flag: `is_b_zero` on the
/// `b` row, `is_c_zero` on the `c` row, the reduction bit `k` on the `p`
/// row. Read locally by that row's role-gated constraints.
pub const CELL_FLAG: usize = 8;
/// `a`'s pointer (cycle-constant per block).
pub const COL_A_PTR: usize = 9;
/// `b`'s pointer (cycle-constant).
pub const COL_B_PTR: usize = 10;
/// `c`'s pointer — the witnessed result (cycle-constant).
pub const COL_C_PTR: usize = 11;
/// the shared modulus's pointer = `bound_ptr` (cycle-constant).
pub const COL_BOUND_PTR: usize = 12;
/// Block-active flag `act ∈ {0, 1}` (cycle-constant): 1 on real op blocks,
/// 0 on padding. Gates every `UintVal` consume so an all-zero padding
/// block stays off the bus — with the zero sentinel gone, nothing provides
/// the `(0, 0, off, 0…)` tuples bare periodic flags would emit there.
pub const COL_ACT: usize = 13;
pub const NUM_MAIN_COLS: usize = 14;

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
/// Term-row cell holding the `UintAdd` provide multiplicity = consumer
/// count (one per eval `UintOp` node, 0 for bare ptr-space ops) — read
/// only by the term-row provide.
pub const TERM_CELL_MULT: usize = 0;

/// Block period: one add op = 8 rows (a / b / c / p one row each, two carry
/// rows, a spare, and the term row).
pub const PERIOD: usize = 8;

// One-hot periodic role selectors (one column each, period 8). Row 6 needs
// no selector — it is the spare row and contributes nothing; the term role
// sits on the last row (7) so the cycle-constancy `not_term` gate drops
// exactly at the block boundary.
const PCOL_A: usize = 0;
const PCOL_B: usize = 1;
const PCOL_C: usize = 2;
const PCOL_P: usize = 3;
const PCOL_CPOS: usize = 4;
const PCOL_CNEG: usize = 5;
const PCOL_TERM: usize = 6;
const NUM_PERIODIC: usize = 7;
/// Row each periodic one-hot column fires on (index = `PCOL_*`).
const ROLE_ROWS: [usize; NUM_PERIODIC] = [0, 1, 2, 3, 4, 5, 7];

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
        ROLE_ROWS
            .iter()
            .map(|&row| {
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

        // Role selectors.
        let sel: [AB::Expr; NUM_PERIODIC] = {
            let p = builder.periodic_values();
            array::from_fn(|i| p[i].into())
        };
        let a_sel = sel[PCOL_A].clone();
        let b_sel = sel[PCOL_B].clone();
        let c_sel = sel[PCOL_C].clone();
        let p_sel = sel[PCOL_P].clone();
        let cpos = sel[PCOL_CPOS].clone();
        let cneg = sel[PCOL_CNEG].clone();
        let term_sel = sel[PCOL_TERM].clone();

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
        // The carry-row weight Σⱼ₌₀⁶ γⱼ·(β^{j+1} − t·βʲ) = (β − t)·Γ(β).
        let carry_term: AB::ExprEF = (0..7).fold(AB::ExprEF::ZERO, |s, j| {
            let w = bp[j + 1].clone() - bp[j].clone() * t32.clone();
            s + w * AB::Expr::from(local[j])
        });

        // Block scalars, read locally on their own rows.
        let is_b_zero: AB::Expr = local[CELL_IS_B_ZERO].into();
        let is_c_zero: AB::Expr = local[CELL_IS_C_ZERO].into();
        let k: AB::Expr = local[CELL_K].into();
        let b_active: AB::Expr = AB::Expr::ONE - is_b_zero.clone();
        let c_active: AB::Expr = AB::Expr::ONE - is_c_zero.clone();

        // Per-row `id` contributions (one selector fires per row, so the
        // cross terms vanish): +a, +b·(1−is_b_zero), −c·(1−is_c_zero),
        // −k·(bound(β)+1), ±carries.
        let contrib: AB::ExprEF = full_sum.clone() * a_sel.clone()
            + full_sum.clone() * (b_sel.clone() * b_active)
            - full_sum.clone() * (c_sel.clone() * c_active)
            - (full_sum.clone() + bp[0].clone()) * (p_sel.clone() * k.clone())
            + carry_term.clone() * cpos.clone()
            - carry_term * cneg.clone();

        builder.when_first_row().assert_zero_ext(id.clone());
        builder.when_transition().assert_zero_ext(id_next - id.clone() - contrib);
        builder.assert_zero_ext(id * term_sel.clone());

        // k is the boolean reduction bit (p-row scalar).
        builder.assert_zero(p_sel.clone() * k.clone() * (AB::Expr::ONE - k));

        // act is the boolean block-active flag (cycle-constant).
        let act: AB::Expr = local[COL_ACT].into();
        builder.assert_zero(act.clone() * (AB::Expr::ONE - act.clone()));

        // A provide must come from an active block. The `UintAdd` provide is
        // gated only by `sel[TERM]` (not `act`), and the operand consumes are
        // act-gated — so an `act = 0` block with zeroed limbs (the SZ closes
        // trivially) and a witnessed term-row `mult` would provide a *false*
        // relation onto the bus. Force the term-row mult to 0 when act = 0.
        builder.assert_zero(
            term_sel.clone() * (AB::Expr::ONE - act.clone()) * local[TERM_CELL_MULT].into(),
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

        // Carry booleanity: γ⁺ / γ⁻ ∈ {0, 1}, seven limbs each on their row.
        for &cell in local.iter().take(7) {
            let lj: AB::Expr = cell.into();
            let boolean = lj.clone() * (AB::Expr::ONE - lj);
            builder.assert_zero((cpos.clone() + cneg.clone()) * boolean);
        }

        // Cycle-constancy: the four ptrs + act are constant within a block
        // (every row but the terminal one, which the not_term gate drops at
        // the block boundary — term sits on the last row of the period).
        let not_term: AB::Expr = AB::Expr::ONE - term_sel;
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
        // 1). Both operand halves consume from the same row now (a, b, c
        // and p each take one row), so no next-row read is needed.
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
        let a_lo = (sel[PCOL_A].clone(), a_ptr.clone(), LB::Expr::ZERO, lo.clone(), consume_deg);
        let a_hi = (sel[PCOL_A].clone(), a_ptr.clone(), LB::Expr::ONE, hi.clone(), consume_deg);
        let b_lo = (
            sel[PCOL_B].clone() * b_active.clone(),
            b_ptr.clone(),
            LB::Expr::ZERO,
            lo.clone(),
            gated_consume_deg,
        );
        let b_hi = (
            sel[PCOL_B].clone() * b_active,
            b_ptr.clone(),
            LB::Expr::ONE,
            hi.clone(),
            gated_consume_deg,
        );
        let c_lo = (
            sel[PCOL_C].clone() * c_active.clone(),
            c_ptr.clone(),
            LB::Expr::ZERO,
            lo.clone(),
            gated_consume_deg,
        );
        let c_hi = (
            sel[PCOL_C].clone() * c_active,
            c_ptr.clone(),
            LB::Expr::ONE,
            hi.clone(),
            gated_consume_deg,
        );
        let p_lo = (sel[PCOL_P].clone(), bound_ptr.clone(), LB::Expr::ZERO, lo, consume_deg);
        let p_hi = (sel[PCOL_P].clone(), bound_ptr.clone(), LB::Expr::ONE, hi, consume_deg);

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
                                    neg_mult.clone() * sel[PCOL_TERM].clone(),
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
