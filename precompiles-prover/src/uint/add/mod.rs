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
//! ext-field register (aux col 1, excluded from σ by `num_logup_cols = 1`):
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
//! ## Layout (narrow, period-16)
//!
//! 4×32 per row (one [`UintVal`] half), mirroring the store's bound rows.
//! a occupies two rows; b, c and p occupy two rows *plus a hub between
//! their halves* hosting the block scalar each family reads
//! (`is_b_zero` / `is_c_zero` / `k`) — the hub serves both halves
//! through the two-row window (the lo row reads it as next, the hi
//! half's events fire on the hub against the next row's limbs), so no
//! scalar needs a column or constancy transport. The carries take two
//! rows each; a `term` row (hosting the provide mult) closes the SZ.
//! Periodic columns are verifier-computed, so the extra roles cost no
//! opening width — the narrow 4-limb trace is Pareto-cheaper for the
//! recursive verifier than an 8-wide / period-8 alternative.
//!
//! Two zero-sentinel modes, one per hub: **`is_c_zero`** drops the `c`
//! side (`a + b ≡ 0` — negation with an unstored zero result) and
//! **`is_b_zero`** drops the `b` side (`a + 0 ≡ c` — the stored-value
//! **equality certificate** `a = c`, both canonical under one modulus;
//! consumed e.g. by the EC group law's `x₁ = x₂` / `y₁ = y₂` case ties).
//!
//! | rows  | role          | cells (4×32 / scalar) | id contributes            |
//! |-------|---------------|-----------------------|---------------------------|
//! | 0–1   | `a` lo/hi     | a's 4×32 halves       | `+a(β)`                   |
//! | 2     | `b` lo        | b's lo half           | `+b_lo(β)` (flag @ next)  |
//! | 3     | `b` hub       | `is_b_zero` (cell 0)  | `+b_hi(β)` (limbs @ next) |
//! | 4     | `b` hi        | b's hi half           | — (rides the hub)         |
//! | 5     | `c` lo        | c's lo half           | `−c_lo(β)` (flag @ next)  |
//! | 6     | `c` hub       | `is_c_zero` (cell 0)  | `−c_hi(β)` (limbs @ next) |
//! | 7     | `c` hi        | c's hi half           | — (rides the hub)         |
//! | 8     | `p` lo        | bound's lo half       | `−k·(bound_lo(β) + 1)` (k @ next) |
//! | 9     | `k` hub       | `k` (cell 0)          | `−k·bound_hi(β)` (limbs @ next) |
//! | 10    | `p` hi        | bound's hi half       | — (consume on its own row) |
//! | 11–12 | `cpos` lo/hi  | γ⁺₀..₃ / γ⁺₄..₆       | `+Σ γ⁺ⱼ(β^{j+1} − t·βʲ)`  |
//! | 13–14 | `cneg` lo/hi  | γ⁻₀..₃ / γ⁻₄..₆       | `−Σ γ⁻ⱼ(β^{j+1} − t·βʲ)`  |
//! | 15    | `term`        | `mult` (cell 0)       | assert `id = 0`           |

pub mod trace;

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

/// Limb / scalar cells per row: 4×32-bit (one `UintVal` half) for a/b/c/p
/// rows, the binary carries γ⁺ / γ⁻ on the carry rows, or the hub / term
/// scalars.
pub const NUM_LIMBS: usize = 4;
/// `a`'s pointer (cycle-constant per block).
pub const COL_A_PTR: usize = 4;
/// `b`'s pointer (cycle-constant).
pub const COL_B_PTR: usize = 5;
/// `c`'s pointer — the witnessed result (cycle-constant).
pub const COL_C_PTR: usize = 6;
/// the shared modulus's pointer = `bound_ptr` (cycle-constant).
pub const COL_BOUND_PTR: usize = 7;
/// Block-active flag `act ∈ {0, 1}` (cycle-constant): 1 on real op blocks,
/// 0 on padding. Gates every `UintVal` consume so an all-zero padding
/// block stays off the bus — with the zero sentinel gone, nothing provides
/// the `(0, 0, off, 0…)` tuples bare periodic flags would emit there.
pub const COL_ACT: usize = 8;
pub const NUM_MAIN_COLS: usize = 9;

// The four ptrs need joint visibility at the term-row provide *and* at
// their scattered consume rows — only cycle-constancy transports that —
// and `act` gates eight rows; everything else is a one-window scalar
// hosted in a spare cell of its read site:

/// B-hub cell holding the `is_b_zero` flag: when set, `b` is the
/// (unstored) zero — the `+b(β)` terms and the `b` `UintVal` consumes
/// are dropped, and `b_ptr` is forced to 0. The block then proves
/// `a + 0 ≡ c (mod p)`, and with `a`, `c` both stored canonical under
/// the shared modulus that is exactly the **equality certificate
/// `a = c`** — value-level, ptr-free, no zero pin. Same
/// between-the-halves window pattern as the C hub.
pub const B_HUB_CELL_IS_B_ZERO: usize = 0;
/// C-hub cell holding the `is_c_zero` flag: when set, `c` is the
/// (unstored) zero — the `−c(β)` term and the `c` `UintVal` consumes are
/// dropped, and `c_ptr` is forced to 0 (address 0 is never stored, so it
/// reads as "none" on the `UintAdd` bus). Lets `a + b ≡ 0 (mod p)`
/// (negation: `b = −a`) avoid referencing a stored zero, which can't be
/// pinned untyped for an arbitrary modulus. The hub sits between the `c`
/// halves: the c-lo events read it as the next row, the c-hi events fire
/// *on* the hub (limbs from the next row) — one structurally shared cell.
pub const C_HUB_CELL_IS_C_ZERO: usize = 0;
/// K-hub cell holding the boolean reduction bit `k`: same between-the-
/// halves pattern over the `p` rows — the p-lo `id` contribution reads it
/// as the next row, the p-hi contribution fires on the hub against the
/// next row's limbs. (The `p` consumes don't mention `k`, so they stay on
/// their own rows.)
pub const K_HUB_CELL_K: usize = 0;
/// Term-row cell holding the `UintAdd` provide multiplicity = consumer
/// count (one per eval `UintOp` node, 0 for bare ptr-space ops) — read
/// only by the term-row provide.
pub const TERM_CELL_MULT: usize = 0;

/// Block period: one add op = 16 rows (a × 2, b / c / p × 2 + a hub
/// each, carries × 4, term).
pub const PERIOD: usize = 16;

// One-hot periodic role selectors (one column each, period 16). Rows 4
// (b-hi) and 7 (c-hi) need no selector — their consumes and `id`
// contributions fire on their hubs via next-row access; the term role
// sits on the last row (15) so the cycle-constancy `not_term` gate
// drops exactly at the block boundary.
const PCOL_A_LO: usize = 0;
const PCOL_A_HI: usize = 1;
const PCOL_B_LO: usize = 2;
const PCOL_B_HUB: usize = 3;
const PCOL_C_LO: usize = 4;
const PCOL_C_HUB: usize = 5;
const PCOL_P_LO: usize = 6;
const PCOL_K_HUB: usize = 7;
const PCOL_P_HI: usize = 8;
const PCOL_CPOS_LO: usize = 9;
const PCOL_CPOS_HI: usize = 10;
const PCOL_CNEG_LO: usize = 11;
const PCOL_CNEG_HI: usize = 12;
const PCOL_TERM: usize = 13;
const NUM_PERIODIC: usize = 14;
/// Row each periodic one-hot column fires on (index = `PCOL_*`).
const ROLE_ROWS: [usize; NUM_PERIODIC] = [0, 1, 2, 3, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15];

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
        let a_lo = sel[PCOL_A_LO].clone();
        let a_hi = sel[PCOL_A_HI].clone();
        let b_lo = sel[PCOL_B_LO].clone();
        let b_hub = sel[PCOL_B_HUB].clone();
        let c_lo = sel[PCOL_C_LO].clone();
        let c_hub = sel[PCOL_C_HUB].clone();
        let p_lo = sel[PCOL_P_LO].clone();
        let k_hub = sel[PCOL_K_HUB].clone();
        let cpos_lo = sel[PCOL_CPOS_LO].clone();
        let cpos_hi = sel[PCOL_CPOS_HI].clone();
        let cneg_lo = sel[PCOL_CNEG_LO].clone();
        let cneg_hi = sel[PCOL_CNEG_HI].clone();
        let term_sel = sel[PCOL_TERM].clone();

        // β^0 .. β^7.
        let beta: AB::ExprEF = builder.permutation_randomness()[1].into();
        let mut bp: Vec<AB::ExprEF> = Vec::with_capacity(8);
        bp.push(AB::ExprEF::ONE);
        for i in 1..8 {
            bp.push(bp[i - 1].clone() * beta.clone());
        }
        let t32: AB::Expr = AB::Expr::from(Felt::new(1u64 << 32).expect("2^32 < Goldilocks p"));

        // `id` register on aux col 1.
        let id: AB::ExprEF =
            current_main::<_, AB::VarEF, 1>(builder.permutation(), REGISTER_COL)[0].into();
        let id_next: AB::ExprEF =
            next_main::<_, AB::VarEF, 1>(builder.permutation(), REGISTER_COL)[0].into();

        // Weighted limb sums of a row's 4×32 limbs: the lo half (β⁰..β³)
        // and the hi half (β⁴..β⁷) — over the local row, and the hi half
        // over the *next* row (the hub rows fire their hi-half terms
        // against the following row's limbs) — plus the per-half carry
        // term Σⱼ limbⱼ·(β^{j+1} − t·βʲ) (lo: j=0..3, hi: j=4..6).
        let lo_sum: AB::ExprEF =
            (0..4).fold(AB::ExprEF::ZERO, |s, k| s + bp[k].clone() * AB::Expr::from(local[k]));
        let hi_sum: AB::ExprEF =
            (0..4).fold(AB::ExprEF::ZERO, |s, k| s + bp[4 + k].clone() * AB::Expr::from(local[k]));
        let hi_sum_next: AB::ExprEF =
            (0..4).fold(AB::ExprEF::ZERO, |s, k| s + bp[4 + k].clone() * AB::Expr::from(next[k]));
        let carry_lo_term: AB::ExprEF = (0..4).fold(AB::ExprEF::ZERO, |s, j| {
            let w = bp[j + 1].clone() - bp[j].clone() * t32.clone();
            s + w * AB::Expr::from(local[j])
        });
        let carry_hi_term: AB::ExprEF = (0..3).fold(AB::ExprEF::ZERO, |s, m| {
            let j = 4 + m;
            let w = bp[j + 1].clone() - bp[j].clone() * t32.clone();
            s + w * AB::Expr::from(local[m])
        });

        // −k·bound(β) − k, k read from the K-hub between the p halves: the
        // p-lo row sees it as the next row's cell and the hub fires the hi
        // half against the next row's limbs; the −k correction at β⁰ is
        // p = bound + 1.
        let k_next: AB::Expr = next[K_HUB_CELL_K].into();
        let k_here: AB::Expr = local[K_HUB_CELL_K].into();
        let p_lo_contrib = (lo_sum.clone() + bp[0].clone()) * k_next;
        let p_hi_contrib = hi_sum_next.clone() * k_here.clone();

        // When is_c_zero (the C-hub cell between the c halves), c is the
        // (unstored) zero: drop the −c(β) terms. Same window pattern: the
        // c-lo row reads the flag as next, the hub fires the hi half.
        // is_b_zero (the B-hub cell) mirrors it on the +b(β) side.
        let czc_next: AB::Expr = next[C_HUB_CELL_IS_C_ZERO].into();
        let czc_here: AB::Expr = local[C_HUB_CELL_IS_C_ZERO].into();
        let c_active_next: AB::Expr = AB::Expr::ONE - czc_next;
        let c_active_here: AB::Expr = AB::Expr::ONE - czc_here.clone();
        let bzc_next: AB::Expr = next[B_HUB_CELL_IS_B_ZERO].into();
        let bzc_here: AB::Expr = local[B_HUB_CELL_IS_B_ZERO].into();
        let b_active_next: AB::Expr = AB::Expr::ONE - bzc_next;
        let b_active_here: AB::Expr = AB::Expr::ONE - bzc_here.clone();

        let contrib: AB::ExprEF = lo_sum.clone() * a_lo
            + hi_sum * a_hi
            + lo_sum.clone() * (b_lo * b_active_next)
            + hi_sum_next.clone() * (b_hub.clone() * b_active_here)
            - lo_sum * (c_lo * c_active_next)
            - hi_sum_next * (c_hub.clone() * c_active_here)
            - p_lo_contrib * p_lo
            - p_hi_contrib * k_hub.clone()
            + carry_lo_term.clone() * cpos_lo.clone()
            + carry_hi_term.clone() * cpos_hi.clone()
            - carry_lo_term * cneg_lo.clone()
            - carry_hi_term * cneg_hi.clone();

        builder.when_first_row().assert_zero_ext(id.clone());
        builder.when_transition().assert_zero_ext(id_next - id.clone() - contrib);
        builder.assert_zero_ext(id * term_sel.clone());

        // k is the boolean reduction bit (a K-hub cell).
        builder.assert_zero(k_hub * k_here.clone() * (AB::Expr::ONE - k_here));

        // act is the boolean block-active flag (cycle-constant).
        let act: AB::Expr = local[COL_ACT].into();
        builder.assert_zero(act.clone() * (AB::Expr::ONE - act.clone()));

        // A provide must come from an active block. The `UintAdd` provide is
        // gated only by `sel[TERM]` (not `act`), and the operand consumes are
        // act-gated — so an `act = 0` block with zeroed limbs (the SZ closes
        // trivially) and a witnessed term-row `mult` would provide a *false*
        // relation onto the bus. Force the term-row mult to 0 when act = 0.
        builder
            .assert_zero(term_sel.clone() * (AB::Expr::ONE - act) * local[TERM_CELL_MULT].into());

        // is_c_zero (a C-hub cell) is boolean, and forces c_ptr = 0 — the
        // zero result has no stored address, and the tuple's c_ptr = 0
        // reads as "≡ 0" to a consumer.
        builder.assert_zero(c_hub.clone() * czc_here.clone() * (AB::Expr::ONE - czc_here.clone()));
        let c_ptr_local: AB::Expr = local[COL_C_PTR].into();
        builder.assert_zero(c_hub * czc_here * c_ptr_local);

        // is_b_zero (a B-hub cell) likewise: boolean, and forces
        // b_ptr = 0 so the tuple reads as the `a + 0 ≡ c` equality form.
        builder.assert_zero(b_hub.clone() * bzc_here.clone() * (AB::Expr::ONE - bzc_here.clone()));
        let b_ptr_local: AB::Expr = local[COL_B_PTR].into();
        builder.assert_zero(b_hub * bzc_here * b_ptr_local);

        // Carry booleanity: γ⁺ / γ⁻ ∈ {0, 1}. cpos_lo / cneg_lo carry 4
        // limbs (γ·₀..₃), cpos_hi / cneg_hi carry 3 (γ·₄..₆).
        for item in local.iter().take(4) {
            let lj: AB::Expr = (*item).into();
            let boolean = lj.clone() * (AB::Expr::ONE - lj);
            builder.assert_zero((cpos_lo.clone() + cneg_lo.clone()) * boolean);
        }
        for item in local.iter().take(3) {
            let lm: AB::Expr = (*item).into();
            let boolean = lm.clone() * (AB::Expr::ONE - lm);
            builder.assert_zero((cpos_hi.clone() + cneg_hi.clone()) * boolean);
        }

        // Cycle-constancy: the four ptrs need joint visibility at the
        // term-row provide and at their consume rows; act gates eight
        // rows. Constant within a block (every row but the terminal one,
        // which the not_term gate drops at the block boundary — term sits
        // on the last row of the period).
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
        let next: [LB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

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

        // The 4×32 limbs of the UintVal recombined view: a row's own, and
        // the next row's (the C-hub emits the c-hi consume against the
        // following row's limbs).
        let limbs: [LB::Expr; 4] = array::from_fn(|k| local[k].into());
        let limbs_next: [LB::Expr; 4] = array::from_fn(|k| next[k].into());

        // When is_c_zero (the C-hub cell), c is the unstored zero:
        // suppress its UintVal consumes (deg-3 multiplicities with the
        // act gate — inside the budget). The c-lo row reads the flag as
        // its next row; the hub reads it locally. is_b_zero (the B-hub
        // cell) suppresses the b consumes the same way.
        let c_active_next: LB::Expr = LB::Expr::ONE - next[C_HUB_CELL_IS_C_ZERO].into();
        let c_active_here: LB::Expr = LB::Expr::ONE - local[C_HUB_CELL_IS_C_ZERO].into();
        let b_active_next: LB::Expr = LB::Expr::ONE - next[B_HUB_CELL_IS_B_ZERO].into();
        let b_active_here: LB::Expr = LB::Expr::ONE - local[B_HUB_CELL_IS_B_ZERO].into();

        let consume_deg = Deg { v: 2, u: 1 };
        let gated_consume_deg = Deg { v: 3, u: 1 };
        let provide_deg = Deg { v: 2, u: 1 };
        // Flattened columns hold ≤ 2 fractions; the mixed p-hi+provide column
        // is a 2-denominator batch (degree-3 numerator, degree-2 denominator).
        let cp_col_deg = Deg { v: 3, u: 2 };

        // (consume flag, ptr, offset, limbs, deg) per operand half, split
        // across two fraction columns so neither exceeds the degree
        // budget. The b-hi / c-hi consumes fire on their hubs (flag local
        // + limbs from the next row); every other half fires on its own
        // limb row.
        let ab_consumes: [(LB::Expr, LB::Expr, LB::Expr, [LB::Expr; 4], Deg); 4] = [
            (
                sel[PCOL_A_LO].clone(),
                a_ptr.clone(),
                LB::Expr::ZERO,
                limbs.clone(),
                consume_deg,
            ),
            (sel[PCOL_A_HI].clone(), a_ptr.clone(), LB::Expr::ONE, limbs.clone(), consume_deg),
            (
                sel[PCOL_B_LO].clone() * b_active_next,
                b_ptr.clone(),
                LB::Expr::ZERO,
                limbs.clone(),
                gated_consume_deg,
            ),
            (
                sel[PCOL_B_HUB].clone() * b_active_here,
                b_ptr.clone(),
                LB::Expr::ONE,
                limbs_next.clone(),
                gated_consume_deg,
            ),
        ];
        let cp_consumes: [(LB::Expr, LB::Expr, LB::Expr, [LB::Expr; 4], Deg); 4] = [
            (
                sel[PCOL_C_LO].clone() * c_active_next,
                c_ptr.clone(),
                LB::Expr::ZERO,
                limbs.clone(),
                gated_consume_deg,
            ),
            (
                sel[PCOL_C_HUB].clone() * c_active_here,
                c_ptr.clone(),
                LB::Expr::ONE,
                limbs_next,
                gated_consume_deg,
            ),
            (
                sel[PCOL_P_LO].clone(),
                bound_ptr.clone(),
                LB::Expr::ZERO,
                limbs.clone(),
                consume_deg,
            ),
            (sel[PCOL_P_HI].clone(), bound_ptr.clone(), LB::Expr::ONE, limbs, consume_deg),
        ];

        // Flattened LogUp (lqd 1), one/two fractions per column. The four
        // gated b/c consumes carry degree-3 multiplicities (`flag·(1−is_zero)·act`)
        // so each sits alone; the degree-2 a/p consumes pair; the UintAdd
        // provide rides with p-hi; col 0 (the running sum) hosts a single
        // degree-2 consume (the +1 gate forbids a degree-3 one there).
        let [a_lo, a_hi, b_lo, b_hub] = ab_consumes;
        let [c_lo, c_hub, p_lo, p_hi] = cp_consumes;

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
        consume_column(builder, &bound_ptr, &act, vec![b_hub], gated_consume_deg);
        consume_column(builder, &bound_ptr, &act, vec![c_lo], gated_consume_deg);
        consume_column(builder, &bound_ptr, &act, vec![c_hub], gated_consume_deg);
    }
}
