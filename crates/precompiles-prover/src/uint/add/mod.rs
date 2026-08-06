//! UintAdd chiplet — modular addition `a + b ≡ c (mod p)` over stored uints.
//!
//! A **relation** AIR over the [UintStore](crate::uint): it mints no value.
//! `a`, `b`, `c` and the modulus all live in the store and are pulled in
//! over [`UintVal`](crate::relations::BusId::UintVal); this chiplet just ties
//! their ptrs to the modular-sum identity and *provides* the
//! [`UintAdd`](crate::relations::BusId::UintAdd) relation, consumed by the
//! eval chip's add / sub / neg `UintOp` nodes.
//!
//! See the design notes for the full design.
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
//! correction at `β⁰`. Verified at the LogUp challenge `β` by one
//! **block-local** ext constraint on the open row's two-row window — the
//! open row sees `a ‖ b` locally and `c ‖ p` on next, so the whole check is
//! a single local assertion (no accumulation register, no closure row, and
//! the trace's final block needs no wrap-around special case):
//!
//! ```text
//! a(β) + b(β) − c(β) − k·bound(β) − k + (β − t)·Γ(β) = 0,    t = 2³²
//! Γ(β) = Σⱼ₌₀⁶ γⱼ·βʲ,    γⱼ ∈ {−1, 0, 1}
//! ```
//!
//! `D(X) = a + b − c − k·bound − k` has `D(t) = 0`, so `(X − t) ∣ D` with a
//! degree-6 quotient → exactly 7 signed carries `γ₀..γ₆`, **no top-carry
//! slot** (the bit-256 overflow cancels in the difference, since
//! `a + b = c + k·p`). Each `γⱼ` — the difference between the binary carry
//! chain of `a + b` and that of `c + k·p` — is **ternary**, range-checked by
//! an ungated `γ(1−γ)(1+γ)` per carry column: the four carry columns host
//! only Γ slots (per [`GAMMA_SLOTS`]), so no row selector is needed and the
//! check stays at degree 3. Operands inherit the store's 16-bit `Range16`
//! through the `UintVal` tie; no-wrap holds trivially (every per-limb
//! coefficient of the identity is `≲ 2³⁴ ≪ 2⁶³`, so field-vanishing
//! coefficients vanish over ℤ and the limb equations chain to the exact
//! integer identity).
//!
//! ## Layout (period-2, two values per row)
//!
//! 16×32 per row (two whole 256-bit values): the **open row** carries
//! `a ‖ b`, the **closing row** `c ‖ p`. The SZ identity is asserted on the
//! open row (whose window sees all four values); the `UintAdd` provide and
//! its multiplicity cell sit on the closing row.
//!
//! Cells 16–19 are the carry columns (γ₀–γ₃ on the open row, γ₄–γ₆ on the
//! closing row, whose fourth slot is structurally zero); cells 20–23 host
//! the block scalars, one per row:
//!
//! | col   | open row (`a ‖ b`)    | closing row (`c ‖ p`) |
//! |-------|-----------------------|-----------------------|
//! | 0–7   | `a`'s limbs           | `c`'s limbs           |
//! | 8–15  | `b`'s limbs           | `p`'s limbs           |
//! | 16–19 | γ₀ γ₁ γ₂ γ₃           | γ₄ γ₅ γ₆ (19 zero)    |
//! | 20    | `is_b_zero`           | `k`                   |
//! | 21    | `w`                   | `c_on`                |
//! | 22    | `wS`                  | `mult`                |
//! | 23    | `b_on`                | `is_c_zero`           |
//! | 24–29 | `a_ptr b_ptr c_ptr bound_ptr act nz` (cycle-constant)|
//!
//! Columns 20 and 23 host a boolean on both rows, so one ungated booleanity
//! check per column covers both residents (`is_b_zero`/`k` and
//! `b_on`/`is_c_zero` respectively).
//!
//! Two zero-sentinel modes, one per row: **`is_c_zero`** drops the `c` side
//! (`a + b ≡ 0` — negation with an unstored zero result) and
//! **`is_b_zero`** drops the `b` side (`a + 0 ≡ c` — the stored-value
//! **equality certificate** `a = c`, both canonical under one modulus;
//! consumed e.g. by the EC group law's `x₁ = x₂` / `y₁ = y₂` case ties).
//!
//! **Nonzero certificate.** A block's cycle-constant `nz` flag ([`COL_NZ`])
//! additionally certifies `b ≠ 0` when set, in place of a full inverse
//! modmul: `S = Σⱼ bⱼ` — a native sum of `b`'s eight 32-bit limbs, no
//! β-weighting, `< 2³⁵ < p_Goldilocks` so no wrap — is `0 ⟺ b = 0`, and
//! `nz · (w·S − 1) = 0` with a witnessed candidate inverse `w`
//! ([`CELL_D_W`], `w·S` hoisted to [`CELL_D_WS`] to keep the check degree 3)
//! proves `S ≠ 0`. `nz` rides the `UintAdd` bus tuple as a 5th field, so a
//! consumer can demand `nz = 1` on the same block that already proves
//! `a + b ≡ c` — the EC group law's generic-add case uses this on its
//! `d = x₂ − x₁` subtraction instead of a separate disequality MAC.

pub mod trace;

use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
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

/// LogUp message for the [`UintAdd`](BusId::UintAdd) relation: the
/// 5-tuple `(bound_ptr, a_ptr, b_ptr, c_ptr, nz)` asserting `a + b ≡ c
/// (mod p)` for the three stored uints sharing modulus `bound_ptr`, plus
/// — when `nz = 1` — the certified fact `b ≠ 0` (see "Nonzero
/// certificate" below). *Provided* by [`UintAddAir`] at the op's
/// consumer count; consumed by the eval chip's add (`a + b = c`), sub
/// (the arrangement `b + r = a`) and neg (`c_ptr = 0`, the `is_c_zero`
/// form) `UintOp` nodes (all `nz = 0`), and by the EC group law's
/// certificates (including the `b_ptr = 0` `is_b_zero` form, the
/// equality certificate `a = c`, and the generic add's `nz = 1` disequality
/// cert on its `d = x₂ − x₁` subtraction). Address 0 is never stored, so
/// a 0 ptr-slot always reads as "the unstored zero", never as a value.
///
/// Encoded as `bus_prefix[UintAdd] + β⁰·bound_ptr + β¹·a_ptr + β²·b_ptr +
/// β³·c_ptr + β⁴·nz`.
#[derive(Debug, Clone)]
pub struct UintAddMsg<E> {
    pub bound_ptr: E,
    pub a_ptr: E,
    pub b_ptr: E,
    pub c_ptr: E,
    pub nz: E,
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
                self.nz.clone(),
            ],
        )
    }
}

// COLUMN LAYOUT
// ================================================================================================

/// Limb cells per value: the full 8×32 view of one 256-bit uint.
pub const NUM_LIMBS: usize = 8;
/// First limb cell of the row's second value — `b` on the open row, `p`
/// on the closing row.
pub const CELL_HI: usize = NUM_LIMBS;
/// Cell columns per row: 16 limbs (two whole values), 4 carry cells
/// (16–19) and 4 block-scalar cells (20–23).
pub const NUM_CELLS: usize = 24;

/// Scalar cell boolean on both rows: `is_b_zero` on the open row, the
/// reduction bit `k` on the closing row — one ungated booleanity check
/// covers the column.
pub const CELL_FLAG: usize = 20;
/// Open-row resident of [`CELL_FLAG`]: when set, `b` is the (unstored)
/// zero — the `+b(β)` term and the `b` `UintVal` consume are dropped, and
/// `b_ptr` is forced to 0. The block then proves `a + 0 ≡ c (mod p)`, and
/// with `a`, `c` both stored canonical under the shared modulus that is
/// exactly the **equality certificate `a = c`** — value-level, ptr-free, no
/// zero pin.
pub const CELL_IS_B_ZERO: usize = CELL_FLAG;
/// Closing-row resident of [`CELL_FLAG`]: the boolean reduction bit `k`.
pub const CELL_K: usize = CELL_FLAG;
/// Open-row cell holding the witnessed candidate inverse `w` of `S = Σⱼ bⱼ`
/// (the eight 32-bit `b` limbs, native-summed — `S < 2³⁵ < p_Goldilocks`,
/// so no wrap) — the nonzero certificate's witness, meaningful only when
/// [`COL_NZ`] is set. See "Nonzero certificate" above.
pub const CELL_D_W: usize = 21;
/// Closing-row cell holding `c_on = act·(1 − is_c_zero)`, the witnessed
/// activity gate for the `c` `UintVal` consume: `cp_sel·c_on` (all local)
/// is degree 2, letting the gated `c` consume pair with `b`'s in one
/// column instead of sitting alone at degree 3 (`sel·(1−is_zero)·act`).
pub const CELL_C_ON: usize = 21;
/// Open-row cell pinning `wS = w · S`, so the nz-cert's main check
/// (`nz · (wS − 1) = 0`) reads one degree-1 cell instead of multiplying `w`
/// and `S` inline at the point that also carries `nz` and the row selector.
pub const CELL_D_WS: usize = 22;
/// Closing-row cell holding the `UintAdd` provide multiplicity = consumer
/// count (one per eval `UintOp` node, 0 for bare ptr-space ops) — read
/// only by the closing row's provide.
pub const TERM_CELL_MULT: usize = 22;
/// Open-row cell holding `b_on = act·(1 − is_b_zero)`, the witnessed
/// activity gate for the `b` `UintVal` consume (the mirror of
/// [`CELL_C_ON`]).
pub const CELL_B_ON: usize = 23;
/// Closing-row cell: when set, `c` is the (unstored) zero — the `−c(β)`
/// term and the `c` `UintVal` consume are dropped, and `c_ptr` is forced
/// to 0 (address 0 is never stored, so it reads as "none" on the `UintAdd`
/// bus). Lets `a + b ≡ 0 (mod p)` (negation: `b = −a`) avoid referencing a
/// stored zero, which can't be pinned untyped for an arbitrary modulus.
/// Boolean together with [`CELL_B_ON`] on the open row — one ungated check
/// covers the column.
pub const CELL_IS_C_ZERO: usize = 23;

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
/// the `(0, 0, off, 0…)` tuples bare row selectors would emit there.
pub const COL_ACT: usize = NUM_CELLS + 4;
/// Nonzero-certificate flag (cycle-constant): 1 when this block additionally
/// certifies `b ≠ 0` — see "Nonzero certificate" above. Read both on the
/// open row (where the certificate is checked) and the closing row (where
/// it rides the `UintAdd` provide tuple), which the cycle-constant column
/// makes free.
pub const COL_NZ: usize = NUM_CELLS + 5;
pub const NUM_MAIN_COLS: usize = NUM_CELLS + 6;

/// Block period: one add op = 2 rows — the open row (`a ‖ b`) and the
/// closing row (`c ‖ p`).
pub const PERIOD: usize = 2;
/// The open row: `a`'s limbs in cells 0–7, `b`'s in 8–15. The SZ identity
/// is asserted here, on the local/next window that sees the whole block.
pub const ROW_AB: usize = 0;
/// The closing row: `c`'s limbs in cells 0–7, `p`'s in 8–15. The `UintAdd`
/// provide fires here.
pub const ROW_CP: usize = 1;

/// Carry vector length: `deg Γ = 6` (see the module identity), 7 limbs.
pub const NUM_GAMMA: usize = 7;
/// First of the four carry columns.
pub const FIRST_GAMMA_COL: usize = 16;
/// Number of carry columns. Each hosts one Γ slot per row (and nothing
/// else), which is what lets the ternary range check run ungated — one
/// degree-3 `γ(1−γ)(1+γ)` per column, no row selector.
pub const NUM_GAMMA_COLS: usize = 4;

/// The signed-carry placement table: slot `j` hosts `γⱼ` at `(row, cell)`.
/// Shared verbatim by the AIR (weights) and trace-gen (placement), so the
/// two cannot drift. The closing row's fourth carry cell (19) is
/// structurally zero.
pub const GAMMA_SLOTS: [(usize, usize); NUM_GAMMA] = [
    (ROW_AB, 16),
    (ROW_AB, 17),
    (ROW_AB, 18),
    (ROW_AB, 19),
    (ROW_CP, 16),
    (ROW_CP, 17),
    (ROW_CP, 18),
];

// Aux (lqd 1): 3 LogUp fraction columns, ≤ 2 fractions each so every
// closing constraint is degree ≤ 3. Each operand consumes its whole value
// in one message from its own row, so the four operand consumes plus the
// provide fit in three columns: col 0 hosts `a` alone (the running sum —
// the gate adds +1, so a degree-3 multiplicity there would bust the
// budget), col 1 the two gated b/c consumes (their witnessed activity
// gates `on = act·(1−is_zero)`, see [`CELL_B_ON`] / [`CELL_C_ON`], keep
// `sel·on` at degree 2), col 2 `p`'s consume mixed with the provide. The
// SZ identity is a block-local main-trace constraint, so the aux trace
// carries no register.
const NUM_LOGUP_COLS: usize = 3;
const AUX_WIDTH: usize = 3;
const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = [1, 2, 2];

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
        // One selector, 1 on the open row; the closing row is its
        // complement.
        vec![vec![Felt::ONE, Felt::ZERO]]
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

        // The one role selector: 1 on the open row, its complement marking
        // the closing row. Every next-reading constraint is ab_sel-gated,
        // so the cyclic last → first window (whose local row is a closing
        // row) is dropped for free.
        let ab_sel: AB::Expr = builder.periodic_values()[0].into();
        let cp_sel: AB::Expr = AB::Expr::ONE - ab_sel.clone();

        // β^0 .. β^7.
        let beta: AB::ExprEF = builder.permutation_randomness()[1].into();
        let mut bp: Vec<AB::ExprEF> = Vec::with_capacity(8);
        bp.push(AB::ExprEF::ONE);
        for i in 1..8 {
            bp.push(bp[i - 1].clone() * beta.clone());
        }
        let t32: AB::Expr = AB::Expr::from(Felt::new(1u64 << 32).expect("2^32 < Goldilocks p"));

        // The four values at β (Σⱼ limbⱼ·βʲ — t = 2³² is the limb radix, so
        // the 32-bit limbs recombine to the 256-bit value at β), all read
        // from the open row's window: a ‖ b local, c ‖ p next.
        let a_beta: AB::ExprEF = (0..NUM_LIMBS)
            .fold(AB::ExprEF::ZERO, |s, j| s + bp[j].clone() * AB::Expr::from(local[j]));
        let b_beta: AB::ExprEF = (0..NUM_LIMBS)
            .fold(AB::ExprEF::ZERO, |s, j| s + bp[j].clone() * AB::Expr::from(local[CELL_HI + j]));
        let c_beta: AB::ExprEF = (0..NUM_LIMBS)
            .fold(AB::ExprEF::ZERO, |s, j| s + bp[j].clone() * AB::Expr::from(next[j]));
        let p_beta: AB::ExprEF = (0..NUM_LIMBS)
            .fold(AB::ExprEF::ZERO, |s, j| s + bp[j].clone() * AB::Expr::from(next[CELL_HI + j]));

        // Block scalars, read from the row that hosts them.
        let is_b_zero: AB::Expr = local[CELL_IS_B_ZERO].into();
        let is_c_zero_next: AB::Expr = next[CELL_IS_C_ZERO].into();
        let k_next: AB::Expr = next[CELL_K].into();

        // Σⱼ (β^{j+1} − t·βʲ)·γⱼ — the (β − t)·Γ(β) term, each slot read
        // from whichever block row the placement table hosts it on.
        let mut carry: AB::ExprEF = AB::ExprEF::ZERO;
        for (j, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
            let w: AB::ExprEF = bp[j + 1].clone() - bp[j].clone() * t32.clone();
            let g: AB::Expr = if row == ROW_AB {
                local[cell].into()
            } else {
                next[cell].into()
            };
            carry += w * g;
        }

        // The block-local SZ identity, one ext constraint on the open
        // row's window: a(β) + b(β)·(1−is_b_zero) − c(β)·(1−is_c_zero)
        // − k·(bound(β)+1) + (β−t)·Γ(β) = 0. Padding rows satisfy it
        // trivially (all-zero cells), so no act gate is needed.
        let identity: AB::ExprEF = a_beta + b_beta * (AB::Expr::ONE - is_b_zero.clone())
            - c_beta * (AB::Expr::ONE - is_c_zero_next)
            - (p_beta + bp[0].clone()) * k_next
            + carry;
        builder.assert_zero_ext(identity * ab_sel.clone());

        // Ternary carries: each carry column hosts only Γ slots (or a
        // structural zero), so the {−1, 0, 1} range check runs ungated on
        // every row — degree 3 with no selector, lqd-safe.
        for &cell in &local[FIRST_GAMMA_COL..FIRST_GAMMA_COL + NUM_GAMMA_COLS] {
            let g: AB::Expr = cell.into();
            builder.assert_zero(g.clone() * (AB::Expr::ONE - g.clone()) * (AB::Expr::ONE + g));
        }

        // Columns 20 and 23 host booleans on both rows (is_b_zero / k and
        // b_on / is_c_zero) — one ungated check per column covers both.
        for col in [CELL_FLAG, CELL_B_ON] {
            let f: AB::Expr = local[col].into();
            builder.assert_zero(f.clone() * (AB::Expr::ONE - f));
        }

        // act / nz: boolean cycle-constant flags.
        let act: AB::Expr = local[COL_ACT].into();
        builder.assert_zero(act.clone() * (AB::Expr::ONE - act.clone()));
        let nz: AB::Expr = local[COL_NZ].into();
        builder.assert_zero(nz.clone() * (AB::Expr::ONE - nz.clone()));

        // A provide must come from an active block. The `UintAdd` provide
        // is gated only by the closing-row selector (not `act`), and the
        // operand consumes are act-gated — so an `act = 0` block with
        // zeroed limbs (the SZ closes trivially) and a witnessed `mult`
        // would provide a *false* relation onto the bus. Force the mult to
        // 0 when act = 0.
        builder.assert_zero(
            cp_sel.clone() * (AB::Expr::ONE - act.clone()) * local[TERM_CELL_MULT].into(),
        );

        // is_c_zero (read locally on the closing row) forces c_ptr = 0 —
        // the zero result has no stored address, and the tuple's c_ptr = 0
        // reads as "≡ 0" to a consumer.
        let is_c_zero: AB::Expr = local[CELL_IS_C_ZERO].into();
        let c_ptr_local: AB::Expr = local[COL_C_PTR].into();
        builder.assert_zero(cp_sel.clone() * is_c_zero.clone() * c_ptr_local);

        // is_b_zero (an open-row scalar) likewise forces b_ptr = 0 so the
        // tuple reads as the `a + 0 ≡ c` equality form.
        let b_ptr_local: AB::Expr = local[COL_B_PTR].into();
        builder.assert_zero(ab_sel.clone() * is_b_zero.clone() * b_ptr_local);

        // b_on / c_on host act·(1 − is_zero): the witnessed activity gates
        // that let the gated b/c UintVal consumes carry a degree-2
        // multiplicity `sel·on` instead of `sel·(1−is_zero)·act`
        // (degree 3). Each is pinned on its own row, all cells local.
        let b_on: AB::Expr = local[CELL_B_ON].into();
        builder.assert_zero(ab_sel.clone() * (b_on - act.clone() * (AB::Expr::ONE - is_b_zero)));
        let c_on: AB::Expr = local[CELL_C_ON].into();
        builder.assert_zero(cp_sel * (c_on - act * (AB::Expr::ONE - is_c_zero)));

        // Nonzero certificate (open row): when `nz = 1`, this block
        // additionally certifies `b ≠ 0` — the disequality cert the EC
        // group law's generic-add case consumes in place of a full inverse
        // modmul. `S = Σⱼ bⱼ` (a native sum of `b`'s eight 32-bit limbs —
        // no β-weighting, so no LogUp challenge needed here — stays
        // `< 2³⁵ < p_Goldilocks`, no wrap) is `0 ⟺ b = 0`; `w` is the
        // witnessed candidate inverse, `wS` its pinned product (hoisted so
        // the main check stays degree 3 instead of stacking
        // `ab_sel·nz·w·S` at degree 5).
        let s_sum: AB::Expr =
            (0..NUM_LIMBS).fold(AB::Expr::ZERO, |s, j| s + AB::Expr::from(local[CELL_HI + j]));
        let w: AB::Expr = local[CELL_D_W].into();
        let ws: AB::Expr = local[CELL_D_WS].into();
        builder.assert_zero(ab_sel.clone() * (ws.clone() - w * s_sum));
        builder.assert_zero(ab_sel.clone() * nz * (ws - AB::Expr::ONE));

        // Cycle-constancy: the four ptrs + act + nz are constant within a
        // block — the open row pins the closing row; the closing → open
        // edge (the block boundary, and the cyclic wrap) is free.
        for col in [COL_A_PTR, COL_B_PTR, COL_C_PTR, COL_BOUND_PTR, COL_ACT, COL_NZ] {
            let here: AB::Expr = local[col].into();
            let there: AB::Expr = next[col].into();
            builder.assert_zero(ab_sel.clone() * (there - here));
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
/// consumes at their full multiplicities. With ≤ 2 degree-2 consumes per
/// column, every closing constraint stays at degree ≤ 3 → lqd 1. `col_deg`
/// is an ignored hint on the constraint path.
fn consume_column<LB>(
    builder: &mut LB,
    bound_ptr: &LB::Expr,
    consumes: Vec<(LB::Expr, LB::Expr, [LB::Expr; 8], Deg)>,
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
                            for (mult, ptr, msg_limbs, deg) in consumes {
                                b.insert(
                                    "consume-uintval",
                                    mult,
                                    UintValMsg {
                                        ptr,
                                        bound_ptr: bound_ptr.clone(),
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

        let ab_sel: LB::Expr = builder.periodic_values()[0].into();
        let cp_sel: LB::Expr = LB::Expr::ONE - ab_sel.clone();

        let a_ptr: LB::Expr = local[COL_A_PTR].into();
        let b_ptr: LB::Expr = local[COL_B_PTR].into();
        let c_ptr: LB::Expr = local[COL_C_PTR].into();
        let bound_ptr: LB::Expr = local[COL_BOUND_PTR].into();
        let act: LB::Expr = local[COL_ACT].into();
        let nz: LB::Expr = local[COL_NZ].into();
        let neg_mult: LB::Expr = LB::Expr::ZERO - local[TERM_CELL_MULT].into();

        // The row's two full 8×32 views: `lo` is the a / c value (cells
        // 0–7 on the open / closing row), `hi` the b / p value (cells
        // 8–15). Which interpretation is live is decided by the
        // multiplicity's row gate; everything is local — no next-row
        // reads anywhere on the lookup path.
        let lo: [LB::Expr; NUM_LIMBS] = array::from_fn(|j| local[j].into());
        let hi: [LB::Expr; NUM_LIMBS] = array::from_fn(|j| local[CELL_HI + j].into());

        // The gated b/c consumes read their witnessed activity gate
        // `on = act·(1 − is_zero)` locally on their firing row. `sel·on`
        // is degree 2 (the pinned `on` folds the act gate in), so the two
        // gated consumes pair per fraction column instead of sitting alone
        // at degree 3 (`sel·(1−is_zero)·act`).
        let b_on: LB::Expr = local[CELL_B_ON].into();
        let c_on: LB::Expr = local[CELL_C_ON].into();

        let consume_deg = Deg { v: 2, u: 1 };
        let provide_deg = Deg { v: 2, u: 1 };
        // Flattened columns hold ≤ 2 fractions; the mixed p+provide column
        // is a 2-denominator batch (degree-3 numerator, degree-2 denominator).
        let cp_col_deg = Deg { v: 3, u: 2 };

        // Each operand consumes its whole `UintVal` from its own row in
        // one message. Every multiplicity is degree 2: a/p carry
        // `sel·act`, the gated b/c carry `sel·on`. (mult, ptr, limbs, deg).
        let a_full = (ab_sel.clone() * act.clone(), a_ptr.clone(), lo.clone(), consume_deg);
        let b_full = (ab_sel * b_on, b_ptr.clone(), hi.clone(), consume_deg);
        let c_full = (cp_sel.clone() * c_on, c_ptr.clone(), lo, consume_deg);
        let p_full = (cp_sel.clone() * act, bound_ptr.clone(), hi, consume_deg);

        // Flattened LogUp (lqd 1). Four merged consumes (one per operand)
        // plus the provide fit in three columns: col 0 hosts `a` alone
        // (the running sum, the +1 gate forbids a degree-3 fraction
        // there), col 1 the two gated b/c consumes, col 2 `p`'s consume
        // mixed with the `UintAdd` provide.

        // col 0: a (running sum, one degree-2 consume).
        consume_column(builder, &bound_ptr, vec![a_full], consume_deg);
        // col 1: b + c (two degree-2 gated consumes).
        consume_column(builder, &bound_ptr, vec![b_full, c_full], consume_deg);
        // col 2: p's consume + the UintAdd provide (mixed batch, both deg-2).
        builder.next_column(
            |col| {
                col.group(
                    "uintadd-pp",
                    |g| {
                        g.batch(
                            "pp",
                            LB::Expr::ONE,
                            |b| {
                                let (mult, ptr, msg_limbs, deg) = p_full;
                                b.insert(
                                    "consume-uintval",
                                    mult,
                                    UintValMsg {
                                        ptr,
                                        bound_ptr: bound_ptr.clone(),
                                        limbs: msg_limbs,
                                    },
                                    deg,
                                );
                                b.insert(
                                    "provide-uintadd",
                                    neg_mult.clone() * cp_sel.clone(),
                                    UintAddMsg {
                                        bound_ptr: bound_ptr.clone(),
                                        a_ptr: a_ptr.clone(),
                                        b_ptr: b_ptr.clone(),
                                        c_ptr: c_ptr.clone(),
                                        nz: nz.clone(),
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
    }
}
