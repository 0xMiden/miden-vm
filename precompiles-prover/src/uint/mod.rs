//! Uint chiplet — 256-bit non-native uint storage.
//!
//! A storage-only chiplet: it interns 256-bit unsigned integers ("uints")
//! keyed by a monotonic `ptr`, range-checks each against a per-value
//! upper bound `p − 1` (the modulus, itself a stored uint referenced by
//! `bound_ptr`), and *provides* the value on the
//! [`UintVal`](crate::relations::BusId::UintVal) (4×32) and
//! [`UintLimbs`](crate::relations::BusId::UintLimbs) (raw 8×16) buses.
//! Arithmetic lives in the [`add`] / [`mul`] relation AIRs over those
//! views; hashing into the transcript is the eval chip's job, which
//! pulls the 4×32 view below and pins it into its Poseidon2 rate lanes.
//!
//! See `docs/chiplets/uint.md` for the full design.
//!
//! ## Range-membership via vertical Schwartz–Zippel
//!
//! Each uint occupies a **period-4 block** (16 cells/row); a one-hot
//! periodic selector marks each row's role. `v` and `comp` each keep
//! their own row per half (`v_lo`/`v_hi` adjacent, so a merged
//! full-value message can read both from one local/next window); `comp`
//! packs both its own halves onto one row (no external consumer needs a
//! `comp` message, so nothing forces it apart); `bound` folds the old
//! dedicated term row's role, hosting both its halves plus every carry
//! plus the ptr gap on one closing row:
//!
//! | row | role    | cells 0–7                | cells 8–15                              |
//! |-----|---------|---------------------------|------------------------------------------|
//! | 0   | `v` lo  | 8×16-bit (recombined → 4×32) | — (dead)                              |
//! | 1   | `v` hi  | 8×16-bit                  | `uintval_mult`@8, `uintlimbs_mult`@9 (10–15 dead) |
//! | 2   | `comp`  | comp lo (8×16-bit)        | comp hi (8×16-bit)                       |
//! | 3   | `bound` (closing) | 4×32-bit lo (0–3) + γ₀..γ₃ (4–7) | 4×32-bit hi (8–11) + γ₄..γ₆ (12–14) + gap (15) |
//!
//! The hub (the two provide multiplicities) now sits **on the `v` hi
//! row** rather than a dedicated row between the halves: the offset-0
//! provide (on `v` lo) still reads the mult via *next* (now `v` hi
//! itself, one row over), and the offset-1 provide reads both the mult
//! and its own limbs *locally* — no more cross-row limb read for the hi
//! half.
//!
//! A single extension-field register `id` (aux col — see
//! [`REGISTER_COL`]) accumulates, per row, the signed `β`-weighted limb
//! sum, so after the block it holds `v(β) + comp(β) − bound(β) +
//! (β−t)·Γ(β)` with `t = 2³²` — the Schwartz–Zippel image of `v + comp =
//! bound` (the carry term accumulates from the bound row, where the γ
//! cells live). Each valid block sums to 0, so the *global* accumulator
//! returns to 0 at every boundary. Since `bound` is now the block's last
//! row *and* hosts a nonzero contribution of its own (its `−direct`
//! terms plus its carry share), the closing check folds that
//! contribution in directly (mirroring [`UintAdd`](crate::uint::add)'s
//! `p_own` pattern) rather than depending on a dedicated all-zero
//! successor row. The register is excluded from σ by the
//! `num_logup_cols` bound (see [`crate::logup`]).
//!
//! ## Buses
//!
//! `ptr` and `bound_ptr` are cycle-constant per block.
//!
//! - **`UintVal`** (aux col 0): the `v` lo row and the `v` hi row *provide* `UintVal(ptr,
//!   bound_ptr, offset, recombined-4×32)` with multiplicity `−uintval_mult` (the hub cells, both
//!   now on `v` hi); the `bound` row *consumes* `UintVal(bound_ptr, bound_ptr, offset,
//!   direct-4×32)` with `+1` for both offsets. Both ptr-slots of the consume are `bound_ptr`, so
//!   it only matches a *self-referential* provider — the modulus row. With `uintval_mult` = the
//!   consumer count, the bus self-balances.
//! - **`Range16`**: each `v`/`comp` 16-bit limb is range-checked (16/uint), forcing limbs `< 2¹⁶`
//!   so the SZ no-wrap bound holds. Provided externally by the byte-pair-LUT chiplet.

pub mod add;
pub mod mul;
pub mod require;
pub mod store_mul;
pub mod trace;

use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_crypto::stark::air::ExtensionBuilder;
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
pub use require::{UintRequire, UintStores};

use crate::{
    logup::{
        Challenges, CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder,
        LookupColumn, LookupGroup, LookupMessage, NUM_PUBLIC_VALUES, NUM_RANDOMNESS,
        NUM_SIGMA_VALUES,
    },
    primitives::byte_pair_lut::Range16Msg,
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, next_main},
};

// MESSAGES
// ================================================================================================

/// LogUp message for the [`UintVal`](BusId::UintVal) relation: a 10-tuple
/// `(ptr, bound_ptr, c0..c7)` exposing a full stored 256-bit uint as eight
/// 32-bit limbs — the **recombined view** (each `c_i = lo16 + 2¹⁶·hi16` of
/// the underlying committed 16-bit limbs) — together with `bound_ptr`,
/// the ptr of the uint storing this value's modulus `p − 1`.
///
/// Carrying `bound_ptr` lets any consumer (eval hash, add/mul) recover
/// the modulus in the same lookup. The limb layout mirrors
/// [`Poseidon2InMsg`](crate::transcript::poseidon2::Poseidon2InMsg) so the
/// eval chip can pin the whole value straight into its rate lanes.
///
/// Encoded as `bus_prefix[UintVal] + β⁰·ptr + β¹·bound_ptr + β²·c0 + … +
/// β⁹·c7`.
#[derive(Debug, Clone)]
pub struct UintValMsg<E> {
    pub ptr: E,
    pub bound_ptr: E,
    pub limbs: [E; 8],
}

impl<E, EF> LookupMessage<E, EF> for UintValMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let [c0, c1, c2, c3, c4, c5, c6, c7] = self.limbs.clone();
        challenges.encode(
            BusId::UintVal as usize,
            [self.ptr.clone(), self.bound_ptr.clone(), c0, c1, c2, c3, c4, c5, c6, c7],
        )
    }
}

/// LogUp message for the [`UintLimbs`](BusId::UintLimbs) relation: an
/// 18-tuple `(ptr, bound_ptr, l0..l15)` exposing a full stored 256-bit
/// uint as its **raw 16×16-bit limbs** — the committed trace cells
/// themselves, already `Range16`-checked here, so a consumer (the [mul
/// chiplet](crate::uint::mul)) inherits the range checks through the bus
/// tie and convolves at 16-bit granularity (the no-wrap bound that 32-bit
/// limbs would bust).
///
/// This view sets [`MAX_MESSAGE_WIDTH`].
///
/// Encoded as `bus_prefix\[UintLimbs] + β⁰·ptr + β¹·bound_ptr + β²·l0 +
/// … + β¹⁷·l15`.
#[derive(Debug, Clone)]
pub struct UintLimbsMsg<E> {
    pub ptr: E,
    pub bound_ptr: E,
    pub limbs: [E; 16],
}

impl<E, EF> LookupMessage<E, EF> for UintLimbsMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let [l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15] =
            self.limbs.clone();
        challenges.encode(
            BusId::UintLimbs as usize,
            [
                self.ptr.clone(),
                self.bound_ptr.clone(),
                l0,
                l1,
                l2,
                l3,
                l4,
                l5,
                l6,
                l7,
                l8,
                l9,
                l10,
                l11,
                l12,
                l13,
                l14,
                l15,
            ],
        )
    }
}

// COLUMN LAYOUT
// ================================================================================================

/// Cells per row: 8×16-bit limbs (`v`/`comp`) or 4×32-bit + carries
/// (`bound`) on cells 0–7, plus their high-half counterpart on cells
/// 8–15 for the rows that host one (`v` hi's hub, `comp`'s hi half,
/// `bound`'s hi half + gap).
pub const NUM_CELLS: usize = 16;
/// uint pointer (cycle-constant per block).
pub const COL_PTR: usize = NUM_CELLS;
/// pointer of the bound uint = modulus (cycle-constant per block).
pub const COL_BOUND_PTR: usize = NUM_CELLS + 1;
pub const NUM_MAIN_COLS: usize = NUM_CELLS + 2;

/// `v`-hi-row cell holding the `UintVal` provide multiplicity = consumer
/// count. One cell serves both halves' provides: the offset-0 provide
/// (on the `v` lo row) reads it as the *next* row, the offset-1 provide
/// (on `v` hi itself) reads it locally.
pub const HUB_CELL_UINTVAL_MULT: usize = 8;
/// `v`-hi-row cell holding the `UintLimbs` (raw 8×16 view) provide
/// multiplicity. Counted separately from `uintval_mult`: the raw view
/// serves the mul chiplet's convolution operands, the 4×32 view serves
/// eval / add / bound-refs.
pub const HUB_CELL_UINTLIMBS_MULT: usize = 9;
/// First carry cell of the bound row's low half: γ₀..γ₃ sit in cells
/// 4–7.
pub const CARRY_LO_BEGIN: usize = 4;
/// First carry cell of the bound row's high half: γ₄..γ₆ sit in cells
/// 12–14.
pub const CARRY_HI_BEGIN: usize = 12;
/// Bound-row cell holding the witnessed ptr gap `ptr' − ptr − 1` to the
/// next block.
pub const TERM_CELL_GAP: usize = 15;

/// Block period: one uint = 4 rows.
pub const PERIOD: usize = 4;

// One-hot periodic role selectors (one column each, period 4).
const PCOL_V_LO: usize = 0;
const PCOL_V_HI: usize = 1;
const PCOL_COMP: usize = 2;
const PCOL_BOUND: usize = 3;

// Aux layout (FLATTENED to lqd 1): the LogUp fraction columns (≤ 2
// fractions each, col 0 a single degree-2 fraction), then the
// Schwartz–Zippel `id` register (excluded from σ via num_logup_cols).
/// Exposed so [`UintStoreMulAir`](crate::uint::store_mul::UintStoreMulAir)
/// can concatenate this chiplet's column shape onto mul's own instead of
/// hand-duplicating the derived column count.
pub(crate) const NUM_LOGUP_COLS: usize = 1 // the merged UintVal provide
    + 1 // the merged UintVal consume + the ptr-gap Range16
    + NUM_CELLS.div_ceil(2) // Range16 on every cell position, two per column
    + 1; // the merged raw UintLimbs provide
const REGISTER_COL: usize = NUM_LOGUP_COLS;
const AUX_WIDTH: usize = NUM_LOGUP_COLS + 1;
pub(crate) const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = {
    let mut shape = [2usize; NUM_LOGUP_COLS];
    shape[0] = 1;
    shape[NUM_LOGUP_COLS - 1] = 1;
    shape
};

// AIR
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
pub struct UintStoreAir;

impl BaseAir<Felt> for UintStoreAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        let o = Felt::ONE;
        let z = Felt::ZERO;
        // One one-hot column per row role.
        vec![
            vec![o, z, z, z], // V_LO  (row 0)
            vec![z, o, z, z], // V_HI  (row 1)
            vec![z, z, o, z], // COMP  (row 2)
            vec![z, z, z, o], // BOUND (row 3)
        ]
    }
}

impl LiftedAir<Felt, QuadFelt> for UintStoreAir {
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
        let (v_lo_sel, v_hi_sel, comp_sel, bound_sel): (AB::Expr, AB::Expr, AB::Expr, AB::Expr) = {
            let p = builder.periodic_values();
            (
                p[PCOL_V_LO].into(),
                p[PCOL_V_HI].into(),
                p[PCOL_COMP].into(),
                p[PCOL_BOUND].into(),
            )
        };

        // β^0 .. β^7 (challenge constants).
        let beta: AB::ExprEF = builder.permutation_randomness()[1].into();
        let mut bp: Vec<AB::ExprEF> = Vec::with_capacity(8);
        bp.push(AB::ExprEF::ONE);
        for i in 1..8 {
            bp.push(bp[i - 1].clone() * beta.clone());
        }

        // `id` register.
        let id: AB::ExprEF =
            current_main::<_, AB::VarEF, 1>(builder.permutation(), REGISTER_COL)[0].into();
        let id_next: AB::ExprEF =
            next_main::<_, AB::VarEF, 1>(builder.permutation(), REGISTER_COL)[0].into();

        // Weighted limb sums. Recombined 32-bit (v/comp): r_k = limb[2k] +
        // 2¹⁶·limb[2k+1]. Direct 32-bit (bound): d_k = limb[k]. k = 0..4.
        // `v`/`comp`'s low half always lives at cells 0–7 (weighted at
        // powers 0–3 for the row's own low content, at powers 4–7 for the
        // row's own high content — since `v` hi's high content sits at
        // cells 0–7 of *its own* row, while `comp`'s high content sits at
        // cells 8–15 of the *same* row as its low content).
        let two16: AB::Expr = AB::Expr::from(Felt::from(1u32 << 16));
        let mut recomb_lo07 = AB::ExprEF::ZERO;
        let mut recomb_hi07 = AB::ExprEF::ZERO;
        let mut recomb_hi815 = AB::ExprEF::ZERO;
        let mut direct_lo = AB::ExprEF::ZERO;
        let mut direct_hi = AB::ExprEF::ZERO;
        for k in 0..4 {
            let r07: AB::Expr =
                AB::Expr::from(local[2 * k]) + two16.clone() * AB::Expr::from(local[2 * k + 1]);
            let r815: AB::Expr = AB::Expr::from(local[8 + 2 * k])
                + two16.clone() * AB::Expr::from(local[8 + 2 * k + 1]);
            recomb_lo07 += bp[k].clone() * r07.clone();
            recomb_hi07 += bp[4 + k].clone() * r07;
            recomb_hi815 += bp[4 + k].clone() * r815;
            direct_lo += bp[k].clone() * AB::Expr::from(local[k]);
            direct_hi += bp[4 + k].clone() * AB::Expr::from(local[8 + k]);
        }

        // Carry terms: Σ c_j·(β^{j+1} − t·β^j), t = 2³², hosted on the
        // bound row — γ₀..γ₃ in cells 4–7, γ₄..γ₆ in cells 12–14.
        let t32: AB::Expr = AB::Expr::from(Felt::new(1u64 << 32).expect("2^32 < Goldilocks p"));
        let mut carry_lo_term = AB::ExprEF::ZERO;
        for j in 0..4 {
            let weight: AB::ExprEF = bp[j + 1].clone() - bp[j].clone() * t32.clone();
            carry_lo_term += weight * AB::Expr::from(local[CARRY_LO_BEGIN + j]);
        }
        let mut carry_hi_term = AB::ExprEF::ZERO;
        for j in 4..7 {
            let weight: AB::ExprEF = bp[j + 1].clone() - bp[j].clone() * t32.clone();
            carry_hi_term += weight * AB::Expr::from(local[CARRY_HI_BEGIN + (j - 4)]);
        }

        // contrib: v/comp add (β-weighted recombine), bound subtracts
        // (direct) and adds its carry cells — gated by role. `comp`
        // contributes both halves from its one row; `bound` likewise.
        let contrib: AB::ExprEF = recomb_lo07.clone() * (v_lo_sel.clone() + comp_sel.clone())
            + recomb_hi07 * v_hi_sel.clone()
            + recomb_hi815 * comp_sel.clone()
            + (carry_lo_term.clone() - direct_lo.clone() + carry_hi_term.clone()
                - direct_hi.clone())
                * bound_sel.clone();

        builder.when_first_row().assert_zero_ext(id.clone());
        builder.when_transition().assert_zero_ext(id_next - id.clone() - contrib);

        // The closing row (`bound`) has a nonzero contribution of its
        // own — its `−direct` terms plus its carry share — so the
        // closure check folds it in directly instead of reading it back
        // from `id_next`, exactly like `UintMulAir`'s `c` row (see that
        // module for the full rationale) and `UintAddAir`'s `p` row.
        let bound_own: AB::ExprEF = carry_lo_term - direct_lo + carry_hi_term - direct_hi;
        builder.assert_zero_ext((id + bound_own) * bound_sel.clone());

        // No first-row anchor: the gap chain alone forces injective ptrs
        // (steps of gap + 1 ∈ [1, 2¹⁶] can't lap the field within any real
        // trace), and every consume names its ptr explicitly, so absolute
        // addresses need no pinning. Honest traces start at the smallest
        // interned pin (ptr ≥ 1); a rogue block at address 0 is inert because ptr 0 is never
        // provided as a real `UintVal` address.

        // Carry booleanity (the no-wrap bound needs binary carries):
        // γ₀..γ₃ in cells 4–7, γ₄..γ₆ in cells 12–14.
        for &cell in
            [CARRY_LO_BEGIN, CARRY_LO_BEGIN + 1, CARRY_LO_BEGIN + 2, CARRY_LO_BEGIN + 3].iter()
        {
            let lj: AB::Expr = local[cell].into();
            builder.assert_zero(bound_sel.clone() * lj.clone() * (AB::Expr::ONE - lj));
        }
        for &cell in [CARRY_HI_BEGIN, CARRY_HI_BEGIN + 1, CARRY_HI_BEGIN + 2].iter() {
            let lj: AB::Expr = local[cell].into();
            builder.assert_zero(bound_sel.clone() * lj.clone() * (AB::Expr::ONE - lj));
        }

        // Cycle-constancy: ptr / bound_ptr are constant within a block
        // (every row but the terminal one). The mults need no transport —
        // they live once, in the hub cells the provides read directly.
        let not_term: AB::Expr = AB::Expr::ONE - bound_sel.clone();
        for col in [COL_PTR, COL_BOUND_PTR] {
            let here: AB::Expr = local[col].into();
            let there: AB::Expr = next[col].into();
            builder.assert_zero(not_term.clone() * (there - here));
        }

        // ptr-gap tie: on a real block boundary (bound row) the witnessed
        // gap = ptr' − ptr − 1, so its Range16 forces strictly-increasing,
        // bounded-gap (hence injective) ptrs. when_transition drops the
        // cyclic last row, where the gap is left free (the prover sets 0).
        let gap: AB::Expr = local[TERM_CELL_GAP].into();
        let ptr_here: AB::Expr = local[COL_PTR].into();
        let ptr_next: AB::Expr = next[COL_PTR].into();
        builder
            .when_transition()
            .assert_zero(bound_sel * (gap + ptr_here + AB::Expr::ONE - ptr_next));

        // Phase 2: LogUp — UintVal (col 0) + Range16.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

impl<LB> LookupAir<LB> for UintStoreAir
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

        let (v_lo_sel, v_hi_sel, comp_sel, bound_sel): (LB::Expr, LB::Expr, LB::Expr, LB::Expr) = {
            let p = builder.periodic_values();
            (
                p[PCOL_V_LO].into(),
                p[PCOL_V_HI].into(),
                p[PCOL_COMP].into(),
                p[PCOL_BOUND].into(),
            )
        };

        let ptr: LB::Expr = local[COL_PTR].into();
        let bound_ptr: LB::Expr = local[COL_BOUND_PTR].into();
        // The provide multiplicities live in `v` hi's own hub cells,
        // read via `next` from `v` lo's row (the only row either merged
        // provide fires from).
        let neg_mult: LB::Expr = LB::Expr::ZERO - next[HUB_CELL_UINTVAL_MULT].into();
        let neg_limbs_mult: LB::Expr = LB::Expr::ZERO - next[HUB_CELL_UINTLIMBS_MULT].into();

        // 4×32 recombined view, full value: the lo half local (this row
        // is `v` lo), the hi half from `v` hi via `next`.
        let two16: LB::Expr = LB::Expr::from(Felt::from(1u32 << 16));
        let recomb: [LB::Expr; 8] = array::from_fn(|k| {
            if k < 4 {
                local[2 * k].into() + two16.clone() * local[2 * k + 1].into()
            } else {
                let k = k - 4;
                next[2 * k].into() + two16.clone() * next[2 * k + 1].into()
            }
        });
        // 4×32 direct view, full value: both halves local (this row is
        // `bound`, hosting both).
        let direct: [LB::Expr; 8] =
            array::from_fn(|k| if k < 4 { local[k].into() } else { local[4 + k].into() });
        // Raw 8×16 view, full value: the lo half local, the hi half via
        // `next`.
        let raw: [LB::Expr; 16] =
            array::from_fn(|j| if j < 8 { local[j].into() } else { next[j - 8].into() });

        let provide_deg = Deg { v: 2, u: 1 };
        let consume_deg = Deg { v: 1, u: 1 };
        // Flattened columns hold ≤ 2 fractions (degree-3 numerator over a
        // degree-2 denominator product); col 0 a single degree-2 fraction.
        let pair_deg = Deg { v: 3, u: 2 };
        let rc_deg = Deg { v: 1, u: 1 };

        // col 0: the merged UintVal provide (running sum, single
        // degree-2 fraction) — fires at `v` lo, reading `v` hi via next.
        builder.next_column(
            |col| {
                col.group(
                    "uintval",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "provide",
                                    neg_mult * v_lo_sel.clone(),
                                    UintValMsg {
                                        ptr: ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                        limbs: recomb,
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
        // col 1: the merged UintVal consume + the per-block ptr-gap
        // Range16, both fired from `bound`.
        builder.next_column(
            |col| {
                col.group(
                    "uintval",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "consume",
                                    bound_sel.clone(),
                                    UintValMsg {
                                        ptr: bound_ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                        limbs: direct,
                                    },
                                    consume_deg,
                                );
                                b.insert(
                                    "range16-gap",
                                    bound_sel.clone(),
                                    Range16Msg { w: local[TERM_CELL_GAP].into() },
                                    consume_deg,
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
        // Range16 gates by cell position: cells 0–7 host every row's own
        // 16-bit content (`v` lo, `v` hi, `comp`'s lo half); cells 8–15
        // only host `comp`'s hi half (`v` hi's cells 8–15 are its hub —
        // multiplicities, never range-checked — and dead cells).
        let cell_gate = |cell: usize| -> LB::Expr {
            if cell < 8 {
                v_lo_sel.clone() + v_hi_sel.clone() + comp_sel.clone()
            } else {
                comp_sel.clone()
            }
        };
        let cell_specs: Vec<(LB::Expr, usize)> =
            (0..NUM_CELLS).map(|cell| (cell_gate(cell), cell)).collect();
        for group in cell_specs
            .chunks(2)
            .map(<[(<LB as LookupBuilder>::Expr, usize)]>::to_vec)
            .collect::<Vec<_>>()
        {
            builder.next_column(
                |col| {
                    col.group(
                        "range16",
                        |g| {
                            g.batch(
                                "f",
                                LB::Expr::ONE,
                                |b| {
                                    for (mult, cell) in group {
                                        b.insert(
                                            "range16-limb",
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
        // col: the merged raw UintLimbs provide, single degree-2
        // fraction — fires at `v` lo, reading `v` hi via next.
        builder.next_column(
            |col| {
                col.group(
                    "uintlimbs",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "provide-raw",
                                    neg_limbs_mult * v_lo_sel,
                                    UintLimbsMsg { ptr, bound_ptr, limbs: raw },
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
    }
}
