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
//! Each uint occupies a **period-8 block** (8 limbs/row); a one-hot
//! periodic selector marks each row's role. Per-block scalars that are
//! read at only one or two rows live in spare *cells* of those rows —
//! the hub row's mults, the bound rows' carries, the term row's gap —
//! instead of full columns; only `ptr` / `bound_ptr` (read on both the
//! v side and the bound / boundary side, beyond any one row's
//! two-row window) ride cycle-constant columns:
//!
//! | row | role        | cells 0..8                                   |
//! |-----|-------------|----------------------------------------------|
//! | 0   | `v` lo      | 8×16-bit (recombined → 4×32)                 |
//! | 1   | `hub`       | `uintval_mult`, `uintlimbs_mult` (cells 0–1) |
//! | 2   | `v` hi      | 8×16-bit                                     |
//! | 3   | `comp` lo   | 8×16-bit                                     |
//! | 4   | `comp` hi   | 8×16-bit                                     |
//! | 5   | `bound` lo  | 4×32-bit (cells 0–3) + carries γ₀..γ₃ (4–7)  |
//! | 6   | `bound` hi  | 4×32-bit (cells 0–3) + carries γ₄..γ₆ (4–6)  |
//! | 7   | `term`      | `gap` (cell 0); assert the block's identity  |
//!
//! The hub sits **between the v halves** so one mult cell serves both
//! provides through the two-row window: the offset-0 provides fire on
//! the `v` lo row (limbs local, mults next), the offset-1 provides fire
//! on the hub (mults local, limbs next) — structurally shared, no copy
//! ties, no constancy transport.
//!
//! A single extension-field register `id` (aux col 2) accumulates, per
//! row, the signed `β`-weighted limb sum, so after the block it holds
//! `v(β) + comp(β) − bound(β) + (β−t)·Γ(β)` with `t = 2³²` — the
//! Schwartz–Zippel image of `v + comp = bound` (the carry term
//! accumulates from the bound rows, where the γ cells live). Each valid
//! block sums to 0, so the *global* accumulator returns to 0 at every
//! boundary; `id == 0` is asserted on each `term` row. The register is
//! excluded from σ by the `num_logup_cols` bound (see [`crate::logup`]).
//!
//! ## Buses
//!
//! `ptr` and `bound_ptr` are cycle-constant per block.
//!
//! - **`UintVal`** (aux col 0): the `v` lo row and the hub *provide* `UintVal(ptr, bound_ptr,
//!   offset, recombined-4×32)` with multiplicity `−uintval_mult` (the hub cell); the `bound` rows
//!   *consume* `UintVal(bound_ptr, bound_ptr, offset, direct-4×32)` with `+1`. Both ptr-slots of
//!   the consume are `bound_ptr`, so it only matches a *self-referential* provider — the modulus
//!   row. With `uintval_mult` = the consumer count, the bus self-balances.
//! - **`Range16`** (aux col 1): each `v`/`comp` 16-bit limb is range- checked (8/row × 4 rows =
//!   32/uint), forcing limbs `< 2¹⁶` so the SZ no-wrap bound holds. Provided externally by the
//!   byte-pair-LUT chiplet.

pub mod add;
pub mod mul;
pub mod require;
pub mod trace;

use core::array;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
};
use miden_crypto::stark::air::ExtensionBuilder;
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
use p3_matrix::dense::RowMajorMatrix;
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

/// LogUp message for the [`UintVal`](BusId::UintVal) relation: a 7-tuple
/// `(ptr, bound_ptr, offset, c0, c1, c2, c3)` exposing one 128-bit half of
/// a stored 256-bit uint as four 32-bit limbs — the **recombined view**
/// (each `c_i = lo16 + 2¹⁶·hi16` of the underlying committed 16-bit limbs)
/// — together with `bound_ptr`, the ptr of the uint storing this value's
/// modulus `p − 1`.
///
/// `offset ∈ {0, 1}` selects the low / high 128-bit chunk; a full value is
/// two messages sharing `(ptr, bound_ptr)`. Carrying `bound_ptr` lets any
/// consumer (eval hash, add/mul) recover the modulus in the same lookup.
/// The limb layout mirrors
/// [`Poseidon2InMsg`](crate::transcript::poseidon2::Poseidon2InMsg) so the
/// eval chip can pin both halves straight into its rate lanes.
///
/// Encoded as `bus_prefix[UintVal] + β⁰·ptr + β¹·bound_ptr + β²·offset +
/// β³·c0 + β⁴·c1 + β⁵·c2 + β⁶·c3`.
#[derive(Debug, Clone)]
pub struct UintValMsg<E> {
    pub ptr: E,
    pub bound_ptr: E,
    pub offset: E,
    pub limbs: [E; 4],
}

impl<E, EF> LookupMessage<E, EF> for UintValMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let [c0, c1, c2, c3] = self.limbs.clone();
        challenges.encode(
            BusId::UintVal as usize,
            [self.ptr.clone(), self.bound_ptr.clone(), self.offset.clone(), c0, c1, c2, c3],
        )
    }
}

/// LogUp message for the [`UintLimbs`](BusId::UintLimbs) relation: an
/// 11-tuple `(ptr, bound_ptr, offset, l0..l7)` exposing one half of a
/// stored 256-bit uint as its **raw 8×16-bit limbs** — the committed
/// trace cells themselves, already `Range16`-checked here, so a consumer
/// (the [mul chiplet](crate::uint::mul)) inherits the range checks
/// through the bus tie and convolves at 16-bit granularity (the no-wrap
/// bound that 32-bit limbs would bust).
///
/// `offset ∈ {0, 1}` selects the low / high 8-limb half; a full value is
/// two messages sharing `(ptr, bound_ptr)`. This view sets
/// [`MAX_MESSAGE_WIDTH`].
///
/// Encoded as `bus_prefix[UintLimbs] + β⁰·ptr + β¹·bound_ptr + β²·offset
/// + β³·l0 + … + β¹⁰·l7`.
#[derive(Debug, Clone)]
pub struct UintLimbsMsg<E> {
    pub ptr: E,
    pub bound_ptr: E,
    pub offset: E,
    pub limbs: [E; 8],
}

impl<E, EF> LookupMessage<E, EF> for UintLimbsMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let [l0, l1, l2, l3, l4, l5, l6, l7] = self.limbs.clone();
        challenges.encode(
            BusId::UintLimbs as usize,
            [
                self.ptr.clone(),
                self.bound_ptr.clone(),
                self.offset.clone(),
                l0,
                l1,
                l2,
                l3,
                l4,
                l5,
                l6,
                l7,
            ],
        )
    }
}

// COLUMN LAYOUT
// ================================================================================================

/// Limb / scalar cells per row (reused per row-role): 8×16-bit limbs, or
/// 4×32-bit + carries, or the hub / term scalars.
pub const NUM_LIMBS: usize = 8;
/// uint pointer (cycle-constant per block).
pub const COL_PTR: usize = 8;
/// pointer of the bound uint = modulus (cycle-constant per block).
pub const COL_BOUND_PTR: usize = 9;
pub const NUM_MAIN_COLS: usize = 10;

/// Hub-row cell holding the `UintVal` provide multiplicity = consumer
/// count. One cell serves both halves' provides: the offset-0 provide
/// (on the v-lo row) reads it as the *next* row, the offset-1 provide
/// (on the hub itself) reads it locally.
pub const HUB_CELL_UINTVAL_MULT: usize = 0;
/// Hub-row cell holding the `UintLimbs` (raw 8×16 view) provide
/// multiplicity. Counted separately from `uintval_mult`: the raw view
/// serves the mul chiplet's convolution operands, the 4×32 view serves
/// eval / add / bound-refs.
pub const HUB_CELL_UINTLIMBS_MULT: usize = 1;
/// Term-row cell holding the witnessed ptr gap `ptr' − ptr − 1` to the
/// next block.
pub const TERM_CELL_GAP: usize = 0;
/// First carry cell on the bound rows: γ₀..γ₃ sit in cells 4–7 of the
/// bound-lo row, γ₄..γ₆ in cells 4–6 of the bound-hi row.
pub const CARRY_CELLS_BEGIN: usize = 4;

/// Block period: one uint = 8 rows.
pub const PERIOD: usize = 8;

// One-hot periodic role selectors (one column each, period 8).
const PCOL_V_LO: usize = 0;
const PCOL_HUB: usize = 1;
const PCOL_V_HI: usize = 2;
const PCOL_COMP_LO: usize = 3;
const PCOL_COMP_HI: usize = 4;
const PCOL_BOUND_LO: usize = 5;
const PCOL_BOUND_HI: usize = 6;
const PCOL_TERM: usize = 7;

// Aux layout (FLATTENED to lqd 1): cols 0..7 = LogUp fraction columns
// (≤ 2 fractions each, col 0 a single degree-2 fraction), col 8 = the
// Schwartz–Zippel `id` register (excluded from σ via num_logup_cols = 8).
// The 15 fractions (UintVal provides/consumes + ptr-gap Range16, eight
// per-limb Range16s, two raw UintLimbs provides) are split so every
// closing constraint is degree ≤ 3. Width disregarded (research/logup-flatten).
const NUM_LOGUP_COLS: usize = 8;
const REGISTER_COL: usize = 8;
const AUX_WIDTH: usize = 9;
const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = [1, 2, 2, 2, 2, 2, 2, 2];

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
            vec![o, z, z, z, z, z, z, z], // V_LO    (row 0)
            vec![z, o, z, z, z, z, z, z], // HUB     (row 1)
            vec![z, z, o, z, z, z, z, z], // V_HI    (row 2)
            vec![z, z, z, o, z, z, z, z], // COMP_LO (row 3)
            vec![z, z, z, z, o, z, z, z], // COMP_HI (row 4)
            vec![z, z, z, z, z, o, z, z], // BOUND_LO(row 5)
            vec![z, z, z, z, z, z, o, z], // BOUND_HI(row 6)
            vec![z, z, z, z, z, z, z, o], // TERM    (row 7)
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

        // Role selectors (extract + drop the periodic borrow).
        let (v_lo, v_hi, comp_lo, comp_hi, bound_lo, bound_hi, term_sel): (
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
        ) = {
            let p = builder.periodic_values();
            (
                p[PCOL_V_LO].into(),
                p[PCOL_V_HI].into(),
                p[PCOL_COMP_LO].into(),
                p[PCOL_COMP_HI].into(),
                p[PCOL_BOUND_LO].into(),
                p[PCOL_BOUND_HI].into(),
                p[PCOL_TERM].into(),
            )
        };

        // β^0 .. β^7 (challenge constants).
        let beta: AB::ExprEF = builder.permutation_randomness()[1].into();
        let mut bp: Vec<AB::ExprEF> = Vec::with_capacity(8);
        bp.push(AB::ExprEF::ONE);
        for i in 1..8 {
            bp.push(bp[i - 1].clone() * beta.clone());
        }

        // `id` register on aux col 2.
        let id: AB::ExprEF =
            current_main::<_, AB::VarEF, 1>(builder.permutation(), REGISTER_COL)[0].into();
        let id_next: AB::ExprEF =
            next_main::<_, AB::VarEF, 1>(builder.permutation(), REGISTER_COL)[0].into();

        // Weighted limb sums. Recombined 32-bit (v/comp): r_k = limb[2k] +
        // 2¹⁶·limb[2k+1]. Direct 32-bit (bound): d_k = limb[k]. k = 0..3.
        let two16: AB::Expr = AB::Expr::from(Felt::from(1u32 << 16));
        let mut lo_recomb = AB::ExprEF::ZERO;
        let mut hi_recomb = AB::ExprEF::ZERO;
        let mut lo_direct = AB::ExprEF::ZERO;
        let mut hi_direct = AB::ExprEF::ZERO;
        for k in 0..4 {
            let r_k: AB::Expr =
                AB::Expr::from(local[2 * k]) + two16.clone() * AB::Expr::from(local[2 * k + 1]);
            let d_k: AB::Expr = AB::Expr::from(local[k]);
            lo_recomb += bp[k].clone() * r_k.clone();
            hi_recomb += bp[4 + k].clone() * r_k;
            lo_direct += bp[k].clone() * d_k.clone();
            hi_direct += bp[4 + k].clone() * d_k;
        }

        // Carry terms: Σ c_j·(β^{j+1} − t·β^j), t = 2³², split across the
        // bound rows hosting the γ cells — γ₀..γ₃ in bound-lo cells 4–7,
        // γ₄..γ₆ in bound-hi cells 4–6 (the id accumulation is additive
        // across rows, so the split is free).
        let t32: AB::Expr = AB::Expr::from(Felt::new(1u64 << 32).expect("2^32 < Goldilocks p"));
        let mut carry_lo_term = AB::ExprEF::ZERO;
        for j in 0..4 {
            let weight: AB::ExprEF = bp[j + 1].clone() - bp[j].clone() * t32.clone();
            carry_lo_term += weight * AB::Expr::from(local[CARRY_CELLS_BEGIN + j]);
        }
        let mut carry_hi_term = AB::ExprEF::ZERO;
        for j in 4..7 {
            let weight: AB::ExprEF = bp[j + 1].clone() - bp[j].clone() * t32.clone();
            carry_hi_term += weight * AB::Expr::from(local[CARRY_CELLS_BEGIN + j - 4]);
        }

        // contrib: v/comp add (β-weighted recombine), bound rows subtract
        // (direct) and add their carry cells — gated by role.
        let contrib: AB::ExprEF = lo_recomb * (v_lo + comp_lo)
            + hi_recomb * (v_hi + comp_hi)
            + (carry_lo_term - lo_direct) * bound_lo.clone()
            + (carry_hi_term - hi_direct) * bound_hi.clone();

        builder.when_first_row().assert_zero_ext(id.clone());
        builder.when_transition().assert_zero_ext(id_next - id.clone() - contrib);
        builder.assert_zero_ext(id * term_sel.clone());

        // No first-row anchor: the gap chain alone forces injective ptrs
        // (steps of gap + 1 ∈ [1, 2¹⁶] can't lap the field within any real
        // trace), and every consume names its ptr explicitly, so absolute
        // addresses need no pinning. Honest traces start at the smallest
        // interned pin (ptr ≥ 1); a rogue block at address 0 is inert because ptr 0 is never
        // provided as a real `UintVal` address.

        // Carry booleanity (the no-wrap bound needs binary carries):
        // γ₀..γ₃ on the bound-lo row, γ₄..γ₆ on the bound-hi row.
        for &cell in local.iter().take(NUM_LIMBS).skip(CARRY_CELLS_BEGIN) {
            let lj: AB::Expr = cell.into();
            builder.assert_zero(bound_lo.clone() * lj.clone() * (AB::Expr::ONE - lj));
        }
        for &cell in local.iter().take(NUM_LIMBS - 1).skip(CARRY_CELLS_BEGIN) {
            let lj: AB::Expr = cell.into();
            builder.assert_zero(bound_hi.clone() * lj.clone() * (AB::Expr::ONE - lj));
        }

        // Cycle-constancy: ptr / bound_ptr are constant within a block
        // (every row but the terminal one). The mults need no transport —
        // they live once, in the hub cells the provides read directly.
        let not_term: AB::Expr = AB::Expr::ONE - term_sel.clone();
        for col in [COL_PTR, COL_BOUND_PTR] {
            let here: AB::Expr = local[col].into();
            let there: AB::Expr = next[col].into();
            builder.assert_zero(not_term.clone() * (there - here));
        }

        // ptr-gap tie: on a real block boundary (term row) the witnessed
        // gap (term cell 0) = ptr' − ptr − 1, so its Range16 forces
        // strictly-increasing, bounded-gap (hence injective) ptrs.
        // when_transition drops the cyclic last row, where the gap is left
        // free (the prover sets 0).
        let gap: AB::Expr = local[TERM_CELL_GAP].into();
        let ptr_here: AB::Expr = local[COL_PTR].into();
        let ptr_next: AB::Expr = next[COL_PTR].into();
        builder
            .when_transition()
            .assert_zero(term_sel * (gap + ptr_here + AB::Expr::ONE - ptr_next));

        // Phase 2: LogUp — UintVal (col 0) + Range16 (col 1).
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

        let (v_lo, hub_sel, v_hi, comp_lo, comp_hi, bound_lo, bound_hi, term_sel): (
            LB::Expr,
            LB::Expr,
            LB::Expr,
            LB::Expr,
            LB::Expr,
            LB::Expr,
            LB::Expr,
            LB::Expr,
        ) = {
            let p = builder.periodic_values();
            (
                p[PCOL_V_LO].into(),
                p[PCOL_HUB].into(),
                p[PCOL_V_HI].into(),
                p[PCOL_COMP_LO].into(),
                p[PCOL_COMP_HI].into(),
                p[PCOL_BOUND_LO].into(),
                p[PCOL_BOUND_HI].into(),
                p[PCOL_TERM].into(),
            )
        };

        let ptr: LB::Expr = local[COL_PTR].into();
        let bound_ptr: LB::Expr = local[COL_BOUND_PTR].into();
        // The provide multiplicities live in the hub cells, between the v
        // halves: the v-lo row reads them as its *next* row, the hub
        // (emitting the offset-1 provides) reads them locally — one cell
        // per mult, no constancy transport, structurally shared across
        // both halves (a split would be the franken-value forgery).
        let neg_mult_next: LB::Expr = LB::Expr::ZERO - next[HUB_CELL_UINTVAL_MULT].into();
        let neg_mult_here: LB::Expr = LB::Expr::ZERO - local[HUB_CELL_UINTVAL_MULT].into();

        // 4×32 views: recombined (v rows; the hub recombines its *next*
        // row, the v-hi limbs) and direct (bound rows).
        let two16: LB::Expr = LB::Expr::from(Felt::from(1u32 << 16));
        let recomb: [LB::Expr; 4] =
            array::from_fn(|k| local[2 * k].into() + two16.clone() * local[2 * k + 1].into());
        let recomb_next: [LB::Expr; 4] =
            array::from_fn(|k| next[2 * k].into() + two16.clone() * next[2 * k + 1].into());
        let direct: [LB::Expr; 4] = array::from_fn(|k| local[k].into());

        let provide_deg = Deg { v: 2, u: 1 };
        let consume_deg = Deg { v: 1, u: 1 };
        // Flattened columns hold ≤ 2 fractions (degree-3 numerator over a
        // degree-2 denominator product); col 0 a single degree-2 fraction.
        let pair_deg = Deg { v: 3, u: 2 };

        // Flattened LogUp (lqd 1): the same fractions — UintVal provides /
        // consumes, the ptr-gap and per-limb Range16s, and the raw UintLimbs
        // provides — re-partitioned ≤ 2 per column (col 0 a single degree-2
        // fraction) so every closing constraint is degree ≤ 3.
        let range_gate: LB::Expr = v_lo.clone() + v_hi + comp_lo + comp_hi;
        let raw: [LB::Expr; 8] = array::from_fn(|j| local[j].into());
        let raw_next: [LB::Expr; 8] = array::from_fn(|j| next[j].into());
        let neg_limbs_mult_next: LB::Expr = LB::Expr::ZERO - next[HUB_CELL_UINTLIMBS_MULT].into();
        let neg_limbs_mult_here: LB::Expr = LB::Expr::ZERO - local[HUB_CELL_UINTLIMBS_MULT].into();
        let rc_deg = Deg { v: 1, u: 1 };

        // col 0: UintVal provide-lo (running sum, single degree-2 fraction).
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
                                    "provide-lo",
                                    neg_mult_next * v_lo.clone(),
                                    UintValMsg {
                                        ptr: ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                        offset: LB::Expr::ZERO,
                                        limbs: recomb.clone(),
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
        // col 1: provide-hi + consume-lo.
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
                                    "provide-hi",
                                    neg_mult_here * hub_sel.clone(),
                                    UintValMsg {
                                        ptr: ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                        offset: LB::Expr::ONE,
                                        limbs: recomb_next.clone(),
                                    },
                                    provide_deg,
                                );
                                b.insert(
                                    "consume-lo",
                                    bound_lo.clone(),
                                    UintValMsg {
                                        ptr: bound_ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                        offset: LB::Expr::ZERO,
                                        limbs: direct.clone(),
                                    },
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
        // col 2: consume-hi + the per-block ptr-gap Range16.
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
                                    "consume-hi",
                                    bound_hi.clone(),
                                    UintValMsg {
                                        ptr: bound_ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                        offset: LB::Expr::ONE,
                                        limbs: direct.clone(),
                                    },
                                    consume_deg,
                                );
                                b.insert(
                                    "range16-gap",
                                    term_sel.clone(),
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
        // cols 3..6: the eight v/comp Range16 limbs, two per column.
        for pair in 0..4usize {
            let (j0, j1) = (2 * pair, 2 * pair + 1);
            let (g0, g1) = (range_gate.clone(), range_gate.clone());
            builder.next_column(
                |col| {
                    col.group(
                        "range16",
                        |g| {
                            g.batch(
                                "f",
                                LB::Expr::ONE,
                                |b| {
                                    b.insert(
                                        "range16-limb",
                                        g0,
                                        Range16Msg { w: local[j0].into() },
                                        rc_deg,
                                    );
                                    b.insert(
                                        "range16-limb",
                                        g1,
                                        Range16Msg { w: local[j1].into() },
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
        }
        // col 7: the raw UintLimbs provides (lo + hi).
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
                                    "provide-raw-lo",
                                    neg_limbs_mult_next * v_lo.clone(),
                                    UintLimbsMsg {
                                        ptr: ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                        offset: LB::Expr::ZERO,
                                        limbs: raw,
                                    },
                                    provide_deg,
                                );
                                b.insert(
                                    "provide-raw-hi",
                                    neg_limbs_mult_here * hub_sel,
                                    UintLimbsMsg {
                                        ptr,
                                        bound_ptr,
                                        offset: LB::Expr::ONE,
                                        limbs: raw_next,
                                    },
                                    provide_deg,
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
    }
}
