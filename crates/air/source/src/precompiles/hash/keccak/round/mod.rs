//! Keccak-round chiplet (TAM-style miniVM).
//!
//! Orchestrates a single Keccak-f\[1600] round via a three-address
//! machine over the [`Memory64`](crate::precompiles::hash::memory64) bus. Repeats
//! 24 times to cover a full permutation; multiple permutations stack
//! cleanly in one trace (and the sponge AIR uses the bus's multiset
//! semantics to overwrite state at absorb boundaries).
//!
//! Each active operation row carries byte decompositions of its operands and canonical XOR, plus
//! two masked-byte XORs that witness any rotation. `BytePairLutMsg` binds the canonical byte-wise
//! XOR, while two split-byte lookups and fixed rotation coefficients bind the `Memory64` result.
//! The periodic program below defines the slot and address layout, including the decomposition for
//! `ρ > 30`.

pub mod program;

use alloc::{borrow::Cow, vec::Vec};
use core::{array, ops::Range};

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
};
use miden_stark::{
    air,
    air::LiftedAirBuilder as _,
    lookup::{self, Deg, LookupBatch, LookupColumn, LookupGroup},
};
use miden_utils_sync::LazyLock;
use p3_field::Dup;
pub use program::{NUM_PERIODIC_COLS, Op, ROUND_PERIOD, Slot, round_program, slots};

use crate::precompiles::{
    hash::memory64::Memory64Msg,
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS, frac_col},
    primitives::byte_pair_lut::{BytePairLutMsg, andnot_result_from_xor},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{halves_le, pack_le},
};

// MAIN COLUMN LAYOUT
// ================================================================================================

/// Row counter; increments by 1 each row. Boundary `ip[0] = 25` at the
/// trace's first row (sponge addresses [0, 25) hold the round-0 lane
/// inputs).
pub const COL_IP: usize = 0;
/// Source A value, byte-decomposed LSB-first. Every active non-NOP row range-checks it through
/// [`BytePairLutMsg`]. Binary logic rows bind it with `b_bytes` and `x_bytes`; pure-ROL rows use
/// `(a, 0, a)`. See [`R_BYTES_RANGE`].
pub const A_BYTES_RANGE: Range<usize> = 1..9;
/// Source B value, byte-decomposed LSB-first. Real second operand only
/// on rows with `is_xor | is_andnot` active; on pure-ROL and NOP rows
/// the trace writer stores 0. On active pure-ROL rows, the byte-pair
/// lookup and the `x = a` passthrough constraint also force this value
/// to 0; on inactive rows its lookup multiplicity is 0.
pub const B_BYTES_RANGE: Range<usize> = 9..17;
/// Canonical XOR `x = a xor b`, byte-decomposed. Rows without a binary logic operation store
/// `x = a` with `b = 0`. Rotation rows rotate `x` directly; pure ANDNOT rows reconstruct their
/// Memory64 result from `(x - a + b) / 2`.
pub const R_BYTES_RANGE: Range<usize> = 17..25;
/// XORs of each half's split byte with its fixed high-bit mask. The canonical byte lookup
/// authenticates both XOR values against fixed masks; periodic coefficients reconstruct the
/// rotated result directly.
pub const ROT_MASK_XOR_RANGE: Range<usize> = 25..27;
/// Active indicator. 1 on active rounds, 0 on each cycle's dead round
/// (the 25th round of every perm cycle) and on trace-tail padding.
/// Constant within each round (changes only at round boundaries —
/// gated by the `p_last` periodic indicator). Every bus multiplicity
/// is multiplied by `act`, so dead rounds and padding rows contribute
/// nothing to the Memory64 or BytePairLut buses. The sponge AIR
/// σ-matches the chiplet's active-rows-only residue; it also forces
/// `act = 1` at row 0 by providing `RC[0]`, which the round's iota row consumes.
pub const COL_ACT: usize = 27;

// All COL_* / *_RANGE indices above are **lane-local** (within one
// [`LANE_WIDTH`]-wide band); the absolute main-trace index is
// `lane * LANE_WIDTH + local`, via [`lane_base`].

/// Width of one permutation-lane's column band.
pub const LANE_WIDTH: usize = 28;
/// Number of permutation-lanes packed side-by-side per row. Each lane runs a
/// contiguous block of permutations in its own column band while sharing the
/// period-128 program, so the row count is ~`1/NUM_LANES`
/// of a single stream. Lane 0 keeps the explicit `ip[0] = 25` anchor; a later
/// lane's absolute `ip` frame (its memory64 address range) is pinned by the
/// bus — its round-0 reads of the sponge-provided initial state force it, so a
/// shifted frame would leave uncancelled bus terms (Σσ ≠ 0). The lanes hold
/// disjoint, contiguous address ranges (one per perm), so the packed memory64
/// multiset equals the union of the per-perm ranges and the sponge consumer
/// reads the same stream.
pub const NUM_LANES: usize = 2;
pub const NUM_MAIN_COLS: usize = LANE_WIDTH * NUM_LANES;

/// Absolute start column of `lane`'s band in the main trace.
#[inline]
pub fn lane_base(lane: usize) -> usize {
    lane * LANE_WIDTH
}

// AUX COLUMN LAYOUT
// ================================================================================================

/// Each lane uses four auxiliary columns for thirteen lookup fractions: destination and both
/// sources, two groups of four byte lookups, and one pair of masked-byte lookups.
/// Column zero is the centered cyclic accumulator for all lanes.
const AUX_LANE_WIDTH: usize = 4;
pub const NUM_AUX_COLS: usize = AUX_LANE_WIDTH * NUM_LANES;

// PERIODIC COLUMN INDICES
// ================================================================================================

pub use program::{
    COL_BACK_A as PCOL_BACK_A, COL_BACK_B as PCOL_BACK_B, COL_DST_MULT as PCOL_DST_MULT,
    COL_IS_ANDNOT as PCOL_IS_ANDNOT, COL_IS_ROL as PCOL_IS_ROL, COL_IS_XOR as PCOL_IS_XOR,
    COL_IS_XORROL as PCOL_IS_XORROL, COL_P_LAST as PCOL_P_LAST,
};

// AIR
// ================================================================================================

/// Keccak-round chiplet AIR. Its period-128 program checks active operands and masked-byte
/// rotation witnesses against [`BytePairLut`](crate::precompiles::primitives::byte_pair_lut), then
/// provides each reconstructed result through [`Memory64`](crate::precompiles::hash::memory64).
#[derive(Debug, Default, Clone, Copy)]
pub struct KeccakRoundAir;

static PERIODIC_COLUMNS: LazyLock<[Vec<Felt>; NUM_PERIODIC_COLS]> = LazyLock::new(round_program);

impl air::LiftedAir for KeccakRoundAir {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: NUM_MAIN_COLS,
            aux_width: NUM_AUX_COLS,
            num_public_values: 0,
            num_challenges: NUM_RANDOMNESS,
            num_exports: NUM_LOGUP_VALUES,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(PERIODIC_COLUMNS.as_slice()),
        }
    }

    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        // Phase 1: local row constraints, replicated per lane over its
        // disjoint column band. The periodic program is shared — every lane
        // sits on the same program slot each row.
        let local = frame.main.current;
        let next_window = frame.main.next;

        let periodic = frame.periodic;
        let p_last = periodic[PCOL_P_LAST].dup();
        let is_xor = periodic[PCOL_IS_XOR].dup();
        let is_andnot = periodic[PCOL_IS_ANDNOT].dup();

        for lane in 0..NUM_LANES {
            let base = lane_base(lane);
            let ip = local[base + COL_IP].dup();
            let next_ip = next_window[base + COL_IP].dup();
            let act = local[base + COL_ACT].dup();
            let next_act = next_window[base + COL_ACT].dup();

            // IP boundary: only lane 0 is anchored at ip = 25 (sponge
            // addresses 0..25 precede the trace IP range). A later lane
            // starts mid address-space at a data-dependent ip; its absolute
            // frame is pinned by the memory64 bus (its round-0 reads of the
            // sponge-provided initial state), so no constant boundary applies.
            if lane == 0 {
                builder
                    .when(frame.first_row())
                    .assert_eq(ip.dup(), AB::Expr::from(Felt::from(25u8)));
            }

            // IP transition: ip' − ip − 1 = 0, per lane. `when_transition` skips the cyclic wrap
            // at row N−1 → 0; the centered LogUp recurrence independently includes that wrap.
            builder.when(frame.transition()).assert_zero(next_ip - ip - AB::Expr::ONE);

            // Active binarity: act ∈ {0, 1}.
            builder.assert_bool(local[base + COL_ACT].dup());

            // Active constant within a round: `(1 − p_last) · (act' − act) =
            // 0`. `p_last` is the period-128 indicator that fires at slot 127
            // (the row whose transition crosses a round boundary), so `act`
            // may change only into slot 0 of the next round. Applied ungated:
            // at the cyclic wrap (row N−1 → 0), N−1 lands on slot 127 (any
            // pow2 height ≥ 128), so `p_last = 1` and the constraint is
            // vacuous. The sponge bus forces `act = 1` at row 0 by providing
            // RC[0] to the iota row, whose `act` equals the round's through this constraint.
            builder.assert_zero((AB::Expr::ONE - p_last.dup()) * (next_act - act));

            // Active pure-ROL rows range-check both vectors through BytePairLut. Each
            // packed u32 embeds injectively in the field, so two equalities bind all eight
            // bytes. NOP and inactive rows have no observable operand/result bus traffic.
            let no_logic = AB::Expr::ONE - is_xor.dup() - is_andnot.dup();
            for half in 0..2 {
                let a: AB::Expr = pack_le(
                    &local[base + A_BYTES_RANGE.start + 4 * half
                        ..base + A_BYTES_RANGE.start + 4 * half + 4],
                    256,
                );
                let r: AB::Expr = pack_le(
                    &local[base + R_BYTES_RANGE.start + 4 * half
                        ..base + R_BYTES_RANGE.start + 4 * half + 4],
                    256,
                );
                builder.assert_zero(no_logic.dup() * (r - a));
            }
        }

        // Phase 2: LogUp argument via the LogUp adapter.
        lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl air::ProverAir<QuadFelt> for KeccakRoundAir {
    type Error = lookup::LookupError;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        lookup::build_logup_aux_trace(self, inputs)
    }
}

/// The value this row writes to `ip` on the Memory64 bus. Active operation rows authenticate
/// `x_bytes` as canonical XOR bytes through BytePairLut.
/// ANDNOT rows reconstruct `(x - a + b) / 2`; rotation rows use XOR directly.
fn memory_provide_c<E: Algebra<Felt>>(
    a_bytes: &[E; 8],
    b_bytes: &[E; 8],
    x_bytes: &[E; 8],
    mask_xors: &[E; 2],
    periodic: &[E; NUM_PERIODIC_COLS],
    is_andnot: E,
) -> [E; 2] {
    let a: [E; 2] = halves_le(a_bytes, 256);
    let b: [E; 2] = halves_le(b_bytes, 256);
    let x: [E; 2] = halves_le(x_bytes, 256);
    array::from_fn(|half| {
        let andnot = andnot_result_from_xor(a[half].dup(), b[half].dup(), x[half].dup());
        let logic = x[half].dup() + is_andnot.dup() * (andnot - x[half].dup());
        // Fixed coefficients include the rotation selector and half swap. Each product in
        // the destination expression has one periodic coefficient and one witness value.
        logic
            + (0..4)
                .map(|i| {
                    periodic[program::COL_OUTPUT_SAME + i].dup() * x_bytes[4 * half + i].dup()
                        + periodic[program::COL_OUTPUT_OTHER + i].dup()
                            * x_bytes[4 * (1 - half) + i].dup()
                })
                .sum::<E>()
            + periodic[program::COL_OUTPUT_MASK_SAME].dup() * mask_xors[half].dup()
            + periodic[program::COL_OUTPUT_MASK_OTHER].dup() * mask_xors[1 - half].dup()
            + periodic[program::COL_OUTPUT_BIAS].dup()
    })
}

// LOOKUP AIR
// ================================================================================================

/// Per lane: three Memory64 fractions, two groups of four byte lookups, and two masked bytes.
pub(crate) const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = build_column_shape();

const fn build_column_shape() -> [usize; NUM_AUX_COLS] {
    let mut shape = [4usize; NUM_AUX_COLS];
    let mut lane = 0;
    while lane < NUM_LANES {
        shape[lane * AUX_LANE_WIDTH] = 3;
        shape[lane * AUX_LANE_WIDTH + 3] = 2;
        lane += 1;
    }
    shape
}

impl<LB> lookup::LookupAir<LB> for KeccakRoundAir
where
    LB: lookup::LookupBuilder<F = Felt>,
{
    fn column_shape(&self) -> &[usize] {
        &COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, frame: &lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        let local = frame.main.current;
        let periodic: &[LB::Expr; NUM_PERIODIC_COLS] =
            frame.periodic.try_into().expect("Keccak round periodic columns");
        // All lanes read the same periodic operation selectors, back-pointers, and multiplicities.
        let is_xor: LB::Expr = periodic[PCOL_IS_XOR].clone();
        let is_andnot: LB::Expr = periodic[PCOL_IS_ANDNOT].clone();
        let is_rol: LB::Expr = periodic[PCOL_IS_ROL].clone();
        let is_xorrol: LB::Expr = periodic[PCOL_IS_XORROL].clone();
        let back_a: LB::Expr = periodic[PCOL_BACK_A].clone();
        let back_b: LB::Expr = periodic[PCOL_BACK_B].clone();
        let dst_mult: LB::Expr = periodic[PCOL_DST_MULT].clone();
        let linear_interaction_deg = Deg { v: 2, u: 1 };
        let dst_deg = Deg { v: 2, u: 2 };
        let memory_deg = Deg { v: 5, u: 4 };
        let quad_deg = Deg { v: 5, u: 4 };

        // Lane-local fractions share one centered accumulator; their union contributes to the
        // same Memory64 and BytePairLut buses.
        for lane in 0..NUM_LANES {
            let base = lane_base(lane);
            let ip = local[base + COL_IP].dup();
            let act = local[base + COL_ACT].dup();

            let a_bytes: &[LB::Expr; 8] = local
                [base + A_BYTES_RANGE.start..base + A_BYTES_RANGE.end]
                .try_into()
                .expect("Keccak round A byte band");
            let b_bytes: &[LB::Expr; 8] = local
                [base + B_BYTES_RANGE.start..base + B_BYTES_RANGE.end]
                .try_into()
                .expect("Keccak round B byte band");
            let x_bytes: &[LB::Expr; 8] = local
                [base + R_BYTES_RANGE.start..base + R_BYTES_RANGE.end]
                .try_into()
                .expect("Keccak round XOR byte band");
            let mask_xors: &[LB::Expr; 2] = local
                [base + ROT_MASK_XOR_RANGE.start..base + ROT_MASK_XOR_RANGE.end]
                .try_into()
                .expect("Keccak round mask XOR band");

            // Multiplicity expressions, all gated by this lane's `act` so
            // dead-round / padding rows contribute nothing to the bus.
            //
            // `is_active`: row reads `src_a` (every non-NOP op does, once). A
            // fused XORROL row sets both `is_xor` and `is_rol`, so subtracting
            // the one-hot `is_xorrol` recovers one read per row at degree 1.
            // This gate also drives the row's `BytePairLut` byte requires, so every row that reads
            // `a` range-checks it.
            let is_active = act.clone()
                * (is_xor.clone() + is_andnot.clone() + is_rol.clone() - is_xorrol.clone());
            // `reads_b`: XOR / ANDNOT / fused XORROL all read `src_b`.
            let reads_b = act.clone() * (is_xor.clone() + is_andnot.clone());
            // Periodic rotation selectors also fire in the inactive tail. Activity gating lets
            // those zero-filled rows omit the masked-byte witnesses.
            let rol_act = act.clone() * is_rol.clone();
            let dst_mult_act = act * dst_mult.clone();

            // The destination denominator has degree two; each source denominator is affine.
            // Packing all three gives denominator degree four and closing-constraint degree five.
            let [c_lo, c_hi] =
                memory_provide_c(a_bytes, b_bytes, x_bytes, mask_xors, periodic, is_andnot.clone());
            // A destination can have several readers, so its provide uses the negative read count.
            let neg_dst_mult: LB::Expr = LB::Expr::ZERO - dst_mult_act;
            let [a_lo, a_hi] = halves_le(a_bytes, 256);
            let [b_lo, b_hi] = halves_le(b_bytes, 256);
            frac_col!(
                builder,
                "memory64",
                memory_deg,
                (
                    "dst",
                    neg_dst_mult,
                    Memory64Msg { addr: ip.clone(), lo: c_lo, hi: c_hi },
                    dst_deg
                ),
                (
                    "src_a",
                    is_active.clone(),
                    Memory64Msg {
                        addr: ip.clone() - back_a.clone(),
                        lo: a_lo,
                        hi: a_hi
                    },
                    linear_interaction_deg
                ),
                (
                    "src_b",
                    reads_b.clone(),
                    Memory64Msg {
                        addr: ip - back_b.clone(),
                        lo: b_lo,
                        hi: b_hi
                    },
                    linear_interaction_deg
                ),
            );
            // Band columns 1 and 2: eight BytePairLut byte requires, four per column.
            // `x_bytes` carry canonical XOR for every active operation, so every denominator stays
            // affine. On pure-ROL rows, the XOR tuple plus `x = a` forces `b = 0`.
            for batch in 0..2 {
                let i0 = batch * 4;
                let i1 = i0 + 1;
                let i2 = i0 + 2;
                let i3 = i0 + 3;
                frac_col!(
                    builder,
                    "byte-pair-lut",
                    quad_deg,
                    (
                        "byte-req",
                        is_active.clone(),
                        BytePairLutMsg::from_xor(
                            a_bytes[i0].dup(),
                            b_bytes[i0].dup(),
                            x_bytes[i0].dup(),
                        ),
                        linear_interaction_deg
                    ),
                    (
                        "byte-req",
                        is_active.clone(),
                        BytePairLutMsg::from_xor(
                            a_bytes[i1].dup(),
                            b_bytes[i1].dup(),
                            x_bytes[i1].dup(),
                        ),
                        linear_interaction_deg
                    ),
                    (
                        "byte-req",
                        is_active.clone(),
                        BytePairLutMsg::from_xor(
                            a_bytes[i2].dup(),
                            b_bytes[i2].dup(),
                            x_bytes[i2].dup(),
                        ),
                        linear_interaction_deg
                    ),
                    (
                        "byte-req",
                        is_active.clone(),
                        BytePairLutMsg::from_xor(
                            a_bytes[i3].dup(),
                            b_bytes[i3].dup(),
                            x_bytes[i3].dup(),
                        ),
                        linear_interaction_deg
                    ),
                );
            }
            // Pair the two degree-two split-byte messages; their closing constraint has degree
            // five.
            let degree = Deg { v: 4, u: 4 };
            builder.next_column(
                |column| {
                    column.group(
                        "byte-pair-lut",
                        |group| {
                            group.batch(
                                "rotation-masks",
                                LB::Expr::ONE,
                                |batch| {
                                    for half in 0..2 {
                                        let byte = (0..4)
                                            .map(|i| {
                                                periodic[program::COL_ROT_BYTE_BEGIN + i].clone()
                                                    * x_bytes[4 * half + i].dup()
                                            })
                                            .sum::<LB::Expr>();
                                        batch.insert(
                                            "masked-byte",
                                            rol_act.clone(),
                                            BytePairLutMsg::from_xor(
                                                byte,
                                                periodic[program::COL_ROT_MASK].clone(),
                                                mask_xors[half].dup(),
                                            ),
                                            Deg { v: 2, u: 2 },
                                        );
                                    }
                                },
                                degree,
                            );
                        },
                        degree,
                    );
                },
                degree,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use miden_core::utils::RowMajorMatrix;
    use miden_stark::air::AirKernel;

    use super::*;

    #[test]
    fn native_round_capture_and_direct_session_preserve_geometry() {
        // Native capture instantiates the complete source with non-Copy owned expression trees.
        let captured = air::capture_with::<_, QuadFelt>(&KeccakRoundAir).unwrap();
        let descriptor = &captured.descriptor;
        let spec = descriptor.spec();
        assert_eq!((spec.main_width, spec.aux_width), (56, 8));
        assert_eq!((spec.num_public_values, spec.num_challenges, spec.num_exports), (0, 2, 1));
        assert_eq!(spec.preprocessed, None);
        assert_eq!(spec.periodic_columns.as_ref(), PERIODIC_COLUMNS.as_slice());
        assert_eq!(COLUMN_SHAPE, [3, 4, 4, 2, 3, 4, 4, 2]);
        assert_eq!(descriptor.analysis().counts(), air::ConstraintCounts { base: 11, ext: 9 });
        assert_eq!(descriptor.analysis().raw_degrees(), air::ConstraintDegrees { base: 2, ext: 5 });
        assert_eq!(descriptor.analysis().layout().base_indices(), &(0..11).collect::<Vec<_>>());
        assert_eq!(descriptor.analysis().layout().ext_indices(), &(11..20).collect::<Vec<_>>());

        let kernel = air::DirectKernel::new(KeccakRoundAir).unwrap();
        let direct =
            air::capture_from_spec::<Felt, QuadFelt>(spec.as_borrowed(), |frame, inputs, sink| {
                kernel.bind(inputs).unwrap().eval(frame, sink)
            })
            .unwrap();
        assert_eq!(direct.descriptor.fingerprint(), descriptor.fingerprint());

        #[cfg(feature = "std")]
        lookup::validate_native(&KeccakRoundAir, spec).unwrap();
    }

    #[derive(Default)]
    struct ZeroRowSink {
        base: usize,
        ext: usize,
    }

    impl air::LiftedAirBuilder for ZeroRowSink {
        type F = Felt;
        type Expr = Felt;
        type ExtExpr = QuadFelt;

        fn emit_base(&mut self, value: Felt, _meta: air::ConstraintMeta<'_>) {
            assert_eq!(value, Felt::ZERO);
            self.base += 1;
        }

        fn emit_ext(&mut self, value: QuadFelt, _meta: air::ConstraintMeta<'_>) {
            assert_eq!(value, QuadFelt::ZERO);
            self.ext += 1;
        }
    }

    #[test]
    fn native_round_direct_session_accepts_inactive_first_row() {
        let mut current = [Felt::ZERO; NUM_MAIN_COLS];
        let mut next = current;
        for lane in 0..NUM_LANES {
            current[lane_base(lane) + COL_IP] = Felt::from(25u32 + lane as u32 * 100);
            next[lane_base(lane) + COL_IP] = current[lane_base(lane) + COL_IP] + Felt::ONE;
        }
        let periodic: [Felt; NUM_PERIODIC_COLS] = array::from_fn(|i| PERIODIC_COLUMNS[i][0]);
        let aux = [QuadFelt::ZERO; NUM_AUX_COLS];
        let frame = air::AirFrame {
            main: air::Rows { current: &current, next: &next },
            preprocessed: air::Rows { current: &[], next: &[] },
            aux: air::Rows { current: &aux, next: &aux },
            periodic: &periodic,
            selectors: air::Selectors {
                first: Felt::ONE,
                last: Felt::ZERO,
                transition: Felt::ONE,
            },
        };
        let challenges = [QuadFelt::from_u8(7), QuadFelt::from_u8(11)];
        let exports = [QuadFelt::ZERO];
        let inputs = air::UniformInputs {
            public_values: &[],
            challenges: &challenges,
            exports: &exports,
        };
        let kernel = air::DirectKernel::new(KeccakRoundAir).unwrap();
        let mut sink = ZeroRowSink::default();
        kernel.bind(inputs).unwrap().eval(&frame, &mut sink);
        assert_eq!((sink.base, sink.ext), (11, 9));
    }

    #[test]
    fn native_round_witness_rejects_wrong_main_width() {
        let main = RowMajorMatrix::new(vec![Felt::ZERO; NUM_MAIN_COLS - 1], NUM_MAIN_COLS - 1);
        let challenges = [QuadFelt::from_u8(7), QuadFelt::from_u8(11)];
        let result = <KeccakRoundAir as air::ProverAir<QuadFelt>>::build_aux_trace(
            &KeccakRoundAir,
            air::AuxTraceInputs {
                main: &main,
                preprocessed: None,
                public_values: &[],
                statement: &[],
                challenges: &challenges,
            },
        );
        assert_eq!(
            result.unwrap_err(),
            lookup::LookupError::MainWidth {
                expected: NUM_MAIN_COLS,
                actual: NUM_MAIN_COLS - 1,
            }
        );
    }

    #[test]
    fn masked_byte_rotation_matches_native_rotation() {
        let columns = round_program();
        for (slot, spec) in slots().iter().enumerate() {
            let (Op::Rol(shift) | Op::XorRol(shift)) = spec.op else {
                continue;
            };
            let periodic = array::from_fn(|column| columns[column][slot]);
            let mask = periodic[program::COL_ROT_MASK].as_canonical_u64() as u8;
            // Exercise every split-byte value in each half, including carries into neighbouring
            // all-one bytes. Compare the field reconstruction with the independent u64 operation.
            for position in 0..8 {
                for byte in 0..=u8::MAX {
                    let single = u64::from(byte) << (8 * position);
                    for input in [single, !single] {
                        let bytes = input.to_le_bytes().map(Felt::from);
                        let xors = array::from_fn(|half| {
                            let selected = (0..4)
                                .map(|i| {
                                    periodic[program::COL_ROT_BYTE_BEGIN + i] * bytes[4 * half + i]
                                })
                                .sum::<Felt>()
                                .as_canonical_u64()
                                as u8;
                            Felt::from(selected ^ mask)
                        });
                        let halves = memory_provide_c(
                            &bytes,
                            &[Felt::ZERO; 8],
                            &bytes,
                            &xors,
                            &periodic,
                            periodic[PCOL_IS_ANDNOT],
                        );
                        let expected = input.rotate_left(shift);
                        assert_eq!(halves[0].as_canonical_u64(), expected & u64::from(u32::MAX));
                        assert_eq!(halves[1].as_canonical_u64(), expected >> 32);
                    }
                }
            }
        }
    }
}
