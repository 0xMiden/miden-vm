//! Keccak-round chiplet (TAM-style miniVM).
//!
//! Orchestrates a single Keccak-f\[1600] round via a three-address
//! machine over the [`Memory64`](crate::hash::memory64) bus. Repeats
//! 24 times to cover a full permutation; multiple permutations stack
//! cleanly in one trace (and the sponge AIR uses the bus's multiset
//! semantics to overwrite state at absorb boundaries).
//!
//! Each row carries its operands and result as byte/limb decompositions
//! and verifies them directly against the [`BytePairLut`](crate::primitives::byte_pair_lut)
//! chiplet (byte-wise op results via `BytePairLutMsg`, 16-bit range checks
//! via `Range16Msg`) — no separate logic/rotate chiplet or intermediate
//! bus is needed.
//!
//! See `docs/chiplets/keccak.md` for the design rationale (slot
//! layout, sponge contract, address-space layout, decomposition for
//! `ρ > 30`).

pub mod program;

use alloc::{vec, vec::Vec};
use core::{array, ops::Range};

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
pub use program::{NUM_PERIODIC_COLS, Op, ROUND_PERIOD, Slot, round_program, slots};

use crate::{
    hash::{keccak::reference::KECCAK_RC, memory64::Memory64Msg},
    logup::{
        CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES, build_logup_aux_trace,
        frac_col,
    },
    primitives::byte_pair_lut::{
        BytePairLutMsg, BytePairLutRequires, BytePairOp, Range16Msg, require_logic64,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, halves_le, next_main, pack_le},
};

// MAIN COLUMN LAYOUT
// ================================================================================================

/// Row counter; increments by 1 each row. Boundary `ip[0] = 25` at the
/// trace's first row (sponge addresses [0, 25) hold the round-0 lane
/// inputs).
pub const COL_IP: usize = 0;
/// Source A value, byte-decomposed LSB-first. Range-checked (and, on
/// rows that read a real logic op, verified against `b_bytes`/`r_bytes`)
/// via the [`BytePairLutMsg`] requires this chiplet issues directly —
/// see [`R_BYTES_RANGE`].
pub const A_BYTES_RANGE: Range<usize> = 1..9;
/// Source B value, byte-decomposed LSB-first. Real second operand only
/// on rows with `is_xor | is_andnot` active; on pure-ROL and NOP rows
/// the effective operand is gated to 0 at the message level (the raw
/// column may hold anything).
pub const B_BYTES_RANGE: Range<usize> = 9..17;
/// Logic result `r = a OP b`, byte-decomposed — or the passthrough
/// `r = a` on rows with no logic op active (pinned by a local
/// constraint). This is the value ROL rotates, and — when `is_rol = 0`
/// — the value written to `ip` on the Memory64 bus.
pub const R_BYTES_RANGE: Range<usize> = 17..25;
/// 16-bit limbs of `(r_half + 2^32)·k` for `r`'s low and high halves
/// (first 4 limbs: low half; next 4: high half), populated iff
/// `is_rol = 1`. Same construction as a rotate chiplet's ROL row, but
/// rotating this row's own `r` rather than a value read from elsewhere.
/// Range-checked via [`Range16Msg`] requires. See [`memory_provide_c`]
/// for how the rotated 64-bit value is reconstructed from these limbs.
pub const ROT_LIMBS_RANGE: Range<usize> = 25..33;
/// Active indicator. 1 on active rounds, 0 on each cycle's dead round
/// (the 25th round of every perm cycle) and on trace-tail padding.
/// Constant within each round (changes only at round boundaries —
/// gated by the `p_last` periodic indicator). Every bus multiplicity
/// is multiplied by `act`, so dead rounds and padding rows contribute
/// nothing to the Memory64 or BytePairLut buses. The sponge AIR
/// σ-matches the chiplet's active-rows-only residue; it also forces
/// `act = 1` at row 0 by providing `RC[0]`, which the chiplet's
/// slot 1 must consume.
pub const COL_ACT: usize = 33;

// All COL_* / *_RANGE indices above are **lane-local** (within one
// [`LANE_WIDTH`]-wide band); the absolute main-trace index is
// `lane * LANE_WIDTH + local`, via [`lane_base`].

/// Width of one permutation-lane's column band.
pub const LANE_WIDTH: usize = 34;
/// Number of permutation-lanes packed side-by-side per row. Each lane runs a
/// contiguous block of permutations in its own column band while sharing the
/// (preprocessed, free) periodic program, so the row count is ~`1/NUM_LANES`
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

/// Interleave the per-lane column bands into one `NUM_MAIN_COLS`-wide
/// row-major matrix, each lane's `LANE_WIDTH` cells placed at its band base.
fn interleave_lanes(lane_cells: &[Vec<Felt>; NUM_LANES], height: usize) -> RowMajorMatrix<Felt> {
    let mut trace = vec![Felt::ZERO; height * NUM_MAIN_COLS];
    for (lane, cells) in lane_cells.iter().enumerate() {
        let base = lane_base(lane);
        for r in 0..height {
            let src = &cells[r * LANE_WIDTH..(r + 1) * LANE_WIDTH];
            let row_start = r * NUM_MAIN_COLS + base;
            trace[row_start..row_start + LANE_WIDTH].copy_from_slice(src);
        }
    }
    RowMajorMatrix::new(trace, NUM_MAIN_COLS)
}

// AUX COLUMN LAYOUT
// ================================================================================================

/// FLATTENED to lqd 1, repeated per lane: each lane's 10-column band holds
/// 19 fractions (all degree-≤2 multiplicities) split ≤ 2 per column, the
/// band's col 0 a single fraction:
/// - band col 0: memory64 dst provide.
/// - band col 1: memory64 `src_a` + `src_b` requires.
/// - band cols 2–5: 8 `BytePairLut` byte requires verifying `r = a OP b` (or `r = a` on pure-ROL
///   rows — see [`R_BYTES_RANGE`]), two per column.
/// - band cols 6–9: 8 `Range16` requires on `rot_limbs`, two per column.
///
/// Aux column 0 (lane 0's dst provide) is the running sum; every later
/// fraction column — including each later lane's dst provide — is folded into
/// it by the col-0 recurrence.
pub const NUM_AUX_COLS: usize = 10 * NUM_LANES;

// The single exposed σ ([`NUM_SIGMA_VALUES`]) follows the VM-wide σ
// contract in [`crate::logup`]; col 0's recurrence aggregating both
// columns' fractions into one residue is the shared shape, not a
// round-specific choice. The shared public values ([`NUM_PUBLIC_VALUES`])
// are the transcript root alone — declared but not read here; the natural
// last-row closing needs no `inv_n` height input.

// PERIODIC COLUMN INDICES
// ================================================================================================

pub use program::{
    COL_BACK_A as PCOL_BACK_A, COL_BACK_B as PCOL_BACK_B, COL_DST_MULT as PCOL_DST_MULT,
    COL_IS_ANDNOT as PCOL_IS_ANDNOT, COL_IS_ROL as PCOL_IS_ROL, COL_IS_XOR as PCOL_IS_XOR,
    COL_IS_XORROL as PCOL_IS_XORROL, COL_K as PCOL_K, COL_P_LAST as PCOL_P_LAST,
    COL_SWAP as PCOL_SWAP,
};

// AIR
// ================================================================================================

/// Keccak-round chiplet AIR. Period-128 program drives a TAM-style row
/// `c = ROL(a OP b, s)` against the [`Memory64`](crate::hash::memory64)
/// bus, verifying each row's operands and result directly against
/// [`BytePairLut`](crate::primitives::byte_pair_lut).
#[derive(Debug, Default, Clone, Copy)]
pub struct KeccakRoundAir;

impl BaseAir<Felt> for KeccakRoundAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        round_program().to_vec()
    }
}

impl LiftedAir<Felt, QuadFelt> for KeccakRoundAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        NUM_AUX_COLS
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
        build_aux(main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        // Phase 1: local row constraints, replicated per lane over its
        // disjoint column band. The periodic program is shared — every lane
        // sits on the same program slot each row.
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next_window: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

        let periodic = builder.periodic_values();
        let p_last: AB::Expr = periodic[PCOL_P_LAST].into();
        let is_xor: AB::Expr = periodic[PCOL_IS_XOR].into();
        let is_andnot: AB::Expr = periodic[PCOL_IS_ANDNOT].into();
        let is_rol: AB::Expr = periodic[PCOL_IS_ROL].into();
        let k: AB::Expr = periodic[PCOL_K].into();
        let two_32 = AB::Expr::from(Felt::new(1u64 << 32).expect("2^32 fits"));

        for lane in 0..NUM_LANES {
            let base = lane_base(lane);
            let ip = local[base + COL_IP];
            let next_ip = next_window[base + COL_IP];
            let act: AB::Expr = local[base + COL_ACT].into();
            let next_act = next_window[base + COL_ACT];

            // IP boundary: only lane 0 is anchored at ip = 25 (sponge
            // addresses 0..25 precede the trace IP range). A later lane
            // starts mid address-space at a data-dependent ip; its absolute
            // frame is pinned by the memory64 bus (its round-0 reads of the
            // sponge-provided initial state), so no constant boundary applies.
            if lane == 0 {
                builder.when_first_row().assert_eq(ip, AB::Expr::from(Felt::from(25u8)));
            }

            // IP transition: ip' − ip − 1 = 0, per lane (gated
            // `when_transition` to skip the cyclic wrap at row N−1 → 0; the
            // LogUp running-sum closes on the last row and no longer wraps).
            builder
                .when_transition()
                .assert_zero(AB::Expr::from(next_ip) - AB::Expr::from(ip) - AB::Expr::ONE);

            // Active binarity: act ∈ {0, 1}.
            builder.assert_bool(local[base + COL_ACT]);

            // Active constant within a round: `(1 − p_last) · (act' − act) =
            // 0`. `p_last` is the period-128 indicator that fires at slot 127
            // (the row whose transition crosses a round boundary), so `act`
            // may change only into slot 0 of the next round. Applied ungated:
            // at the cyclic wrap (row N−1 → 0), N−1 lands on slot 127 (any
            // pow2 height ≥ 128), so `p_last = 1` and the constraint is
            // vacuous. The sponge bus forces `act = 1` at row 0 by providing
            // RC[0] which slot 1 must consume, so no boundary is needed.
            builder.assert_zero(
                (AB::Expr::ONE - p_last.clone()) * (AB::Expr::from(next_act) - act.clone()),
            );

            // Passthrough pin: on rows with no logic op active (pure-ROL and
            // NOP rows), `r = a`. Byte-wise so it matches the byte-level
            // range check `r_bytes` inherits below (see `eval`'s lookup
            // half): `(1 − is_xor − is_andnot) · (r_bytes[i] − a_bytes[i]) =
            // 0` for each byte `i`.
            let logic_active = is_xor.clone() + is_andnot.clone();
            let no_logic = AB::Expr::ONE - logic_active;
            for i in 0..8 {
                let a_byte = local[base + A_BYTES_RANGE.start + i];
                let r_byte = local[base + R_BYTES_RANGE.start + i];
                builder.assert_zero(
                    no_logic.clone() * (AB::Expr::from(r_byte) - AB::Expr::from(a_byte)),
                );
            }

            // Rotation limb-decomposition binding: on an active ROL row,
            // `rot_limbs` must be the 16-bit limb decomposition of
            // `(r_half + 2^32)·k` for each half of this row's own `r`
            // (byte-committed above) — the same identity a rotate
            // chiplet's ROL row enforces, applied to `r` instead of a
            // value read from elsewhere. Without this, `rot_limbs` is
            // only Range16-checked (see `eval`'s lookup half) and
            // `rotated_halves` — which `memory_provide_c` uses to derive
            // the value written to memory — can be driven to any result.
            //
            // Gated by `act · is_rol`, not `is_rol` alone: `is_rol` is a
            // periodic column and keeps firing on this row's periodic
            // slot through the dead round and trace-tail padding, but
            // `push_row` writes an all-Nop, all-zero row there (`rot_limbs
            // = 0`, `r = 0`) — an `is_rol`-only gate would wrongly demand
            // `2^32·k = 0` on those padding rows and break completeness.
            let r_bytes: [AB::Var; 8] = array::from_fn(|i| local[base + R_BYTES_RANGE.start + i]);
            let rot_limbs: [AB::Var; 8] =
                array::from_fn(|i| local[base + ROT_LIMBS_RANGE.start + i]);
            let [r_lo, r_hi] = halves_le(&r_bytes, 256);
            let lo_decomp: AB::Expr = pack_le(&rot_limbs[0..4], 1u64 << 16);
            let hi_decomp: AB::Expr = pack_le(&rot_limbs[4..8], 1u64 << 16);
            let rol_gate = act.clone() * is_rol.clone();
            builder
                .assert_zero(rol_gate.clone() * ((r_lo + two_32.clone()) * k.clone() - lo_decomp));
            builder.assert_zero(rol_gate * ((r_hi + two_32.clone()) * k.clone() - hi_decomp));
        }

        // Phase 2: LogUp argument via the LogUp adapter.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

/// Reconstruct the rotated 64-bit value's `(lo, hi)` halves from
/// `rot_limbs`, the periodic `k` (the *reduced* rotation multiplier,
/// `≤ 2^30` — see [`program::rol_decompose`]), and `swap` (1 on fused
/// slots whose *true* rotation `ρ ≥ 32`, where the reduced shift is
/// `ρ − 32` and the true output's 32-bit halves are the reduced
/// output's halves swapped). Same limb-pairing formula a rotate
/// chiplet's ROL row uses (`c0 = limb0+limb6`, …), applied to this
/// row's own `rot_limbs` instead of a value read from elsewhere.
fn rotated_halves<E: Algebra<Felt>, V: Copy + Into<E>>(
    rot_limbs: &[V; 8],
    k: E,
    swap: E,
) -> [E; 2] {
    let two_16 = E::from(Felt::from(1u32 << 16));
    let limb: [E; 8] = array::from_fn(|i| rot_limbs[i].into());
    let c0 = limb[0].clone() + limb[6].clone();
    let c1 = limb[1].clone() + limb[7].clone();
    let c2 = limb[2].clone() + limb[4].clone();
    let c3 = limb[3].clone() + limb[5].clone();
    let lo = c0 + c1 * two_16.clone() - k.clone();
    let hi = c2 + c3 * two_16 - k;
    // Full-range rotation: for ρ ≥ 32 the reduced rotation's halves are
    // half-swapped to recover the true `ROL(r, ρ)` (`ROL(x, ρ) =
    // halfswap(ROL(x, ρ − 32))`).
    let lo_final = lo.clone() + swap.clone() * (hi.clone() - lo.clone());
    let hi_final = hi.clone() + swap * (lo - hi);
    [lo_final, hi_final]
}

/// The value this row writes to `ip` on the Memory64 bus: the rotated
/// value (reconstructed from `rot_limbs`) when `is_rol = 1`, else the
/// passthrough logic result `r` (packed from `r_bytes`).
fn memory_provide_c<E: Algebra<Felt>, V: Copy + Into<E>>(
    r_bytes: &[V; 8],
    rot_limbs: &[V; 8],
    k: E,
    swap: E,
    is_rol: E,
) -> [E; 2] {
    let [r_lo, r_hi] = halves_le(r_bytes, 256);
    let [rot_lo, rot_hi] = rotated_halves(rot_limbs, k, swap);
    let lo = r_lo.clone() + is_rol.clone() * (rot_lo - r_lo);
    let hi = r_hi.clone() + is_rol * (rot_hi - r_hi);
    [lo, hi]
}

// LOOKUP AIR
// ================================================================================================

/// Aux column shape (FLATTENED to lqd 1), repeated per lane (band-local):
/// - band col 0: memory64 dst provide (one degree-≤3 fraction; lane 0's is the running sum).
/// - band col 1: memory64 `src_a` + `src_b` requires.
/// - band cols 2–5: 8 `BytePairLut` byte requires, two per column.
/// - band cols 6–9: 8 `Range16` requires on `rot_limbs`, two per column.
///
/// Every closing constraint is degree ≤ 3, so `log_quotient_degree = 1`
/// (aux blowup factor = 2). Width disregarded.
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = build_column_shape();

const fn build_column_shape() -> [usize; NUM_AUX_COLS] {
    let mut shape = [2usize; NUM_AUX_COLS];
    let mut lane = 0;
    while lane < NUM_LANES {
        // Band-local col 0 is a single fraction (dst provide).
        shape[lane * 10] = 1;
        lane += 1;
    }
    shape
}

impl<LB> LookupAir<LB> for KeccakRoundAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        NUM_AUX_COLS
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
        let periodic = builder.periodic_values();
        // The periodic program is shared across lanes — every lane reads the
        // same op selectors / back-pointers / k / dst_mult each row.
        let is_xor: LB::Expr = periodic[PCOL_IS_XOR].into();
        let is_andnot: LB::Expr = periodic[PCOL_IS_ANDNOT].into();
        let is_rol: LB::Expr = periodic[PCOL_IS_ROL].into();
        let is_xorrol: LB::Expr = periodic[PCOL_IS_XORROL].into();
        let back_a: LB::Expr = periodic[PCOL_BACK_A].into();
        let back_b: LB::Expr = periodic[PCOL_BACK_B].into();
        let k: LB::Expr = periodic[PCOL_K].into();
        let dst_mult: LB::Expr = periodic[PCOL_DST_MULT].into();
        let swap: LB::Expr = periodic[PCOL_SWAP].into();
        // Byte-pair-LUT op tag: the real op tag on XOR/ANDNOT rows, and
        // defaults to Xor (tag 1) on rows with no logic active — combined
        // with `gated_b` below (forced to 0 there), this issues
        // `BPL(Xor, a, 0, r)` on those rows, which range-checks `a_bytes`
        // and (redundantly with the passthrough pin in `KeccakRoundAir::eval`)
        // forces `r = a`. This is what replaces a rotate chiplet's
        // chain-trick range check now that every row commits its own bytes.
        let bpl_op = LB::Expr::ONE - is_andnot.clone();
        let logic_active = is_xor.clone() + is_andnot.clone();

        let interaction_deg = Deg { v: 1, u: 1 };
        let triple_deg = Deg { v: 3, u: 3 };
        let pair_deg = Deg { v: 2, u: 2 };
        let dst_deg = Deg { v: 5, u: 2 };

        // Each lane emits its own 10-column band of fractions over its
        // disjoint data columns, reading the shared periodic gates. Lane 0's
        // dst provide is the running sum (aux col 0); every later lane's
        // fractions — its dst provide included — are ordinary fraction
        // columns the col-0 recurrence folds in. The bus contribution is the
        // union over lanes (an unchanged multiset), so the single σ matches
        // a single stream.
        for lane in 0..NUM_LANES {
            let base = lane_base(lane);
            let ip: LB::Expr = local[base + COL_IP].into();
            let act: LB::Expr = local[base + COL_ACT].into();

            let a_bytes: [LB::Var; 8] = array::from_fn(|i| local[base + A_BYTES_RANGE.start + i]);
            let b_bytes: [LB::Var; 8] = array::from_fn(|i| local[base + B_BYTES_RANGE.start + i]);
            let r_bytes: [LB::Var; 8] = array::from_fn(|i| local[base + R_BYTES_RANGE.start + i]);
            let rot_limbs: [LB::Var; 8] =
                array::from_fn(|i| local[base + ROT_LIMBS_RANGE.start + i]);

            // Multiplicity expressions, all gated by this lane's `act` so
            // dead-round / padding rows contribute nothing to the bus.
            //
            // `is_active`: row reads `src_a` (every non-NOP op does, once). A
            // fused XORROL row sets both `is_xor` and `is_rol`, so subtracting
            // the one-hot `is_xorrol` recovers one read per row at degree 1.
            // This same gate now also drives the row's `BytePairLut` byte
            // requires — every row that reads `a` at all range-checks it.
            let is_active = act.clone()
                * (is_xor.clone() + is_andnot.clone() + is_rol.clone() - is_xorrol.clone());
            // `reads_b`: XOR / ANDNOT / fused XORROL all read `src_b`.
            let reads_b = act.clone() * (is_xor.clone() + is_andnot.clone());
            let rol_act = act.clone() * is_rol.clone();
            let dst_mult_act = act.clone() * dst_mult.clone();

            // band col 0: memory64 dst provide. Mixed-sign multiplicities:
            // `mult = -dst_mult` for the provide (signed via `g.insert`, since
            // `g.remove` hard-codes mult = -1 and would mis-account multi-value
            // writes — `dst_mult ∈ {1, 2, 3, 5, 12}`). Gated by `act`. The
            // written value is this row's own `r` (passthrough) or its
            // rotated form (reconstructed from `rot_limbs`), muxed by `is_rol`
            // — see `memory_provide_c`.
            let [c_lo, c_hi] =
                memory_provide_c(&r_bytes, &rot_limbs, k.clone(), swap.clone(), is_rol.clone());
            let neg_dst_mult: LB::Expr = LB::Expr::ZERO - dst_mult_act;
            frac_col!(
                builder,
                "memory64",
                dst_deg,
                (
                    "dst",
                    neg_dst_mult,
                    Memory64Msg { addr: ip.clone(), lo: c_lo, hi: c_hi },
                    interaction_deg
                ),
            );
            // band col 1: memory64 src_a + src_b requires.
            let [a_lo, a_hi] = halves_le(&a_bytes, 256);
            let [b_lo, b_hi] = halves_le(&b_bytes, 256);
            frac_col!(
                builder,
                "memory64",
                triple_deg,
                (
                    "src_a",
                    is_active.clone(),
                    Memory64Msg {
                        addr: ip.clone() - back_a.clone(),
                        lo: a_lo,
                        hi: a_hi
                    },
                    interaction_deg
                ),
                (
                    "src_b",
                    reads_b.clone(),
                    Memory64Msg {
                        addr: ip - back_b.clone(),
                        lo: b_lo,
                        hi: b_hi
                    },
                    interaction_deg
                ),
            );
            // band cols 2–5: 8 BytePairLut byte requires verifying
            // `r_bytes[i] = op(a_bytes[i], gated_b_bytes[i])`. `gated_b`
            // forces the effective second operand to 0 on rows with no real
            // logic op (message-field gating, not a column constraint — the
            // raw `b_bytes` column may hold anything there since its
            // contribution is zeroed regardless).
            for pair in 0..4 {
                let i0 = pair * 2;
                let i1 = i0 + 1;
                let gated_b0 = logic_active.clone() * LB::Expr::from(b_bytes[i0]);
                let gated_b1 = logic_active.clone() * LB::Expr::from(b_bytes[i1]);
                frac_col!(
                    builder,
                    "byte-pair-lut",
                    pair_deg,
                    (
                        "byte-req",
                        is_active.clone(),
                        BytePairLutMsg {
                            op: bpl_op.clone(),
                            a: a_bytes[i0].into(),
                            b: gated_b0,
                            c: r_bytes[i0].into()
                        },
                        interaction_deg
                    ),
                    (
                        "byte-req",
                        is_active.clone(),
                        BytePairLutMsg {
                            op: bpl_op.clone(),
                            a: a_bytes[i1].into(),
                            b: gated_b1,
                            c: r_bytes[i1].into()
                        },
                        interaction_deg
                    ),
                );
            }
            // band cols 6–9: 8 Range16 requires on rot_limbs, two per column.
            for pair in 0..4 {
                let i0 = pair * 2;
                let i1 = i0 + 1;
                frac_col!(
                    builder,
                    "range16",
                    pair_deg,
                    (
                        "limb",
                        rol_act.clone(),
                        Range16Msg { w: rot_limbs[i0].into() },
                        interaction_deg
                    ),
                    (
                        "limb",
                        rol_act.clone(),
                        Range16Msg { w: rot_limbs[i1].into() },
                        interaction_deg
                    ),
                );
            }
        }
    }
}

// TRACE GENERATION
// ================================================================================================

/// Boundary IP for the chiplet's first row. Sponge addresses
/// `[0, 25)`, `25`, and `26` hold the round-0 lane inputs (natural
/// row-major: `state[i]` at addr `i`), `RC[0]`, and `zero[0]` (which
/// coincides with the chiplet-produced zero at slot 1's IP);
/// trace IPs start here.
pub const IP_BOUNDARY: u64 = 25;

/// Active Keccak rounds per permutation. The full perm cycle is one
/// longer ([`PERM_CYCLE`]) — the extra round is the dead round whose
/// 128 IPs space perm N's outputs apart from perm N+1's round-0 inputs
/// (see "Multi-permutation traces" in `docs/chiplets/keccak.md`).
pub const NUM_ROUNDS: usize = 24;

/// Rows per perm cycle: 24 active rounds + 1 dead round.
pub const PERM_CYCLE: usize = (NUM_ROUNDS + 1) * ROUND_PERIOD;

/// Split the logic result computation from the (optional) rotate, since
/// the merged row needs both `r` (byte-committed, BPL-checked) and the
/// final `c` (written to memory) separately.
fn simulate_logic(op: Op, a: u64, b: u64) -> u64 {
    match op {
        Op::Nop | Op::Rol(_) => a,
        Op::Xor | Op::XorRol(_) => a ^ b,
        Op::Andnot => (!a) & b,
    }
}

fn simulate_rotate(op: Op, r: u64) -> u64 {
    match op {
        Op::Rol(s) | Op::XorRol(s) => r.rotate_left(s),
        _ => r,
    }
}

/// Decompose a `u64` into 8 little-endian bytes as `Felt`s.
fn bytes_le(x: u64) -> [Felt; 8] {
    x.to_le_bytes().map(Felt::from)
}

/// `rot_limbs` for rotating `r` by the *reduced* shift `2^shift` (`shift
/// ≤ 30` — see [`program::rol_decompose`]): 16-bit limbs of
/// `(r_half + 2^32)·k`, low half first. Mirrors a rotate chiplet's ROL
/// row construction. Returned as raw `u16`s (for driving the
/// `Range16` requires) alongside their `Felt` form (for the trace row).
fn rot_limbs_for(r: u64, shift: u32) -> [u16; 8] {
    let k = 1u64 << shift;
    let r_lo = r & 0xffff_ffff;
    let r_hi = r >> 32;
    let lo_offset_k = (r_lo + (1u64 << 32)).wrapping_mul(k);
    let hi_offset_k = (r_hi + (1u64 << 32)).wrapping_mul(k);
    let lo_limbs = u64_as_four_u16_limbs(lo_offset_k);
    let hi_limbs = u64_as_four_u16_limbs(hi_offset_k);
    [
        lo_limbs[0],
        lo_limbs[1],
        lo_limbs[2],
        lo_limbs[3],
        hi_limbs[0],
        hi_limbs[1],
        hi_limbs[2],
        hi_limbs[3],
    ]
}

/// Decompose a `u64` into four 16-bit limbs LSB-first.
fn u64_as_four_u16_limbs(x: u64) -> [u16; 4] {
    [
        (x & 0xffff) as u16,
        ((x >> 16) & 0xffff) as u16,
        ((x >> 32) & 0xffff) as u16,
        ((x >> 48) & 0xffff) as u16,
    ]
}

/// Build one row's `LANE_WIDTH` field elements and drive the
/// `BytePairLutRequires` ledger for its byte/limb checks. `spec` is the
/// slot's program entry; `a`, `b` are the (already-read) source operand
/// values; `act` gates whether this row's bus interactions fire.
fn push_row(
    trace: &mut Vec<Felt>,
    bpl_req: &mut BytePairLutRequires,
    ip: u64,
    spec: &Slot,
    a: u64,
    b: u64,
    act: bool,
) {
    let is_andnot = matches!(spec.op, Op::Andnot);
    let logic_active = matches!(spec.op, Op::Xor | Op::Andnot | Op::XorRol(_));
    // Matches the AIR's `is_active = act·(is_xor+is_andnot+is_rol-is_xorrol)`
    // gate exactly: every non-NOP op reads `src_a` once, so `is_active`
    // reduces to `act && reads_a` (NOP is the only op that reads nothing).
    let reads_a = !matches!(spec.op, Op::Nop);
    let is_rol = matches!(spec.op, Op::Rol(_) | Op::XorRol(_));
    let b_eff = if logic_active { b } else { 0 };
    let r = simulate_logic(spec.op, a, b_eff);
    if act && reads_a {
        let bpl_op = if is_andnot { BytePairOp::AndNot } else { BytePairOp::Xor };
        require_logic64(bpl_req, bpl_op, a, b_eff);
    }

    let mut rot_limbs = [0u16; 8];
    if let Op::Rol(s) | Op::XorRol(s) = spec.op {
        let (shift, _swap) = program::rol_decompose(s);
        rot_limbs = rot_limbs_for(r, shift);
        if act {
            for limb in rot_limbs {
                bpl_req.require_range16(limb);
            }
        }
    }

    trace.push(Felt::new(ip).expect("ip fits in canonical Goldilocks"));
    trace.extend(bytes_le(a));
    trace.extend(bytes_le(b_eff));
    trace.extend(bytes_le(r));
    trace.extend(rot_limbs.map(Felt::from));
    trace.push(Felt::from(act as u8));
    let _ = is_rol;
}

/// Build the main trace for `states.len()` stacked Keccak-f\[1600]
/// permutations, each starting from its own initial state. All perms
/// share the same 24-round constant schedule.
///
/// Layout: each perm gets one [`PERM_CYCLE`] = 25 rounds = 3200 rows
/// of trace (24 active + 1 dead). The N cycles concatenate from row 0,
/// then the trace is padded to the next power of two. Inactive rows
/// (each cycle's dead round + the trace tail beyond N cycles) still
/// walk the period-128 program for witness consistency (IP keeps
/// incrementing) but carry `act = 0`, zeroing their bus contribution.
///
/// Standalone-test entry point: unlike [`generate_trace`], this does not
/// drive a [`BytePairLutRequires`] ledger — the byte/limb columns are
/// populated directly from the computed values, sufficient for row-local
/// `check_constraints` (the `BytePairLut` interaction is a cross-AIR bus
/// concern, checked separately by the session-level bus-balance tests).
pub fn generate_trace_from_states(
    states: &[[u64; 25]],
    rcs: &[u64; NUM_ROUNDS],
) -> RowMajorMatrix<Felt> {
    let mut scratch = BytePairLutRequires::new();
    generate_trace_from_states_inner(states, rcs, &mut scratch)
}

fn generate_trace_from_states_inner(
    states: &[[u64; 25]],
    rcs: &[u64; NUM_ROUNDS],
    bpl_req: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    assert!(!states.is_empty(), "at least one perm required");
    let num_perms = states.len();
    let active_rows_per_cycle = NUM_ROUNDS * ROUND_PERIOD;
    let perms_per_lane = num_perms.div_ceil(NUM_LANES);
    let height = (perms_per_lane * PERM_CYCLE).next_power_of_two().max(2);
    let program = slots();

    // Memory keyed by absolute IP — the original per-perm address layout is
    // preserved across lanes (see `generate_trace`). Initial state at
    // `[n·3200, n·3200 + 25)`, RC[r] at `25 + n·3200 + r·128`.
    let mem_size = IP_BOUNDARY as usize + NUM_LANES * perms_per_lane * PERM_CYCLE + 1;
    let mut memory = vec![0u64; mem_size];

    for (n, state) in states.iter().enumerate() {
        let perm_base = (n * PERM_CYCLE) as u64;
        for (idx, &lane) in state.iter().enumerate() {
            memory[(perm_base + idx as u64) as usize] = lane;
        }
        for r in 0..NUM_ROUNDS {
            memory[(IP_BOUNDARY + perm_base + (r * ROUND_PERIOD) as u64) as usize] = rcs[r];
        }
    }

    let lane_cells: [Vec<Felt>; NUM_LANES] = array::from_fn(|lane| {
        let base_perm = lane * perms_per_lane;
        let lane_perms = num_perms.saturating_sub(base_perm).min(perms_per_lane);
        let row_offset = base_perm * PERM_CYCLE;
        let mut cells = Vec::with_capacity(height * LANE_WIDTH);

        for r in 0..height {
            let ip = IP_BOUNDARY + (row_offset + r) as u64;
            let perm_in_lane = r / PERM_CYCLE;
            let row_in_cycle = r % PERM_CYCLE;

            if perm_in_lane >= lane_perms {
                push_row(
                    &mut cells,
                    bpl_req,
                    ip,
                    &Slot {
                        op: Op::Nop,
                        back_a: 0,
                        back_b: 0,
                        dst_mult: 0,
                    },
                    0,
                    0,
                    false,
                );
                continue;
            }

            let spec = program[r % ROUND_PERIOD];
            let act = row_in_cycle < active_rows_per_cycle;

            let reads_a = !matches!(spec.op, Op::Nop);
            let reads_b = matches!(spec.op, Op::Xor | Op::Andnot | Op::XorRol(_));
            let a = if reads_a {
                memory[ip.wrapping_sub(spec.back_a) as usize]
            } else {
                0
            };
            let b = if reads_b {
                memory[ip.wrapping_sub(spec.back_b) as usize]
            } else {
                0
            };
            let r_val = simulate_logic(spec.op, a, b);
            let c_val = simulate_rotate(spec.op, r_val);

            if act && spec.dst_mult > 0 {
                memory[ip as usize] = c_val;
            }

            push_row(&mut cells, bpl_req, ip, &spec, a, b, act);
        }
        cells
    });

    interleave_lanes(&lane_cells, height)
}

/// Read the post-permutation states from each of N Keccak-f
/// permutations stacked in the same way [`generate_trace`] arranges
/// them. Used by integration tests to compare against a reference
/// Keccak implementation.
///
/// For each perm n ∈ [0, states.len()): the 25 output lanes live at
/// the χ-XOR / ι output slots of round 23 of cycle n — lane (0, 0) at
/// slot 103 (ι output), the other 24 lanes at slots 104..128 in
/// row-major lane index order.
pub fn extract_outputs(states: &[[u64; 25]], rcs: &[u64; NUM_ROUNDS]) -> Vec<[u64; 25]> {
    assert!(!states.is_empty(), "at least one perm required");
    let num_perms = states.len();
    let active_rows_per_cycle = NUM_ROUNDS * ROUND_PERIOD;
    let total_rows = num_perms * PERM_CYCLE;
    let program = slots();

    let mut memory = vec![0u64; IP_BOUNDARY as usize + total_rows];
    for (n, state) in states.iter().enumerate() {
        let perm_base = (n * PERM_CYCLE) as u64;
        for (idx, &lane) in state.iter().enumerate() {
            memory[(perm_base + idx as u64) as usize] = lane;
        }
        for r in 0..NUM_ROUNDS {
            memory[(IP_BOUNDARY + perm_base + (r * ROUND_PERIOD) as u64) as usize] = rcs[r];
        }
    }

    // Walk each cycle's active rounds (skip the dead round; its
    // `act = 0` means nothing's written there either way).
    for row in 0..total_rows {
        let row_in_cycle = row % PERM_CYCLE;
        if row_in_cycle >= active_rows_per_cycle {
            continue;
        }
        let slot = row % ROUND_PERIOD;
        let ip = IP_BOUNDARY + row as u64;
        let spec = program[slot];
        let reads_a = !matches!(spec.op, Op::Nop);
        let reads_b = matches!(spec.op, Op::Xor | Op::Andnot | Op::XorRol(_));
        let a = if reads_a {
            memory[ip.wrapping_sub(spec.back_a) as usize]
        } else {
            0
        };
        let b = if reads_b {
            memory[ip.wrapping_sub(spec.back_b) as usize]
        } else {
            0
        };
        let r = simulate_logic(spec.op, a, b);
        let c = simulate_rotate(spec.op, r);
        if spec.dst_mult > 0 {
            memory[ip as usize] = c;
        }
    }

    let mut outputs = Vec::with_capacity(num_perms);
    for n in 0..num_perms {
        let perm_base = (n * PERM_CYCLE) as u64;
        let last_round_base = IP_BOUNDARY + perm_base + (23 * ROUND_PERIOD) as u64;
        let mut out = [0u64; 25];
        for (idx, out_limb) in out.iter_mut().enumerate() {
            let slot = if idx == 0 {
                program::SLOT_IOTA
            } else {
                program::SLOT_CHI_XOR_BEGIN + (idx - 1)
            };
            *out_limb = memory[(last_round_base + slot as u64) as usize];
        }
        outputs.push(out);
    }
    outputs
}

/// Single-perm convenience wrapper around [`extract_outputs`].
pub fn extract_output(state: &[u64; 25], rcs: &[u64; NUM_ROUNDS]) -> [u64; 25] {
    extract_outputs(core::slice::from_ref(state), rcs)
        .into_iter()
        .next()
        .expect("single-perm extract")
}

// PROVER
// ================================================================================================

/// Witness-bearing companion to [`KeccakRoundAir`]. The aux trace is
/// produced by the generic [`build_logup_aux_trace`] driver — no
/// chiplet-specific aux-trace code lives here.
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&KeccakRoundAir, main, challenges)
}

// REQUIRES LEDGER
// ================================================================================================

/// Deferred-tracegen ledger for the round chiplet. The sponge appends
/// 24 `state_in`s per Keccak permutation via
/// [`Self::require_round`] — one per round, in `(perm, round)` lex
/// order — and [`generate_trace`] lays out the trace, inserting the
/// dead 25th round-period of each perm cycle automatically.
///
/// Round is bus-bound to sponge at fixed IP-space addresses
/// (`sponge_seq_id = 32·perm_idx`), so there's no autonomous
/// perm-index allocation — the implicit `perm_idx = idx / 24`
/// matches sponge's expectation by construction. Position in
/// `rounds` carries the index.
#[derive(Debug, Default, Clone)]
pub struct RoundRequires {
    rounds: Vec<[u64; 25]>,
}

impl RoundRequires {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one round's `state_in`. The sponge submits these in
    /// `(perm, round)` lex order — 24 per permutation — using
    /// [`keccak_round`](crate::hash::keccak::reference::keccak_round)
    /// to evolve state between submissions. Only round 0 of each perm
    /// is load-bearing for memory seeding; rounds 1–23 are derivative
    /// and currently informational (a future debug build could
    /// cross-check them against the simulator).
    pub fn require_round(&mut self, state_in: [u64; 25]) {
        self.rounds.push(state_in);
    }

    /// Total rounds submitted.
    pub fn total_rounds(&self) -> u32 {
        self.rounds.len() as u32
    }

    /// Total full perms (= `total_rounds / 24`).
    pub fn total_perms(&self) -> u32 {
        self.total_rounds() / NUM_ROUNDS as u32
    }
}

/// Build the chiplet trace from a [`RoundRequires`] ledger, driving
/// the supplied `bpl_req` accumulator for the byte/limb checks each
/// active row makes.
///
/// Internal `KECCAK_RC` is used; no RC parameter — sponge doesn't
/// supply it. Trace height = `next_pow2(num_perms · PERM_CYCLE)`,
/// minimum one full perm cycle. Inactive rows (each perm's 25th
/// dead round + tail beyond `num_perms`) walk the period-128 program
/// for witness consistency but emit no bus mults (`act = 0`).
pub fn generate_trace(
    requires: RoundRequires,
    bpl_req: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    assert!(
        requires.rounds.len().is_multiple_of(NUM_ROUNDS),
        "RoundRequires must hold a multiple of {NUM_ROUNDS} rounds (got {})",
        requires.rounds.len(),
    );
    let num_perms = requires.total_perms() as usize;
    let active_rows_per_cycle = NUM_ROUNDS * ROUND_PERIOD;
    // Whole permutations split across lanes in contiguous blocks; the busiest
    // lane sets the height.
    let perms_per_lane = num_perms.max(1).div_ceil(NUM_LANES);
    let height = (perms_per_lane * PERM_CYCLE).next_power_of_two().max(2);
    let program = slots();

    // Memory keyed by absolute IP — each perm owns a fixed address range
    // regardless of which lane and rows hold it, so the memory64 multiset and
    // the sponge consumer see a per-perm layout. Sized to cover every perm's
    // range (lane content reads stay inside it).
    let mem_size = IP_BOUNDARY as usize + NUM_LANES * perms_per_lane * PERM_CYCLE + 1;
    let mut memory = vec![0u64; mem_size];

    for n in 0..num_perms {
        let perm_base = (n * PERM_CYCLE) as u64;
        let round0_state = &requires.rounds[n * NUM_ROUNDS];
        for (idx, &lane) in round0_state.iter().enumerate() {
            memory[(perm_base + idx as u64) as usize] = lane;
        }
        for r in 0..NUM_ROUNDS {
            memory[(IP_BOUNDARY + perm_base + (r * ROUND_PERIOD) as u64) as usize] = KECCAK_RC[r];
        }
    }

    // Lay each lane into its own band. `array::from_fn` runs lanes in index
    // order, so the BytePairLut requires are driven in perm order
    // (0, 1, 2, …) exactly as a single stream would.
    let lane_cells: [Vec<Felt>; NUM_LANES] = array::from_fn(|lane| {
        let base_perm = lane * perms_per_lane;
        let lane_perms = num_perms.saturating_sub(base_perm).min(perms_per_lane);
        let row_offset = base_perm * PERM_CYCLE;
        let mut cells = Vec::with_capacity(height * LANE_WIDTH);

        for r in 0..height {
            let ip = IP_BOUNDARY + (row_offset + r) as u64;
            let perm_in_lane = r / PERM_CYCLE;
            let row_in_cycle = r % PERM_CYCLE;

            // Beyond this lane's permutations: pure padding. IP keeps
            // incrementing (for the per-lane `ip' = ip + 1` constraint) but
            // the row reads no memory and emits no bus mults (`act = 0`).
            if perm_in_lane >= lane_perms {
                push_row(
                    &mut cells,
                    bpl_req,
                    ip,
                    &Slot {
                        op: Op::Nop,
                        back_a: 0,
                        back_b: 0,
                        dst_mult: 0,
                    },
                    0,
                    0,
                    false,
                );
                continue;
            }

            let spec = program[r % ROUND_PERIOD];
            let act = row_in_cycle < active_rows_per_cycle;

            let reads_a = !matches!(spec.op, Op::Nop);
            let reads_b = matches!(spec.op, Op::Xor | Op::Andnot | Op::XorRol(_));
            let a = if reads_a {
                memory[ip.wrapping_sub(spec.back_a) as usize]
            } else {
                0
            };
            let b = if reads_b {
                memory[ip.wrapping_sub(spec.back_b) as usize]
            } else {
                0
            };
            let r_val = simulate_logic(spec.op, a, b);
            let c_val = simulate_rotate(spec.op, r_val);

            if act && spec.dst_mult > 0 {
                memory[ip as usize] = c_val;
            }

            push_row(&mut cells, bpl_req, ip, &spec, a, b, act);
        }
        cells
    });

    interleave_lanes(&lane_cells, height)
}
