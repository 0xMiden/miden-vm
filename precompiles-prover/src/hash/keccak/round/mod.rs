//! Keccak-round chiplet (TAM-style miniVM).
//!
//! Orchestrates a single Keccak-f\[1600] round via a three-address
//! machine over the [`Memory64`](crate::hash::memory64) bus. Repeats
//! 24 times to cover a full permutation; multiple permutations stack
//! cleanly in one trace (and the sponge AIR uses the bus's multiset
//! semantics to overwrite state at absorb boundaries).
//!
//! See `docs/chiplets/keccak.md` for the design rationale (slot
//! layout, sponge contract, address-space layout, decomposition for
//! `ρ > 30`).

pub mod program;

use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
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
    primitives::{
        bitwise64::{Bitwise64Requires, Logic64Msg, Logic64Op, Rol64Msg, XorRol64Msg},
        byte_pair_lut::BytePairLutRequires,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, next_main, split_u64},
};

// MAIN COLUMN LAYOUT
// ================================================================================================

/// Row counter; increments by 1 each row. Boundary `ip[0] = 25` at the
/// trace's first row (sponge addresses [0, 25) hold the round-0 lane
/// inputs).
pub const COL_IP: usize = 0;
/// Source A value as 32-bit halves (matched against the memory bus).
pub const COL_A_LO: usize = 1;
pub const COL_A_HI: usize = 2;
/// Source B value (unused on pure-ROL rows).
pub const COL_B_LO: usize = 3;
pub const COL_B_HI: usize = 4;
/// Destination value: `c = ROL(a OP b, s)`. The logic intermediate `r`
/// is no longer committed — the bitwise64 buses (`Logic64`/`Rol64`/the
/// fused `XorRol64`) relate `a`, `b`, `c` directly, so the round carries
/// only the operands and the result.
pub const COL_C_LO: usize = 5;
pub const COL_C_HI: usize = 6;
/// Active indicator. 1 on active rounds, 0 on each cycle's dead round
/// (the 25th round of every perm cycle) and on trace-tail padding.
/// Constant within each round (changes only at round boundaries —
/// gated by the `p_last` periodic indicator). Every bus multiplicity
/// is multiplied by `act`, so dead rounds and padding rows contribute
/// nothing to either Memory64 or Bitwise64 buses. The sponge AIR
/// σ-matches the chiplet's active-rows-only residue; it also forces
/// `act = 1` at row 0 by providing `RC[0]`, which the chiplet's slot 1
/// must consume.
pub const COL_ACT: usize = 7;

// All COL_* indices above are **lane-local** (within one [`LANE_WIDTH`]-wide
// band); the absolute main-trace index is `lane * LANE_WIDTH + local`, via
// [`lane_base`].

/// Width of one permutation-lane's column band.
pub const LANE_WIDTH: usize = 8;
/// Number of permutation-lanes packed side-by-side per row. Each lane runs a
/// contiguous block of permutations in its own column band while sharing the
/// (preprocessed, free) periodic program, so the row count is ~`1/NUM_LANES`
/// of a single stream. Lane 0 keeps the explicit `ip[0] = 25` anchor; a later
/// lane's absolute `ip` frame (its memory64 address range) is pinned by the
/// bus — its round-0 reads of the sponge-provided initial state force it, so a
/// shifted frame would leave uncancelled bus terms (Σσ ≠ 0). The lanes hold
/// disjoint, contiguous address ranges (the original per-perm layout is
/// preserved), so the memory64 multiset is unchanged and the sponge consumer
/// is untouched.
pub const NUM_LANES: usize = 2;
pub const NUM_MAIN_COLS: usize = LANE_WIDTH * NUM_LANES;

/// Absolute start column of `lane`'s band in the main trace.
#[inline]
pub fn lane_base(lane: usize) -> usize {
    lane * LANE_WIDTH
}

// AUX COLUMN LAYOUT
// ================================================================================================

/// FLATTENED to lqd 1, repeated per lane: each lane's 4-column band holds
/// five fractions (all degree-2 multiplicities) split ≤ 2 per column, the
/// band's col 0 a single fraction:
/// - band col 0: memory64 dst provide.
/// - band col 1: memory64 `src_a` + `src_b` requires.
/// - band col 2: bitwise64 `Logic64` (pure-logic) + `Rol64` (pure-ROL) requires.
/// - band col 3: bitwise64 fused `XorRol64` require (θ-apply+ρ rows).
///
/// Aux column 0 (lane 0's dst provide) is the running sum; every later
/// fraction column — including each later lane's dst provide — is folded into
/// it by the col-0 recurrence.
pub const NUM_AUX_COLS: usize = 4 * NUM_LANES;

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
};

// AIR
// ================================================================================================

/// Keccak-round chiplet AIR. Period-128 program drives a TAM-style row
/// `c = ROL(a OP b, s)` against the [`Memory64`](crate::hash::memory64)
/// bus and the Bitwise64 chiplet's Logic64/Rol64 buses.
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
            builder
                .assert_zero((AB::Expr::ONE - p_last.clone()) * (AB::Expr::from(next_act) - act));
        }

        // No `c`-pinning constraints: the bitwise64 buses relate `a`, `b`,
        // `c` directly — `Logic64(op, a, b, c)` (pure-logic), `Rol64(a, c, k)`
        // (pure-ROL), and `XorRol64(a, b, c, k)` (fused) each pin `c` on the
        // rows that provide memory. NOP rows touch no bus (and write no
        // memory), so their `c` is free.

        // Phase 2: LogUp argument via the LogUp adapter.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

/// Aux column shape (FLATTENED to lqd 1), repeated per lane (band-local):
/// - band col 0: memory64 dst provide (one degree-2 fraction; lane 0's is the running sum, the
///   gated σ-close at degree 3).
/// - band col 1: memory64 `src_a` + `src_b` requires.
/// - band col 2: Bitwise64 Logic64 + Rol64 requires.
/// - band col 3: Bitwise64 fused XorRol64 require.
///
/// Every closing constraint is degree ≤ 3, so `log_quotient_degree = 1`
/// (aux blowup factor = 2). Width disregarded (research/logup-flatten).
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = build_column_shape();

const fn build_column_shape() -> [usize; NUM_AUX_COLS] {
    let mut shape = [2usize; NUM_AUX_COLS];
    let mut lane = 0;
    while lane < NUM_LANES {
        // Band-local cols 0 and 3 are single fractions.
        shape[lane * 4] = 1;
        shape[lane * 4 + 3] = 1;
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

        let interaction_deg = Deg { v: 1, u: 1 };
        let triple_deg = Deg { v: 3, u: 3 };
        let pair_deg = Deg { v: 2, u: 2 };

        // Each lane emits its own 4-column band over its disjoint data
        // columns, reading the shared periodic gates. Lane 0's dst provide is
        // the running sum (aux col 0); every later lane's fractions — its dst
        // provide included — are ordinary fraction columns the col-0
        // recurrence folds in. The bus contribution is the union over lanes
        // (an unchanged multiset), so the single σ matches a single stream.
        for lane in 0..NUM_LANES {
            let base = lane_base(lane);
            let ip: LB::Expr = local[base + COL_IP].into();
            let a_lo: LB::Expr = local[base + COL_A_LO].into();
            let a_hi: LB::Expr = local[base + COL_A_HI].into();
            let b_lo: LB::Expr = local[base + COL_B_LO].into();
            let b_hi: LB::Expr = local[base + COL_B_HI].into();
            let c_lo: LB::Expr = local[base + COL_C_LO].into();
            let c_hi: LB::Expr = local[base + COL_C_HI].into();
            let act: LB::Expr = local[base + COL_ACT].into();

            // Multiplicity expressions, all gated by this lane's `act` so
            // dead-round / padding rows contribute nothing to the bus.
            //
            // `is_active`: row reads `src_a` (every non-NOP op does, once). A
            // fused XORROL row sets both `is_xor` and `is_rol`, so subtracting
            // the one-hot `is_xorrol` recovers one read per row at degree 1.
            let is_active = act.clone()
                * (is_xor.clone() + is_andnot.clone() + is_rol.clone() - is_xorrol.clone());
            // `reads_b`: XOR / ANDNOT / fused XORROL all read `src_b`.
            let reads_b = act.clone() * (is_xor.clone() + is_andnot.clone());
            // bitwise64 consume gates: pure-logic, pure-ROL, fused — disjoint,
            // summing to `is_active`.
            let pure_logic = act.clone() * (is_xor.clone() + is_andnot.clone() - is_xorrol.clone());
            let pure_rol = act.clone() * (is_rol.clone() - is_xorrol.clone());
            let xorrol_act = act.clone() * is_xorrol.clone();
            let dst_mult_act = act.clone() * dst_mult.clone();

            // band col 0: memory64 dst provide. Mixed-sign multiplicities:
            // `mult = -dst_mult` for the provide (signed via `g.insert`, since
            // `g.remove` hard-codes mult = -1 and would mis-account multi-value
            // writes — `dst_mult ∈ {1, 2, 3, 5, 12}`). Gated by `act`.
            let neg_dst_mult: LB::Expr = LB::Expr::ZERO - dst_mult_act;
            frac_col!(
                builder,
                "memory64",
                triple_deg,
                (
                    "dst",
                    neg_dst_mult,
                    Memory64Msg {
                        addr: ip.clone(),
                        lo: c_lo.clone(),
                        hi: c_hi.clone()
                    },
                    interaction_deg
                ),
            );
            // band col 1: memory64 src_a + src_b requires.
            frac_col!(
                builder,
                "memory64",
                triple_deg,
                (
                    "src_a",
                    is_active,
                    Memory64Msg {
                        addr: ip.clone() - back_a.clone(),
                        lo: a_lo.clone(),
                        hi: a_hi.clone()
                    },
                    interaction_deg
                ),
                (
                    "src_b",
                    reads_b,
                    Memory64Msg {
                        addr: ip - back_b.clone(),
                        lo: b_lo.clone(),
                        hi: b_hi.clone()
                    },
                    interaction_deg
                ),
            );
            // band col 2: bitwise64 pure-logic `Logic64(op, a, b, c)` + pure-ROL
            // `Rol64(a, c, k)`. `c` is the row's committed output, pinned by the
            // relation. `op = is_xor` (AndNot tag 0, Xor tag 1).
            frac_col!(
                builder,
                "bitwise64",
                pair_deg,
                (
                    "logic64",
                    pure_logic,
                    Logic64Msg {
                        op: is_xor.clone(),
                        a_lo: a_lo.clone(),
                        a_hi: a_hi.clone(),
                        b_lo: b_lo.clone(),
                        b_hi: b_hi.clone(),
                        c_lo: c_lo.clone(),
                        c_hi: c_hi.clone()
                    },
                    interaction_deg
                ),
                (
                    "rol64",
                    pure_rol,
                    Rol64Msg {
                        a_lo: a_lo.clone(),
                        a_hi: a_hi.clone(),
                        b_lo: c_lo.clone(),
                        b_hi: c_hi.clone(),
                        k: k.clone()
                    },
                    interaction_deg
                ),
            );
            // band col 3: bitwise64 fused `XorRol64(a, b, c, k)` for θ-apply+ρ
            // rows — `c = rol(a ⊕ b, k)` in one consume.
            frac_col!(
                builder,
                "bitwise64",
                interaction_deg,
                (
                    "xorrol64",
                    xorrol_act,
                    XorRol64Msg {
                        a_lo,
                        a_hi,
                        b_lo,
                        b_hi,
                        c_lo,
                        c_hi,
                        k: k.clone()
                    },
                    interaction_deg
                ),
            );
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

/// Build the main trace for `states.len()` stacked Keccak-f\[1600]
/// permutations, each starting from its own initial state. All perms
/// share the same 24-round constant schedule.
///
/// Layout: each perm gets one [`PERM_CYCLE`] = 25 rounds = 3200 rows
/// of trace (24 active + 1 dead). The N cycles concatenate from row 0,
/// then the trace is padded to the next power of two. Inactive rows
/// (each cycle's dead round + the trace tail beyond N cycles) still
/// walk the period-128 program for witness consistency (IP keeps
/// incrementing, r- and c-pinning still satisfied) but carry
/// `act = 0`, zeroing their bus contribution.
///
/// Perm n's round-0 input addresses are `[n·3200, n·3200 + 25)`
/// (disjoint from perm n−1's last-perm outputs at
/// `[(n−1)·3200 + 3072, (n−1)·3200 + 3097)`); each perm's initial
/// state is seeded into those address slots before the simulation
/// walks the program. The chiplet alone does not chain perm n's
/// outputs into perm n+1's inputs — that's the sponge AIR's role in
/// a full proof.
///
/// Standalone-test entry point. The integrated stack uses
/// [`generate_trace`] (`&RoundRequires`-driven, also drives Bitwise64
/// / BytePairLut requires).
pub fn generate_trace_from_states(
    states: &[[u64; 25]],
    rcs: &[u64; NUM_ROUNDS],
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
                push_row(&mut cells, ip, 0, 0, 0, false);
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
            let c_val = simulate_op(spec.op, a, b);

            if act && spec.dst_mult > 0 {
                memory[ip as usize] = c_val;
            }

            push_row(&mut cells, ip, a, b, c_val, act);
        }
        cells
    });

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

/// Execute one slot's operation, returning the destination value
/// `c = rol(a OP b, s)` (the logic result, then the rotate; `OP`/`s`
/// degenerate to identity per op). The intermediate `r` is no longer
/// committed, so it is not returned.
fn simulate_op(op: Op, a: u64, b: u64) -> u64 {
    let r = match op {
        Op::Nop | Op::Rol(_) => a,
        Op::Xor | Op::XorRol(_) => a ^ b,
        Op::Andnot => (!a) & b,
    };
    match op {
        Op::Nop | Op::Xor | Op::Andnot => r,
        Op::Rol(s) | Op::XorRol(s) => r.rotate_left(s),
    }
}

fn push_row(trace: &mut Vec<Felt>, ip: u64, a: u64, b: u64, c: u64, act: bool) {
    let [a_lo, a_hi] = split_u64(a);
    let [b_lo, b_hi] = split_u64(b);
    let [c_lo, c_hi] = split_u64(c);
    trace.extend([
        Felt::new(ip).expect("ip fits in canonical Goldilocks"),
        a_lo,
        a_hi,
        b_lo,
        b_hi,
        c_lo,
        c_hi,
        Felt::from(act as u8),
    ]);
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
        let c = simulate_op(spec.op, a, b);
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
/// the supplied `bw64_req` / `bpl_req` accumulators for the Logic64
/// and Rol64 emissions each active row makes.
///
/// Internal `KECCAK_RC` is used; no RC parameter — sponge doesn't
/// supply it. Trace height = `next_pow2(num_perms · PERM_CYCLE)`,
/// minimum one full perm cycle. Inactive rows (each perm's 25th
/// dead round + tail beyond `num_perms`) walk the period-128 program
/// for witness consistency but emit no bus mults (`act = 0`).
pub fn generate_trace(
    requires: RoundRequires,
    bw64_req: &mut Bitwise64Requires,
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

    // Memory keyed by absolute IP — the original per-perm address layout is
    // preserved (lanes only repartition which trace rows hold which perm), so
    // the memory64 multiset and the sponge consumer are unchanged. Sized to
    // cover every perm's range (lane content reads stay inside it).
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
    // order, so the Bitwise64/BPL requires are driven in perm order
    // (0, 1, 2, …) exactly as a single stream would — bitwise64 is unaffected.
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
                push_row(&mut cells, ip, 0, 0, 0, false);
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
            let c_val = simulate_op(spec.op, a, b);

            if act && spec.dst_mult > 0 {
                memory[ip as usize] = c_val;
            }

            // Drive Bitwise64 / BPL for the per-row emissions. A fused XORROL
            // issues one `require_xorrol` (the XOR then a fused ROL on its
            // result), so bitwise64 provides one `XorRol64` instead of a
            // `Logic64 + Rol64` pair.
            if act {
                match spec.op {
                    Op::Xor => {
                        bw64_req.require(bpl_req, Logic64Op::Xor, a, b);
                    },
                    Op::Andnot => {
                        bw64_req.require(bpl_req, Logic64Op::AndNot, a, b);
                    },
                    Op::Rol(s) => {
                        bw64_req.require_rol(bpl_req, a, 1u64 << s);
                    },
                    Op::XorRol(s) => {
                        bw64_req.require_xorrol(bpl_req, a, b, 1u64 << s);
                    },
                    Op::Nop => {},
                }
            }

            push_row(&mut cells, ip, a, b, c_val, act);
        }
        cells
    });

    // Interleave the lane bands into one NUM_MAIN_COLS-wide row-major matrix.
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
