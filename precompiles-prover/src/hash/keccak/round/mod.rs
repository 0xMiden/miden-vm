//! Keccak-round chiplet (TAM-style miniVM).
//!
//! Orchestrates a single Keccak-f\[1600] round via a three-address
//! machine over the [`Memory64`](crate::hash::memory64) bus. Repeats
//! 24 times to cover a full permutation; multiple permutations stack
//! cleanly in one trace (and the sponge AIR uses the bus's multiset
//! semantics to overwrite state at absorb boundaries).
//!
//! See the design notes for the design rationale (slot
//! layout, sponge contract, address-space layout, decomposition for
//! `ρ > 30`).

pub mod program;

use alloc::{vec, vec::Vec};

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
    },
    primitives::{
        bitwise64::{Bitwise64Requires, Logic64Msg, Logic64Op, Rol64Msg},
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
/// Logic intermediate: `r = a OP b` on logic rows, `r = a` otherwise.
pub const COL_R_LO: usize = 5;
pub const COL_R_HI: usize = 6;
/// Destination value: `c = ROL(r, s)` on ROL rows, `c = r` otherwise.
pub const COL_C_LO: usize = 7;
pub const COL_C_HI: usize = 8;
/// Active indicator. 1 on active rounds, 0 on each cycle's dead round
/// (the 25th round of every perm cycle) and on trace-tail padding.
/// Constant within each round (changes only at round boundaries —
/// gated by the `p_last` periodic indicator). Every bus multiplicity
/// is multiplied by `act`, so dead rounds and padding rows contribute
/// nothing to either Memory64 or Bitwise64 buses. The sponge AIR
/// σ-matches the chiplet's active-rows-only residue; it also forces
/// `act = 1` at row 0 by providing `RC[0]`, which the chiplet's slot 1
/// must consume.
pub const COL_ACT: usize = 9;
pub const NUM_MAIN_COLS: usize = 10;

// AUX COLUMN LAYOUT
// ================================================================================================

/// Two aux columns, one per bus on the row:
///
/// - col 0: memory64 bus — batch of 3 (dst provide, `src_a` require, `src_b` require). Mixed-sign
///   multiplicities in the same batch: `mult = -dst_mult` for the provide, `+is_active` and
///   `+is_logic` for the requires.
/// - col 1: bitwise64 bus — batch of 2 (Logic64 + Rol64 requires).
pub const NUM_AUX_COLS: usize = 2;

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
        // Phase 1: local row constraints.
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next_window: [AB::Var; 10] = next_main::<_, _, 10>(builder.main(), 0);
        let next_ip = next_window[COL_IP];
        let next_act = next_window[COL_ACT];

        let periodic = builder.periodic_values();
        let is_xor: AB::Expr = periodic[PCOL_IS_XOR].into();
        let is_andnot: AB::Expr = periodic[PCOL_IS_ANDNOT].into();
        let is_rol: AB::Expr = periodic[PCOL_IS_ROL].into();
        let p_last: AB::Expr = periodic[PCOL_P_LAST].into();
        let act: AB::Expr = local[COL_ACT].into();

        // IP boundary: ip = 25 at row 0 (sponge addresses 0..25 precede
        // the trace IP range).
        builder
            .when_first_row()
            .assert_eq(local[COL_IP], AB::Expr::from(Felt::from(25u8)));

        // IP transition: ip' − ip − 1 = 0 (gated `when_transition` to
        // skip the `ip` increment's own cyclic wrap at row N−1 → 0; the
        // LogUp running-sum closes on the last row and no longer wraps).
        builder
            .when_transition()
            .assert_zero(AB::Expr::from(next_ip) - AB::Expr::from(local[COL_IP]) - AB::Expr::ONE);

        // Active binarity: act ∈ {0, 1}.
        builder.assert_bool(local[COL_ACT]);

        // Active constant within a round: `(1 − p_last) · (act' − act) = 0`.
        // `p_last` is the period-128 indicator that fires at slot 127 —
        // the row whose transition crosses a round boundary. So `act`
        // is allowed to change only into slot 0 of the next round; on
        // all other transitions it must stay constant. Applied ungated:
        // at the cyclic wrap (row N−1 → 0), N−1 lands on slot 127 (for
        // any pow2 trace height ≥ 128), so `p_last = 1` there and the
        // constraint is vacuous — no `when_transition` needed. The
        // sponge bus forces `act = 1` at row 0 by providing RC[0] which
        // the chiplet's slot 1 must consume, so no `when_first_row`
        // boundary is needed either.
        builder.assert_zero((AB::Expr::ONE - p_last) * (AB::Expr::from(next_act) - act));

        // r = a when neither logic flag is set. Pins r so the Rol64
        // message — which reads `r` as input — sees the right value on
        // pure-ROL rows. Vacuous on NOP rows (any r works; nothing
        // downstream reads it).
        let no_logic = AB::Expr::ONE - is_xor - is_andnot;
        builder.assert_zero(
            no_logic.clone() * (AB::Expr::from(local[COL_R_LO]) - AB::Expr::from(local[COL_A_LO])),
        );
        builder.assert_zero(
            no_logic * (AB::Expr::from(local[COL_R_HI]) - AB::Expr::from(local[COL_A_HI])),
        );

        // c = r when the row has no ROL. Pins c on pure-logic rows so
        // the memory provide sees the logic output (Rol64 gated off
        // would otherwise leave c unconstrained).
        let no_rol = AB::Expr::ONE - is_rol;
        builder.assert_zero(
            no_rol.clone() * (AB::Expr::from(local[COL_C_LO]) - AB::Expr::from(local[COL_R_LO])),
        );
        builder.assert_zero(
            no_rol * (AB::Expr::from(local[COL_C_HI]) - AB::Expr::from(local[COL_R_HI])),
        );

        // Phase 2: LogUp argument via the LogUp adapter.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

/// Aux column shape, one entry per column:
/// - col 0: batch of 3 (memory dst provide + `src_a` + `src_b` requires).
/// - col 1: batch of 2 (Bitwise64 Logic64 + Rol64 requires).
///
/// Col 0 hosts the σ-closing: `u, v` (the batched denominator product
/// and numerator) are each deg 3 after the 3-batch recurrence, and the
/// last-row close gates the constraint by the degree-1 `is_transition` /
/// `is_last_row` selector — `u·(acc_next − Σ acc) − v` on transitions,
/// `u·(σ − Σ acc) − v` on the last row — so col 0 lands at deg 5 (was 4
/// under the older ungated `u·(acc_next + σ·inv_n − Σ acc) − v` form).
/// Col 1's deg is 3 (ungated fraction column). `log_quotient_degree`
/// stays 2 (`⌈log₂ 4⌉ = ⌈log₂ 3⌉ = 2`); aux blowup factor = 4.
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [3, 2];

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
        let is_xor: LB::Expr = periodic[PCOL_IS_XOR].into();
        let is_andnot: LB::Expr = periodic[PCOL_IS_ANDNOT].into();
        let is_rol: LB::Expr = periodic[PCOL_IS_ROL].into();
        let is_xorrol: LB::Expr = periodic[PCOL_IS_XORROL].into();
        let back_a: LB::Expr = periodic[PCOL_BACK_A].into();
        let back_b: LB::Expr = periodic[PCOL_BACK_B].into();
        let k: LB::Expr = periodic[PCOL_K].into();
        let dst_mult: LB::Expr = periodic[PCOL_DST_MULT].into();

        let ip: LB::Expr = local[COL_IP].into();
        let a_lo: LB::Expr = local[COL_A_LO].into();
        let a_hi: LB::Expr = local[COL_A_HI].into();
        let b_lo: LB::Expr = local[COL_B_LO].into();
        let b_hi: LB::Expr = local[COL_B_HI].into();
        let r_lo: LB::Expr = local[COL_R_LO].into();
        let r_hi: LB::Expr = local[COL_R_HI].into();
        let c_lo: LB::Expr = local[COL_C_LO].into();
        let c_hi: LB::Expr = local[COL_C_HI].into();
        let act: LB::Expr = local[COL_ACT].into();

        // Multiplicity expressions, all gated by `act` so trace-tail
        // padding rows contribute nothing to the bus. The sponge AIR
        // σ-matches the chiplet's active-only residue.
        //
        // `is_active`: row reads `src_a` (every non-NOP op does, exactly
        // once). A fused XORROL row sets both `is_xor` and `is_rol`, so the
        // bare selector sum double-counts it; subtracting the one-hot
        // `is_xorrol` recovers the one-read-per-row count at degree 1.
        let is_active =
            act.clone() * (is_xor.clone() + is_andnot.clone() + is_rol.clone() - is_xorrol);
        // `is_logic`: row has a logic op (XOR or ANDNOT). Mutex with NOP
        // / pure-ROL rows. Gates Logic64 message and src_b memory read.
        let is_logic = act.clone() * (is_xor.clone() + is_andnot);
        // `is_rol_act` and `dst_mult_act`: ROL gate and provide mult,
        // both gated by `act`.
        let is_rol_act = act.clone() * is_rol;
        let dst_mult_act = act * dst_mult;

        // Per-emission and per-column degree annotations. Framework
        // metadata — production adapters ignore these; the names keep
        // the call sites legible.
        let interaction_deg = Deg { v: 1, u: 1 };
        let triple_deg = Deg { v: 3, u: 3 };
        let pair_deg = Deg { v: 2, u: 2 };

        // ---- col 0: memory64 bus — provide + 2 requires in one batch
        // Mixed-sign multiplicities: `mult = -dst_mult` for the provide
        // (signed via `g.insert` rather than `g.remove`, because
        // `g.remove` hard-codes mult = -1 on both prover and constraint
        // paths and would mis-account for multi-value writes —
        // `dst_mult ∈ {1, 2, 3, 5, 12}` in this program). Requires use
        // `mult = +is_active` / `+is_logic`. All gated by `act` so
        // padding rows produce zero per-row delta on the bus.
        let neg_dst_mult: LB::Expr = LB::Expr::ZERO - dst_mult_act;
        builder.next_column(
            |col| {
                col.group(
                    "memory64",
                    |g| {
                        g.batch(
                            "dst-plus-srcs",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "dst",
                                    neg_dst_mult,
                                    Memory64Msg {
                                        addr: ip.clone(),
                                        lo: c_lo.clone(),
                                        hi: c_hi.clone(),
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "src_a",
                                    is_active.clone(),
                                    Memory64Msg {
                                        addr: ip.clone() - back_a.clone(),
                                        lo: a_lo.clone(),
                                        hi: a_hi.clone(),
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "src_b",
                                    is_logic.clone(),
                                    Memory64Msg {
                                        addr: ip.clone() - back_b.clone(),
                                        lo: b_lo.clone(),
                                        hi: b_hi.clone(),
                                    },
                                    interaction_deg,
                                );
                            },
                            triple_deg,
                        );
                    },
                    triple_deg,
                );
            },
            triple_deg,
        );

        // ---- col 1: Bitwise64 bus — Logic64 + Rol64 requires --------
        // `op` slot uses `is_xor` (not `is_andnot`) because
        // `Logic64Op::AndNot` has tag 0 and `Logic64Op::Xor` has tag 1.
        builder.next_column(
            |col| {
                col.group(
                    "bitwise64",
                    |g| {
                        g.batch(
                            "logic-rol",
                            LB::Expr::ONE,
                            |b| {
                                // Logic64 verifies r = (a XOR b) or
                                // r = andnot(a, b). On pure-ROL rows
                                // this fires at mult 0 and the local
                                // r-pinning constraint (r = a) takes
                                // over.
                                b.insert(
                                    "logic64",
                                    is_logic.clone(),
                                    Logic64Msg {
                                        op: is_xor.clone(),
                                        a_lo: a_lo.clone(),
                                        a_hi: a_hi.clone(),
                                        b_lo: b_lo.clone(),
                                        b_hi: b_hi.clone(),
                                        c_lo: r_lo.clone(),
                                        c_hi: r_hi.clone(),
                                    },
                                    interaction_deg,
                                );
                                // Rol64 verifies c = ROL(r, log2(k)).
                                // On pure-logic rows this fires at mult
                                // 0 and the c-pinning constraint
                                // (c = r) takes over.
                                b.insert(
                                    "rol64",
                                    is_rol_act,
                                    Rol64Msg {
                                        a_lo: r_lo,
                                        a_hi: r_hi,
                                        b_lo: c_lo,
                                        b_hi: c_hi,
                                        k,
                                    },
                                    interaction_deg,
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
/// (see "Multi-permutation traces" in the design notes).
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
    let trace_size = num_perms * PERM_CYCLE;
    let height = trace_size.next_power_of_two().max(2);
    let program = slots();

    // Memory keyed by IP. IPs span `[0, IP_BOUNDARY + height)` —
    // initial state at `[0, 25)`, trace IPs at `[IP_BOUNDARY, ..)` —
    // so a flat Vec gives O(1) access without hashing. Unwritten
    // slots stay at `0`, which is the right default for memory reads
    // at addresses the chiplet doesn't write (e.g. sponge-only IPs).
    let mut memory = vec![0u64; IP_BOUNDARY as usize + height];

    for (n, state) in states.iter().enumerate() {
        let perm_base = (n * PERM_CYCLE) as u64;
        // Round-0 input addresses [n·3200, n·3200 + 25) — perm n's
        // initial state. (For n = 0 this is `[0, 25)`; for n > 0 the
        // addresses sit at the tail of cycle n−1's dead round.)
        for (idx, &lane) in state.iter().enumerate() {
            memory[(perm_base + idx as u64) as usize] = lane;
        }
        // RC[r] at IP `25 + n·3200 + r·128` (slot 0 of round r of
        // cycle n). Round 24 is dead and has no RC.
        for r in 0..NUM_ROUNDS {
            memory[(IP_BOUNDARY + perm_base + (r * ROUND_PERIOD) as u64) as usize] = rcs[r];
        }
    }

    let mut trace = Vec::with_capacity(height * NUM_MAIN_COLS);

    for row in 0..height {
        let slot = row % ROUND_PERIOD;
        let ip = IP_BOUNDARY + row as u64;
        let spec = program[slot];
        // Active iff this row sits in one of the N perms and within
        // that perm's 24 active rounds (not the cycle's dead round
        // and not the trace tail beyond N · PERM_CYCLE).
        let perm_idx = row / PERM_CYCLE;
        let row_in_cycle = row % PERM_CYCLE;
        let act = perm_idx < num_perms && row_in_cycle < active_rows_per_cycle;

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

        let (r_val, c_val) = simulate_op(spec.op, a, b);

        // Memory writes happen only on active rows. Dead-round and
        // padding rows leave memory untouched (and emit no bus mults
        // thanks to `act = 0`).
        if act && spec.dst_mult > 0 {
            memory[ip as usize] = c_val;
        }

        push_row(&mut trace, ip, a, b, r_val, c_val, act);
    }

    RowMajorMatrix::new(trace, NUM_MAIN_COLS)
}

/// Execute one slot's operation, returning the intermediate `r` (logic
/// result; equals `a` on non-logic rows) and the final `c` (ROL'd r;
/// equals `r` on non-ROL rows).
fn simulate_op(op: Op, a: u64, b: u64) -> (u64, u64) {
    let r = match op {
        Op::Nop | Op::Rol(_) => a,
        Op::Xor | Op::XorRol(_) => a ^ b,
        Op::Andnot => (!a) & b,
    };
    let c = match op {
        Op::Nop | Op::Xor | Op::Andnot => r,
        Op::Rol(s) | Op::XorRol(s) => r.rotate_left(s),
    };
    (r, c)
}

fn push_row(trace: &mut Vec<Felt>, ip: u64, a: u64, b: u64, r: u64, c: u64, act: bool) {
    let [a_lo, a_hi] = split_u64(a);
    let [b_lo, b_hi] = split_u64(b);
    let [r_lo, r_hi] = split_u64(r);
    let [c_lo, c_hi] = split_u64(c);
    trace.extend([
        Felt::new(ip).expect("ip fits in canonical Goldilocks"),
        a_lo,
        a_hi,
        b_lo,
        b_hi,
        r_lo,
        r_hi,
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
        let (_, c) = simulate_op(spec.op, a, b);
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
    let trace_size = num_perms.max(1) * PERM_CYCLE;
    let height = trace_size.next_power_of_two().max(2);
    let program = slots();

    // Memory keyed by IP — same layout as `generate_trace_from_states`.
    let mut memory = vec![0u64; IP_BOUNDARY as usize + height];

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

    let mut trace = Vec::with_capacity(height * NUM_MAIN_COLS);

    for row in 0..height {
        let slot = row % ROUND_PERIOD;
        let ip = IP_BOUNDARY + row as u64;
        let spec = program[slot];
        let perm_idx = row / PERM_CYCLE;
        let row_in_cycle = row % PERM_CYCLE;
        let act = perm_idx < num_perms && row_in_cycle < active_rows_per_cycle;

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

        let (r_val, c_val) = simulate_op(spec.op, a, b);

        if act && spec.dst_mult > 0 {
            memory[ip as usize] = c_val;
        }

        // Drive Bitwise64 / BPL for the per-row Logic64 / Rol64
        // emissions. Bw64 requires that the input to a pure ROL be
        // held by a free Carrier — by construction of the round
        // chiplet's program (every ROL consumes a value a prior LOGIC
        // produced) that invariant holds at run-time.
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
                    let r = bw64_req.require(bpl_req, Logic64Op::Xor, a, b);
                    bw64_req.require_rol(bpl_req, r, 1u64 << s);
                },
                Op::Nop => {},
            }
        }

        push_row(&mut trace, ip, a, b, r_val, c_val, act);
    }

    RowMajorMatrix::new(trace, NUM_MAIN_COLS)
}
