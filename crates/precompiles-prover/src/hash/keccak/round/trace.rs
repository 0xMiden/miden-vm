//! Witness generation for the Keccak round chiplet.

use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{Felt, utils::RowMajorMatrix};

use super::*;
use crate::{
    hash::keccak::reference::KECCAK_RC,
    primitives::byte_pair_lut::{BytePairLutRequires, BytePairOp, require_logic64},
};

/// Interleave the per-lane column bands into one `NUM_MAIN_COLS`-wide
/// row-major matrix, each lane's `LANE_WIDTH` cells placed at its band base.
fn interleave_lanes(lane_cells: &[Vec<Felt>; NUM_LANES], height: usize) -> RowMajorMatrix<Felt> {
    let mut trace = vec![Felt::ZERO; height * NUM_MAIN_COLS];
    for r in 0..height {
        let row_start = r * NUM_MAIN_COLS;
        for (lane, cells) in lane_cells.iter().enumerate() {
            let base = lane_base(lane);
            let src = &cells[r * LANE_WIDTH..(r + 1) * LANE_WIDTH];
            trace[row_start + base..row_start + base + LANE_WIDTH].copy_from_slice(src);
        }
    }
    RowMajorMatrix::new(trace, NUM_MAIN_COLS)
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
