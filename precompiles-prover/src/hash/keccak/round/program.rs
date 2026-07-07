//! Keccak round program: 128 slots, encoded as 10 length-128 periodic
//! columns over the chiplet's trace.
//!
//! Each slot describes one TAM operation `c = ROL(a OP b, s)`. The ten
//! columns are:
//!
//! - `is_xor`, `is_andnot`, `is_rol` — selector flags. A fused XORROL row sets both `is_xor` and
//!   `is_rol`.
//! - `is_xorrol` — 1 exactly on fused XORROL rows (= `is_xor · is_rol`, precomputed). Lets the
//!   chiplet recover a one-per-row "reads src_a" count from the otherwise-overlapping selectors
//!   without a degree bump.
//! - `swap` — 1 on fused XORROL slots whose true rotation `ρ ≥ 32` (see [`COL_SWAP`]).
//! - `back_a`, `back_b` — source A / B back-offsets (`src_addr = ip - back`).
//! - `k` — ROL shift multiplier `2^s` (0 when `is_rol = 0`).
//! - `dst_mult` — destination provide multiplicity (0 on NOP rows).
//! - `p_last` — 1 at slot 127 (the round's last slot), 0 elsewhere. Used as the round-boundary
//!   indicator for the `act` within-round- constant constraint: a row with `p_last = 1` is the row
//!   whose transition into the next slot crosses a round boundary, so `act` is allowed to change
//!   there.
//!
//! Slot layout (period 128):
//!
//! ```text
//! [  0,   1)  RC slot                (NOP; sponge writes RC[r] at IP)
//! [  1,   2)  ZERO slot              (NOP; unused since full-range rotation)
//! [  2,  22)  θ C-computation        (20 XORs, balanced trees)
//! [ 22,  27)  θ D-ROL                (5 ROL(1) ops)
//! [ 27,  32)  θ D-XOR                (5 XOR ops)
//! [ 32,  69)  θ-apply + ρπ           (37 fused/trailing ops)
//! [ 69,  94)  χ ANDNOTs              (25 ops)
//! [ 94, 102)  8 NO-OP slackers
//! [102, 103)  χ XOR for lane (0,0)   (intermediate, read by ι)
//! [103, 104)  ι: chi_00 ⊕ RC         (final output for lane (0,0))
//! [104, 128)  χ XORs for 24 other lanes (final outputs)
//! ```
//!
//! Post-ι row-major arrangement of the next-round inputs lets the
//! sponge map `state[i]` to address `i` directly: `state[0]` = lane (0,0)
//! at sponge addr 0, …, `state[24]` = lane (4,4) at sponge addr 24.
//! `RC[r]` sits at addr 25 (= IP of slot 0 in each round); `zero[r]` at
//! addr 26 (= IP of slot 1).
//!
//! See `docs/chiplets/keccak.md` for the address-space layout
//! and sponge contract.

use alloc::{vec, vec::Vec};

use miden_core::Felt;

use crate::relations::ProvideMult;

/// Length of one round's preprocessed period.
pub const ROUND_PERIOD: usize = 128;

/// Number of preprocessed columns produced by [`round_program`].
pub const NUM_PERIODIC_COLS: usize = 10;

/// Column indices in the periodic table.
pub const COL_IS_XOR: usize = 0;
pub const COL_IS_ANDNOT: usize = 1;
pub const COL_IS_ROL: usize = 2;
pub const COL_BACK_A: usize = 3;
pub const COL_BACK_B: usize = 4;
pub const COL_K: usize = 5;
pub const COL_DST_MULT: usize = 6;
/// 1 exactly on fused XORROL slots (= `is_xor · is_rol`). A XORROL row
/// sets both `is_xor` and `is_rol`, so `is_xor + is_andnot + is_rol`
/// counts it twice; subtracting this column recovers the true
/// one-read-per-row `src_a` multiplicity at degree 1.
pub const COL_IS_XORROL: usize = 8;
/// 1 on fused XORROL slots whose true rotation `ρ ≥ 32`, where the chiplet
/// shift is `ρ − 32 ≤ 30` and the rolled output's 32-bit halves are swapped
/// (`ROL(x, ρ) = halfswap(ROL(x, ρ − 32))`). The round commits the true `c`
/// for memory but sends bitwise64 the half-swapped `c` (what it provides).
pub const COL_SWAP: usize = 9;
/// 1 at slot 127 of each round (the round's last slot), 0 elsewhere.
/// Gates the round-boundary toggles of [`act`](super::COL_ACT): the
/// within-round-constant constraint multiplies the column difference
/// by `(1 - p_last)`, which vanishes exactly at the row whose
/// transition into the next slot crosses a round boundary.
pub const COL_P_LAST: usize = 7;

// SLOT-LAYOUT CONSTANTS
// ================================================================================================

/// RC slot — NOP; sponge writes `RC[r]` at this IP.
pub const SLOT_RC: usize = 0;
/// NOP with no readers: full-range rotation (see `emit_apply_rpi`) has no
/// additive-split trailing-ROL rows, so nothing consumes a memory-bus zero
/// cell (`Andnot(RC, RC) = 0`) here for a `src_b`.
pub const SLOT_ZERO: usize = 1;
/// First slot of θ C-computation (4 XORs per parity tree, 5 trees).
pub const SLOT_C_BEGIN: usize = 2;
/// First slot of θ D-ROL (5 `ROL(C, 1)` ops).
pub const SLOT_D_ROL_BEGIN: usize = 22;
/// First slot of θ D-XOR (5 `C[i] ⊕ rcj` ops; produces D[0..5]).
pub const SLOT_D_XOR_BEGIN: usize = 27;
/// First slot of θ-apply + ρπ block.
pub const SLOT_APPLY_RPI_BEGIN: usize = 32;
/// First slot of χ ANDNOT block (25 ops).
pub const SLOT_CHI_ANDNOT_BEGIN: usize = 69;
/// Slot of χ XOR for lane (0, 0) (intermediate, read by ι).
pub const SLOT_CHI00: usize = 102;
/// Slot of ι (output for lane (0,0), `chi_00 ⊕ RC`). Placed before
/// the other χ XORs so that next round's cross-round reads see the
/// 25 lanes in natural row-major order: `state[i]` at sponge address
/// `i` (i.e. `state[0] = lane(0,0)` at slot 103).
pub const SLOT_IOTA: usize = 103;
/// First slot of χ XOR block for non-(0,0) lanes (24 ops). Laid out
/// row-major over `(x, y) ≠ (0, 0)` with index `x + 5y ∈ [1, 24]`:
/// `state[idx] = lane at SLOT_CHI_XOR_BEGIN + idx − 1`.
pub const SLOT_CHI_XOR_BEGIN: usize = 104;

/// Slot of the C[x] output (last step of x's parity tree).
const fn slot_c(x: usize) -> usize {
    SLOT_C_BEGIN + 4 * x + 3
}

/// Slot of the D-ROL output for column x — produces `ROL(C[(x+1) mod 5], 1)`.
const fn slot_d_rol(x: usize) -> usize {
    SLOT_D_ROL_BEGIN + x
}

/// Slot of D[x] (D-XOR output).
const fn slot_d(x: usize) -> usize {
    SLOT_D_XOR_BEGIN + x
}

/// Slot of the previous round's χ output for lane (x, y), used for
/// cross-round reads in this round.
///
/// Lane (0, 0) lives at the ι output slot; the other 24 lanes live at
/// the χ XOR block, in row-major order indexed by `x + 5y − 1`.
const fn slot_lane_prev(x: usize, y: usize) -> usize {
    if x == 0 && y == 0 {
        SLOT_IOTA
    } else {
        SLOT_CHI_XOR_BEGIN + (x + 5 * y - 1)
    }
}

/// Slot of B[x][y] (the ρπ-rotated value for output lane (x, y)) in
/// the current round.
///
/// **Convention**: the index `(x, y)` is the *post-π* lane position.
/// After ρ+π, `B[x][y] = ROL(A[π⁻¹(x, y)], ρ[π⁻¹(x, y)])`. Slots are
/// laid out in row-major order of the post-π index, each lane taking
/// 1/2/3 slots according to `ρ` at its pre-π source.
const fn slot_b(x: usize, y: usize) -> usize {
    let lane = x + 5 * y;
    [
        32, // out(0,0) ← in(0,0), ρ=0:  1 slot
        34, // out(1,0) ← in(1,1), ρ=44: 2 slots, B at last
        36, // out(2,0) ← in(2,2), ρ=43: 2 slots
        37, // out(3,0) ← in(3,3), ρ=21: 1 slot
        38, // out(4,0) ← in(4,4), ρ=14: 1 slot
        39, // out(0,1) ← in(3,0), ρ=28: 1 slot
        40, // out(1,1) ← in(4,1), ρ=20: 1 slot
        41, // out(2,1) ← in(0,2), ρ=3:  1 slot
        43, // out(3,1) ← in(1,3), ρ=45: 2 slots
        46, // out(4,1) ← in(2,4), ρ=61: 3 slots
        47, // out(0,2) ← in(1,0), ρ=1:  1 slot
        48, // out(1,2) ← in(2,1), ρ=6:  1 slot
        49, // out(2,2) ← in(3,2), ρ=25: 1 slot
        50, // out(3,2) ← in(4,3), ρ=8:  1 slot
        51, // out(4,2) ← in(0,4), ρ=18: 1 slot
        52, // out(0,3) ← in(4,0), ρ=27: 1 slot
        54, // out(1,3) ← in(0,1), ρ=36: 2 slots
        55, // out(2,3) ← in(1,2), ρ=10: 1 slot
        56, // out(3,3) ← in(2,3), ρ=15: 1 slot
        58, // out(4,3) ← in(3,4), ρ=56: 2 slots
        61, // out(0,4) ← in(2,0), ρ=62: 3 slots
        63, // out(1,4) ← in(3,1), ρ=55: 2 slots
        65, // out(2,4) ← in(4,2), ρ=39: 2 slots
        67, // out(3,4) ← in(0,3), ρ=41: 2 slots
        68, // out(4,4) ← in(1,4), ρ=2:  1 slot
    ][lane]
}

/// Inverse of Keccak's π permutation: given an output lane `(x', y')`,
/// return the input lane `(x, y)` such that `π(x, y) = (x', y')`.
///
/// `π(x, y) = (y, (2x + 3y) mod 5)`, so `y = x'` and
/// `x = (3y' + x') mod 5` (using `2⁻¹ ≡ 3 mod 5`).
const fn pi_inverse(out_x: usize, out_y: usize) -> (usize, usize) {
    ((3 * out_y + out_x) % 5, out_x)
}

/// Slot of t[x][y] (the χ ANDNOT output for lane (x, y)).
const fn slot_t(x: usize, y: usize) -> usize {
    SLOT_CHI_ANDNOT_BEGIN + (x + 5 * y)
}

// SLOT SPEC
// ================================================================================================

/// Where a source operand lives in the address space.
#[derive(Debug, Clone, Copy)]
enum Source {
    /// Read from slot `s` of the same round (intra-round).
    Local(usize),
    /// Read previous round's χ output for lane (x, y) (cross-round).
    Lane(usize, usize),
    /// No read (selector for this slot doesn't pull a source).
    None,
}

impl Source {
    /// Back-offset from `read_slot` to the source. For cross-round
    /// reads, `back = P + read_slot − source_slot`; for intra-round
    /// reads, `back = read_slot − source_slot`.
    fn back_off(self, read_slot: usize) -> u64 {
        match self {
            Source::Local(s) => (read_slot - s) as u64,
            Source::Lane(x, y) => (ROUND_PERIOD + read_slot - slot_lane_prev(x, y)) as u64,
            Source::None => 0,
        }
    }
}

/// Operation type for one slot. Per the fused TAM op
/// `c = ROL(a OP b, s)`:
///
/// - `Nop`: all selectors and dst_mult zero. RC slot or padding.
/// - `Xor`: pure XOR (`is_xor = 1`, `k = 0`).
/// - `Andnot`: pure ANDNOT (`is_andnot = 1`, `k = 0`).
/// - `Rol(s)`: pure ROL by `s ∈ [1, 30]` bits (`is_rol = 1`, `k = 2^s`). Reads only src_a.
/// - `XorRol(s)`: fused XOR-then-ROL (`is_xor = 1`, `is_rol = 1`, `k = 2^s`). `s ≥ 1` enforced at
///   construction; `s = 0` degenerates to plain `Xor`.
#[derive(Debug, Clone, Copy)]
pub enum Op {
    Nop,
    Xor,
    Andnot,
    Rol(u32),
    XorRol(u32),
}

#[derive(Debug, Clone, Copy)]
struct SlotSpec {
    op: Op,
    src_a: Source,
    src_b: Source,
    dst_mult: ProvideMult,
}

impl SlotSpec {
    const NOP: SlotSpec = SlotSpec {
        op: Op::Nop,
        src_a: Source::None,
        src_b: Source::None,
        dst_mult: 0,
    };
}

/// Public, materialized view of a single program slot. Materializes the
/// source back-offsets that the trace generator and aux builder need
/// (without exposing the internal `Source` enum).
#[derive(Debug, Clone, Copy)]
pub struct Slot {
    pub op: Op,
    /// Source A back-offset: `src_a_addr = ip − back_a`.
    pub back_a: u64,
    /// Source B back-offset: `src_b_addr = ip − back_b`. Zero on pure-ROL
    /// rows and NOPs.
    pub back_b: u64,
    /// Destination provide multiplicity (zero on NOP rows).
    pub dst_mult: ProvideMult,
}

/// Materialized program slots, indexed by slot number `[0, ROUND_PERIOD)`.
pub fn slots() -> [Slot; ROUND_PERIOD] {
    let table = slot_table();
    core::array::from_fn(|i| Slot {
        op: table[i].op,
        back_a: table[i].src_a.back_off(i),
        back_b: table[i].src_b.back_off(i),
        dst_mult: table[i].dst_mult,
    })
}

// SLOT-TABLE CONSTRUCTION
// ================================================================================================

/// Build the 128-entry slot specification table, following the layout
/// laid out in this module's docstring.
fn slot_table() -> [SlotSpec; ROUND_PERIOD] {
    let mut s = [SlotSpec::NOP; ROUND_PERIOD];

    // --- ZERO slot: NOP ---------------------------------------------
    // Full-range rotation (the half-swap in `emit_apply_rpi`) has no
    // additive-split trailing-ROL rows, so no memory-bus zero cell
    // (`Andnot(RC, RC) = 0`) is consumed here for a `src_b`. The slot is a
    // NOP and RC[r] is read just once per round (by ι), matching the sponge's
    // single-read RC provide.

    // --- C-computation: 5 linear 4-XOR chains, slots 2..22 ----------
    // C[x] = l0 ⊕ l1 ⊕ l2 ⊕ l3 ⊕ l4, folded *linearly* so each XOR reads
    // the running accumulator as src_a — bw64 chains the whole chain with
    // no lone intermediates. (A balanced tree strands one carrier per
    // column: its two inner XORs both feed the combiner, which can chain
    // only one of them.) XOR is associative, so C[x] is unchanged.
    for x in 0..5 {
        let base = SLOT_C_BEGIN + 4 * x;
        s[base] = SlotSpec {
            op: Op::Xor,
            src_a: Source::Lane(x, 0),
            src_b: Source::Lane(x, 1),
            dst_mult: 1,
        };
        s[base + 1] = SlotSpec {
            op: Op::Xor,
            src_a: Source::Local(base),
            src_b: Source::Lane(x, 2),
            dst_mult: 1,
        };
        s[base + 2] = SlotSpec {
            op: Op::Xor,
            src_a: Source::Local(base + 1),
            src_b: Source::Lane(x, 3),
            dst_mult: 1,
        };
        s[base + 3] = SlotSpec {
            op: Op::Xor,
            src_a: Source::Local(base + 2),
            src_b: Source::Lane(x, 4),
            // C[x] is read 2× later: D[x+1] ROL + D[x−1] XOR.
            dst_mult: 2,
        };
    }

    // --- D-ROL: ROL(C[1], 1), ROL(C[2], 1), …, ROL(C[0], 1) ---------
    // Order: rc_for_D[0..5] = ROL(C[(i+1) mod 5], 1).
    for i in 0..5 {
        s[SLOT_D_ROL_BEGIN + i] = SlotSpec {
            op: Op::Rol(1),
            src_a: Source::Local(slot_c((i + 1) % 5)),
            src_b: Source::None,
            dst_mult: 1, // read once by D-XOR.
        };
    }

    // --- D-XOR: D[i] = C[(i + 4) mod 5] ⊕ ROL(C[(i + 1) mod 5], 1) --
    for i in 0..5 {
        s[SLOT_D_XOR_BEGIN + i] = SlotSpec {
            op: Op::Xor,
            src_a: Source::Local(slot_c((i + 4) % 5)),
            src_b: Source::Local(slot_d_rol(i)),
            dst_mult: 5, // D[i] applied to 5 lanes.
        };
    }

    // --- θ-apply + ρπ: 37 slots starting at 32 ----------------------
    // Loop over OUTPUT lanes (post-π). For each, look up the input
    // (pre-π) lane via π⁻¹ and emit either:
    //   - 1 row (ρ = 0 or ρ ≤ 30): XORROL(A[in], D[in_x], ρ).
    //   - 2 rows (30 < ρ ≤ 60): XORROL(_, _, 30) then XORROL(_, 0, ρ−30).
    //   - 3 rows (60 < ρ ≤ 63): XORROL(_, _, 30), XORROL(_, 0, 30), XORROL(_, 0, ρ−60).
    // Trailing rows are XORROL with `src_b = ZERO slot` (not pure ROL):
    // the dummy `Xor` lets Bitwise64's IR materialize a LOGIC predecessor
    // and a Carrier that the Rol row recycles, satisfying the
    // ROL-after-LOGIC soundness invariant on the Bitwise64 chiplet.
    // Decomposition splits assume Bitwise64's `s ∈ [0, 30]` limit;
    // B[out] (the rotated value at the post-π position) is the last
    // row's output (dst_mult 3, χ reads 3×).
    for out_y in 0..5 {
        for out_x in 0..5 {
            emit_apply_rpi(&mut s, out_x, out_y);
        }
    }

    // --- χ ANDNOT: 25 slots at 69..94 -------------------------------
    for y in 0..5 {
        for x in 0..5 {
            s[slot_t(x, y)] = SlotSpec {
                op: Op::Andnot,
                src_a: Source::Local(slot_b((x + 1) % 5, y)),
                src_b: Source::Local(slot_b((x + 2) % 5, y)),
                dst_mult: 1, // read by matching χ XOR.
            };
        }
    }

    // --- χ XOR for lane (0,0) at slot 102 ---------------------------
    // Operands swapped (B↔T): the andnot result T has fan-out 1, so its
    // only chance to chain is here — putting it in `src_a` lets bw64's
    // a-only reorder recycle it. B (fan-out 3) then chains at its andnot
    // instead. XOR commutes, so this is a data-only operand relabel: the
    // round emits Logic64(Xor, T, B, r) and bw64 provides the match — no
    // AIR/column change, and the digest is unchanged.
    s[SLOT_CHI00] = SlotSpec {
        op: Op::Xor,
        src_a: Source::Local(slot_t(0, 0)),
        src_b: Source::Local(slot_b(0, 0)),
        dst_mult: 1, // read by ι only.
    };

    // --- ι at slot 103: chi_00 ⊕ RC ---------------------------------
    // Placed BEFORE the other χ XORs so the 25 next-round inputs land
    // in natural row-major order: state[0] = lane (0,0) at addr 0
    // (from slot 103), state[24] = lane (4,4) at addr 24 (from slot 127).
    s[SLOT_IOTA] = SlotSpec {
        op: Op::Xor,
        src_a: Source::Local(SLOT_CHI00),
        // RC[r] is provided by the sponge at the IP of the current
        // round's RC slot. back_b = 103 − 0 = 103.
        src_b: Source::Local(SLOT_RC),
        dst_mult: 2, // read by next round's C-comp and θ-apply for lane (0,0).
    };

    // --- χ XOR for non-(0,0) lanes at slots 104..128 ----------------
    // Row-major over (x, y) with (x + 5y) ∈ [1, 24], so the next round
    // reads state[idx] at sponge addr idx for each non-(0,0) lane.
    for lane_idx in 1..25 {
        let x = lane_idx % 5;
        let y = lane_idx / 5;
        s[SLOT_CHI_XOR_BEGIN + (lane_idx - 1)] = SlotSpec {
            op: Op::Xor,
            // Swapped (B↔T): chain the fan-out-1 T on `a`. See SLOT_CHI00.
            src_a: Source::Local(slot_t(x, y)),
            src_b: Source::Local(slot_b(x, y)),
            dst_mult: 2, // read by next round's C-comp and θ-apply.
        };
    }

    s
}

/// Emit the slot(s) for output lane (out_x, out_y) of θ-apply + ρπ.
/// Resolves the input (pre-π) lane via π⁻¹.
fn emit_apply_rpi(s: &mut [SlotSpec; ROUND_PERIOD], out_x: usize, out_y: usize) {
    // FIPS 202 ρ table, x rows × y cols.
    const RHO: [[u32; 5]; 5] = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ];

    let (in_x, in_y) = pi_inverse(out_x, out_y);
    let rho = RHO[in_x][in_y];
    let b_slot = slot_b(out_x, out_y);
    let d_slot = slot_d(in_x);
    let a_src = Source::Lane(in_x, in_y);
    let d_src = Source::Local(d_slot);
    // Operand order on the apply XOR. Chain the fan-out-5 D on `a` *only*
    // where the state lane A is already chained at the linear C-tree —
    // that's the column's first lane (in_y == 0), which is the C-tree
    // base's src_a. There A can't chain here anyway (its carrier is spent
    // at the C-tree), so putting D in src_a recovers one D carrier per
    // column for free. For in_y != 0 the lane *is* chained here, so keep it
    // in src_a — swapping those is a net loss (measured: blanket-swapping
    // all lanes costs +234 rows/keccak).
    let (apply_a, apply_b) = if in_y == 0 { (d_src, a_src) } else { (a_src, d_src) };

    // dst_mult for the final B[x][y] cell: read 3× in χ (as base for
    // (x, y), +1 arg for (x−1, y), +2 arg for (x−2, y)).
    let final_mult = 3;

    // Full-range rotation in one fused op. ρ > 30 is handled by the round's
    // half-swap (ROL by 32 = swap halves), so bitwise64 only ever sees the
    // reduced shift `ρ − 32 ≤ 30` (see `rol_decompose` / `COL_SWAP`). No
    // additive 30+30+rest split — the former intermediate slots stay NOP and
    // the ZERO cell is gone. Keccak's ρ never lands in [31, 35], so the
    // reduced shift is always within bitwise64's `s ≤ 30` bound.
    let op = if rho == 0 {
        Op::Xor // Lane (0, 0): plain XOR, no rotation.
    } else {
        Op::XorRol(rho)
    };
    s[b_slot] = SlotSpec {
        op,
        src_a: apply_a,
        src_b: apply_b,
        dst_mult: final_mult,
    };
}

/// Decompose a true rotation `s ∈ [0, 63]` into `(chiplet_shift, swap)` such
/// that `ROL(x, s) = halfswap^swap(ROL(x, chiplet_shift))`, with
/// `chiplet_shift ≤ 30` for every keccak ρ. For `s ≥ 32` the free 32-bit
/// half-swap absorbs the high bit (`ROL(x, 32) = halfswap(x)`), leaving
/// `s − 32`; keccak ρ never lands in `[31, 35]`, so `s − 32 ≤ 30`.
pub fn rol_decompose(s: u32) -> (u32, bool) {
    if s >= 32 { (s - 32, true) } else { (s, false) }
}

// PERIODIC-COLUMN MATERIALIZATION
// ================================================================================================

/// Build the 9 periodic columns (one per row of the per-row format)
/// for one Keccak round. Returned in canonical column order
/// (`is_xor`, `is_andnot`, `is_rol`, `back_a`, `back_b`, `k`,
/// `dst_mult`, `p_last`, `is_xorrol`).
pub fn round_program() -> [Vec<Felt>; NUM_PERIODIC_COLS] {
    let table = slot_table();
    let mut cols: [Vec<Felt>; NUM_PERIODIC_COLS] =
        core::array::from_fn(|_| vec![Felt::ZERO; ROUND_PERIOD]);

    for (slot, spec) in table.iter().enumerate() {
        let (is_xor, is_andnot, is_rol, is_xorrol, k, swap) = match spec.op {
            Op::Nop => (0, 0, 0, 0, 0u64, false),
            Op::Xor => (1, 0, 0, 0, 0, false),
            Op::Andnot => (0, 1, 0, 0, 0, false),
            Op::Rol(s) => (0, 0, 1, 0, 1u64 << s, false),
            Op::XorRol(s) => {
                let (shift, swap) = rol_decompose(s);
                (1, 0, 1, 1, 1u64 << shift, swap)
            },
        };
        cols[COL_IS_XOR][slot] = Felt::from(is_xor as u8);
        cols[COL_IS_ANDNOT][slot] = Felt::from(is_andnot as u8);
        cols[COL_IS_ROL][slot] = Felt::from(is_rol as u8);
        cols[COL_IS_XORROL][slot] = Felt::from(is_xorrol as u8);
        cols[COL_SWAP][slot] = Felt::from(swap as u8);
        cols[COL_BACK_A][slot] =
            Felt::new(spec.src_a.back_off(slot)).expect("back_a fits in canonical Goldilocks");
        cols[COL_BACK_B][slot] =
            Felt::new(spec.src_b.back_off(slot)).expect("back_b fits in canonical Goldilocks");
        cols[COL_K][slot] = Felt::new(k).expect("k fits in canonical Goldilocks");
        cols[COL_DST_MULT][slot] = Felt::from(spec.dst_mult);
    }

    // `p_last` fires at the round's last slot (slot 127) — the row
    // whose transition crosses into the next round, where `act` is
    // allowed to toggle.
    cols[COL_P_LAST][ROUND_PERIOD - 1] = Felt::ONE;

    cols
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_counts_match_design() {
        let table = slot_table();
        let mut nop = 0;
        let mut xor = 0;
        let mut andnot = 0;
        let mut rol = 0;
        let mut xorrol = 0;
        for spec in &table {
            match spec.op {
                Op::Nop => nop += 1,
                Op::Xor => xor += 1,
                Op::Andnot => andnot += 1,
                Op::Rol(_) => rol += 1,
                Op::XorRol(_) => xorrol += 1,
            }
        }
        // 1 RC + 1 now-NOP ZERO slot + 8 slackers + 12 freed apply+ρπ
        // intermediates (the additive-split rows full-range rotation drops).
        assert_eq!(nop, 22, "nop");
        // 20 C-comp + 5 D-XOR + 1 (lane (0,0) apply+ρπ) + 1 χ for (0,0)
        // + 24 other χ XORs + 1 ι = 52.
        assert_eq!(xor, 52, "xor");
        // 25 χ ANDNOTs (the ZERO-slot Andnot is gone).
        assert_eq!(andnot, 25, "andnot");
        // Pure ROL: only 5 D-ROL rows.
        assert_eq!(rol, 5, "rol");
        // One fused XORROL per rotated apply+ρπ lane (24 lanes; lane (0,0)
        // is plain XOR). Full-range rotation means no trailing-row splits.
        assert_eq!(xorrol, 24, "xorrol");
        assert_eq!(nop + xor + andnot + rol + xorrol, ROUND_PERIOD);
    }

    #[test]
    fn b_slot_table_unique_and_in_range() {
        let mut seen = std::collections::HashSet::new();
        for x in 0..5 {
            for y in 0..5 {
                let slot = slot_b(x, y);
                assert!(
                    (SLOT_APPLY_RPI_BEGIN..SLOT_CHI_ANDNOT_BEGIN).contains(&slot),
                    "B[{x}][{y}] at slot {slot} outside apply+ρπ block",
                );
                assert!(seen.insert(slot), "B slot {slot} reused");
            }
        }
    }

    #[test]
    fn round_program_lengths() {
        let cols = round_program();
        for (i, col) in cols.iter().enumerate() {
            assert_eq!(col.len(), ROUND_PERIOD, "col {i} length");
        }
    }
}
