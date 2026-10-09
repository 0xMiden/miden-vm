//! Fixed 4096-slot SHA-512 compression program and short periodic tables.
//!
//! | Rows | Phase | Instructions |
//! |------|-------|--------------|
//! | 0..32 | Masks | Two shift masks, then NOPs |
//! | 32..1312 | Words | 80 words, 16 lanes each; the first 16 use only the input lane |
//! | 1312..1440 | Bootstrap | Eight state inputs placed like the preceding four hash rounds |
//! | 1440..4000 | Hash | 80 rounds, 32 lanes each, including one round constant |
//! | 4000..4032 | Feedforward | Eight state additions, then NOPs |
//! | 4032..4096 | Padding | NOPs |
//!
//! Bootstrap placement makes all hash-source addresses affine in the round number,
//! including the first four rounds. The program builder derives actual fanouts;
//! the AIR authenticates their closed-form values through the round metadata bus.

use alloc::{vec, vec::Vec};

use miden_core::Felt;

use crate::relations::ProvideMult;

pub const COMPRESSION_PERIOD: usize = 4096;
pub const MAX_PERIODIC_LENGTH: usize = 128;
pub const INPUT_ADDR_BASE: u32 = 4096;
pub const OUTPUT_SLOTS: [u32; 8] = [4000, 4001, 4002, 4003, 4004, 4005, 4006, 4007];

// The short periodic table consists of the 80-entry metadata table, the lane
// selectors, and six phase-specific 32-lane instruction templates.
pub const NUM_METADATA_PERIODIC_COLS: usize = 8;
pub const COL_META_T: usize = 0;
pub const COL_META_INPUT_WORD: usize = 1;
pub const COL_META_W_MULT: usize = 2;
pub const COL_META_A_MULT: usize = 3;
pub const COL_META_E_MULT: usize = 4;
pub const COL_META_K_LO: usize = 5;
pub const COL_META_K_HI: usize = 6;
pub const COL_META_VALID: usize = 7;
pub const COL_LANE: usize = 8;
pub const COL_P32_LAST: usize = 9;
pub const COL_WORD_FIRST: usize = 10;
pub const COL_HASH_FIRST: usize = 11;
pub const COL_WORD_LAST: usize = 12;
pub const COL_LANE_HALF: usize = 13;
pub const TEMPLATE_BEGIN: usize = 14;
pub const TEMPLATE_COLS: usize = 19;
pub const NUM_PERIODIC_COLS: usize = TEMPLATE_BEGIN + 6 * TEMPLATE_COLS;

pub const T_IS_INPUT: usize = 0;
pub const T_IS_CONST: usize = 1;
pub const T_IS_XOR: usize = 2;
pub const T_IS_AND: usize = 3;
pub const T_IS_ANDNOT: usize = 4;
pub const T_IS_ADD: usize = 5;
pub const T_IS_ROL: usize = 6;
pub const T_SRC_A_BASE: usize = 7;
pub const T_SRC_A_CYCLE_COEFF: usize = 8;
pub const T_SRC_B_BASE: usize = 9;
pub const T_SRC_B_CYCLE_COEFF: usize = 10;
pub const T_DST_CONST: usize = 11;
pub const T_DST_W: usize = 12;
pub const T_DST_A: usize = 13;
pub const T_DST_E: usize = 14;
pub const T_ROL_K: usize = 15;
pub const T_SWAP: usize = 16;
pub const T_CONST_LO: usize = 17;
pub const T_CONST_HI: usize = 18;

pub const PHASE_MASK: usize = 0;
pub const PHASE_WORDS: usize = 1;
pub const PHASE_BOOTSTRAP: usize = 2;
pub const PHASE_HASH: usize = 3;
pub const PHASE_FEED_FORWARD: usize = 4;
pub const PHASE_PADDING: usize = 5;
pub const NUM_PHASES: usize = 6;
pub const PHASE_BASES: [u32; NUM_PHASES] = [0, 32, 1312, 1440, 4000, 4032];
/// Number of 32-row cycles in each phase; a word-schedule cycle contains two 16-row words.
pub const PHASE_CYCLES: [u32; NUM_PHASES] = [1, 40, 4, 80, 1, 2];

/// Authenticated data for round `t`; multiplicities count future reads of `W[t]`, `a[t]`,
/// and `e[t]`. Entries 80..128 are invalid padding for the periodic lookup table.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RoundMetadata {
    pub t: u32,
    pub input_word: u32,
    pub w_mult: u32,
    pub a_mult: u32,
    pub e_mult: u32,
    pub k_lo: u32,
    pub k_hi: u32,
    pub valid: u32,
}

pub fn round_metadata() -> [RoundMetadata; MAX_PERIODIC_LENGTH] {
    core::array::from_fn(|t| {
        if t >= 80 {
            return RoundMetadata::default();
        }
        // W[t] is read once by its hash round, then by schedule words t+16, t+15, t+7,
        // and t+2 when those words lie in 16..80. Each small sigma reads its input three times.
        let w_mult = 1
            + u32::from(t <= 63)
            + 3 * u32::from((1..=64).contains(&t))
            + u32::from((9..=72).contains(&t))
            + 3 * u32::from((14..=77).contains(&t));
        // A newly computed a/e shifts through four state positions. Count its reads in the
        // next four rounds, plus one feedforward read for values surviving the last round.
        let a_mult = 5 * u32::from(t <= 78)
            + 2 * u32::from(t <= 77)
            + u32::from(t <= 76)
            + u32::from(t <= 75)
            + u32::from(t >= 76);
        let e_mult = 5 * u32::from(t <= 78)
            + u32::from(t <= 77)
            + u32::from(t <= 76)
            + u32::from(t <= 75)
            + u32::from(t >= 76);
        RoundMetadata {
            t: t as u32,
            input_word: u32::from(t < 16),
            w_mult,
            a_mult,
            e_mult,
            k_lo: K[t] as u32,
            k_hi: (K[t] >> 32) as u32,
            valid: 1,
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Input,
    Const(u64),
    Xor,
    And,
    AndNot,
    Add,
    Rol(u32),
    Nop,
}

/// One instruction whose destination address is its index in the compression program.
/// `Input` uses `src_a` as an external word index; other reading operations use slot addresses.
/// `dst_mult` counts all consumers, including the IO read of a feedforward result.
#[derive(Debug, Clone, Copy)]
pub struct Slot {
    pub op: Op,
    pub src_a: u32,
    pub src_b: u32,
    pub dst_mult: ProvideMult,
}

impl Slot {
    pub const NOP: Self = Self {
        op: Op::Nop,
        src_a: 0,
        src_b: 0,
        dst_mult: 0,
    };
    pub fn sources_before_destination(&self, index: usize) -> bool {
        if matches!(self.op, Op::Input | Op::Const(_) | Op::Nop) {
            true
        } else if matches!(self.op, Op::Rol(_)) {
            (self.src_a as usize) < index
        } else {
            (self.src_a as usize) < index && (self.src_b as usize) < index
        }
    }
}

pub const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

struct Builder {
    slots: Vec<Slot>,
}
impl Builder {
    fn emit(&mut self, op: Op, a: u32, b: u32) -> u32 {
        let n = self.slots.len() as u32;
        self.slots.push(Slot { op, src_a: a, src_b: b, dst_mult: 0 });
        n
    }
    fn input(&mut self, index: u32) -> u32 {
        self.emit(Op::Input, index, 0)
    }
    fn pad_to(&mut self, next_slot: usize) {
        assert!(self.slots.len() <= next_slot);
        self.slots.resize(next_slot, Slot::NOP);
    }
    fn constant(&mut self, v: u64) -> u32 {
        self.emit(Op::Const(v), 0, 0)
    }
    fn bin(&mut self, op: Op, a: u32, b: u32) -> u32 {
        self.emit(op, a, b)
    }
    fn rol(&mut self, x: u32, s: u32) -> u32 {
        assert!((1..=30).contains(&(s % 32)));
        self.emit(Op::Rol(s), x, 0)
    }
    fn rotr(&mut self, x: u32, s: u32) -> u32 {
        let l = 64 - s;
        if l == 31 || l == 63 {
            // The biased rotation decomposition supports shifts mod 32 in 1..=30 only.
            // Split these rotations so neither instruction needs the excluded shift of 31.
            let first = self.rol(x, 30);
            self.rol(first, l - 30)
        } else {
            self.rol(x, l)
        }
    }
    fn xor3(&mut self, x: u32, y: u32, z: u32) -> u32 {
        let t = self.bin(Op::Xor, x, y);
        self.bin(Op::Xor, t, z)
    }
}

fn build() -> [Slot; COMPRESSION_PERIOD] {
    let mut b = Builder {
        slots: Vec::with_capacity(COMPRESSION_PERIOD),
    };
    let mask6 = b.constant(0x03ff_ffff_ffff_ffff);
    let mask7 = b.constant(0x01ff_ffff_ffff_ffff);
    let mut w = [0u32; 80];
    for (t, word) in w.iter_mut().take(16).enumerate() {
        b.pad_to(32 + 16 * t + 15);
        *word = b.input(t as u32);
    }
    for t in 16..80 {
        let s0r1 = b.rotr(w[t - 15], 1);
        let s0r8 = b.rotr(w[t - 15], 8);
        let s0r7 = b.rotr(w[t - 15], 7);
        let s0m = b.bin(Op::And, s0r7, mask7);
        let s0 = b.xor3(s0r1, s0r8, s0m);
        let s1r19 = b.rotr(w[t - 2], 19);
        let s1r61 = b.rotr(w[t - 2], 61);
        let s1r6 = b.rotr(w[t - 2], 6);
        let s1m = b.bin(Op::And, s1r6, mask6);
        let s1 = b.xor3(s1r19, s1r61, s1m);
        let x = b.bin(Op::Add, w[t - 16], s0);
        let y = b.bin(Op::Add, x, w[t - 7]);
        w[t] = b.bin(Op::Add, y, s1);
    }
    let mut h = [0u32; 8];
    // Place d/h, c/g, b/f, then a/e in the a/e output lanes of four virtual prior rounds.
    // The first real round can then use the same relative source addresses as later rounds.
    for cycle in 0..4 {
        b.pad_to(1312 + 32 * cycle + 23);
        h[3 - cycle] = b.input(16 + (3 - cycle) as u32);
        h[7 - cycle] = b.input(16 + (7 - cycle) as u32);
    }
    let mut state = h;
    for (t, &word) in w.iter().enumerate() {
        b.pad_to(1440 + 32 * t);
        let k = b.constant(K[t]);
        let [a, bb, c, d, e, f, g, hh] = state;
        let s1r14 = b.rotr(e, 14);
        let s1r18 = b.rotr(e, 18);
        let s1r41 = b.rotr(e, 41);
        let s1 = b.xor3(s1r14, s1r18, s1r41);
        let ch_l = b.bin(Op::And, e, f);
        let ch_r = b.bin(Op::AndNot, e, g);
        let ch = b.bin(Op::Xor, ch_l, ch_r);
        let s0r28 = b.rotr(a, 28);
        let s0r34 = b.rotr(a, 34);
        let s0r39 = b.rotr(a, 39);
        let s0 = b.xor3(s0r28, s0r34, s0r39);
        let ab = b.bin(Op::And, a, bb);
        let axb = b.bin(Op::Xor, a, bb);
        let caxb = b.bin(Op::And, c, axb);
        let maj = b.bin(Op::Xor, ab, caxb);
        let t1a = b.bin(Op::Add, hh, s1);
        let t1b = b.bin(Op::Add, t1a, ch);
        let t1c = b.bin(Op::Add, t1b, k);
        let t1 = b.bin(Op::Add, t1c, word);
        let t2 = b.bin(Op::Add, s0, maj);
        let new_a = b.bin(Op::Add, t1, t2);
        let new_e = b.bin(Op::Add, d, t1);
        state = [new_a, a, bb, c, new_e, e, f, g];
    }
    b.pad_to(4000);
    for i in 0..8 {
        b.bin(Op::Add, h[i], state[i]);
    }
    assert_eq!(b.slots.len(), 4008, "SHA-512 program layout changed");
    let mut slots = b.slots;
    slots.resize(COMPRESSION_PERIOD, Slot::NOP);
    let mut fanout = vec![0u32; COMPRESSION_PERIOD];
    for slot in &slots {
        if !matches!(slot.op, Op::Input | Op::Const(_) | Op::Nop) {
            fanout[slot.src_a as usize] += 1;
        }
        if matches!(slot.op, Op::Xor | Op::And | Op::AndNot | Op::Add) {
            fanout[slot.src_b as usize] += 1;
        }
    }
    // Each feedforward result is consumed once by the invocation-binding AIR.
    for s in OUTPUT_SLOTS {
        fanout[s as usize] += 1;
    }
    for (i, slot) in slots.iter().enumerate() {
        assert!(slot.sources_before_destination(i), "source after destination at slot {i}");
    }
    assert!(fanout.iter().all(|&n| n <= 64), "SHA-512 fanout exceeds 64");
    for (slot, mult) in slots.iter_mut().zip(fanout) {
        slot.dst_mult = mult;
    }
    slots.try_into().ok().unwrap()
}

pub fn slots() -> [Slot; COMPRESSION_PERIOD] {
    build()
}
pub fn real_slot_count(slots: &[Slot; COMPRESSION_PERIOD]) -> usize {
    slots.iter().filter(|s| !matches!(s.op, Op::Nop)).count()
}

// Each address is affine in the phase's cycle counter. Bootstrap covers four
// cycles in a period-128 template so its eight initial-state fanouts are fixed.
fn template_slot(
    phase: usize,
    row: usize,
    cycle: usize,
    slots: &[Slot; COMPRESSION_PERIOD],
) -> Slot {
    let address = match phase {
        PHASE_WORDS => 32 + 16 * 16 + 32 * cycle + row % 32,
        PHASE_HASH => 1440 + 32 * cycle + row % 32,
        // Bootstrap starts at global row 1312 == 32 mod 128; undo that periodic-table offset.
        PHASE_BOOTSTRAP => 1312 + (row + 96) % 128,
        _ => PHASE_BASES[phase] as usize + row % 32,
    };
    slots[address]
}

fn template_field(
    phase: usize,
    row: usize,
    field: usize,
    slots: &[Slot; COMPRESSION_PERIOD],
) -> Felt {
    let slot = template_slot(phase, row, 0, slots);
    let next = template_slot(phase, row, 1, slots);
    let lane = row % 32;
    let word_output = phase == PHASE_WORDS && lane % 16 == 15;
    let a_output = phase == PHASE_HASH && lane == 23;
    let e_output = phase == PHASE_HASH && lane == 24;
    match field {
        T_IS_INPUT => Felt::from((matches!(slot.op, Op::Input)) as u8),
        T_IS_CONST => Felt::from((matches!(slot.op, Op::Const(_))) as u8),
        T_IS_XOR => Felt::from((matches!(slot.op, Op::Xor)) as u8),
        T_IS_AND => Felt::from((matches!(slot.op, Op::And)) as u8),
        T_IS_ANDNOT => Felt::from((matches!(slot.op, Op::AndNot)) as u8),
        T_IS_ADD => Felt::from((matches!(slot.op, Op::Add)) as u8),
        T_IS_ROL => Felt::from((matches!(slot.op, Op::Rol(_))) as u8),
        T_SRC_A_BASE => Felt::from(slot.src_a),
        T_SRC_B_BASE => Felt::from(slot.src_b),
        T_SRC_A_CYCLE_COEFF | T_SRC_B_CYCLE_COEFF => {
            let source = |slot: Slot| {
                if field == T_SRC_A_CYCLE_COEFF {
                    slot.src_a
                } else {
                    slot.src_b
                }
            };
            let base = source(slot);
            let step = i64::from(source(next)) - i64::from(base);
            let cycles = match phase {
                // The first eight word cycles use the separate input-word template.
                PHASE_WORDS => PHASE_CYCLES[PHASE_WORDS] as usize - 8,
                PHASE_HASH => PHASE_CYCLES[PHASE_HASH] as usize,
                _ => 1,
            };
            for cycle in 2..cycles {
                assert_eq!(
                    i64::from(source(template_slot(phase, row, cycle, slots))),
                    i64::from(base) + cycle as i64 * step,
                    "SHA-512 source template is not affine: phase {phase}, lane {row}, cycle {cycle}"
                );
            }
            Felt::from(source(next)) - Felt::from(base)
        },
        T_DST_CONST => Felt::from(if word_output || a_output || e_output {
            0
        } else {
            slot.dst_mult
        }),
        T_DST_W => Felt::from((word_output) as u8),
        T_DST_A => Felt::from((a_output) as u8),
        T_DST_E => Felt::from((e_output) as u8),
        T_ROL_K => Felt::from(match slot.op {
            Op::Rol(r) => 1u32 << (r % 32),
            _ => 0,
        }),
        T_SWAP => Felt::from((matches!(slot.op, Op::Rol(r) if r >= 32)) as u8),
        T_CONST_LO => Felt::from(match slot.op {
            Op::Const(v) if phase != PHASE_HASH => v as u32,
            _ => 0,
        }),
        T_CONST_HI => Felt::from(match slot.op {
            Op::Const(v) if phase != PHASE_HASH => (v >> 32) as u32,
            _ => 0,
        }),
        _ => unreachable!(),
    }
}

/// Short periodic tables authenticate the round metadata and instruction templates.
/// No polynomial has the full 4096-row compression period.
pub fn compression_program() -> [Vec<Felt>; NUM_PERIODIC_COLS] {
    let metadata = round_metadata();
    let slots = slots();
    core::array::from_fn(|column| {
        let period = if column < NUM_METADATA_PERIODIC_COLS
            || (column >= TEMPLATE_BEGIN
                && (column - TEMPLATE_BEGIN) / TEMPLATE_COLS == PHASE_BOOTSTRAP)
        {
            MAX_PERIODIC_LENGTH
        } else {
            32
        };
        let mut values: Vec<Felt> = (0..period)
            .map(|row| {
                if column < NUM_METADATA_PERIODIC_COLS {
                    let m = metadata[row];
                    return Felt::from(
                        [m.t, m.input_word, m.w_mult, m.a_mult, m.e_mult, m.k_lo, m.k_hi, m.valid]
                            [column],
                    );
                }
                match column {
                    COL_LANE => Felt::from((row % 32) as u32),
                    COL_P32_LAST => Felt::from((row % 32 == 31) as u8),
                    COL_WORD_FIRST => Felt::from((row % 16 == 0) as u8),
                    COL_HASH_FIRST => Felt::from((row % 32 == 0) as u8),
                    COL_WORD_LAST => Felt::from((row % 16 == 15) as u8),
                    COL_LANE_HALF => Felt::from((row % 32 / 16) as u32),
                    _ => template_field(
                        (column - TEMPLATE_BEGIN) / TEMPLATE_COLS,
                        row,
                        (column - TEMPLATE_BEGIN) % TEMPLATE_COLS,
                        &slots,
                    ),
                }
            })
            .collect();
        // Constant and repeated templates need only their shortest dyadic period.
        while values.len() > 1 && values[..values.len() / 2] == values[values.len() / 2..] {
            values.truncate(values.len() / 2);
        }
        values
    })
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn templates_reject_non_affine_late_sources() {
        for (phase, address) in [(PHASE_WORDS, 32 + 16 * 78), (PHASE_HASH, 1440 + 32 * 79)] {
            for field in [T_SRC_A_CYCLE_COEFF, T_SRC_B_CYCLE_COEFF] {
                let mut program = slots();
                // Changing a late round leaves the two samples used to derive the template
                // untouched. Building that template must fail before it can define a new AIR.
                if field == T_SRC_A_CYCLE_COEFF {
                    program[address].src_a += 1;
                } else {
                    program[address].src_b += 1;
                }
                assert!(
                    std::panic::catch_unwind(|| template_field(phase, 0, field, &program)).is_err(),
                    "phase {phase}, source field {field}: a non-affine schedule must be rejected"
                );
            }
        }
    }
}
