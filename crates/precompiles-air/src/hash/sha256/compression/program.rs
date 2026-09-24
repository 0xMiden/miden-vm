//! Fixed 4096-slot SHA-256 compression program and short periodic tables.
//!
//! | Rows | Phase | Instructions |
//! |------|-------|--------------|
//! | 0..32 | Masks | Two shift masks, then NOPs |
//! | 32..1056 | Words | 64 words, 16 lanes each; the first 16 use only the input lane |
//! | 1056..1184 | Bootstrap | Eight state inputs placed like the preceding four hash rounds |
//! | 1184..3232 | Hash | 64 rounds, 32 lanes each, including one round constant |
//! | 3232..3264 | Feedforward | Eight state additions, then NOPs |
//! | 3264..4096 | Padding | NOPs |
//!
//! Each computed schedule word takes fifteen instructions and leaves lane 14 idle, so every word
//! lands on lane 15. Bootstrap placement makes all hash-source addresses affine in the round
//! number, including the first four rounds. The program builder derives actual fanouts;
//! the AIR authenticates their closed-form values through the round metadata bus.

use alloc::{vec, vec::Vec};

use miden_core::Felt;

use crate::relations::ProvideMult;

pub const COMPRESSION_PERIOD: usize = 4096;
pub const MAX_PERIODIC_LENGTH: usize = 128;
pub const INPUT_ADDR_BASE: u32 = 4096;
pub const OUTPUT_SLOTS: [u32; 8] = [3232, 3233, 3234, 3235, 3236, 3237, 3238, 3239];

// The short periodic table consists of the 64-entry metadata table, the lane
// selectors, and six phase-specific 32-lane instruction templates.
pub const NUM_METADATA_PERIODIC_COLS: usize = 7;
pub const COL_META_T: usize = 0;
pub const COL_META_INPUT_WORD: usize = 1;
pub const COL_META_W_MULT: usize = 2;
pub const COL_META_A_MULT: usize = 3;
pub const COL_META_E_MULT: usize = 4;
pub const COL_META_K: usize = 5;
pub const COL_META_VALID: usize = 6;
pub const COL_LANE: usize = 7;
pub const COL_P32_LAST: usize = 8;
pub const COL_WORD_FIRST: usize = 9;
pub const COL_HASH_FIRST: usize = 10;
pub const COL_WORD_LAST: usize = 11;
pub const COL_LANE_HALF: usize = 12;
pub const TEMPLATE_BEGIN: usize = 13;
pub const TEMPLATE_COLS: usize = 17;
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
pub const T_CONST: usize = 16;

pub const PHASE_MASK: usize = 0;
pub const PHASE_WORDS: usize = 1;
pub const PHASE_BOOTSTRAP: usize = 2;
pub const PHASE_HASH: usize = 3;
pub const PHASE_FEED_FORWARD: usize = 4;
pub const PHASE_PADDING: usize = 5;
pub const NUM_PHASES: usize = 6;
pub const PHASE_BASES: [u32; NUM_PHASES] = [0, 32, 1056, 1184, 3232, 3264];
pub const PHASE_CYCLES: [u32; NUM_PHASES] = [1, 32, 4, 64, 1, 26];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundMetadata {
    pub t: u32,
    pub input_word: u32,
    pub w_mult: u32,
    pub a_mult: u32,
    pub e_mult: u32,
    pub k: u32,
    pub valid: u32,
}

pub fn round_metadata() -> [RoundMetadata; MAX_PERIODIC_LENGTH] {
    core::array::from_fn(|t| {
        if t >= 64 {
            return RoundMetadata {
                t: 0,
                input_word: 0,
                w_mult: 0,
                a_mult: 0,
                e_mult: 0,
                k: 0,
                valid: 0,
            };
        }
        let w_mult = 1
            + u32::from(t <= 47)
            + 3 * u32::from((1..=48).contains(&t))
            + u32::from((9..=56).contains(&t))
            + 3 * u32::from((14..=61).contains(&t));
        let a_mult = 5 * u32::from(t <= 62)
            + 2 * u32::from(t <= 61)
            + u32::from(t <= 60)
            + u32::from(t <= 59)
            + u32::from(t >= 60);
        let e_mult = 5 * u32::from(t <= 62)
            + u32::from(t <= 61)
            + u32::from(t <= 60)
            + u32::from(t <= 59)
            + u32::from(t >= 60);
        RoundMetadata {
            t: t as u32,
            input_word: u32::from(t < 16),
            w_mult,
            a_mult,
            e_mult,
            k: K[t],
            valid: 1,
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Input,
    Const(u32),
    Xor,
    And,
    AndNot,
    Add,
    Rol(u32),
    Nop,
}

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

/// SHA-256 round constants (FIPS 180-4 §4.2.2).
pub const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
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
    fn constant(&mut self, v: u32) -> u32 {
        self.emit(Op::Const(v), 0, 0)
    }
    fn bin(&mut self, op: Op, a: u32, b: u32) -> u32 {
        self.emit(op, a, b)
    }
    fn rol(&mut self, x: u32, s: u32) -> u32 {
        assert!((1..=30).contains(&s));
        self.emit(Op::Rol(s), x, 0)
    }
    fn rotr(&mut self, x: u32, s: u32) -> u32 {
        self.rol(x, 32 - s)
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
    let mask3 = b.constant(0x1fff_ffff);
    let mask10 = b.constant(0x003f_ffff);
    let mut w = [0u32; 64];
    for (t, word) in w.iter_mut().take(16).enumerate() {
        b.pad_to(32 + 16 * t + 15);
        *word = b.input(t as u32);
    }
    for t in 16..64 {
        let s0r7 = b.rotr(w[t - 15], 7);
        let s0r18 = b.rotr(w[t - 15], 18);
        let s0r3 = b.rotr(w[t - 15], 3);
        let s0m = b.bin(Op::And, s0r3, mask3);
        let s0 = b.xor3(s0r7, s0r18, s0m);
        let s1r17 = b.rotr(w[t - 2], 17);
        let s1r19 = b.rotr(w[t - 2], 19);
        let s1r10 = b.rotr(w[t - 2], 10);
        let s1m = b.bin(Op::And, s1r10, mask10);
        let s1 = b.xor3(s1r17, s1r19, s1m);
        let x = b.bin(Op::Add, w[t - 16], s0);
        let y = b.bin(Op::Add, x, w[t - 7]);
        // Fifteen instructions per word: the output stays on lane 15.
        b.pad_to(32 + 16 * t + 15);
        w[t] = b.bin(Op::Add, y, s1);
    }
    let mut h = [0u32; 8];
    for cycle in 0..4 {
        b.pad_to(1056 + 32 * cycle + 23);
        h[3 - cycle] = b.input(16 + (3 - cycle) as u32);
        h[7 - cycle] = b.input(16 + (7 - cycle) as u32);
    }
    let mut state = h;
    for (t, &word) in w.iter().enumerate() {
        b.pad_to(1184 + 32 * t);
        let k = b.constant(K[t]);
        let [a, bb, c, d, e, f, g, hh] = state;
        let s1r6 = b.rotr(e, 6);
        let s1r11 = b.rotr(e, 11);
        let s1r25 = b.rotr(e, 25);
        let s1 = b.xor3(s1r6, s1r11, s1r25);
        let ch_l = b.bin(Op::And, e, f);
        let ch_r = b.bin(Op::AndNot, e, g);
        let ch = b.bin(Op::Xor, ch_l, ch_r);
        let s0r2 = b.rotr(a, 2);
        let s0r13 = b.rotr(a, 13);
        let s0r22 = b.rotr(a, 22);
        let s0 = b.xor3(s0r2, s0r13, s0r22);
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
    b.pad_to(3232);
    for i in 0..8 {
        b.bin(Op::Add, h[i], state[i]);
    }
    assert_eq!(b.slots.len(), 3240, "SHA-256 program layout changed");
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
    assert!(fanout.iter().all(|&n| n <= 64), "SHA-256 fanout exceeds 64");
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
        PHASE_HASH => 1184 + 32 * cycle + row % 32,
        PHASE_BOOTSTRAP => 1056 + (row + 96) % 128,
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
                    "SHA-256 source template is not affine: phase {phase}, lane {row}, cycle {cycle}"
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
            Op::Rol(r) => 1u32 << r,
            _ => 0,
        }),
        T_CONST => Felt::from(match slot.op {
            Op::Const(v) if phase != PHASE_HASH => v,
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
                        [m.t, m.input_word, m.w_mult, m.a_mult, m.e_mult, m.k, m.valid][column],
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
        for (phase, address) in [(PHASE_WORDS, 32 + 16 * 62), (PHASE_HASH, 1184 + 32 * 63)] {
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
