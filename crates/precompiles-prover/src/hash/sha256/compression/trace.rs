use alloc::{vec, vec::Vec};

#[cfg(test)]
use miden_core::utils::RowMajorMatrix;
use miden_core::{Felt, field::Field};
use miden_precompiles_air::hash::sha256::compression::{
    self,
    program::{self, Op},
};

use crate::primitives::byte_pair_lut::{BytePairLutRequires, BytePairOp};

#[derive(Debug, Clone, Copy)]
pub struct CompressionInput {
    pub state: [u32; 8],
    pub block: [u32; 16],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionOutput {
    pub block_id: u32,
    pub state: [u32; 8],
}
#[derive(Debug, Default, Clone)]
pub struct Sha256CompressionRequires {
    records: Vec<CompressionInput>,
}

impl Sha256CompressionRequires {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn num_blocks(&self) -> usize {
        self.records.len()
    }
    pub fn trace_height(&self) -> Option<usize> {
        self.records
            .len()
            .checked_mul(program::COMPRESSION_PERIOD)?
            .max(program::MAX_PERIODIC_LENGTH)
            .checked_next_power_of_two()
    }
    pub fn require(&mut self, state: [u32; 8], block: [u32; 16]) -> CompressionOutput {
        let block_id = u32::try_from(self.records.len()).expect("SHA-256 block id overflow");
        let output = compress(&state, &block);
        self.records.push(CompressionInput { state, block });
        CompressionOutput { block_id, state: output }
    }
}

fn compress(state: &[u32; 8], block: &[u32; 16]) -> [u32; 8] {
    let mut w = [0u32; 64];
    w[..16].copy_from_slice(block);
    let mut t = 16;
    while t < 64 {
        let x = w[t - 15];
        let y = w[t - 2];
        let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x.rotate_right(3) & 0x1fff_ffff);
        let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y.rotate_right(10) & 0x003f_ffff);
        w[t] = w[t - 16].wrapping_add(s0).wrapping_add(w[t - 7]).wrapping_add(s1);
        t += 1;
    }
    let mut s = *state;
    for (&k, &word) in program::K.iter().zip(w.iter()) {
        let [a, b, c, d, e, f, g, h] = s;
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (c & (a ^ b));
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(k).wrapping_add(word);
        let t2 = s0.wrapping_add(maj);
        s = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
    }
    core::array::from_fn(|i| state[i].wrapping_add(s[i]))
}

fn populate_block(
    rec: &CompressionInput,
    slots: &[program::Slot; program::COMPRESSION_PERIOD],
    rows: &mut [Felt],
    row_width: usize,
    mem: &mut [u32],
    bpl: &mut BytePairLutRequires,
) {
    mem.fill(0);
    for (i, s) in slots.iter().enumerate() {
        if matches!(s.op, Op::Nop) {
            continue;
        }
        let a = mem[s.src_a as usize];
        let b = mem[s.src_b as usize];
        let mut limbs = [0u16; 4];
        let mut carry = 0u32;
        let r = match s.op {
            Op::Input => {
                let index = s.src_a as usize;
                let value = if index < 16 {
                    rec.block[index]
                } else {
                    rec.state[index - 16]
                };
                for byte in value.to_le_bytes() {
                    bpl.require(BytePairOp::Xor, 0, byte);
                }
                value
            },
            Op::Const(v) => {
                for byte in v.to_le_bytes() {
                    bpl.require(BytePairOp::Xor, 0, byte);
                }
                v
            },
            Op::Xor => {
                for (x, y) in a.to_le_bytes().into_iter().zip(b.to_le_bytes()) {
                    bpl.require(BytePairOp::Xor, x, y);
                }
                a ^ b
            },
            Op::And => {
                for (x, y) in a.to_le_bytes().into_iter().zip(b.to_le_bytes()) {
                    bpl.require(BytePairOp::AndNot, 255 - x, y);
                }
                a & b
            },
            Op::AndNot => {
                for (x, y) in a.to_le_bytes().into_iter().zip(b.to_le_bytes()) {
                    bpl.require(BytePairOp::AndNot, x, y);
                }
                (!a) & b
            },
            Op::Add => {
                let (sum, overflow) = a.overflowing_add(b);
                for byte in sum.to_le_bytes() {
                    bpl.require(BytePairOp::Xor, 0, byte);
                }
                carry = overflow as u32;
                sum
            },
            Op::Rol(sh) => {
                for byte in a.to_le_bytes() {
                    bpl.require(BytePairOp::Xor, byte, 0);
                }
                let decomposition = (u64::from(a) + (1u64 << 32)) * (1u64 << sh);
                for (j, limb) in limbs.iter_mut().enumerate() {
                    *limb = ((decomposition >> (16 * j)) & 0xffff) as u16;
                }
                for limb in limbs {
                    bpl.require_range16(limb);
                }
                a.rotate_left(sh)
            },
            Op::Nop => 0,
        };
        mem[i] = r;
        let witness_a = if matches!(s.op, Op::Input | Op::Const(_)) { 0 } else { a };
        let witness_b = if matches!(s.op, Op::Input | Op::Const(_) | Op::Rol(_)) {
            0
        } else {
            b
        };
        let base = i * row_width;
        rows[base + compression::COL_A_BEGIN..base + compression::COL_A_BEGIN + 4]
            .copy_from_slice(&witness_a.to_le_bytes().map(Felt::from));
        if matches!(s.op, Op::Rol(_)) {
            rows[base + compression::COL_ROT_BEGIN..base + compression::COL_ROT_BEGIN + 4]
                .copy_from_slice(&limbs.map(Felt::from));
        } else {
            rows[base + compression::COL_B_BEGIN..base + compression::COL_B_BEGIN + 4]
                .copy_from_slice(&witness_b.to_le_bytes().map(Felt::from));
        }
        let raw = match s.op {
            Op::Rol(_) => a,
            _ => r,
        };
        rows[base + compression::COL_R_BEGIN..base + compression::COL_R_BEGIN + 4]
            .copy_from_slice(&raw.to_le_bytes().map(Felt::from));
        if matches!(s.op, Op::Add) {
            rows[base + compression::COL_CARRY] = Felt::from(carry);
        }
    }
}

#[cfg(test)]
pub fn generate_trace(
    requires: Sha256CompressionRequires,
    bpl: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    generate_trace_padded_to(requires, bpl, 0)
}
#[cfg(test)]
pub fn generate_trace_padded_to(
    requires: Sha256CompressionRequires,
    bpl: &mut BytePairLutRequires,
    min_height: usize,
) -> RowMajorMatrix<Felt> {
    let height = requires
        .trace_height()
        .expect("SHA-256 trace height overflow")
        .max(min_height)
        .checked_next_power_of_two()
        .expect("SHA-256 trace height overflow");
    let mut values = vec![Felt::ZERO; height * compression::NUM_MAIN_COLS];
    populate_trace(&requires, bpl, &mut values, compression::NUM_MAIN_COLS);
    RowMajorMatrix::new(values, compression::NUM_MAIN_COLS)
}

/// Populate the compression columns in a zero-initialized trace. The combined SHA-256 AIR
/// supplies a wider row so compression and IO can write directly into one allocation.
pub(crate) fn populate_trace(
    requires: &Sha256CompressionRequires,
    bpl: &mut BytePairLutRequires,
    values: &mut [Felt],
    row_width: usize,
) {
    assert!(row_width >= compression::NUM_MAIN_COLS);
    assert_eq!(values.len() % row_width, 0);
    assert!(
        values.len() / row_width >= requires.trace_height().expect("SHA-256 trace height overflow")
    );
    let slots = program::slots();
    let metadata = program::round_metadata();
    for (index, row) in values.chunks_exact_mut(row_width).enumerate() {
        let block = index / program::COMPRESSION_PERIOD;
        row[compression::COL_BLOCK_ID] =
            Felt::from(u32::try_from(block).expect("SHA-256 block id overflow"));
        row[compression::COL_ACT] = Felt::from((block < requires.records.len()) as u8);
        let slot_index = index % program::COMPRESSION_PERIOD;
        fill_control(row, slot_index, &metadata);
        fill_program(row, slots[slot_index]);
    }
    // Populate directly into the final allocation; reuse scratch words across blocks.
    let mut memory = vec![0u32; program::COMPRESSION_PERIOD];
    for (rows, rec) in values
        .chunks_exact_mut(program::COMPRESSION_PERIOD * row_width)
        .zip(&requires.records)
    {
        populate_block(rec, &slots, rows, row_width, &mut memory, bpl);
    }
}

fn fill_control(
    row: &mut [Felt],
    index: usize,
    metadata: &[program::RoundMetadata; program::MAX_PERIODIC_LENGTH],
) {
    let phase = program::PHASE_BASES.iter().rposition(|&base| index >= base as usize).unwrap();
    let cycle = (index - program::PHASE_BASES[phase] as usize) / 32;
    row[compression::COL_PHASE_BEGIN + phase] = Felt::ONE;
    row[compression::COL_CYCLE] = Felt::from(cycle as u32);
    let delta = Felt::from((cycle + 1) as u32) - Felt::from(program::PHASE_CYCLES[phase]);
    row[compression::COL_PHASE_END] = Felt::from((delta == Felt::ZERO) as u8);
    row[compression::COL_PHASE_INV] = delta.try_inverse().unwrap_or(Felt::ZERO);
    let round = match phase {
        program::PHASE_WORDS => 2 * cycle + index % 32 / 16,
        program::PHASE_HASH => cycle,
        _ => 0,
    };
    let m = metadata[round];
    row[compression::COL_META_T..=compression::COL_META_K]
        .copy_from_slice(&[m.t, m.input_word, m.w_mult, m.a_mult, m.e_mult, m.k].map(Felt::from));
}

fn fill_program(row: &mut [Felt], slot: program::Slot) {
    let opcode = match slot.op {
        Op::Input => Some(0),
        Op::Const(_) => Some(1),
        Op::Xor => Some(2),
        Op::And => Some(3),
        Op::AndNot => Some(4),
        Op::Add => Some(5),
        Op::Rol(_) => Some(6),
        Op::Nop => None,
    };
    if let Some(opcode) = opcode {
        row[compression::COL_PROG_BEGIN + opcode] = Felt::ONE;
    }
    row[compression::COL_SRC_A] = Felt::from(slot.src_a);
    row[compression::COL_SRC_B] = Felt::from(slot.src_b);
    if let Op::Rol(shift) = slot.op {
        row[compression::COL_ROL_K] = Felt::from(1u32 << shift);
    }
}
