#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

#[cfg(test)]
use miden_core::utils::RowMajorMatrix;
use miden_core::{
    Felt,
    deferred::{Node, deferred_chunks_frame},
    field::PrimeCharacteristicRing,
};
use miden_precompiles::Sha256Precompile;
use miden_precompiles_air::hash::sha256::io::{self, program::IV};

use crate::{
    hash::sha256::compression::Sha256CompressionRequires,
    primitives::byte_pair_lut::{BytePairLutRequires, BytePairOp},
    relations::ProvideMult,
    transcript::eidos::{
        EidosDigest,
        trace::{AbsorptionOutput, EidosRequires},
    },
};

#[derive(Debug, Clone, Copy)]
pub struct Sha256IoOutput {
    pub digest: [u8; 32],
    pub h_sha256: EidosDigest,
    pub invocation: u32,
}

#[derive(Debug, Clone)]
struct Block {
    id: u32,
    words: [u32; 16],
    state: [u32; 8],
}

#[derive(Debug, Clone)]
struct Invocation {
    input: Vec<u8>,
    blocks: Vec<Block>,
    digest: [u8; 32],
    raw_eidos: AbsorptionOutput,
    digest_eidos: AbsorptionOutput,
    node_eidos: AbsorptionOutput,
    out_mult: ProvideMult,
}

#[derive(Debug, Default, Clone)]
pub struct Sha256IoRequires {
    invocations: Vec<Invocation>,
}

impl Sha256IoRequires {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn num_blocks(&self) -> usize {
        self.invocations.iter().map(|inv| inv.blocks.len()).sum()
    }

    /// Count additional uses of an already registered claim without repeating its hashing work.
    pub(crate) fn add_consumers(&mut self, invocation: u32, consumers: ProvideMult) {
        let invocation = &mut self.invocations[invocation as usize];
        invocation.out_mult = invocation
            .out_mult
            .checked_add(consumers)
            .expect("too many SHA-256 claim consumers");
    }

    /// Record one assertion, allocating compression blocks and shared Eidos chains.
    pub fn require(
        &mut self,
        input: &[u8],
        compression: &mut Sha256CompressionRequires,
        eidos: &mut EidosRequires,
    ) -> Sha256IoOutput {
        let len = u32::try_from(input.len()).expect("SHA-256 input length exceeds u32");
        let mut padded = input.to_vec();
        padded.push(0x80);
        let padded_len = padded
            .len()
            .checked_add(8)
            .expect("SHA-256 input length overflow")
            .div_ceil(64)
            .checked_mul(64)
            .expect("SHA-256 input length overflow");
        padded.resize(padded_len - 8, 0);
        padded.extend_from_slice(&(u64::from(len) * 8).to_be_bytes());

        let mut state = IV;
        let blocks = padded
            .as_chunks::<64>()
            .0
            .iter()
            .map(|bytes| {
                let words = core::array::from_fn(|i| {
                    u32::from_be_bytes(bytes[i * 4..i * 4 + 4].try_into().expect("four-byte word"))
                });
                let output = compression.require(state, words);
                let block = Block { id: output.block_id, words, state };
                state = output.state;
                block
            })
            .collect();
        let digest = core::array::from_fn(|i| state[i / 4].to_be_bytes()[i % 4]);
        let raw_eidos = require_chunks(input, eidos);
        let digest_eidos = require_chunks(&digest, eidos);
        let node_eidos = eidos.require_one_shot(
            Sha256Precompile::assert_frame(len),
            raw_eidos.digest.0,
            digest_eidos.digest.0,
        );
        eidos.require_digest(node_eidos.digest).expect("recorded assertion digest");
        let h_sha256 = node_eidos.digest;
        let invocation =
            u32::try_from(self.invocations.len()).expect("SHA-256 invocation count exceeds u32");
        self.invocations.push(Invocation {
            input: input.to_vec(),
            blocks,
            digest,
            raw_eidos,
            digest_eidos,
            node_eidos,
            out_mult: 1,
        });
        Sha256IoOutput { digest, h_sha256, invocation }
    }
}

fn require_chunks(bytes: &[u8], eidos: &mut EidosRequires) -> AbsorptionOutput {
    let node = Node::chunks_from_bytes(bytes);
    let chunks = node.payload().as_data().expect("CHUNKS data payload");
    let n_chunks = u32::try_from(chunks.len()).expect("CHUNKS count exceeds u32");
    let output = eidos.require_absorption(
        deferred_chunks_frame(n_chunks),
        chunks.iter().map(|chunk| {
            (
                chunk[..4].try_into().expect("block low"),
                chunk[4..].try_into().expect("block high"),
            )
        }),
    );
    eidos.require_digest(output.digest).expect("recorded CHUNKS digest");
    output
}

#[cfg(test)]
pub fn generate_trace(
    requires: Sha256IoRequires,
    bpl: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    generate_trace_padded_to(requires, bpl, 0)
}

#[cfg(test)]
pub fn generate_trace_padded_to(
    requires: Sha256IoRequires,
    bpl: &mut BytePairLutRequires,
    min_height: usize,
) -> RowMajorMatrix<Felt> {
    let height = requires
        .num_blocks()
        .checked_mul(io::IO_PERIOD)
        .expect("SHA-256 IO height overflow")
        .max(io::IO_PERIOD)
        .max(min_height)
        .checked_next_power_of_two()
        .expect("SHA-256 IO height overflow");
    let mut values = vec![Felt::ZERO; height * io::NUM_MAIN_COLS];
    for (i, row) in values.as_chunks_mut::<{ io::NUM_MAIN_COLS }>().0.iter_mut().enumerate() {
        row[io::COL_BLOCK_ID] =
            Felt::from_u32(u32::try_from(i / io::IO_PERIOD).expect("SHA-256 block id overflow"));
    }
    populate_rows(requires, bpl, |index, row| {
        values[index * io::NUM_MAIN_COLS..(index + 1) * io::NUM_MAIN_COLS].copy_from_slice(row);
    });
    RowMajorMatrix::new(values, io::NUM_MAIN_COLS)
}

/// Emit only the active IO rows, allowing the combined AIR to place them in compression NOPs.
pub(crate) fn populate_rows(
    requires: Sha256IoRequires,
    bpl: &mut BytePairLutRequires,
    mut write_row: impl FnMut(usize, &[Felt; io::NUM_MAIN_COLS]),
) {
    let mut row_index = 0;
    for inv in requires.invocations {
        let len = inv.input.len();
        for (block_index, block) in inv.blocks.iter().enumerate() {
            let final_block = block_index + 1 == inv.blocks.len();
            for i in 0..io::IO_PERIOD {
                let mut row = [Felt::ZERO; io::NUM_MAIN_COLS];
                assert_eq!(row_index / io::IO_PERIOD, block.id as usize);
                row[io::COL_BLOCK_ID] = Felt::from_u32(block.id);
                let offset = block_index * 64 + i * 8;
                let left = len.saturating_sub(offset) as u32;
                row[io::COL_ACT] = Felt::ONE;
                row[io::COL_FIRST_BLOCK] = Felt::from_bool(block_index == 0);
                row[io::COL_FINAL_BLOCK] = Felt::from_bool(final_block);
                row[io::COL_BEFORE] = Felt::from_bool(offset <= len);
                row[io::COL_LEFT] = Felt::from_u32(left);
                row[io::COL_LEFT_LO16] = Felt::from_u16(left as u16);
                row[io::COL_LEFT_HI16] = Felt::from_u16((left >> 16) as u16);
                bpl.require_range16(left as u16);
                bpl.require_range16((left >> 16) as u16);
                row[io::COL_LEN] = Felt::from_u32(len as u32);
                let chunk_index = offset / 32;
                row[io::COL_CHUNK_ACTIVE] =
                    Felt::from_bool(chunk_index == 0 || chunk_index * 32 < len);
                let raw_head = inv.raw_eidos.span.head().as_u32();
                let raw_tail = inv.raw_eidos.span.tail().as_u32();
                row[io::COL_INPUT_EIDOS] =
                    Felt::from_u32((raw_head + chunk_index as u32).min(raw_tail));
                row[io::COL_INPUT_HEAD] = Felt::from_u32(raw_head);
                row[io::COL_DIGEST_EIDOS] = Felt::from_u32(inv.digest_eidos.span.head().as_u32());
                row[io::COL_NODE_EIDOS] = Felt::from_u32(inv.node_eidos.span.head().as_u32());
                for j in 0..8 {
                    let byte = inv.input.get(offset + j).copied().unwrap_or(0);
                    row[io::COL_RAW_BEGIN + j] = Felt::from_u8(byte);
                    row[io::COL_MSG_BEGIN + j] = Felt::from_bool(offset + j < len);
                    bpl.require(BytePairOp::Xor, 0, byte);
                }
                if offset >= 8 {
                    let previous = core::array::from_fn(|j| {
                        inv.input.get(offset - 8 + j).copied().unwrap_or(0)
                    });
                    row[io::COL_PREVIOUS_RAW..io::COL_PREVIOUS_RAW + 2]
                        .copy_from_slice(&pack_le(previous));
                }
                if i % 4 == 2 {
                    let head = core::array::from_fn(|j| {
                        inv.input.get(offset - 16 + j).copied().unwrap_or(0)
                    });
                    row[io::COL_CHUNK_HEAD_RAW..io::COL_CHUNK_HEAD_RAW + 2]
                        .copy_from_slice(&pack_le(head));
                }
                row[io::COL_WORD_LO] = Felt::from_u32(block.words[2 * i + 1]);
                row[io::COL_WORD_HI] = Felt::from_u32(block.words[2 * i]);
                if i < 4 {
                    row[io::COL_STATE_LO] = Felt::from_u32(block.state[2 * i + 1]);
                    row[io::COL_STATE_HI] = Felt::from_u32(block.state[2 * i]);
                    if final_block {
                        for j in 0..8 {
                            let byte = inv.digest[i * 8 + j];
                            row[io::COL_DIGEST_BEGIN + j] = Felt::from_u8(byte);
                            bpl.require(BytePairOp::Xor, 0, byte);
                        }
                        if i > 0 {
                            let previous = inv.digest[(i - 1) * 8..i * 8]
                                .try_into()
                                .expect("previous digest row");
                            row[io::COL_PREVIOUS_DIGEST..io::COL_PREVIOUS_DIGEST + 2]
                                .copy_from_slice(&pack_le(previous));
                        }
                        if i % 4 == 2 {
                            let head = inv.digest[(i - 2) * 8..(i - 1) * 8]
                                .try_into()
                                .expect("chunk head digest row");
                            row[io::COL_CHUNK_HEAD_DIGEST..io::COL_CHUNK_HEAD_DIGEST + 2]
                                .copy_from_slice(&pack_le(head));
                        }
                    }
                }
                if final_block && i == io::IO_PERIOD - 1 {
                    bpl.require_range16(block.words[2 * i] as u16);
                    row[io::COL_OUT_MULT] = Felt::from_u32(inv.out_mult);
                    row[io::COL_H_INPUT..io::COL_H_INPUT + 4]
                        .copy_from_slice(&inv.raw_eidos.digest.0);
                    row[io::COL_H_DIGEST..io::COL_H_DIGEST + 4]
                        .copy_from_slice(&inv.digest_eidos.digest.0);
                    for (col, value) in io::H_SHA256_COLS.into_iter().zip(inv.node_eidos.digest.0) {
                        row[col] = value;
                    }
                }
                write_row(row_index, &row);
                row_index += 1;
            }
        }
    }
}

fn pack_le(bytes: [u8; 8]) -> [Felt; 2] {
    core::array::from_fn(|i| {
        Felt::from_u32(u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().expect("four bytes")))
    })
}
