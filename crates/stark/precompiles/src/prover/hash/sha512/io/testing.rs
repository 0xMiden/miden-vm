//! Standalone component traces for SHA-512 regression tests.

use alloc::vec;

use miden_air_definitions::precompiles::hash::sha512::io;
use miden_core::{Felt, utils::RowMajorMatrix};

use super::trace::{Sha512IoRequires, populate_rows};
use crate::prover::primitives::byte_pair_lut::BytePairLutRequires;

pub fn generate_trace(
    requires: Sha512IoRequires,
    bpl: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    generate_trace_padded_to(requires, bpl, 0)
}

pub fn generate_trace_padded_to(
    requires: Sha512IoRequires,
    bpl: &mut BytePairLutRequires,
    min_height: usize,
) -> RowMajorMatrix<Felt> {
    let height = requires
        .num_blocks()
        .checked_mul(io::IO_PERIOD)
        .expect("SHA-512 IO height overflow")
        .max(io::IO_PERIOD)
        .max(min_height)
        .checked_next_power_of_two()
        .expect("SHA-512 IO height overflow");
    let mut values = vec![Felt::ZERO; height * io::NUM_MAIN_COLS];
    for (i, row) in values.as_chunks_mut::<{ io::NUM_MAIN_COLS }>().0.iter_mut().enumerate() {
        row[io::COL_BLOCK_ID] =
            Felt::from_u32(u32::try_from(i / io::IO_PERIOD).expect("SHA-512 block id overflow"));
    }
    populate_rows(requires, bpl, |index, row| {
        values[index * io::NUM_MAIN_COLS..(index + 1) * io::NUM_MAIN_COLS].copy_from_slice(row);
    });
    RowMajorMatrix::new(values, io::NUM_MAIN_COLS)
}
