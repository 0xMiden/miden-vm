//! Trace generation sharing compression NOP rows with invocation-binding witnesses.

use alloc::vec;

use miden_core::{Felt, utils::RowMajorMatrix};
use miden_precompiles_air::hash::sha512::{IO_COLUMNS, IO_ROW_START};

use super::{
    NUM_MAIN_COLS,
    compression::{self, Sha512CompressionRequires},
    io::{self, Sha512IoRequires},
};
use crate::primitives::byte_pair_lut::BytePairLutRequires;

pub fn generate_trace(
    compression: Sha512CompressionRequires,
    io: Sha512IoRequires,
    bpl: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    assert_eq!(compression.num_blocks(), io.num_blocks(), "SHA-512 block count mismatch");
    let height = compression.trace_height();
    let mut values = vec![Felt::ZERO; height * NUM_MAIN_COLS];
    compression::populate_trace(&compression, bpl, &mut values, NUM_MAIN_COLS);
    io::populate_rows(io, bpl, |index, io_row| {
        let block = index / io::IO_PERIOD;
        let lane = index % io::IO_PERIOD;
        let row_index = block * compression::COMPRESSION_PERIOD + IO_ROW_START + lane;
        let row = &mut values[row_index * NUM_MAIN_COLS..(row_index + 1) * NUM_MAIN_COLS];
        assert_eq!(row[compression::COL_BLOCK_ID], io_row[io::COL_BLOCK_ID]);
        for (column, value) in IO_COLUMNS.into_iter().zip(io_row) {
            row[column] = *value;
        }
    });
    RowMajorMatrix::new(values, NUM_MAIN_COLS)
}
