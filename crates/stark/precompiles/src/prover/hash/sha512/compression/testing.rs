//! Standalone component traces for SHA-512 regression tests.

use alloc::vec;

use miden_air_definitions::precompiles::hash::sha512::compression;
use miden_core::{Felt, utils::RowMajorMatrix};

use super::trace::{Sha512CompressionRequires, populate_trace};
use crate::prover::primitives::byte_pair_lut::BytePairLutRequires;

pub fn generate_trace(
    requires: Sha512CompressionRequires,
    bpl: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    generate_trace_padded_to(requires, bpl, 0)
}

pub fn generate_trace_padded_to(
    requires: Sha512CompressionRequires,
    bpl: &mut BytePairLutRequires,
    min_height: usize,
) -> RowMajorMatrix<Felt> {
    let height = requires
        .trace_height()
        .expect("SHA-512 trace height overflow")
        .max(min_height)
        .checked_next_power_of_two()
        .expect("SHA-512 trace height overflow");
    let mut values = vec![Felt::ZERO; height * compression::NUM_MAIN_COLS];
    populate_trace(&requires, bpl, &mut values, compression::NUM_MAIN_COLS);
    RowMajorMatrix::new(values, compression::NUM_MAIN_COLS)
}
