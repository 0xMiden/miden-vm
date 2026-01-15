use miden_air::trace::{
    AUX_TRACE_RAND_ELEMENTS, CHIPLETS_BUS_AUX_TRACE_OFFSET, chiplets::hasher::HASH_CYCLE_LEN,
};
use miden_core::{ONE, Operation, Word, ZERO};
use miden_utils_testing::rand::rand_value;

use super::{
    super::utils::build_span_with_respan_ops, AdviceInputs, ExecutionTrace, Felt,
    build_trace_from_ops, build_trace_from_ops_with_inputs, build_trace_from_program,
    init_state_from_words, rand_array,
};

mod bitwise;
mod hasher;
mod memory;
