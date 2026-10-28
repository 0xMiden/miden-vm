//! Test support for constructing and mutating PVM Eidos compression witnesses.

use alloc::vec;

use miden_core::Felt;

use super::{
    layout::{BLOCK_PERIOD, NUM_COLS},
    trace::{
        EidosCompressionFeltRow, NoopByteLookupRecorder, write_felt_trace_block,
        write_pvm_footer_output,
    },
};
use crate::shared::eidos::{layout::FOOTER_START, testing::write_core_felt_footer_rows};

/// Materialized 32-row compression trace block and its final working state.
pub struct EidosCompressionFeltTraceBlock {
    /// Main-trace rows for one physical compression.
    pub rows: [EidosCompressionFeltRow; BLOCK_PERIOD],
    /// Working state after all seven rounds, before output feed-forward.
    pub final_v: [u32; 16],
}

/// Generates one field-valued compression trace block with the supplied physical cycle ID.
///
/// # Panics
///
/// Panics if `compression_cycle_id >= Felt::ORDER_U64`.
pub fn generate_felt_trace_block_with_cycle_id(
    block: [u32; 16],
    h: [u32; 8],
    compression_cycle_id: u64,
) -> EidosCompressionFeltTraceBlock {
    let mut rows = vec![[Felt::ZERO; NUM_COLS]; BLOCK_PERIOD];
    let final_v = write_felt_trace_block(&mut rows, block, h, compression_cycle_id);
    let rows = rows
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed Eidos compression trace length"));

    EidosCompressionFeltTraceBlock { rows, final_v }
}

/// Rewrites a block's footer from independently supplied compression inputs and working state.
///
/// This intentionally permits inconsistent inputs so malformed-witness tests can isolate footer
/// constraints without modifying the compression rounds.
pub fn rewrite_felt_footer_for_test(
    rows: &mut [EidosCompressionFeltRow; BLOCK_PERIOD],
    block: [u32; 16],
    h: [u32; 8],
    final_v: [u32; 16],
    compression_cycle_id: u64,
) {
    for row in rows.iter_mut().skip(FOOTER_START) {
        row.fill(Felt::ZERO);
    }
    let mut write_footer_interface = write_pvm_footer_output;
    write_core_felt_footer_rows(
        rows,
        block,
        h,
        final_v,
        compression_cycle_id,
        &mut NoopByteLookupRecorder,
        &mut write_footer_interface,
    );
}
