//! Miden VM trace interface around the shared Eidos compression core.

use alloc::vec;

use miden_core::{Felt, field::PrimeField64};

use super::{layout::*, model::initial_working_state};
#[cfg(test)]
pub(crate) use crate::shared::eidos::trace::CV_STORAGE_COEFFICIENT_INVERSES;
pub(crate) use crate::shared::eidos::trace::TraceRow;
#[cfg(test)]
use crate::shared::eidos::trace::write_core_footer_rows;
pub use crate::shared::eidos::trace::{
    ByteLookupRecorder, EidosCompressionByteLookup, EidosCompressionFeltRow,
    retag_felt_trace_block_cycle_id,
};
use crate::shared::eidos::trace::{
    validate_compression_cycle_id, validate_packed_inputs,
    write_core_felt_trace_block_into_zeroed_with_lookups, write_core_trace_rows_from_state,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// External relation represented by a physical Eidos compression cycle.
pub enum TraceMode {
    /// A single native-hash compression request.
    Compression,
    /// Aggregated native-hash requests with the same input and output.
    ///
    /// The controller emits every real request with unit multiplicity. This variant records their
    /// aggregate count on the provider side of the compression-link bus.
    CompressionWithMultiplicity { multiplicity: u64 },
    /// One AEAD/XOF request at the specified VM clock cycle.
    AeadXof { clk: u64 },
}

impl TraceMode {
    fn compression_multiplicity(self) -> u64 {
        match self {
            Self::Compression => 1,
            Self::CompressionWithMultiplicity { multiplicity } => multiplicity,
            Self::AeadXof { .. } => 0,
        }
    }
}

/// Materialized 32-row Eidos compression trace block and its final 16-word working state.
pub struct EidosCompressionFeltTraceBlock {
    /// Main-trace rows for one physical compression.
    pub rows: [EidosCompressionFeltRow; BLOCK_PERIOD],
    /// Eidos compression working state after all seven rounds, before output feed-forward.
    pub final_v: [u32; 16],
}

struct NoopByteLookupRecorder;

impl ByteLookupRecorder for NoopByteLookupRecorder {
    fn record(&mut self, _lookup: EidosCompressionByteLookup, _lhs: u8, _rhs: u8, _result: u32) {}
}

/// Generates one field-valued Eidos compression trace block with physical cycle ID zero.
///
/// # Panics
///
/// Panics if the mode metadata or a packed input is not a canonical field element.
pub fn generate_felt_trace_block(
    block: [u32; 16],
    h: [u32; 8],
    mode: TraceMode,
) -> EidosCompressionFeltTraceBlock {
    generate_felt_trace_block_with_cycle_id(block, h, 0, mode)
}

/// Generates one field-valued Eidos compression trace block with the specified physical cycle ID.
///
/// # Panics
///
/// Panics if the compression cycle ID, mode metadata, or a packed input is not a canonical field
/// element.
pub fn generate_felt_trace_block_with_cycle_id(
    block: [u32; 16],
    h: [u32; 8],
    compression_cycle_id: u64,
    mode: TraceMode,
) -> EidosCompressionFeltTraceBlock {
    let mut rows = vec![[Felt::ZERO; NUM_COLS]; BLOCK_PERIOD];
    let mut recorder = NoopByteLookupRecorder;
    let final_v = write_trace_rows(&mut rows, block, h, compression_cycle_id, mode, &mut recorder);
    let rows = rows
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed Eidos compression trace length"));

    EidosCompressionFeltTraceBlock { rows, final_v }
}

/// Writes one Eidos compression cycle after clearing its 32-row destination.
///
/// `compression_cycle_id` must be the zero-based physical cycle index in the complete Eidos
/// compression trace. The AIR pins the first ID to zero, keeps it constant within a cycle, and
/// increments it between cycles.
///
/// # Panics
///
/// Panics if `rows` contains fewer than 32 rows, the compression cycle ID or mode metadata is not a
/// canonical field element, or a packed input is not canonical.
pub fn write_felt_trace_block(
    rows: &mut [EidosCompressionFeltRow],
    block: [u32; 16],
    h: [u32; 8],
    compression_cycle_id: u64,
    mode: TraceMode,
) -> [u32; 16] {
    assert!(
        rows.len() >= BLOCK_PERIOD,
        "32-row EidosCompression writer needs at least one full block",
    );

    for row in rows.iter_mut().take(BLOCK_PERIOD) {
        row.fill(Felt::ZERO);
    }
    let mut recorder = NoopByteLookupRecorder;
    write_felt_trace_block_into_zeroed_with_lookups(
        rows,
        block,
        h,
        compression_cycle_id,
        mode,
        &mut recorder,
    )
}

/// Writes one Eidos compression cycle into zeroed rows and records its byte-table lookups.
///
/// Unlike [`write_felt_trace_block`], this function does not clear the destination. Every cell in
/// the first 32 rows must already be zero so that inactive interface columns remain canonical.
///
/// # Panics
///
/// Panics if `rows` contains fewer than 32 rows, the compression cycle ID or mode metadata is not a
/// canonical field element, or a packed input is not canonical.
/// In debug builds, it also panics if the first 32 rows contain a nonzero cell.
pub fn write_felt_trace_block_into_zeroed_with_lookups<R>(
    rows: &mut [EidosCompressionFeltRow],
    block: [u32; 16],
    h: [u32; 8],
    compression_cycle_id: u64,
    mode: TraceMode,
    recorder: &mut R,
) -> [u32; 16]
where
    R: ByteLookupRecorder,
{
    validate_trace_mode(mode);
    let mut write_footer_interface = |row: &mut EidosCompressionFeltRow, output: &[u64; 4]| {
        write_mvm_footer_interface(row, output, mode);
    };
    write_core_felt_trace_block_into_zeroed_with_lookups(
        rows,
        block,
        h,
        compression_cycle_id,
        recorder,
        &mut write_footer_interface,
    )
}

pub(super) fn write_trace_rows<T, R>(
    rows: &mut [T],
    block: [u32; 16],
    h: [u32; 8],
    compression_cycle_id: u64,
    mode: TraceMode,
    recorder: &mut R,
) -> [u32; 16]
where
    T: TraceRow,
    R: ByteLookupRecorder,
{
    debug_assert!(rows.len() >= BLOCK_PERIOD);
    validate_trace_metadata(compression_cycle_id, mode);
    validate_packed_inputs(&block, &h);
    let mut write_footer_interface = |row: &mut T, output: &[u64; 4]| {
        write_mvm_footer_interface(row, output, mode);
    };
    write_core_trace_rows_from_state(
        rows,
        block,
        h,
        initial_working_state(h),
        compression_cycle_id,
        recorder,
        &mut write_footer_interface,
    )
}

#[cfg(test)]
pub(super) fn write_trace_rows_from_state<T, R>(
    rows: &mut [T],
    block: [u32; 16],
    h: [u32; 8],
    v: [u32; 16],
    compression_cycle_id: u64,
    mode: TraceMode,
    recorder: &mut R,
) -> [u32; 16]
where
    T: TraceRow,
    R: ByteLookupRecorder,
{
    let mut write_footer_interface = |row: &mut T, output: &[u64; 4]| {
        write_mvm_footer_interface(row, output, mode);
    };
    write_core_trace_rows_from_state(
        rows,
        block,
        h,
        v,
        compression_cycle_id,
        recorder,
        &mut write_footer_interface,
    )
}

fn validate_trace_metadata(compression_cycle_id: u64, mode: TraceMode) {
    validate_compression_cycle_id(compression_cycle_id);

    validate_trace_mode(mode);
}

fn validate_trace_mode(mode: TraceMode) {
    let metadata = match mode {
        TraceMode::Compression => None,
        TraceMode::CompressionWithMultiplicity { multiplicity } => Some(multiplicity),
        TraceMode::AeadXof { clk } => Some(clk),
    };
    assert!(
        metadata.is_none_or(|value| value < Felt::ORDER_U64),
        "Eidos compression trace metadata must be a canonical field element",
    );
}

#[cfg(test)]
pub(super) fn write_footer_rows<T, R>(
    rows: &mut [T],
    block: [u32; 16],
    h: [u32; 8],
    v: [u32; 16],
    compression_cycle_id: u64,
    mode: TraceMode,
    recorder: &mut R,
) where
    T: TraceRow,
    R: ByteLookupRecorder,
{
    let mut write_footer_interface = |row: &mut T, output: &[u64; 4]| {
        write_mvm_footer_interface(row, output, mode);
    };
    write_core_footer_rows(
        rows,
        block,
        h,
        v,
        compression_cycle_id,
        recorder,
        &mut write_footer_interface,
    );
}

fn write_mvm_footer_interface<T: TraceRow>(row: &mut T, output: &[u64; 4], mode: TraceMode) {
    row.set_u64(F_COMPRESSION_MULTIPLICITY_COL, mode.compression_multiplicity());
    match mode {
        TraceMode::AeadXof { clk } => {
            row.set_u64(F_MODE_COL, 1);
            row.set_u64(F_INTERFACE_TAIL0_COL, clk);
        },
        TraceMode::Compression | TraceMode::CompressionWithMultiplicity { .. } => {
            for (idx, &value) in output.iter().enumerate() {
                row.set_u64(footer_interface_tail_col(idx), value);
            }
        },
    }
}
