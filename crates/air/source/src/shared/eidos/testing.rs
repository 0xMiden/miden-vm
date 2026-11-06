//! Test support for independently supplied shared compression witnesses.

use super::trace::{ByteLookupRecorder, EidosCompressionFeltRow, write_core_footer_rows};

/// Writes the shared footer cells from an independently supplied final working state.
///
/// `write_footer_interface` receives each footer row and the four packed compression outputs. It
/// must populate the interface-specific footer cells before the encoder derives the remaining
/// witness coordinates.
#[doc(hidden)]
pub fn write_core_felt_footer_rows<R, W>(
    rows: &mut [EidosCompressionFeltRow],
    block: [u32; 16],
    h: [u32; 8],
    final_v: [u32; 16],
    compression_cycle_id: u64,
    recorder: &mut R,
    write_footer_interface: &mut W,
) where
    R: ByteLookupRecorder,
    W: FnMut(&mut EidosCompressionFeltRow, &[u64; 4]),
{
    write_core_footer_rows(
        rows,
        block,
        h,
        final_v,
        compression_cycle_id,
        recorder,
        write_footer_interface,
    );
}
