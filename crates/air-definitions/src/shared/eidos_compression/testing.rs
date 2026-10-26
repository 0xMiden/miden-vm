use miden_core::Felt;
use miden_lifted_air::LiftedAirBuilder;

pub use super::{
    constraints::enforce_fused_rows, periodic::get_periodic_column_values,
    selectors::EidosCompressionSelectors,
};
use super::{
    constraints::{enforce_core_footer_rows, enforce_mvm_footer_output},
    trace::{ByteLookupRecorder, EidosCompressionFeltRow, write_core_footer_rows},
};

pub const MVM_MODE_COL: usize = super::layout::F_MODE_COL;

/// Enforces the footer constraints shared with the PVM compression AIR.
///
/// The MVM mode column must be zero so that the shared output slots carry the ordinary digest.
pub fn enforce_common_footer_rows<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    selectors: &EidosCompressionSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    enforce_core_footer_rows(builder, local, next, selectors, |builder, footer, packed_output| {
        enforce_mvm_footer_output(builder, local, selectors, footer, packed_output);
    });
}

/// Writes the shared footer cells from an independently supplied final working state.
///
/// `write_footer_interface` receives each footer row and the four packed compression outputs.
/// It must populate the interface-specific footer cells before the encoder derives the
/// remaining witness coordinates.
pub(crate) fn write_core_felt_footer_rows<R, W>(
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
