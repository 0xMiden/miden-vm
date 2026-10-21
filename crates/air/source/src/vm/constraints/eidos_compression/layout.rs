//! Miden VM interface columns in the shared Eidos compression layout.

pub use crate::shared::eidos::layout::*;

/// Number of auxiliary columns used by the complete MVM compression AIR.
pub const AUX_COLS: usize = 20;
const _: () = assert!(AUX_COLS == NARROW_AUX_COLS + 2);

pub const F_INTERFACE_TAIL_BASE_COL: usize = F_OUTPUT_BASE_COL;
pub const F_INTERFACE_TAIL0_COL: usize = F_INTERFACE_TAIL_BASE_COL;
pub const F_CLK_COL: usize = F_INTERFACE_TAIL0_COL;

/// Number of controller requests represented by this compression cycle.
///
/// This is intentionally a field-valued count rather than a boolean: identical controller requests
/// may be aggregated into one physical compression. Soundness relies on every controller request
/// being emitted with unit multiplicity and locally tied to a real event; the compression provider
/// then contributes the negated aggregate count.
pub const F_COMPRESSION_MULTIPLICITY_COL: usize = 64;

/// VM mode flag overlaid on the globally ternary-constrained k3 columns.
pub const F_MODE_COL: usize = G_K3_BASE_COL;

pub const fn footer_interface_tail_col(idx: usize) -> usize {
    footer_output_col(idx)
}

const _: () = assert!(F_CLK_COL < NUM_COLS);
