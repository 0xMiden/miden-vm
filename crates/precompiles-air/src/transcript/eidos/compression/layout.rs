//! PVM interface aliases for the shared 32-row Eidos compression layout.

pub use miden_air::eidos_compression::core::layout::*;

/// Number of auxiliary columns used by the shared narrow lookup core.
pub const AUX_COLS: usize = 18;
const _: () = assert!(AUX_COLS == NARROW_AUX_COLS);

/// Packed digest cells used by the PVM compression interface.
pub const F_DIGEST_BASE_COL: usize = F_OUTPUT_BASE_COL;

pub const fn footer_digest_col(idx: usize) -> usize {
    footer_output_col(idx)
}

const _: () = assert!(F_DIGEST_BASE_COL + 4 <= NUM_COLS);
