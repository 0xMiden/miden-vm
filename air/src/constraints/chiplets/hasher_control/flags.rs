//! Semantic row-kind flags for the controller sub-chiplet.
//!
//! [`ControllerFlags`] is a pure naming layer over compositions of the hasher-internal
//! sub-selectors `(s0, s1, s2)` on the current and next rows. Each field gives a
//! meaningful name to a bit-pattern product so constraint code never references
//! raw `cols.s0 / cols.s1 / cols.s2` as ad-hoc gate factors.
//!
//! This struct contains **no** chiplet-level scope (`is_active`, `is_transition`):
//! those live on [`ChipletFlags`] and are combined with these row flags by
//! multiplication at each call site.
//!
//! ## Selector encoding (current row, within controller rows)
//!
//! | s0 | s1 | s2 | Row type | Flag |
//! |----|----|----|----------|------|
//! |  1 |  0 |  0 | Sponge input (LINEAR_HASH / 2-to-1 / HPERM) | `is_sponge_input` |
//! |  1 |  0 |  1 | MP input (Merkle path verify) | `is_merkle_input` |
//! |  1 |  1 |  0 | MV input (old-path Merkle root update) | `is_merkle_input` / `is_mv_input` |
//! |  1 |  1 |  1 | MU input (new-path Merkle root update) | `is_merkle_input` |
//! |  0 |  0 |  0 | HOUT output (return digest) | `is_hout` / `is_output` |
//! |  0 |  0 |  1 | SOUT output (return full state) | `is_sout` / `is_output` |
//! |  0 |  1 |  * | Padding (inactive slot) | `is_padding` |
//!
//! On permutation rows (`s_perm = 1`), `s0/s1/s2` hold S-box witnesses, so these
//! flags are don't-care there — constraint code gates them by `ChipletFlags.is_active`
//! (= `s_ctrl`) at the call site.
//!
//! ## Operation semantics
//!
//! - **Sponge** (`is_sponge_input`): LINEAR_HASH (multi-batch span), single 2-to-1 hash, or HPERM.
//!   In sponge mode, capacity is set once on the first input and carried through across
//!   continuations; in tree mode (Merkle ops), capacity is zeroed at every level.
//! - **MP**: MPVERIFY — read-only Merkle path check. Does not interact with the sibling table.
//! - **MV**: old-path leg of MRUPDATE. Each MV row inserts a sibling into the virtual sibling
//!   table via the hash_kernel bus.
//! - **MU**: new-path leg of MRUPDATE. Each MU row removes a sibling from the virtual sibling
//!   table. The table balance ensures the same siblings are used for both the old and new paths.

use miden_core::field::PrimeCharacteristicRing;

use crate::constraints::{chiplets::columns::ControllerCols, utils::BoolNot};

// CONTROLLER FLAGS
// ================================================================================================

/// Named compositions of the controller sub-selectors `(s0, s1, s2)` on the current
/// and next rows.
///
/// Pure row-kind layer — contains no chiplet-level scope. Combine with [`ChipletFlags`](
/// super::super::selectors::ChipletFlags) at the call site by multiplication.
pub struct ControllerFlags<E> {
    // ========================================================================
    // Current row — compositions of cols.{s0, s1, s2}
    // ========================================================================
    /// Input row: `s0` (deg 1). Covers all input operations (sponge + Merkle variants).
    pub is_input: E,

    /// Output row: `(1-s0)*(1-s1)` (deg 2). Covers HOUT and SOUT.
    pub is_output: E,

    /// Padding row: `(1-s0)*s1` (deg 2). Inactive controller slot.
    pub is_padding: E,

    /// Sponge input row (LINEAR_HASH / 2-to-1 / HPERM): `s0*(1-s1)*(1-s2)` (deg 3).
    pub is_sponge_input: E,

    /// Any Merkle input row (MP/MV/MU): `s0*(s1+s2-s1*s2)` (deg 3).
    ///
    /// The expression `s1 + s2 - s1*s2` equals `s1 OR s2` for binary inputs.
    pub is_merkle_input: E,

    /// HOUT (return digest) output: `(1-s0)*(1-s1)*(1-s2)` (deg 3).
    pub is_hout: E,

    /// SOUT (return full state) output: `(1-s0)*(1-s1)*s2` (deg 3).
    pub is_sout: E,

    // ========================================================================
    // Next row — compositions of cols_next.{s0, s1, s2}
    // ========================================================================
    /// Next row is an output row: `(1-s0')*(1-s1')` (deg 2).
    pub is_output_next: E,

    /// Next row is a padding row: `(1-s0')*s1'` (deg 2).
    pub is_padding_next: E,

    /// Next row is a sponge input — LINEAR_HASH continuation: `s0'*(1-s1')*(1-s2')` (deg 3).
    pub is_sponge_input_next: E,

    /// Next row is any Merkle input (MP/MV/MU): `s0'*(s1'+s2'-s1'*s2')` (deg 3).
    pub is_merkle_input_next: E,

    /// Next row is an MV input — old-path MRUPDATE start: `s0'*s1'*(1-s2')` (deg 3).
    pub is_mv_input_next: E,

    // ========================================================================
    // Degree-optimized special
    // ========================================================================
    /// `s1' + s2'` — degree-1 Merkle-next indicator.
    ///
    /// Non-boolean (MU gives 2) but zero exactly on non-Merkle controller inputs
    /// (sponge has `s1=s2=0`). Used in digest routing where the full
    /// `is_merkle_input_next` (deg 3) would push the constraint over the degree cap.
    ///
    /// Soundness: a malicious prover could mislabel a Merkle input as sponge
    /// (`s1=s2=0`) to zero this selector and bypass routing. This is caught by the
    /// bus: any `(1,0,0)` input row fires `f_sponge` and generates a sponge bus
    /// message with no matching decoder request.
    pub merkle_next_lite: E,
}

impl<E: PrimeCharacteristicRing + Clone> ControllerFlags<E> {
    /// Build all row-kind flags from the current and next row's sub-selector columns.
    pub fn new<V: Copy + Into<E>>(cols: &ControllerCols<V>, cols_next: &ControllerCols<V>) -> Self {
        // --- Current row ---
        let s0: E = cols.s0.into();
        let s1: E = cols.s1.into();
        let s2: E = cols.s2.into();
        let not_s0 = s0.clone().not();
        let not_s1 = s1.clone().not();
        let not_s2 = s2.clone().not();

        let is_input = s0.clone();
        let is_output = not_s0.clone() * not_s1.clone();
        let is_padding = not_s0 * s1.clone();
        let is_sponge_input = s0.clone() * not_s1.clone() * not_s2.clone();
        let is_merkle_input = s0 * (s1.clone() + s2.clone() - s1 * s2.clone());
        let is_hout = is_output.clone() * not_s2;
        let is_sout = is_output.clone() * s2;

        // --- Next row ---
        let s0n: E = cols_next.s0.into();
        let s1n: E = cols_next.s1.into();
        let s2n: E = cols_next.s2.into();
        let not_s0n = s0n.clone().not();
        let not_s1n = s1n.clone().not();
        let not_s2n = s2n.clone().not();

        let is_output_next = not_s0n.clone() * not_s1n.clone();
        let is_padding_next = not_s0n * s1n.clone();
        let is_sponge_input_next = s0n.clone() * not_s1n * not_s2n.clone();
        let is_merkle_input_next =
            s0n.clone() * (s1n.clone() + s2n.clone() - s1n.clone() * s2n.clone());
        let is_mv_input_next = s0n * s1n.clone() * not_s2n;
        let merkle_next_lite = s1n + s2n;

        Self {
            is_input,
            is_output,
            is_padding,
            is_sponge_input,
            is_merkle_input,
            is_hout,
            is_sout,
            is_output_next,
            is_padding_next,
            is_sponge_input_next,
            is_merkle_input_next,
            is_mv_input_next,
            merkle_next_lite,
        }
    }
}
