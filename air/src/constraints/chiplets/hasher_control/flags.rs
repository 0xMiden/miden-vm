//! Pre-computed controller chiplet flags.
//!
//! The [`ControllerFlags`] struct bundles chiplet-level scope flags and sub-operation
//! flags into a single flat struct. It is built once in the entry point and passed to
//! every constraint function, so no function needs to recompute selector products or
//! chain multiple `.when()` calls for common conditions.
//!
//! ## Flag layers
//!
//! 1. **Chiplet-level scope** (`is_active`, `is_transition`, `is_last`): derived from
//!    [`ChipletFlags`], these determine whether the controller owns the current row and whether a
//!    valid next row exists.
//!
//! 2. **Sub-operation flags** (`on_*`): pre-computed products of `is_active * <selector_combo>`.
//!    These are the primary interface for constraint code — use `cf.on_sponge` instead of chaining
//!    `.when(is_active).when(s0).when(not_s1).when(not_s2)`.
//!
//! 3. **Next-row selectors** (`f_*_next`): raw selector expressions on the next row, for building
//!    single-use transition gates. Every use is inside a transition context.
//!
//! ## is_active scope
//!
//! `is_active = s_ctrl = chiplets[0]` covers ALL controller rows (input, output, and
//! padding). The hasher-internal sub-selector `s0` (= `chiplets[1]`) distinguishes
//! input rows (`s0=1`) from output/padding rows (`s0=0`).
//!
//! On permutation rows (`s_perm = 1`), `s0, s1, s2` are S-box witnesses — the `on_*`
//! flags are don't-care there (the `s_ctrl` factor zeros them out).
//!
//! ## Selector encoding (within controller rows)
//!
//! | s0 | s1 | s2 | Row type | Flag |
//! |-----|----|----|----------|------|
//! |  1  |  0 |  0 | Sponge input (LINEAR_HASH / 2-to-1 / HPERM) | `on_sponge` |
//! |  1  |  0 |  1 | MP input (Merkle path verify) | `on_merkle_input` |
//! |  1  |  1 |  0 | MV input (old-path Merkle root update) | `on_merkle_input` |
//! |  1  |  1 |  1 | MU input (new-path Merkle root update) | `on_merkle_input` |
//! |  0  |  0 |  0 | HOUT output (return digest) | `on_hout` |
//! |  0  |  0 |  1 | SOUT output (return full state) | `on_sout` |
//! |  0  |  1 |  * | Padding (inactive slot) | `on_padding` |
//!
//! ## Operation semantics
//!
//! - **Sponge** (`on_sponge`): LINEAR_HASH (multi-batch span), single 2-to-1 hash, or HPERM. In
//!   sponge mode, capacity is set once on the first input and carried through across continuations;
//!   in tree mode (Merkle ops), capacity is zeroed at every level.
//! - **MP** (`on_merkle_input`): MPVERIFY — read-only Merkle path check. Does not interact with the
//!   sibling table.
//! - **MV** (`on_merkle_input`): old-path leg of MRUPDATE. Each MV row inserts a sibling into the
//!   virtual sibling table via the hash_kernel bus.
//! - **MU** (`on_merkle_input`): new-path leg of MRUPDATE. Each MU row removes a sibling from the
//!   virtual sibling table. The table balance ensures the same siblings are used for both the old
//!   and new paths.

use miden_core::field::PrimeCharacteristicRing;

use crate::constraints::{
    chiplets::{columns::ControllerCols, selectors::ChipletFlags},
    utils::BoolNot,
};

// CONTROLLER FLAGS
// ================================================================================================

/// Pre-computed flag expressions for the controller sub-chiplet.
///
/// The base scope flags (`is_active`, `is_transition`, `is_last`) come from
/// [`ChipletFlags`], computed in `build_chiplet_selectors`. This struct adds
/// sub-operation flags from `s0`/`s1`/`s2`.
pub struct ControllerFlags<E> {
    // -------------------------------------------------------------------------
    // ChipletFlags-style scope (from build_chiplet_selectors)
    // -------------------------------------------------------------------------
    /// Controller sub-chiplet is active on the current row.
    ///
    /// `s_ctrl = chiplets[0]` (degree 1). Active on ALL controller rows
    /// (input, output, and padding).
    pub is_active: E,

    /// Controller is active on both current and next row (degree 3).
    pub is_transition: E,

    // -------------------------------------------------------------------------
    // Sub-operation flags (using s0, s1, s2 within controller rows)
    // -------------------------------------------------------------------------
    /// Active on a controller input row: `is_active * s0` (degree 2).
    ///
    /// Covers all input operations (sponge + all Merkle variants).
    pub on_input: E,

    /// Active on a controller output row: `is_active * (1-s0) * (1-s1)` (degree 3).
    ///
    /// Covers both HOUT and SOUT output operations.
    pub on_output: E,

    /// Active on a controller padding row: `is_active * (1-s0) * s1` (degree 3).
    pub on_padding: E,

    /// Active on a sponge-mode input row: `on_input * (1-s1) * (1-s2)` (degree 4).
    ///
    /// LINEAR_HASH, single 2-to-1 hash, and HPERM input rows.
    pub on_sponge: E,

    /// Active on any Merkle input row: `on_input * (s1+s2-s1*s2)` (degree 4).
    ///
    /// Covers MP, MV, and MU. The expression `s1 + s2 - s1*s2` equals `s1 OR s2`
    /// when both are binary (at least one of s1, s2 is 1).
    pub on_merkle_input: E,

    /// Active on a HOUT (return digest) output row: `on_output * (1-s2)` (degree 4).
    pub on_hout: E,

    /// Active on a SOUT (return full state) output row: `on_output * s2` (degree 4).
    pub on_sout: E,

    // -------------------------------------------------------------------------
    // Next-row selectors (for transition constraints)
    // -------------------------------------------------------------------------
    /// Next row is a sponge input: `s0' * (1-s1') * (1-s2')` (degree 3).
    pub f_sponge_next: E,

    /// Next row is an MV input: `s0' * s1' * (1-s2')` (degree 3).
    pub f_mv_next: E,

    /// Next row is a Merkle input: `s0' * (s1'+s2'-s1'*s2')` (degree 3).
    pub f_merkle_input_next: E,

    /// Next row is an output row: `(1-s0') * (1-s1')` (degree 2).
    pub f_output_next: E,
}

impl<E: PrimeCharacteristicRing + Clone> ControllerFlags<E> {
    /// Build controller flags from pre-computed chiplet flags and the current/next
    /// row's columns (for s0/s1/s2 sub-operation flags).
    pub fn new<V: Copy + Into<E>>(
        chiplet_flags: &ChipletFlags<E>,
        cols: &ControllerCols<V>,
        cols_next: &ControllerCols<V>,
    ) -> Self {
        let is_active = chiplet_flags.is_active.clone();

        // Current row sub-selectors.
        let s0: E = cols.s0.into();
        let s1: E = cols.s1.into();
        let s2: E = cols.s2.into();
        let not_s0 = s0.clone().not();
        let not_s1 = s1.clone().not();
        let not_s2 = s2.clone().not();

        // Next row sub-selectors.
        let s0n: E = cols_next.s0.into();
        let s1n: E = cols_next.s1.into();
        let s2n: E = cols_next.s2.into();
        let not_s0n = s0n.clone().not();
        let not_s1n = s1n.clone().not();
        let not_s2n = s2n.clone().not();

        // --- Sub-operation flags ---
        // on_input = is_active * s0  (deg 2)
        let on_input = is_active.clone() * s0;
        // on_output = is_active * (1-s0) * (1-s1)  (deg 3)
        let on_output = is_active.clone() * not_s0.clone() * not_s1.clone();
        // on_padding = is_active * (1-s0) * s1  (deg 3)
        let on_padding = is_active.clone() * not_s0 * s1.clone();
        // on_sponge = on_input * (1-s1) * (1-s2)  (deg 4)
        let on_sponge = on_input.clone() * not_s1 * not_s2;
        // on_merkle_input = on_input * (s1 + s2 - s1*s2)  (deg 4)
        let on_merkle_input = on_input.clone() * (s1.clone() + s2.clone() - s1 * s2);
        // on_hout = on_output * (1-s2)  (deg 4)
        let on_hout = on_output.clone() * Into::<E>::into(cols.s2).not();
        // on_sout = on_output * s2  (deg 4)
        let on_sout = on_output.clone() * Into::<E>::into(cols.s2);

        // --- Next-row sub-selectors ---
        // f_sponge_next = s0' * (1-s1') * (1-s2')  (deg 3)
        let f_sponge_next = s0n.clone() * not_s1n.clone() * not_s2n;
        // f_mv_next = s0' * s1' * (1-s2')  (deg 3)
        let f_mv_next = s0n.clone() * s1n.clone() * s2n.clone().not();
        // f_merkle_input_next = s0' * (s1' + s2' - s1'*s2')  (deg 3)
        let f_merkle_input_next = s0n * (s1n.clone() + s2n.clone() - s1n * s2n);
        // f_output_next = (1-s0') * (1-s1')  (deg 2)
        let f_output_next = not_s0n * not_s1n;

        Self {
            is_active,
            is_transition: chiplet_flags.is_transition.clone(),
            on_input,
            on_output,
            on_padding,
            on_sponge,
            on_merkle_input,
            on_hout,
            on_sout,
            f_sponge_next,
            f_mv_next,
            f_merkle_input_next,
            f_output_next,
        }
    }
}
