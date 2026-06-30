//! Semantic row-kind flags for the single-row hasher controller.
//!
//! [`ControllerFlags`] is a pure naming layer over compositions of the hasher-internal
//! sub-selectors `(s0, s1, s2)`. It carries no chiplet-level scope; callers combine these flags
//! with [`ChipletFlags`](super::super::selectors::ChipletFlags).
//!
//! ## Selector encoding
//!
//! | s0 | s1 | s2 | Row type |
//! |----|----|----|----------|
//! |  1 |  0 |  0 | Hash start: full BlakeG input state |
//! |  0 |  0 |  0 | Hash continuation: full BlakeG input state |
//! |  1 |  0 |  1 | MP row |
//! |  1 |  1 |  0 | MV row |
//! |  1 |  1 |  1 | MU row |
//! |  0 |  1 |  0 | Padding |
//!
//! The two remaining patterns are invalid.

use miden_core::field::PrimeCharacteristicRing;

use crate::constraints::{chiplets::columns::ControllerCols, utils::BoolNot};

// CONTROLLER FLAGS
// ================================================================================================

/// Named compositions of the controller sub-selectors `(s0, s1, s2)` on the current row.
#[derive(Clone)]
pub struct ControllerFlags<E> {
    pub is_hash: E,
    pub is_merkle: E,
    pub is_padding: E,
    pub is_invalid: E,
}

impl<E: PrimeCharacteristicRing + Clone> ControllerFlags<E> {
    /// Build all row-kind flags from the current row's sub-selector columns.
    pub fn new<V: Copy + Into<E>>(cols: &ControllerCols<V>) -> Self {
        let s0: E = cols.s0.into();
        let s1: E = cols.s1.into();
        let s2: E = cols.s2.into();
        let not_s0 = s0.not();
        let not_s1 = s1.not();
        let not_s2 = s2.not();

        let is_hash = not_s1.clone() * not_s2.clone();
        let is_mp = s0.clone() * not_s1 * s2.clone();
        let is_mv = s0.clone() * s1.clone() * not_s2.clone();
        let is_mu = s0 * s1.clone() * s2.clone();
        let is_padding = not_s0.clone() * s1 * not_s2;
        let is_invalid = not_s0 * s2;
        let is_merkle = is_mp + is_mv + is_mu;

        Self {
            is_hash,
            is_merkle,
            is_padding,
            is_invalid,
        }
    }
}
