//! Contains utility type aliases and functions for use as part of the SMT forest.

use crate::{Word, merkle::smt::full::SMT_DEPTH};

// TYPE ALIASES
// ================================================================================================

/// The mutation set used by the forest backends to provide reverse mutations that describe the
/// changes necessary to revert the tree to its previous state.
pub type MutationSet = crate::merkle::smt::MutationSet<SMT_DEPTH, Word, Word>;
