//! Shared 32-row Eidos compression arithmetization.
//!
//! Each cycle contains 28 fused G rows and four footer rows. This module owns the compression
//! equations, physical layout, narrow lookup encoding, and witness coordinates. Relation adapters
//! supply their bus namespaces and bind the footer interface to VM controller/AEAD requests or
//! PVM transcript digests.

pub(crate) mod algebra;
pub(crate) mod constraints;
#[doc(hidden)]
pub mod layout;
pub(crate) mod lookup;
pub(crate) mod model;
pub(crate) mod narrow;
pub(crate) mod periodic;
#[doc(hidden)]
pub mod rotation_lookup;
pub(crate) mod schedule;
pub(crate) mod selectors;
#[doc(hidden)]
pub mod trace;

pub use algebra::{
    cv_storage_coefficient, cv_storage_offset, cv_word_base, sum_input_b, universal_cv_word,
};
pub use constraints::{enforce_core_footer_rows, enforce_fused_rows};
pub use lookup::{
    EidosCompressionCols, LookupMultiplicitySign, NarrowLookupConfig, XorExpression,
    emit_narrow_lookup_columns,
};
pub use model::{initial_working_state, low_output};
pub use periodic::get_periodic_column_values;
pub use schedule::{FusedStep, fused_step_at};
pub use selectors::EidosCompressionSelectors;
