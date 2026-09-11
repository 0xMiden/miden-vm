//! PVM-owned 32-row Eidos compression core.
//!
//! The PVM embeds this core in a wider transcript trace and uses a digest footer instead of the
//! Miden VM's controller and AEAD interface. It shares the compression primitive and byte-pair
//! table semantics with the VM. A differential test evaluates the common constraints against the
//! same witness rows in both AIRs.

mod algebra;
pub(crate) mod constraints;
#[cfg(test)]
mod constraints_tests;
#[doc(hidden)]
pub mod layout;
#[cfg(test)]
mod layout_tests;
mod lookup;
mod model;
mod periodic;
mod schedule;
pub(crate) mod selectors;
#[doc(hidden)]
pub mod trace;

pub(super) use algebra::universal_cv_word;
pub(super) use lookup::{
    EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE, EidosCompressionCols, emit_lookup_columns,
};
pub(crate) use periodic::{NUM_PERIODIC_COLUMNS, get_periodic_column_values};
