//! PVM adapter for the shared 32-row Eidos compression core.
//!
//! The PVM embeds the shared core in a wider transcript trace and uses a digest footer instead of
//! the Miden VM's controller and AEAD interface. This module defines the PVM-specific lookup
//! namespace, trace writer, and packed-digest binding.

pub(crate) mod constraints;
#[cfg(test)]
mod constraints_tests;
#[doc(hidden)]
pub mod layout;
#[cfg(test)]
mod layout_tests;
mod lookup;
#[cfg(any(test, feature = "testing"))]
#[doc(hidden)]
pub mod testing;
#[doc(hidden)]
pub mod trace;

pub(super) use lookup::{EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE, emit_lookup_columns};
pub(super) use miden_air::eidos_compression::core::EidosCompressionCols;
