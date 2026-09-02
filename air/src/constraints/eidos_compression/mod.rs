//! Standalone 32-row Eidos compression arithmetization.
//!
//! Each cycle contains 28 fused G rows followed by four footer rows. The fused rows execute the
//! seven Eidos compression rounds; the footer rows assemble the message, input chaining value,
//! compression output, and XOF output used by the external buses.
//!
//! # Physical-cycle binding
//!
//! Every cycle carries a canonical `compression_cycle_id`: the first cycle is zero, the value is
//! constant over all 32 rows, and it increments between cycles. Every internal message-word and
//! chaining-value binding includes that identity. The chaining-value relation carries all eight
//! raw words atomically; message-word slots carry the ID directly. This prevents inputs from one
//! physical compression from satisfying the internal lookups of another.
//!
//! The Miden VM instantiates this module as its native compression AIR. The processor constructs
//! the same 32-row blocks through the public trace-writing API exported below.

mod algebra;

pub(crate) mod layout;

#[cfg(test)]
mod layout_tests;

pub(crate) mod lookup;

#[cfg(test)]
mod lookup_tests;

pub(crate) mod constraints;

#[cfg(test)]
mod constraints_tests;

pub(crate) mod model;

#[cfg(test)]
mod model_tests;

pub(crate) mod periodic;

#[cfg(test)]
mod periodic_tests;

pub(crate) mod selectors;

#[cfg(test)]
mod selectors_tests;

pub(crate) mod schedule;

#[cfg(test)]
mod schedule_tests;

pub(crate) mod trace;

#[cfg(test)]
mod trace_tests;

#[cfg(test)]
pub(crate) mod views;

#[cfg(test)]
mod views_tests;

pub use layout::NUM_COLS;
pub use lookup::EidosCompressionCols;
pub use trace::{
    ByteLookupRecorder, EidosCompressionByteLookup, EidosCompressionFeltRow,
    EidosCompressionFeltTraceBlock, TraceMode, generate_felt_trace_block,
    retag_felt_trace_block_cycle_id, write_felt_trace_block,
    write_felt_trace_block_into_zeroed_with_lookups,
};
