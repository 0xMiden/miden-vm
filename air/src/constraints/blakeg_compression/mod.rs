//! BlakeG compression AIR.
//!
//! The active standalone BlakeG AIR uses the 32-row layout defined in the `air32_*` modules.
//! The public AIR wrapper in `multi_air.rs` wires these modules into main constraints, periodic
//! columns, and LogUp lookup columns.

pub mod air32_layout;

#[cfg(test)]
mod air32_layout_tests;

pub mod air32_lookup;

#[cfg(test)]
mod air32_lookup_tests;

#[cfg(test)]
mod air32_constraints;

#[cfg(test)]
mod air32_constraints_tests;

pub mod air32_model;

#[cfg(test)]
mod air32_model_tests;

pub mod air32_periodic;

#[cfg(test)]
mod air32_periodic_tests;

pub mod air32_selectors;

#[cfg(test)]
mod air32_selectors_tests;

pub mod air32_symbolic;

#[cfg(test)]
mod air32_symbolic_tests;

pub mod air32_schedule;

#[cfg(test)]
mod air32_schedule_tests;

pub mod air32_trace;

#[cfg(test)]
mod air32_trace_tests;

#[cfg(test)]
pub mod air32_views;

#[cfg(test)]
mod air32_views_tests;
