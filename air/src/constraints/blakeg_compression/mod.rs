//! BlakeG compression AIR.
//!
//! The standalone BlakeG AIR uses a 32-row compression cycle. The public AIR wrapper in
//! `multi_air.rs` wires this module into main constraints, periodic columns, and LogUp lookup
//! columns.

pub mod layout;

#[cfg(test)]
mod layout_tests;

pub mod lookup;

#[cfg(test)]
mod lookup_tests;

#[cfg(test)]
mod constraints;

#[cfg(test)]
mod constraints_tests;

pub mod model;

#[cfg(test)]
mod model_tests;

pub mod periodic;

#[cfg(test)]
mod periodic_tests;

pub mod selectors;

#[cfg(test)]
mod selectors_tests;

pub mod symbolic;

#[cfg(test)]
mod symbolic_tests;

pub mod schedule;

#[cfg(test)]
mod schedule_tests;

pub mod trace;

#[cfg(test)]
mod trace_tests;

#[cfg(test)]
pub mod views;

#[cfg(test)]
mod views_tests;
