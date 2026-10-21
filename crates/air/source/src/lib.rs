#![no_std]

//! Authored VM and precompile AIRs, trace schemas, and shared equations.
//!
//! Production evaluators, protocol configuration, and derived artifacts live in `miden-air`.

#[macro_use]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod precompile;
pub mod shared;
pub mod vm;
