#![no_std]

//! Handwritten AIR definitions and trace schemas consumed by Miden artifact generation.
//!
//! Production proof configuration and generated evaluators live in `miden-air`.

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod vm;
