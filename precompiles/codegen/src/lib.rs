#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod descriptors;

pub use descriptors::*;

#[cfg(feature = "std")]
pub mod masm;
