#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
pub mod masm;

#[cfg(feature = "air")]
pub mod verifier;
