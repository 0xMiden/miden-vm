#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod precompile;
pub mod shared;
pub mod vm;
