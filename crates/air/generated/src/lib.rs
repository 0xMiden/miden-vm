#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod precompiles;
pub mod shared;
pub mod vm;
