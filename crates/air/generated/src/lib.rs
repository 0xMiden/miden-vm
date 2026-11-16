#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod kernel;

pub mod precompiles;
pub mod vm;
