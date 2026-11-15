#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod native_kernel;

pub mod precompiles;
pub mod vm;
