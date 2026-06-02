#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use miden_core::deferred::PrecompileRegistry;

/// Returns a [`PrecompileRegistry`] containing the deferred precompiles provided by this crate.
pub fn registry() -> PrecompileRegistry {
    PrecompileRegistry::new()
}
