#![no_std]

//! Authored VM and precompile AIRs, trace schemas, and shared equations.
//!
//! [`vm`] describes the VM's four AIRs, public inputs, typed LogUp messages, and auxiliary-trace
//! construction. [`precompiles`] describes the precompile VM's AIRs, trace schemas, lookup
//! messages, and fixed boundary contributions. [`shared::eidos`] owns common compression equations,
//! physical layout, lookup encoding, and trace coordinates; VM and precompile adapters supply their
//! bus mappings and controller, AEAD, or transcript interfaces. Common geometry helpers also live
//! in [`shared`].
//!
//! [`vm::MidenAir`] evaluates handwritten constraints directly. The constraint compiler captures
//! these definitions to generate the evaluators consumed by `miden-air`; independent checks compare
//! the generated evaluators and degree metadata against this source. Production AIR owns PCS
//! presets, protocol IDs, and identity pins. Authored statement binding, input validation, and
//! external LogUp closure live in [`vm::statement`] and [`precompiles::statement`]. Production
//! [`miden_stark::air::MultiAir`] implementations select generated evaluators and call these source
//! functions; this crate does not define ordinary runtime `MultiAir` types.
//!
//! # Capture and testing
//!
//! The normal runtime does not include the ACE compiler. Enable `compiler` for symbolic capture,
//! relation compilation, and generation tooling in `compiler::vm` and `compiler::precompiles`.
//! Production builds use these tools as host build dependencies and embed compiled ACE
//! instructions. Without default features, the authored AIRs support `no_std` with `alloc`.
//!
//! Test standalone and composed AIRs through their complete evaluators on valid traces with active
//! lookups. For optimized evaluators, compare constraint values and assertion order with the
//! authored evaluator on arbitrary field assignments.
//!
//! Breaking API changes and replacement imports are documented in `miden_ace::migration`.

#[macro_use]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "compiler")]
pub mod compiler;

pub mod precompiles;
pub mod shared;
pub mod vm;
