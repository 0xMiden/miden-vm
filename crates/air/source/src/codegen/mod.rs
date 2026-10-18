//! Source-owned generation workflow. Compilation/rendering uses package-local templates and
//! ordinary authored AIR values. Output paths are explicit; default writes never accept new pins.

pub mod constraints;
pub mod evaluator;
pub use constraints::Mode;

pub mod precompile;
mod pvm_ood_frames;
