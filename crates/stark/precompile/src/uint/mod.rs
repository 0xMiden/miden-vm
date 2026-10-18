pub use miden_precompiles_air::uint::*;

pub mod add;
pub mod mul;
pub mod require;
pub mod store_mul;
pub mod trace;

pub use require::{UintRequire, UintStores};
