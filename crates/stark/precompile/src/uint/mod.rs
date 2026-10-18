pub use miden_air::precompile::uint::*;

pub mod add;
pub mod mul;
pub mod require;
pub mod store_mul;
pub mod trace;

pub use require::{UintRequire, UintStores};
