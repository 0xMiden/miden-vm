//! Authored AIR definitions, trace schemas, and lookup relations for Miden precompiles.
//!
//! Production relation metadata lives in [`miden_air::precompile`](https://docs.rs/miden-air/latest/miden_air/precompile/index.html).

pub mod air;
#[cfg(feature = "codegen")]
pub mod codegen;
pub mod ec;
pub mod fixed;
pub mod hash;
pub mod logup;
pub mod math;
pub mod primitives;
pub mod relations;
pub mod transcript;
pub mod uint;
pub mod utils;

pub use air::{ChipletAir, NUM_CHIPLETS};

/// Returns [`ChipletAir::all`] instance indices in committed-trace order.
pub fn proof_order_from_log_heights(log_heights: &[u8; NUM_CHIPLETS]) -> [usize; NUM_CHIPLETS] {
    let mut order = core::array::from_fn(|index| index);
    order.sort_by_key(|&index| (log_heights[index], index));
    order
}
