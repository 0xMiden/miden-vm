//! Miden-side wiring for the LogUp lookup-argument module.

pub(crate) mod buses;
pub mod chiplet_air;
mod extension_impls;
pub mod main_air;
pub mod messages;
pub mod miden_air;

pub use messages::{BusId, MIDEN_MAX_MESSAGE_WIDTH};
