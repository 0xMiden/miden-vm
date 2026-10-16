#![no_std]
//! Temporary source compatibility for the legacy PVM artifact generator.
pub use miden_air::precompiles::*;
pub mod protocol;
pub use protocol::PVM_RELATION_DIGEST;
pub mod stark_config {
    pub use miden_air::precompiles::stark_config::*;
}
