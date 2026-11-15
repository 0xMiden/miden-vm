//! Prepared native execution for independently completed VM source ports.

use crate::native_kernel::define_native_kernel;

#[allow(clippy::eq_op)]
mod evaluators {
    include!(concat!(env!("OUT_DIR"), "/native_evaluators.rs"));
}

mod descriptors {
    include!(concat!(env!("OUT_DIR"), "/native_descriptors.rs"));
}

define_native_kernel!(
    /// Generated execution of the authored Core relation, including its lookup columns.
    ///
    /// Construction owns an embedded descriptor without source recapture or fixed-table building.
    /// Witness construction remains on the authored
    /// [`CoreAir`](miden_air_definitions::vm::CoreAir).
    /// The canonical multi-AIR runtime selects its current wrapper until activation.
    CoreKernel,
    descriptor_core,
    precompute_core,
    eval_core,
    CORE_PREPARED_TERMS
);

define_native_kernel!(
    /// Generated execution of the VM Eidos compression relation and its fingerprint register.
    ///
    /// Witness construction remains on the authored
    /// [`EidosCompressionAir`](miden_air_definitions::vm::EidosCompressionAir).
    /// The descriptor is embedded; the canonical runtime retains its current wrapper until activation.
    EidosCompressionKernel,
    descriptor_eidos_compression,
    precompute_eidos_compression,
    eval_eidos_compression,
    EIDOS_COMPRESSION_PREPARED_TERMS
);
