//! Prepared native execution for independently completed VM source ports.

use miden_air_definitions::vm::MidenAir as Source;

use crate::native_kernel::define_native_dispatch;

#[allow(clippy::eq_op)]
mod evaluators {
    include!(concat!(env!("OUT_DIR"), "/native_evaluators.rs"));
}

mod descriptors {
    include!(concat!(env!("OUT_DIR"), "/native_descriptors.rs"));
}

define_native_dispatch!(super::MidenAir, Source, VmPrepared;
    Core => (CORE_DESCRIPTOR, descriptor_core, CORE_GEOMETRY, precompute_core, eval_core, CORE_PREPARED_TERMS),
    Chiplets => (CHIPLETS_DESCRIPTOR, descriptor_chiplets, CHIPLETS_GEOMETRY, precompute_chiplets, eval_chiplets, CHIPLETS_PREPARED_TERMS),
    EidosCompression => (EIDOS_DESCRIPTOR, descriptor_eidos_compression, EIDOS_COMPRESSION_GEOMETRY, precompute_eidos_compression, eval_eidos_compression, EIDOS_COMPRESSION_PREPARED_TERMS),
    And8Lookup => (AND8_DESCRIPTOR, descriptor_and8_lookup, AND8_LOOKUP_GEOMETRY, precompute_and8_lookup, eval_and8_lookup, AND8_LOOKUP_PREPARED_TERMS),
);
