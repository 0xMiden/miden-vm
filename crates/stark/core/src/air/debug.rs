//! Structural assertions over native kernel descriptors.
//!
//! Runtime statement constructors validate caller dimensions. Structural checks inspect the
//! validated kernel descriptor only; setup owns and validates all fixed matrix construction.

use p3_field::{ExtensionField, Field};

use crate::air::{MultiAir, native::AirKernel};

/// Assert a collection's descriptor schemas and this engine's positive auxiliary-width contract.
///
/// This never invokes a source, fixed factory, or witness builder. An empty collection or invalid
/// trusted kernel definition panics; caller/proof shape errors use the runtime constructors.
pub fn assert_multi_air_valid<F, EF, MA>(multi_air: &MA)
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    let airs = multi_air.airs();
    assert!(!airs.is_empty(), "MultiAir::airs() must be non-empty");

    for (idx, air) in airs.iter().enumerate() {
        let spec = air.descriptor().spec();
        spec.validate().expect("validated kernel descriptor schema");
        assert!(spec.aux_width > 0, "AIR {idx}: this proof engine requires auxiliary columns");
    }
}
