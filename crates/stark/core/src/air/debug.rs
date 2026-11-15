//! Descriptor structural assertions and transitional source-builder shape diagnostics.
//!
//! Runtime statement constructors validate caller dimensions. Structural checks inspect the
//! validated kernel descriptor only; setup owns and validates all fixed matrix construction.

use p3_field::{ExtensionField, Field};

use crate::air::{LiftedAir, LiftedAirBuilder, MultiAir, WindowAccess, native::AirKernel};

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

/// Assert a concrete builder's accessor dimensions match `air` — preprocessed,
/// main and aux trace, public values, randomness, aux values, and periodic values.
///
/// Under the [`LiftedAir`] evaluation contract, successful symbolic evaluation and this shape
/// check establish that `eval`'s input accesses are in bounds. Prepared data must also satisfy
/// [`LiftedAir::eval`]'s contract.
pub fn check_builder_shape<F, EF, A, AB>(air: &A, builder: &AB)
where
    F: Field,
    A: LiftedAir<F, EF>,
    AB: LiftedAirBuilder<F = F>,
{
    let check = |part: &str, expected: usize, actual: usize| {
        assert!(
            actual == expected,
            "{part} dimension mismatch: expected {expected}, got {actual}"
        );
    };

    let preprocessed = builder.preprocessed();
    check(
        "preprocessed (current)",
        air.preprocessed_width(),
        preprocessed.current_slice().len(),
    );
    check("preprocessed (next)", air.preprocessed_width(), preprocessed.next_slice().len());

    let main = builder.main();
    check("main (current)", air.width(), main.current_slice().len());
    check("main (next)", air.width(), main.next_slice().len());

    let perm = builder.permutation();
    check("aux (current)", air.aux_width(), perm.current_slice().len());
    check("aux (next)", air.aux_width(), perm.next_slice().len());

    check("public values", air.num_public_values(), builder.public_values().len());
    check("randomness", air.num_randomness(), builder.permutation_randomness().len());
    check("aux values", air.num_aux_values(), builder.permutation_values().len());
    check("periodic values", air.periodic_columns().len(), builder.periodic_values().len());
}
