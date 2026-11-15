//! Check that additional auxiliary identities fit the ordinary lookup error budget.
//!
//! For each AIR, the analyzer bounds their challenge degree by d*H, where H is the maximum trace
//! height. The lookup coefficient includes (W+2)*F*H, where W is the maximum message width and F
//! is the total number of fractions per row across AIRs. We therefore check d <= (W+2)*F.
//!
//! These bounds combine by maximum: for fixed incorrect committed inputs, acceptance requires
//! passing a failed check selected before sampling. Each AIR's correctness argument establishes
//! which identities enforce its arithmetic.

use miden_air::vm::security;
use miden_air_definitions::{
    compiler::vm::derive_air_shape,
    vm::{AIRS, MidenAir},
};
use miden_constraint_compiler::ir::{
    GraphBuilder, auxiliary, capture_native_into, capture_native_into_with, with_sum_folding,
};
use miden_stark::{air::LiftedAir, lookup};

#[test]
fn native_source_geometry_keeps_the_vm_security_shape() {
    let native = derive_air_shape().unwrap();
    assert_eq!(native, security::AIR_SHAPE);
}

#[test]
fn auxiliary_identities_fit_the_lookup_budget() {
    // Root membership compares independently captured graphs. Keep primitive sum association
    // independent of the surrounding AIR's consumer counts for this analysis.
    with_sum_folding(false, || {
        let shape = derive_air_shape().unwrap();
        assert_eq!(shape, security::AIR_SHAPE);
        let lookup_shape = shape.lookup.unwrap();
        let lookup_coefficient = (u64::from(lookup_shape.max_message_width) + 2)
            * u64::from(lookup_shape.fractions_per_row);
        for air in AIRS {
            let mut builder = GraphBuilder::new();
            let (full, _) = capture_native_into(&air, &mut builder).unwrap();
            let (lookup, _) =
                capture_native_into_with(&air, &mut builder, |frame, inputs, sink| {
                    lookup::eval_lookup(&air, frame, inputs, sink);
                })
                .unwrap();
            let degree = auxiliary::beta_degree_bound(
                &builder.freeze(),
                &full.ext_roots,
                &lookup.ext_roots,
                air.spec().aux_width,
                &air.spec().periodic_columns,
            )
            .unwrap_or_else(|error| panic!("{air:?}: {error}"));
            let expected_degree = match air {
                MidenAir::EidosCompression => 119,
                MidenAir::Core | MidenAir::Chiplets | MidenAir::And8Lookup => 0,
            };
            assert_eq!(degree, expected_degree, "{air:?}: auxiliary challenge degree changed");
            assert!(
                degree as u64 <= lookup_coefficient,
                "{air:?}: degree coefficient {degree} exceeds lookup coefficient {lookup_coefficient}"
            );
        }
    });
}
