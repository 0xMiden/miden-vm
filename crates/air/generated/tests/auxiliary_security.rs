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
use miden_constraint_compiler::ir::{GraphBuilder, auxiliary, capture_into, capture_into_with};
use miden_core::{Felt, field::QuadFelt};
use miden_stark::{
    air::{BaseAir, LiftedAir},
    lookup::{ConstraintLookupBuilder, LookupAir},
};

#[test]
fn auxiliary_identities_fit_the_lookup_budget() {
    let shape = derive_air_shape();
    assert_eq!(shape, security::AIR_SHAPE);
    let lookup_shape = shape.lookup.unwrap();
    let lookup_coefficient =
        (u64::from(lookup_shape.max_message_width) + 2) * u64::from(lookup_shape.fractions_per_row);
    for air in AIRS {
        let mut builder = GraphBuilder::new();
        let full = capture_into(&air, &mut builder);
        let lookup = capture_into_with(&air, &mut builder, |b| {
            let mut lb = ConstraintLookupBuilder::new(b, &air);
            LookupAir::eval(&air, &mut lb);
            lb.finish();
        });
        let degree = auxiliary::beta_degree_bound(
            &builder.freeze(),
            &full.ext_roots,
            &lookup.ext_roots,
            LiftedAir::<Felt, QuadFelt>::aux_width(&air),
            &air.periodic_columns(),
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
}
