//! Check that additional auxiliary identities fit the ordinary lookup error budget.
//!
//! For each AIR, the analyzer bounds their challenge degree by d*H, where H is the maximum trace
//! height. The lookup coefficient includes (W+2)*F*H, where W is the maximum message width and F
//! is the total number of fractions per row across AIRs. We therefore check d <= (W+2)*F.
//!
//! These bounds combine by maximum: for fixed incorrect committed inputs, acceptance requires
//! passing a failed check selected before sampling. Each AIR's correctness argument establishes
//! which identities enforce its arithmetic.

use miden_air_definitions::{
    compiler::vm::derive_air_shape as derive_vm_shape,
    precompiles::{ChipletAir, geometry::derive_air_shape as derive_pvm_shape},
    vm::{AIRS, MidenAir},
};
use miden_constraint_compiler::ir::{
    GraphBuilder, auxiliary, capture_native_into, capture_native_into_with,
};
use miden_core::{Felt, field::QuadFelt};
use miden_stark::{
    air::{self, LiftedAir},
    lookup,
};

type Symbolic = air::SymbolicSink<Felt, QuadFelt>;

fn lookup_coefficient(shape: miden_stark::security::LookupShape) -> u64 {
    (u64::from(shape.max_message_width) + 2) * u64::from(shape.fractions_per_row)
}

fn check_degree<A>(air: &A, label: impl core::fmt::Debug, expected: usize, lookup_coefficient: u64)
where
    A: LiftedAir<F = Felt>
        + for<'r, 's> lookup::LookupAir<lookup::ConstraintLookupBuilder<'r, 's, Symbolic>>,
{
    let mut builder = GraphBuilder::new();
    let (full, _) = capture_native_into(air, &mut builder).unwrap();
    let (lookup, _) = capture_native_into_with(air, &mut builder, |frame, inputs, sink| {
        lookup::eval_lookup(air, frame, inputs, sink);
    })
    .unwrap();
    let spec = air.spec();
    let degree = auxiliary::beta_degree_bound(
        &builder.freeze(),
        &full.ext_roots,
        &lookup.ext_roots,
        spec.aux_width,
        &spec.periodic_columns,
    )
    .unwrap_or_else(|error| panic!("{label:?}: {error}"));
    assert_eq!(degree, expected, "{label:?}: auxiliary challenge degree changed");
    assert!(
        degree as u64 <= lookup_coefficient,
        "{label:?}: degree coefficient {degree} exceeds lookup coefficient {lookup_coefficient}"
    );
}

#[test]
fn vm_auxiliary_identities_fit_the_lookup_budget() {
    let shape = derive_vm_shape().unwrap();
    assert_eq!(shape, miden_air::vm::security::AIR_SHAPE);
    let lookup_coefficient = lookup_coefficient(shape.lookup.unwrap());
    for air in AIRS {
        let expected = match air {
            MidenAir::EidosCompression => 119,
            MidenAir::Core | MidenAir::Chiplets | MidenAir::And8Lookup => 0,
        };
        check_degree(&air, air, expected, lookup_coefficient);
    }
}

#[test]
fn pvm_auxiliary_identities_fit_the_lookup_budget() {
    let shape = derive_pvm_shape().unwrap();
    assert_eq!(shape, miden_air::precompiles::protocol::PROTOCOL.air_shape);
    let lookup_coefficient = lookup_coefficient(shape.lookup.unwrap());
    for air in ChipletAir::all() {
        let expected = match air {
            ChipletAir::EidosCompression => 119,
            ChipletAir::UintStoreMul => 31,
            ChipletAir::UintAdd => 7,
            ChipletAir::ChunkNodeSponge
            | ChipletAir::KeccakRound
            | ChipletAir::BytePairLut
            | ChipletAir::TranscriptEval
            | ChipletAir::EcPointStoreGroups
            | ChipletAir::EcGroupAdd
            | ChipletAir::EcMsm
            | ChipletAir::Sha512
            | ChipletAir::Sha256 => 0,
        };
        check_degree(&air, air, expected, lookup_coefficient);
    }
}
