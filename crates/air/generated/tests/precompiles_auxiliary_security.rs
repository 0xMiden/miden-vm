//! Check auxiliary identities against the security budget derived from every deployed AIR.
//! The shared accounting argument is documented in `auxiliary_security.rs`.

use miden_air_definitions::precompiles::{
    ChipletAir,
    ec::{add::EcGroupAddAir, msm::EcMsmAir, point_store_groups::EcPointStoreGroupsAir},
    geometry::derive_air_shape,
    hash::{
        chunk_node_sponge::ChunkNodeSpongeAir, keccak::round::KeccakRoundAir, sha256::Sha256Air,
        sha512::Sha512Air,
    },
    primitives::byte_pair_lut::BytePairLutAir,
    transcript::{eidos::EidosCompressionAir, eval::TranscriptEvalAir},
    uint::{add::UintAddAir, store_mul::UintStoreMulAir},
};
use miden_constraint_compiler::ir::{GraphBuilder, auxiliary, capture_into, capture_into_with};
use miden_core::{Felt, field::QuadFelt};
use miden_stark::{
    air::{LiftedAir, symbolic::SymbolicAirBuilder},
    lookup::{ConstraintLookupBuilder, LookupAir},
};

type Symbolic = SymbolicAirBuilder<Felt, QuadFelt>;

fn degree<A>(air: &A) -> Result<usize, &'static str>
where
    A: LiftedAir<Felt, QuadFelt> + for<'a> LookupAir<ConstraintLookupBuilder<'a, Symbolic>>,
{
    let mut builder = GraphBuilder::new();
    let full = capture_into(air, &mut builder);
    let lookup = capture_into_with(air, &mut builder, |b| {
        let mut lb = ConstraintLookupBuilder::new(b, air);
        LookupAir::eval(air, &mut lb);
        lb.finish();
    });
    auxiliary::beta_degree_bound(
        &builder.freeze(),
        &full.ext_roots,
        &lookup.ext_roots,
        air.aux_width(),
        &air.periodic_columns(),
    )
}

#[test]
fn auxiliary_identities_fit_the_lookup_budget() {
    let shape = derive_air_shape();
    assert_eq!(shape, miden_air::precompiles::protocol::PROTOCOL.air_shape);
    let lookup = shape.lookup.unwrap();
    let lookup_coefficient =
        (u64::from(lookup.max_message_width) + 2) * u64::from(lookup.fractions_per_row);
    for air in ChipletAir::all() {
        // Exhaustive dispatch requires each new chiplet to supply its ordinary lookup capture.
        let (degree, expected_degree) = match air {
            ChipletAir::ChunkNodeSponge => (degree(&ChunkNodeSpongeAir), 0),
            ChipletAir::EidosCompression => (degree(&EidosCompressionAir), 119),
            ChipletAir::KeccakRound => (degree(&KeccakRoundAir), 0),
            ChipletAir::BytePairLut => (degree(&BytePairLutAir), 0),
            ChipletAir::TranscriptEval => (degree(&TranscriptEvalAir), 0),
            ChipletAir::UintStoreMul => (degree(&UintStoreMulAir), 31),
            ChipletAir::UintAdd => (degree(&UintAddAir), 7),
            ChipletAir::EcPointStoreGroups => (degree(&EcPointStoreGroupsAir), 0),
            ChipletAir::EcGroupAdd => (degree(&EcGroupAddAir), 0),
            ChipletAir::EcMsm => (degree(&EcMsmAir), 0),
            ChipletAir::Sha512 => (degree(&Sha512Air), 0),
            ChipletAir::Sha256 => (degree(&Sha256Air), 0),
        };
        let degree = degree.unwrap_or_else(|error| panic!("{air:?}: {error}"));
        assert_eq!(degree, expected_degree, "{air:?}: auxiliary challenge degree changed");
        assert!(
            degree as u64 <= lookup_coefficient,
            "{air:?}: degree coefficient {degree} exceeds lookup coefficient {lookup_coefficient}"
        );
    }
}
