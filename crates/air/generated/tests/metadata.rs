//! Expectations use authored accessors and fresh symbolic evaluation, never generated tables.
use miden_air::{
    metadata::{AirMetadata, ColumnWidths, RelationGeometry},
    precompile, vm,
};
use miden_air_source::precompile::{
    self as source_pvm,
    logup::{LookupAir, ProverLookupBuilder},
};
use miden_core::{
    Felt,
    field::{BasedVectorSpace, QuadFelt},
};
use miden_stark::air::{ConstraintCounts, ConstraintDegrees, LiftedAir};

fn pvm_lookup(air: source_pvm::Air) -> (usize, usize) {
    fn shape<A: for<'a> LookupAir<ProverLookupBuilder<'a, Felt, QuadFelt>>>(
        air: A,
    ) -> (usize, usize) {
        (
            LookupAir::<ProverLookupBuilder<'_, Felt, QuadFelt>>::column_shape(&air)
                .iter()
                .sum(),
            LookupAir::<ProverLookupBuilder<'_, Felt, QuadFelt>>::max_message_width(&air),
        )
    }
    use source_pvm::{
        ec::{add::EcGroupAddAir, msm::EcMsmAir, point_store_groups::EcPointStoreGroupsAir},
        hash::{
            chunk_node_sponge::ChunkNodeSpongeAir, keccak::round::KeccakRoundAir,
            sha256::Sha256Air, sha512::Sha512Air,
        },
        primitives::byte_pair_lut::BytePairLutAir,
        transcript::{eidos::EidosCompressionAir, eval::TranscriptEvalAir},
        uint::{add::UintAddAir, store_mul::UintStoreMulAir},
    };
    match air {
        source_pvm::Air::ChunkNodeSponge => shape(ChunkNodeSpongeAir),
        source_pvm::Air::EidosCompression => shape(EidosCompressionAir),
        source_pvm::Air::KeccakRound => shape(KeccakRoundAir),
        source_pvm::Air::BytePairLut => shape(BytePairLutAir),
        source_pvm::Air::TranscriptEval => shape(TranscriptEvalAir),
        source_pvm::Air::UintStoreMul => shape(UintStoreMulAir),
        source_pvm::Air::UintAdd => shape(UintAddAir),
        source_pvm::Air::EcPointStoreGroups => shape(EcPointStoreGroupsAir),
        source_pvm::Air::EcGroupAdd => shape(EcGroupAddAir),
        source_pvm::Air::EcMsm => shape(EcMsmAir),
        source_pvm::Air::Sha512 => shape(Sha512Air),
        source_pvm::Air::Sha256 => shape(Sha256Air),
    }
}

fn check_air<A: LiftedAir<Felt, QuadFelt>>(
    actual: AirMetadata,
    source: &A,
    lookup: (usize, usize),
) {
    assert_eq!(
        actual.widths,
        ColumnWidths {
            preprocessed: source.preprocessed_width(),
            main: source.width(),
            aux: source.aux_width()
        }
    );
    assert_eq!(actual.constraints, ConstraintCounts::from_air::<Felt, QuadFelt, _>(source));
    assert_eq!(actual.degrees, ConstraintDegrees::from_air::<Felt, QuadFelt, _>(source));
    assert_eq!(actual.lookup.fractions_per_row as usize, lookup.0);
    assert_eq!(actual.lookup.max_message_width as usize, lookup.1);
}

#[test]
fn canonical_facts_match_raw_schema_and_independent_symbolic_counts() {
    for air in vm::AIRS.into_iter().rev() {
        let source = air.source();
        check_air(
            air.metadata(),
            &source,
            (
                source.column_shape().iter().sum(),
                miden_air_source::vm::logup::MIDEN_MAX_MESSAGE_WIDTH,
            ),
        );
    }
    for air in precompile::Air::all().into_iter().rev() {
        check_air(air.metadata(), &air.source(), pvm_lookup(air.source()));
    }
    const CORE: AirMetadata = vm::Air::Core.metadata();
    check_air(
        CORE,
        &miden_air_source::vm::Air::Core,
        (
            miden_air_source::vm::Air::Core.column_shape().iter().sum(),
            miden_air_source::vm::logup::MIDEN_MAX_MESSAGE_WIDTH,
        ),
    );
}

// Independent matrix/quotient/batching formulas, evaluated from raw source accessors.
fn check_geometry<A: LiftedAir<Felt, QuadFelt>>(
    actual: RelationGeometry,
    airs: &[A],
    alignment: usize,
) {
    let ext = <QuadFelt as BasedVectorSpace<Felt>>::DIMENSION;
    let mut columns = [0usize; 3];
    let mut counts = [0usize; 2];
    let mut degree = 0;
    for air in airs {
        for (sum, width) in
            columns
                .iter_mut()
                .zip([air.preprocessed_width(), air.width(), air.aux_width() * ext])
        {
            *sum += width.div_ceil(alignment) * alignment;
        }
        let c = ConstraintCounts::from_air::<Felt, QuadFelt, _>(air);
        counts[0] += c.base;
        counts[1] += c.ext;
        degree = degree.max(ConstraintDegrees::from_air::<Felt, QuadFelt, _>(air).max());
    }
    let logical = degree.saturating_sub(1).max(1);
    let chunks = 1usize << (logical.ilog2() + u32::from(!logical.is_power_of_two()));
    let quotient_width = (chunks * ext).div_ceil(alignment) * alignment;
    assert_eq!(actual.num_airs, airs.len());
    assert_eq!([actual.constraints.base, actual.constraints.ext], counts);
    assert_eq!(actual.num_composed_constraints(), counts.iter().sum::<usize>() + airs.len() - 1);
    assert_eq!(actual.max_constraint_degree, degree);
    assert_eq!(actual.logical_quotient_chunks(), logical);
    assert_eq!(actual.quotient_chunks(), chunks);
    assert_eq!(actual.quotient_width(), quotient_width);
    assert_eq!(
        [actual.committed.preprocessed, actual.committed.main, actual.committed.aux],
        columns
    );
    assert_eq!(
        actual.num_deep_terms() as usize,
        columns.iter().sum::<usize>() + quotient_width + 2
    );
}

#[test]
fn full_and_selected_geometry_matches_independent_formulas_for_all_alignments() {
    use precompile::Air as P;
    use vm::Air as V;
    for alignment in [1, 8, 17] {
        check_geometry(vm::geometry(&vm::AIRS, alignment), &miden_air_source::vm::AIRS, alignment);
        check_geometry(
            precompile::geometry(&P::all(), alignment),
            &source_pvm::Air::all(),
            alignment,
        );
        for selected in [&[V::And8Lookup][..], &[V::EidosCompression, V::Core][..]] {
            check_geometry(
                vm::geometry(selected, alignment),
                &selected.iter().map(|air| air.source()).collect::<Vec<_>>(),
                alignment,
            );
        }
        for selected in [&[P::Sha256][..], &[P::Sha512, P::BytePairLut, P::ChunkNodeSponge][..]] {
            let geometry = precompile::geometry(selected, alignment);
            check_geometry(
                geometry,
                &selected.iter().map(|air| air.source()).collect::<Vec<_>>(),
                alignment,
            );
            let lookup = selected.iter().map(|air| pvm_lookup(air.source())).collect::<Vec<_>>();
            assert_eq!(
                geometry.lookup.fractions_per_row as usize,
                lookup.iter().map(|s| s.0).sum::<usize>()
            );
            assert_eq!(
                geometry.lookup.max_message_width as usize,
                lookup.iter().map(|s| s.1).max().unwrap()
            );
            let reversed = selected.iter().copied().rev().collect::<Vec<_>>();
            assert_eq!(geometry, precompile::geometry(&reversed, alignment));
        }
        assert_eq!(
            vm::security::num_deep_terms(alignment),
            miden_air_source::vm::security::num_deep_terms(alignment)
        );
        assert_eq!(
            precompile::security::num_deep_terms(alignment),
            source_pvm::security::num_deep_terms(alignment)
        );
    }
    assert_eq!(vm::security::AIR_SHAPE, miden_air_source::vm::security::derive_air_shape());
    assert_eq!(precompile::security::AIR_SHAPE, source_pvm::security::derive_air_shape());
    const SINGLE: RelationGeometry = vm::geometry(&[V::Core], 8);
    check_geometry(SINGLE, &[miden_air_source::vm::Air::Core], 8);
}

#[test]
fn staged_metadata_is_fresh() {
    for ((_, generated), staged) in
        miden_air_source::codegen::metadata::generate().into_iter().zip([
            include_str!("../artifacts/vm-metadata.rs"),
            include_str!("../artifacts/precompile-metadata.rs"),
        ])
    {
        assert_eq!(generated, staged, "run make regenerate-constraints");
    }
}

#[test]
fn security_wrappers_use_geometry_at_each_alignment() {
    use miden_core::proof::HashFunction;
    for alignment in [1, 8, 17] {
        for hash in [HashFunction::Eidos, HashFunction::Blake3_256, HashFunction::Keccak] {
            let params = miden_air::config::pcs_params();
            let vm = vm::security::proof_security_parameters(&params, 22, 17, alignment, hash);
            let expected = miden_air_source::vm::security::proof_security_parameters_with_shape(
                &params,
                22,
                17,
                miden_stark::security::AirShape {
                    num_deep_terms: Some(miden_air_source::vm::security::num_deep_terms(alignment)),
                    ..miden_air_source::vm::security::derive_air_shape()
                },
                hash,
            );
            assert_eq!(vm, expected);
            assert_eq!(
                vm::security::conjectured_security_level_for_alignment(
                    params.num_queries() as u32,
                    params.query_pow_bits() as u32,
                    params.deep_pow_bits() as u32,
                    params.folding_pow_bits() as u32,
                    22,
                    17,
                    alignment,
                    hash
                ),
                expected.conjectured_security_level()
            );
            let params = precompile::stark_config::precompile_pcs_params();
            let pvm = precompile::security::proof_security_parameters(&params, 22, alignment, hash);
            let expected = source_pvm::security::proof_security_parameters_with_shape(
                &params,
                22,
                miden_stark::security::AirShape {
                    num_deep_terms: Some(source_pvm::security::num_deep_terms(alignment)),
                    ..source_pvm::security::derive_air_shape()
                },
                hash,
            );
            assert_eq!(pvm, expected);
            assert_eq!(
                precompile::security::conjectured_security_level_for_alignment(
                    &params, 22, alignment, hash
                ),
                expected.conjectured_security_level()
            );
            if hash == HashFunction::Eidos && alignment == 8 {
                assert_eq!(
                    vm.conjectured_security_report(),
                    vm::security::security_report(&vm.protocol_params, 22, hash, 17)
                );
                assert_eq!(
                    vm::security::conjectured_security_level(
                        vm.protocol_params.num_queries,
                        vm.protocol_params.query_pow_bits,
                        vm.protocol_params.deep_pow_bits,
                        vm.protocol_params.folding_pow_bits,
                        22,
                        17
                    ),
                    vm.conjectured_security_level()
                );
                assert_eq!(
                    precompile::security::conjectured_security_level(&params, 22),
                    pvm.conjectured_security_level()
                );
                assert_eq!(
                    pvm.conjectured_security_report(),
                    precompile::security::security_report(&pvm.protocol_params, 22)
                );
            }
        }
    }
}

#[test]
fn geometry_rejects_overflow_and_invalid_shape_in_release_too() {
    use std::panic::catch_unwind;
    assert!(catch_unwind(|| vm::geometry(&[], 8)).is_err());
    assert!(catch_unwind(|| vm::geometry(&vm::AIRS, 0)).is_err());
    assert!(
        catch_unwind(|| ColumnWidths { aux: usize::MAX, ..Default::default() }.committed(1))
            .is_err()
    );
    assert!(
        catch_unwind(|| ColumnWidths { main: usize::MAX, ..Default::default() }.committed(8))
            .is_err()
    );
    if let Some(large_alignment) = (u32::MAX as usize).checked_add(1) {
        assert!(
            catch_unwind(|| vm::geometry(&[vm::Air::Core], large_alignment).air_shape()).is_err()
        );
    }
    let mut large = vm::Air::Core.metadata();
    large.constraints.base = usize::MAX;
    assert!(catch_unwind(|| RelationGeometry::new(8).with_air(large).air_shape()).is_err());
    large = vm::Air::Core.metadata();
    large.degrees.base = usize::MAX;
    assert!(catch_unwind(|| RelationGeometry::new(8).with_air(large).air_shape()).is_err());
}
