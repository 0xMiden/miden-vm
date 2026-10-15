use alloc::vec;

use miden_core::{
    deferred::{Node, PrecompileWitness},
    proof::{HashFunction, StarkProof},
    utils::Matrix,
};
use miden_crypto::hash::{
    keccak::Keccak256,
    sha2::{Sha256, Sha512},
};
use miden_precompiles::{
    Keccak256Precompile, Sha256Precompile, Sha512Precompile, UintDomain, UintPrecompile,
};
use miden_precompiles_air::{
    ChipletAir,
    proof::{decode_proof, encode_proof},
};
use miden_precompiles_verifier::verify_deferred;

use super::batch_witness::WitnessFixture;
use crate::{
    PrecompileProvingError, PvmAirVariant, SessionInputError,
    deferred::session::{ImportLimits, import_witnesses_with_variant},
    prove_precompiles, prove_precompiles_with_variant, prove_precompiles_with_variant_and_budget,
};

fn witness(variant: PvmAirVariant) -> PrecompileWitness {
    let mut fixture = WitnessFixture::new();
    // Arithmetic remains available even when every optional hash AIR is omitted.
    let one = fixture
        .register(UintPrecompile::value_node(UintDomain::U256, [1, 0, 0, 0, 0, 0, 0, 0]))
        .unwrap();
    let eq = fixture
        .register(Node::join(UintPrecompile::op_frame(UintPrecompile::EQ_OP_ID), one, one).unwrap())
        .unwrap();
    fixture.log_statement(eq).unwrap();
    let input = b"PVM variants";
    let preimage = fixture.register(Node::chunks_from_bytes(input)).unwrap();
    for (enabled, expected, frame) in [
        (
            PvmAirVariant::KECCAK,
            Keccak256::hash(input).as_bytes().to_vec(),
            Keccak256Precompile::assert_frame(input.len() as u32),
        ),
        (
            PvmAirVariant::SHA256,
            Sha256::hash(input).as_bytes().to_vec(),
            Sha256Precompile::assert_frame(input.len() as u32),
        ),
        (
            PvmAirVariant::SHA512,
            Sha512::hash(input).as_bytes().to_vec(),
            Sha512Precompile::assert_frame(input.len() as u32),
        ),
    ] {
        if variant.contains(enabled) {
            let expected = fixture.register(Node::chunks_from_bytes(&expected)).unwrap();
            let claim = fixture.register(Node::join(frame, preimage, expected).unwrap()).unwrap();
            fixture.log_statement(claim).unwrap();
        }
    }
    fixture.witness()
}

#[test]
fn optional_hash_witnesses_are_rejected_before_proving_budget_check() {
    for variant in PvmAirVariant::ALL_VARIANTS {
        for required in [PvmAirVariant::KECCAK, PvmAirVariant::SHA256, PvmAirVariant::SHA512] {
            if !variant.contains(required) {
                let error = prove_precompiles_with_variant_and_budget(
                    vec![witness(required)],
                    HashFunction::Blake3_256,
                    variant,
                    0,
                )
                .unwrap_err();
                assert!(
                    matches!(
                        error,
                        PrecompileProvingError::Input(SessionInputError::Invalid {
                            reason: "hash precompile is disabled in the selected PVM AIR variant",
                            ..
                        })
                    ),
                    "disabled hash must be rejected during the initial import scan: {error}"
                );
            }
        }
    }
}

#[test]
fn optional_hash_trace_selection_preserves_lookup_balance() {
    for variant in PvmAirVariant::ALL_VARIANTS {
        let imported =
            import_witnesses_with_variant(vec![witness(variant)], ImportLimits::default(), variant)
                .unwrap();
        let traces = imported.finish_with_variant(variant);
        // Checking the entire selected relation detects dummy SHA padding rows that accidentally
        // add byte-pair lookup demand even when the corresponding AIR is omitted.
        traces.check();
        let mains = traces.into_mains();
        let selected: vec::Vec<_> =
            ChipletAir::all().into_iter().filter(|air| air.is_in_variant(variant)).collect();
        assert_eq!(mains.len(), selected.len());
        for (main, air) in mains.iter().zip(selected) {
            assert!(main.height() > 0, "selected {air:?} trace must exist");
        }
    }
}

#[test]
fn every_native_variant_proves_enabled_hashes_and_rejects_other_variant_headers() {
    for variant in PvmAirVariant::ALL_VARIANTS {
        let witness = witness(variant);
        let root = witness.root_unchecked();
        let proof =
            prove_precompiles_with_variant(vec![witness], HashFunction::Blake3_256, variant)
                .unwrap();
        verify_deferred(&proof.proof, root).unwrap();
        let (encoded_variant, payload) = decode_proof(proof.proof.bytes()).unwrap();
        assert_eq!(encoded_variant, variant);
        for other in PvmAirVariant::ALL_VARIANTS {
            if other == variant {
                continue;
            }
            let forged =
                StarkProof::new(encode_proof(other, payload.to_vec()), HashFunction::Blake3_256);
            assert!(
                verify_deferred(&forged, root).is_err(),
                "variant {variant:?} must not verify with header {other:?}, including equal AIR counts"
            );
        }
    }
}

#[test]
fn reduced_native_variant_supports_every_commitment_hash() {
    let variant = PvmAirVariant::NONE;
    for hash_fn in [
        HashFunction::Blake3_256,
        HashFunction::Rpo256,
        HashFunction::Rpx256,
        HashFunction::Poseidon2,
        HashFunction::Keccak,
        HashFunction::Eidos,
    ] {
        let witness = witness(variant);
        let root = witness.root_unchecked();
        let proof = prove_precompiles_with_variant(vec![witness], hash_fn, variant).unwrap();
        verify_deferred(&proof.proof, root).unwrap();
    }
}

#[test]
fn default_proving_selects_the_exact_hash_union_across_the_batch() {
    for variant in PvmAirVariant::ALL_VARIANTS {
        let proof = prove_precompiles(vec![witness(variant)], HashFunction::Blake3_256).unwrap();
        assert_eq!(decode_proof(proof.proof.bytes()).unwrap().0, variant);
        verify_deferred(&proof.proof, proof.aggregate_root().unwrap()).unwrap();
    }

    let proof = prove_precompiles(
        vec![
            witness(PvmAirVariant::KECCAK),
            witness(PvmAirVariant::NONE),
            witness(PvmAirVariant::SHA512),
            witness(PvmAirVariant::KECCAK),
        ],
        HashFunction::Blake3_256,
    )
    .unwrap();
    assert_eq!(
        decode_proof(proof.proof.bytes()).unwrap().0,
        PvmAirVariant::KECCAK.union(PvmAirVariant::SHA512),
        "batch selection must include hashes from every constituent, preserving repetitions",
    );
    verify_deferred(&proof.proof, proof.aggregate_root().unwrap()).unwrap();
}

#[test]
fn explicit_variant_keeps_unused_hash_airs() {
    let proof = prove_precompiles_with_variant(
        vec![witness(PvmAirVariant::NONE)],
        HashFunction::Blake3_256,
        PvmAirVariant::ALL,
    )
    .unwrap();
    assert_eq!(decode_proof(proof.proof.bytes()).unwrap().0, PvmAirVariant::ALL);
    verify_deferred(&proof.proof, proof.aggregate_root().unwrap()).unwrap();
}
