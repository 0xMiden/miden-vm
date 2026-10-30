use miden_core::{
    Felt,
    field::{BasedVectorSpace, PrimeCharacteristicRing, QuadFelt},
    proof::{MAX_STARK_PROOF_BYTES, PrecompileProof},
};
use miden_processor::{ExecutionError, operation::OperationError};
use miden_serde_utils::deserialize_schema_exact;
use miden_stark::{
    StarkConfig, VerifierInstance,
    air::{MultiAir, Statement},
    config::{EidosConfig, observe_protocol_params},
    lmcs::proof::BatchProofView,
    proof::{StarkProof, StarkProofData},
    testing::{Coset, canonical_domain},
};
use rstest::rstest;
use serde_wincode::{SerdeCompat, wincode};

use crate::helpers::{masm_push_felts, masm_store_felts, read_memory_felt, stark_constant};

const QUERY_PTR: u32 = 1_000;
const FLAG_PTR: u32 = 2_000;
const DOMAIN_GENERATOR: u32 = 7;
const DOMAIN_OFFSET: u32 = 3;
const Q_X: [u32; 2] = [17, 19];
const Q_Z: [u32; 2] = [23, 29];
const Q_GZ: [u32; 2] = [31, 37];

/// Derives every sampled DEEP query from the native transcript and authenticated row openings.
/// Sampling order and duplicate indices are preserved; no MASM advice or memory enters the oracle.
fn native_queries<MA: MultiAir<Felt, QuadFelt>>(
    bytes: &[u8],
    config: &EidosConfig,
    statement: &Statement<Felt, QuadFelt, MA>,
    preprocessed: [u64; 4],
) -> Vec<[Felt; 4]> {
    let data =
        deserialize_schema_exact::<SerdeCompat<StarkProofData<Felt, QuadFelt, EidosConfig>>, _>(
            bytes,
            wincode::config::Configuration::default()
                .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>(),
        )
        .unwrap();
    let verifier = VerifierInstance::new(config, statement, Some(preprocessed.into())).unwrap();
    let mut challenger = config.challenger();
    observe_protocol_params(config.pcs(), &mut challenger);
    verifier
        .verify(&data, challenger.clone())
        .expect("native STARK verification must pass");
    let (proof, _) = StarkProof::from_data(&verifier, &data, challenger).unwrap();
    let domain = canonical_domain::<Felt>(
        *proof.log_trace_heights().iter().max().unwrap(),
        config.pcs().log_blowup(),
    );
    let pcs = &proof.pcs_proof;
    let deep = &pcs.deep_proof;
    let points = [proof.z, proof.z * domain.trace_subgroup().generator()];
    let reduced_ood: [QuadFelt; 2] = core::array::from_fn(|p| {
        deep.evals
            .iter()
            .flatten()
            .flat_map(|matrix| {
                assert_eq!(matrix.values.len(), points.len() * matrix.width);
                &matrix.values[p * matrix.width..(p + 1) * matrix.width]
            })
            .fold(QuadFelt::ZERO, |acc, value| acc * deep.challenge_columns + *value)
    });
    // A shorter commitment uses the low bits of the full-domain query index.
    let masks: Vec<_> = pcs
        .deep_witnesses
        .iter()
        .map(|batch| {
            let first = batch.indices().next().unwrap();
            (1usize << batch.path(first).unwrap().len()) - 1
        })
        .collect();
    pcs.query_indices
        .iter()
        .map(|&index| {
            let reduced_row = pcs
                .deep_witnesses
                .iter()
                .zip(&masks)
                .flat_map(|(batch, mask)| batch.opening(index & mask).unwrap().iter_values())
                .fold(QuadFelt::ZERO, |acc, value| acc * deep.challenge_columns + value);
            let point = domain.lde_coset().point_at(index as u64);
            let value = (reduced_ood[0] - reduced_row) / (points[0] - point)
                + deep.challenge_points * (reduced_ood[1] - reduced_row) / (points[1] - point);
            let coefficients = value.as_basis_coefficients_slice();
            [
                domain.lde_coset().subgroup().generator().exp_u64(index as u64),
                Felt::new_unchecked(index as u64),
                coefficients[0],
                coefficients[1],
            ]
        })
        .collect()
}

fn assert_stored_queries(test: &miden_utils_testing::Test, expected: &[[Felt; 4]]) {
    assert!(
        expected.windows(2).any(|pair| pair[0][1] != pair[1][1]),
        "fixture must distinguish a repeated-query bug"
    );
    let (processor, ctx) = super::ace_read_check::execute_verifier(test);
    let read = |addr| processor.memory().read_element(ctx, Felt::from_u32(addr)).unwrap();
    assert_eq!(read(stark_constant("NUM_QUERIES_PTR")), Felt::from_usize(expected.len()));
    let start =
        u32::try_from(read(stark_constant("FRI_QUERIES_ADDRESS_PTR")).as_canonical_u64()).unwrap();
    assert_eq!(start + 4 * expected.len() as u32, stark_constant("FRI_COM_PTR"));
    for (slot, expected) in expected.iter().enumerate() {
        let actual: [Felt; 4] = core::array::from_fn(|lane| read(start + (4 * slot + lane) as u32));
        assert_eq!(actual, *expected, "stored FRI query {slot} differs from Rust");
    }
}

pub(super) fn check_vm_queries(source: &str) {
    use miden_air::vm::{MidenMultiAir, config};
    use miden_air_definitions::vm::PublicInputs;
    use miden_utils_testing::recursive_verifier::generate_advice_inputs;
    use miden_vm_stark::setup::config::eidos_config;

    let (proof, claim) = super::generate_recursive_proof(source, super::fib_stack_inputs(), None);
    let public_inputs = PublicInputs::new(
        claim.to_program_info(),
        *claim.stack_inputs(),
        *claim.stack_outputs(),
        proof.vm().precompile_root,
    );
    let (public_values, aux_inputs) = public_inputs.to_air_inputs();
    let statement =
        Statement::new(MidenMultiAir::new(), vec![(0, public_values)], aux_inputs).unwrap();
    let config = eidos_config(config::pcs_params(), config::RELATION_DIGEST);
    let expected = native_queries(
        proof.vm().proof.bytes(),
        &config,
        &statement,
        config::EIDOS_PREPROCESSED_COMMITMENT,
    );
    let data = generate_advice_inputs(super::vm_verify_proof_root(), &proof, &claim).unwrap();
    super::run_recursive_verifier(&data);
    let test = build_test!(
        &super::vm_verify_proof_program(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map
    );
    assert_stored_queries(&test, &expected);
}

pub(super) fn check_pvm_queries(test: &miden_utils_testing::Test, proof: &PrecompileProof) {
    use miden_air::precompiles::{
        ChipletAir, ChipletMultiAir, PVM_RELATION_DIGEST, policy::precompile_pcs_params,
        protocol::PVM_PREPROCESSED_COMMITMENT,
    };
    use miden_precompiles_stark::setup::config::eidos_config;

    let root = proof.aggregate_root().unwrap();
    let statement = Statement::new(
        ChipletMultiAir::new(),
        vec![(ChipletAir::TRANSCRIPT_EVAL_INDEX, root.as_elements().to_vec())],
        vec![],
    )
    .unwrap();
    let config =
        eidos_config(precompile_pcs_params(), PVM_RELATION_DIGEST.map(Felt::new_unchecked));
    let expected =
        native_queries(proof.proof.bytes(), &config, &statement, PVM_PREPROCESSED_COMMITMENT);
    assert_stored_queries(test, &expected);
}

fn quad(pair: [u32; 2]) -> QuadFelt {
    QuadFelt::new(pair.map(Felt::from_u32))
}

fn query_source(
    index: u32,
    z: QuadFelt,
    gz: QuadFelt,
    beta: QuadFelt,
    zero_numerators: bool,
) -> String {
    let mut points = (-z).as_basis_coefficients_slice().to_vec();
    points.extend_from_slice((-gz).as_basis_coefficients_slice());
    let (qx, qz, qgz) = if zero_numerators {
        ([0; 2], [0; 2], [0; 2])
    } else {
        (Q_X, Q_Z, Q_GZ)
    };
    let frame = [
        501,
        502,
        503,
        504,
        qx[0],
        qx[1],
        qx[0],
        qx[1],
        index,
        QUERY_PTR,
        QUERY_PTR + 8,
        qz[0],
        qz[1],
        qgz[0],
        qgz[1],
        QUERY_PTR,
    ]
    .map(Felt::from_u32);
    format!(
        "
        use {{LDE_DOMAIN_GENERATOR_PTR, DOMAIN_OFFSET_PTR}} from miden::core::stark::constants
        use miden::core::stark::deep_queries
        begin
            {points}
            {beta}
            push.{DOMAIN_GENERATOR} mem_store.LDE_DOMAIN_GENERATOR_PTR
            push.{DOMAIN_OFFSET} mem_store.DOMAIN_OFFSET_PTR
            {frame}
            exec.deep_queries::compute_deep_query
            mem_store.{FLAG_PTR}
            dropw
            repeat.7 drop end
        end
        ",
        points = masm_store_felts(&points, stark_constant("TMP1_PTR")),
        beta = masm_store_felts(
            beta.as_basis_coefficients_slice(),
            stark_constant("DEEP_COMPOSITION_COEFS_PTR"),
        ),
        frame = masm_push_felts(&frame),
    )
}

#[rstest]
#[case::zero_index_and_beta(0, [0, 0])]
#[case::unit_beta(1, [1, 0])]
#[case::maximum_index(u32::MAX, [13, 19])]
fn deep_query_matches_two_quotients(
    #[case] index: u32,
    #[case] beta: [u32; 2],
    #[values(false, true)] with_caller: bool,
) {
    let z = quad([3, 5]);
    let gz = quad([11, 13]);
    let beta = quad(beta);
    let source = query_source(index, z, gz, beta, false);
    let caller: [u64; 16] = core::array::from_fn(|i| 501 + i as u64);
    let inputs = if with_caller { caller.as_slice() } else { &[] };
    let test = build_test!(&source, inputs);
    let (output, _) = test.execute_for_output().unwrap();

    let poe = Felt::from_u32(DOMAIN_GENERATOR).exp_u64(u64::from(index));
    let x = QuadFelt::from(poe * Felt::from_u32(DOMAIN_OFFSET));
    let expected = (quad(Q_X) + quad(Q_Z)) / (x - z) + beta * ((quad(Q_X) + quad(Q_GZ)) / (x - gz));
    assert_eq!(read_memory_felt(&output, QUERY_PTR), poe);
    assert_eq!(read_memory_felt(&output, QUERY_PTR + 1), Felt::from_u32(index));
    let coefficients: &[Felt] = expected.as_basis_coefficients_slice();
    for (i, value) in coefficients.iter().enumerate() {
        assert_eq!(read_memory_felt(&output, QUERY_PTR + 2 + i as u32), *value);
    }
    assert_eq!(read_memory_felt(&output, FLAG_PTR), Felt::ONE);
    let expected_stack = if with_caller {
        caller.map(Felt::new_unchecked)
    } else {
        [Felt::ZERO; 16]
    };
    assert_eq!(output.stack.get_num_elements(16), expected_stack);
    test.check_constraints();
}

#[rstest]
#[case::z(true, false)]
#[case::gz(false, true)]
#[case::both(true, true)]
fn deep_query_rejects_zero_denominators_with_zero_numerators(
    #[case] zero_z: bool,
    #[case] zero_gz: bool,
) {
    let index = 3;
    let poe = Felt::from_u32(DOMAIN_GENERATOR).exp_u64(u64::from(index));
    let x = QuadFelt::from(poe * Felt::from_u32(DOMAIN_OFFSET));
    let z = if zero_z { x } else { quad([3, 5]) };
    let gz = if zero_gz { x } else { quad([11, 13]) };
    let source = query_source(index, z, gz, QuadFelt::ZERO, true);
    let error = build_test!(&source, &[])
        .execute()
        .expect_err("zero denominator must be rejected");
    assert!(matches!(
        error,
        ExecutionError::OperationError { err: OperationError::DivideByZero, .. }
    ));
}
