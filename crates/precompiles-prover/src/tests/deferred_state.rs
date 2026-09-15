use std::{format, string::String, vec, vec::Vec};

use k256::{ProjectivePoint, elliptic_curve::sec1::ToSec1Point};
use miden_air::lookup::Challenges;
use miden_core::{
    Felt,
    deferred::{Digest, Node as VmNode, PrecompileWitness, TRUE_DIGEST as VM_TRUE_DIGEST},
    field::{PrimeCharacteristicRing, QuadFelt},
    proof::{HashFunction, StarkProof},
    serde::{Deserializable, Serializable},
    utils::Matrix,
};
use miden_precompiles::{
    CurveId, CurvePrecompile, Keccak256Precompile, UintDomain, UintPrecompile,
};
use miden_precompiles_air::{NUM_CHIPLETS, memory, stark_config::precompile_pcs_params};
use miden_precompiles_verifier::{VerifyError, verify_deferred};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

use crate::{
    PrecompileProvingError, check_memory_budget,
    deferred::session::session_from_witnesses,
    hash::{
        chunk::{COL_F_BEGIN as CHUNK_COL_F_BEGIN, COL_F_END as CHUNK_COL_F_END},
        chunk_node::NODE_COL_OFFSET,
        chunk_node_sponge::{ChunkNodeSpongeAir, SPONGE_COL_OFFSET},
        keccak::{
            node::{
                COL_ABSORPTION_ID_CHUNKS as NODE_COL_ABSORPTION_ID_CHUNKS, COL_ACT as NODE_COL_ACT,
                COL_H_INPUT_CHUNKS_BEGIN, COL_N_CHUNKS as NODE_COL_N_CHUNKS,
            },
            sponge::{COL_ACT as SPONGE_COL_ACT, SPONGE_PERIOD, trace::keccak_oracle},
        },
    },
    logup::LookupMessage,
    math::{U256, from_hex, to_limbs32},
    prove_precompiles, prove_precompiles_with_budget,
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    session::{Session, SessionTraces},
    stark_config::DEFAULT_HASH_FUNCTION,
    tests::{
        SessionTracesTestExt, batch_witness::WitnessFixture, bus_balance::session_stack_residual,
        verify_deferred as verify_session,
    },
    transcript::eidos::{
        COL_CHAIN_HEAD_ID, EidosDigest, EidosOutMsg, NUM_MAIN_COLS as EIDOS_NUM_MAIN_COLS,
        compression::layout::{BLOCK_PERIOD as EIDOS_COMPRESSION_CYCLE_LEN, footer_digest_col},
    },
};

/// A raw Keccak-only portable fixture and the prover-typed view of its root.
#[derive(Debug)]
struct SyntheticKeccakWitness {
    state: WitnessFixture,
    input_digest: Digest,
    expected_digest: Digest,
    assertion_digest: Digest,
    vm_root: Digest,
    root: EidosDigest,
}

/// Builds the Keccak-only committed graph for `input`:
/// `AND(TRUE_DIGEST, Keccak256Assert(chunks(input), chunks(keccak256(input))))`.
fn synthetic_keccak_state(input: &[u8]) -> SyntheticKeccakWitness {
    let mut state = WitnessFixture::new();

    let input_digest = state
        .register(VmNode::chunks_from_bytes(input))
        .expect("VM should register input chunks");
    let expected_digest = state
        .register(VmNode::chunks(keccak_digest_chunks(input)).expect("digest chunks are non-empty"))
        .expect("VM should register expected digest chunks");
    let assertion_digest = state
        .register(Keccak256Precompile::assert_node(
            len_bytes(input),
            input_digest,
            expected_digest,
        ))
        .expect("Keccak assertion should register structurally");

    let vm_root = state
        .log_statement(assertion_digest)
        .expect("true Keccak assertion should log into the deferred root");
    debug_assert_eq!(vm_root, VmNode::and(VM_TRUE_DIGEST, assertion_digest).digest());
    debug_assert_eq!(state.root(), vm_root);

    SyntheticKeccakWitness {
        state,
        input_digest,
        expected_digest,
        assertion_digest,
        vm_root,
        root: EidosDigest::from(vm_root),
    }
}

fn keccak_session_traces(input: &[u8]) -> SessionTraces {
    let mut session = Session::new();
    let (_, claim) = session.keccak(input);
    let root = session.assert_and_fold([claim]);
    session.finish(root)
}

fn keccak_digest_chunks(input: &[u8]) -> Vec<[Felt; 8]> {
    vec![keccak_oracle(input).to_u32s().map(Felt::from_u32)]
}

fn len_bytes(input: &[u8]) -> u32 {
    u32::try_from(input.len()).expect("Keccak MVP inputs fit in a u32 byte-length parameter")
}

fn register_keccak_assertion(state: &mut WitnessFixture, input: &[u8]) -> Digest {
    let input_digest = state
        .register(VmNode::chunks_from_bytes(input))
        .expect("register Keccak input chunks");
    let expected_digest = state
        .register(VmNode::chunks(keccak_digest_chunks(input)).expect("digest chunks are non-empty"))
        .expect("register Keccak expected digest chunks");
    state
        .register(Keccak256Precompile::assert_node(
            u32::try_from(input.len()).expect("test input length fits u32"),
            input_digest,
            expected_digest,
        ))
        .expect("matching Keccak assertion registers")
}

fn register_uint_value(state: &mut WitnessFixture, domain: UintDomain, value: U256) -> Digest {
    state
        .register(UintPrecompile::value_node(domain, to_limbs32(value)))
        .expect("register uint value node")
}

fn register_uint_op(state: &mut WitnessFixture, op_id: u64, lhs: Digest, rhs: Digest) -> Digest {
    state
        .register(VmNode::join(UintPrecompile::op_frame(op_id), lhs, rhs).expect("uint op frame"))
        .expect("register uint op node")
}

fn register_curve_point(state: &mut WitnessFixture, curve: CurveId, x: U256, y: U256) -> Digest {
    let x_digest = register_uint_value(state, curve.base_domain(), x);
    let y_digest = register_uint_value(state, curve.base_domain(), y);
    state
        .register(CurvePrecompile::affine_node_from_digests(curve, x_digest, y_digest))
        .expect("register curve point value node")
}

fn register_curve_identity(state: &mut WitnessFixture, curve: CurveId) -> Digest {
    state
        .register(CurvePrecompile::identity_node(curve))
        .expect("register curve identity node")
}

fn register_curve_generator(state: &mut WitnessFixture, curve: CurveId) -> Digest {
    state
        .register(CurvePrecompile::generator_node(curve))
        .expect("register curve generator node")
}

fn register_curve_op(state: &mut WitnessFixture, op_id: u64, lhs: Digest, rhs: Digest) -> Digest {
    state
        .register(VmNode::join(CurvePrecompile::op_frame(op_id), lhs, rhs).expect("curve op frame"))
        .expect("register curve op node")
}

fn register_curve_msm(state: &mut WitnessFixture, pairs: Vec<(Digest, Digest)>) -> Digest {
    let n_pairs = u32::try_from(pairs.len()).expect("test MSM pair count fits in u32");
    state
        .register(
            VmNode::try_pair_list(CurvePrecompile::msm_frame(n_pairs), pairs)
                .expect("curve msm pair list is non-empty"),
        )
        .expect("register curve msm node")
}

fn be_to_u256(bytes: impl AsRef<[u8]>) -> U256 {
    let hex: String = bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    from_hex(&hex)
}

fn k256_coords(point: &ProjectivePoint) -> (U256, U256) {
    let enc = point.to_affine().to_sec1_point(false);
    (
        be_to_u256(enc.x().expect("finite point")),
        be_to_u256(enc.y().expect("finite point")),
    )
}

fn k1_points() -> [(U256, U256); 3] {
    let g = ProjectivePoint::GENERATOR;
    let g2 = g + g;
    let g3 = g + g + g;
    [k256_coords(&g), k256_coords(&g2), k256_coords(&g3)]
}

fn all_node_vm_state() -> WitnessFixture {
    let mut state = WitnessFixture::new();

    let curve = CurveId::Secp256k1;
    let domain = UintDomain::K1Base;
    let scalar_domain = curve.scalar_domain();
    let [(gx, gy), (g2x, g2y), (g3x, g3y)] = k1_points();

    let mut claims = Vec::new();

    claims.push(register_keccak_assertion(&mut state, b"all-node synthetic dag"));

    let u11 = register_uint_value(&mut state, domain, U256::from(11u8));
    let u7 = register_uint_value(&mut state, domain, U256::from(7u8));

    let add = register_uint_op(&mut state, UintPrecompile::ADD_OP_ID, u11, u7);
    let add_expected = register_uint_value(&mut state, domain, U256::from(18u8));
    claims.push(register_uint_op(&mut state, UintPrecompile::EQ_OP_ID, add, add_expected));

    let sub = register_uint_op(&mut state, UintPrecompile::SUB_OP_ID, u11, u7);
    let sub_expected = register_uint_value(&mut state, domain, U256::from(4u8));
    claims.push(register_uint_op(&mut state, UintPrecompile::EQ_OP_ID, sub, sub_expected));

    let mul = register_uint_op(&mut state, UintPrecompile::MUL_OP_ID, u11, u7);
    let mul_expected = register_uint_value(&mut state, domain, U256::from(77u8));
    claims.push(register_uint_op(&mut state, UintPrecompile::EQ_OP_ID, mul, mul_expected));

    let g_digest = register_curve_point(&mut state, curve, gx, gy);
    let g2_digest = register_curve_point(&mut state, curve, g2x, g2y);
    let g3_digest = register_curve_point(&mut state, curve, g3x, g3y);
    let inf_digest = register_curve_identity(&mut state, curve);

    claims.push(register_curve_op(&mut state, CurvePrecompile::EQ_OP_ID, inf_digest, inf_digest));

    let add_digest = register_curve_op(&mut state, CurvePrecompile::ADD_OP_ID, g_digest, g2_digest);
    claims.push(register_curve_op(&mut state, CurvePrecompile::EQ_OP_ID, add_digest, g3_digest));

    let sub_digest = register_curve_op(&mut state, CurvePrecompile::SUB_OP_ID, g3_digest, g_digest);
    claims.push(register_curve_op(&mut state, CurvePrecompile::EQ_OP_ID, sub_digest, g2_digest));

    let one_digest = register_uint_value(&mut state, scalar_domain, from_hex("1"));
    let msm_digest =
        register_curve_msm(&mut state, vec![(g_digest, one_digest), (g2_digest, one_digest)]);
    claims.push(register_curve_op(&mut state, CurvePrecompile::EQ_OP_ID, msm_digest, g3_digest));

    for claim in claims {
        state.log_statement(claim).expect("truthy synthetic claim logs");
    }

    state
}

fn translated_traces_check(state: &WitnessFixture) {
    let traces = session_from_witnesses(vec![state.witness()]).unwrap().finish();
    assert_eq!(traces.public_root(), EidosDigest::from(state.root()));
    traces.check();
}

fn prove_fixture(
    state: &WitnessFixture,
    hash_fn: HashFunction,
) -> Result<StarkProof, PrecompileProvingError> {
    Ok(prove_precompiles(vec![state.witness()], hash_fn)?.proof)
}

#[test]
fn shared_truthy_dag_from_wire_proves_and_verifies() {
    // Includes Keccak, uint and EC equality leaves, plus nested arithmetic and MSM claims.
    let mut state = all_node_vm_state();
    for _ in 0..8 {
        state.log_statement(state.root()).unwrap();
    }
    let bytes = state.witness().to_bytes();
    let witness = PrecompileWitness::read_from_bytes(&bytes).unwrap();
    let traces = session_from_witnesses(vec![witness]).unwrap().finish();
    assert_eq!(traces.public_root(), EidosDigest::from(state.root()));
    traces.check();
    let verified = verify_session(&traces.prove()).expect("shared truthy DAG proof must verify");
    assert_eq!(verified, state.root());
}

#[test]
fn synthetic_keccak_deferred_state_reconstructs_root() {
    let input: Vec<u8> = (0u8..33).collect();
    let synthetic = synthetic_keccak_state(&input);

    assert_eq!(synthetic.state.root(), synthetic.vm_root);
    assert_eq!(
        synthetic.vm_root,
        VmNode::and(VM_TRUE_DIGEST, synthetic.assertion_digest).digest(),
    );
    assert_eq!(synthetic.root, EidosDigest::from(synthetic.vm_root));
    assert!(synthetic.state.get_node(&synthetic.input_digest).is_some());
    assert!(synthetic.state.get_node(&synthetic.expected_digest).is_some());
    assert!(synthetic.state.get_node(&synthetic.assertion_digest).is_some());
}

#[test]
fn session_public_root_matches_synthetic_deferred_state_for_keccak_inputs() {
    let cases: [(&str, Vec<u8>); 9] = [
        ("empty", Vec::new()),
        ("short", b"abc".to_vec()),
        ("one_chunk_minus_one_limb", vec![0xa5; 31]),
        ("one_chunk", vec![0xa5; 32]),
        ("two_chunks", vec![0xa5; 33]),
        ("keccak_rate_boundary", vec![0xa5; 136]),
        ("post_keccak_rate_boundary", vec![0xa5; 137]),
        ("trailing_zero", b"abc\0".to_vec()),
        ("explicit_padding_zeroes", vec![0, 0, 0, 0, 0]),
    ];

    for (name, input) in cases {
        let synthetic = synthetic_keccak_state(&input);
        let traces = keccak_session_traces(&input);
        assert_eq!(traces.public_root(), synthetic.root, "case {name}");
    }
}

#[test]
fn session_public_root_matches_synthetic_deferred_state_for_all_supported_node_types() {
    translated_traces_check(&all_node_vm_state());
}

#[test]
fn deferred_session_translates_curve_claims_for_all_fixed_curves() {
    let mut state = WitnessFixture::new();

    for curve in CurveId::ALL {
        let identity = register_curve_identity(&mut state, curve);
        let generator = register_curve_generator(&mut state, curve);

        let identity_eq =
            register_curve_op(&mut state, CurvePrecompile::EQ_OP_ID, identity, identity);
        state.log_statement(identity_eq).expect("identity equality logs");

        let generator_eq =
            register_curve_op(&mut state, CurvePrecompile::EQ_OP_ID, generator, generator);
        state.log_statement(generator_eq).expect("generator equality logs");

        let sum = register_curve_op(&mut state, CurvePrecompile::ADD_OP_ID, generator, identity);
        let sum_eq = register_curve_op(&mut state, CurvePrecompile::EQ_OP_ID, sum, generator);
        state.log_statement(sum_eq).expect("generator plus identity logs");
    }

    translated_traces_check(&state);
}

#[test]
fn deferred_state_accepts_msm_with_all_zero_scalars() {
    // 0·P = 𝒪, checked against an independently committed identity point.
    let mut state = WitnessFixture::new();

    let curve = CurveId::Secp256k1;
    let point = register_curve_generator(&mut state, curve);
    let scalar = register_uint_value(&mut state, curve.scalar_domain(), U256::ZERO);
    let msm = register_curve_msm(&mut state, vec![(point, scalar)]);
    let identity = register_curve_identity(&mut state, curve);
    let msm_eq = register_curve_op(&mut state, CurvePrecompile::EQ_OP_ID, msm, identity);
    state.log_statement(msm_eq).expect("all-zero MSM equality logs");

    translated_traces_check(&state);
}

#[test]
fn deferred_state_accepts_msm_with_repeated_base() {
    // a·P + b·P = (a + b)·P, checked against an independently committed `5·G`.
    let mut state = WitnessFixture::new();

    let curve = CurveId::Secp256k1;
    let point = register_curve_generator(&mut state, curve);
    let two = register_uint_value(&mut state, curve.scalar_domain(), U256::from(2u64));
    let three = register_uint_value(&mut state, curve.scalar_domain(), U256::from(3u64));
    let msm = register_curve_msm(&mut state, vec![(point, two), (point, three)]);
    let five_g = ProjectivePoint::GENERATOR * k256::Scalar::from(5u64);
    let (fx, fy) = k256_coords(&five_g);
    let five_g_node = register_curve_point(&mut state, curve, fx, fy);
    let msm_eq = register_curve_op(&mut state, CurvePrecompile::EQ_OP_ID, msm, five_g_node);
    state.log_statement(msm_eq).expect("repeated-base MSM equality logs");

    translated_traces_check(&state);
}

#[test]
fn trailing_zero_input_changes_root() {
    let abc = synthetic_keccak_state(b"abc");
    let abc_zero = synthetic_keccak_state(b"abc\0");

    // CHUNKS binds the padded Felt length, not the original byte length, so these inputs share the
    // same one-block encoding. The Keccak assertion frame's `len_bytes` and digest child
    // distinguish them.
    assert_eq!(abc.input_digest, abc_zero.input_digest);
    assert_ne!(abc.expected_digest, abc_zero.expected_digest);
    assert_ne!(abc.assertion_digest, abc_zero.assertion_digest);
    assert_ne!(abc.root, abc_zero.root);

    let abc_traces = keccak_session_traces(b"abc");
    let abc_zero_traces = keccak_session_traces(b"abc\0");
    assert_eq!(abc_traces.public_root(), abc.root);
    assert_eq!(abc_zero_traces.public_root(), abc_zero.root);
    assert_ne!(abc_traces.public_root(), abc_zero_traces.public_root());
}

#[test]
fn keccak_deferred_state_proof_verifies_and_rejects_trailing_bytes() {
    let input = b"abc";
    let synthetic = synthetic_keccak_state(input);
    let traces = session_from_witnesses(vec![synthetic.state.witness()]).unwrap().finish();
    assert_eq!(traces.public_root(), synthetic.root);

    let proof = traces.prove();
    assert_eq!(EidosDigest::from(proof.1), synthetic.root);
    verify_session(&proof).expect("Keccak deferred-state proof should verify");

    // The proof encoding is exact: an otherwise-valid proof with a trailing byte is rejected.
    let stark = prove_fixture(&synthetic.state, DEFAULT_HASH_FUNCTION)
        .expect("Keccak deferred state should prove");
    let mut proof_bytes = stark.bytes().to_vec();
    proof_bytes.push(0);
    let trailing = StarkProof::new(proof_bytes, stark.hash_fn());
    let err = verify_deferred(&trailing, synthetic.vm_root)
        .expect_err("trailing proof bytes must be rejected");
    assert!(matches!(
        err,
        VerifyError::Deserialization(wincode::error::ReadError::TrailingBytes)
    ));
}

#[test]
fn prove_deferred_state_proves_non_empty_root() {
    let synthetic = synthetic_keccak_state(b"abc");

    let proof = prove_fixture(&synthetic.state, DEFAULT_HASH_FUNCTION)
        .expect("Keccak deferred state should prove");

    verify_deferred(&proof, synthetic.vm_root).expect("Keccak deferred-state proof should verify");
    assert!(
        verify_deferred(&proof, VM_TRUE_DIGEST).is_err(),
        "the proof must be bound to the state's exact root",
    );
}

#[test]
fn insufficient_budget_rejects_before_building_traces() {
    // Observe the real trace-building entry point without allocating an oversized witness.
    struct RejectTraceBuild;
    impl tracing::Subscriber for RejectTraceBuild {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            assert_ne!(attrs.metadata().name(), "build_trace", "budget must be checked first");
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, _: &tracing::Event<'_>) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    let witness = synthetic_keccak_state(b"abc").state.witness();
    tracing::subscriber::with_default(RejectTraceBuild, || {
        assert!(matches!(
            prove_precompiles_with_budget(vec![witness], HashFunction::Blake3_256, 0),
            Err(PrecompileProvingError::MemoryBudgetExceeded { budget_bytes: 0, .. })
        ));
    });
}

#[test]
fn memory_estimate_overflow_is_distinct_from_exceeding_the_budget() {
    assert!(matches!(
        check_memory_budget(None, u64::MAX),
        Err(PrecompileProvingError::MemoryEstimateOverflow)
    ));
    assert!(matches!(
        check_memory_budget(Some(u64::MAX), u64::MAX - 1),
        Err(PrecompileProvingError::MemoryBudgetExceeded {
            estimated_bytes: u64::MAX,
            budget_bytes
        }) if budget_bytes == u64::MAX - 1
    ));
}

/// Tests the exact byte-budget boundary computed from actual padded chiplet heights.
#[test]
fn prove_precompiles_with_budget_corner_cases() {
    let synthetic = synthetic_keccak_state(b"abc");

    // Measure the exact modelled peak for the state's real (small) padded chiplet heights.
    let traces = session_from_witnesses(vec![synthetic.state.witness()])
        .expect("Keccak-only witness should import")
        .finish();
    let heights: [usize; NUM_CHIPLETS] = traces.mains().map(Matrix::height);
    let params = precompile_pcs_params();
    let exact_peak = memory::prover_peak_bytes(&heights, &params, HashFunction::Blake3_256)
        .expect("modelled peak fits in u64");

    // At the exact peak, the budget check passes and the state proves.
    prove_precompiles_with_budget(
        vec![synthetic.state.witness()],
        HashFunction::Blake3_256,
        exact_peak,
    )
    .expect("budget equal to the exact modelled peak must succeed");

    // One byte under the exact peak, the budget check must fail with the typed error.
    let err = prove_precompiles_with_budget(
        vec![synthetic.state.witness()],
        HashFunction::Blake3_256,
        exact_peak - 1,
    )
    .expect_err("budget one byte under the exact modelled peak must fail");
    assert!(
        matches!(
            err,
            PrecompileProvingError::MemoryBudgetExceeded { estimated_bytes, budget_bytes }
                if estimated_bytes == exact_peak && budget_bytes == exact_peak - 1
        ),
        "expected MemoryBudgetExceeded {{ estimated_bytes: {exact_peak}, budget_bytes: {} }}, \
         got: {err:?}",
        exact_peak - 1
    );
}

/// Each `HashFunction` selects a distinct preprocessed-bundle cache slot
/// (`miden_precompiles_air::preprocessed`, keyed by LMCS type). Proving and
/// verifying twice per hash function exercises both the cold path (first
/// call in the process, builds and caches the bundle) and the warm path
/// (later calls, reused from cache) for every slot, guarding against a
/// mismatched or stale cached bundle being reused across hash functions.
#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn prove_deferred_state_round_trips_for_every_hash_function() {
    let synthetic = synthetic_keccak_state(b"abc");
    let hash_fns = [
        HashFunction::Eidos,
        HashFunction::Blake3_256,
        HashFunction::Rpo256,
        HashFunction::Rpx256,
        HashFunction::Poseidon2,
        HashFunction::Keccak,
    ];

    for hash_fn in hash_fns {
        for pass in 0..2 {
            let proof = prove_fixture(&synthetic.state, hash_fn)
                .unwrap_or_else(|e| panic!("{hash_fn:?} pass {pass} should prove: {e}"));
            verify_deferred(&proof, synthetic.vm_root)
                .unwrap_or_else(|e| panic!("{hash_fn:?} pass {pass} should verify: {e}"));
        }
    }
}

/// Reconstruct the full eleven-chiplet LogUp balance, including verifier-side fixed-boundary
/// consumes. This checks the generated traces against each AIR's lookup evaluator;
/// relation-level tests cover the external balance assertion separately.
fn assert_session_balanced(traces: &SessionTraces, rng: &mut impl Rng) {
    let challenges = Challenges::new(
        QuadFelt::new([Felt::new(rng.random()).unwrap(), Felt::new(rng.random()).unwrap()]),
        QuadFelt::new([Felt::new(rng.random()).unwrap(), Felt::new(rng.random()).unwrap()]),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let mains = traces.mains();
    let residual = session_stack_residual(&mains, &[], &challenges);
    assert!(
        residual.is_empty(),
        "session stack imbalance: {} unmatched denom(s); e.g. net {:?} on {}",
        residual.len(),
        residual.first().map(|(m, _)| *m),
        residual.first().map(|(_, s)| s.as_str()).unwrap_or(""),
    );
}

/// Exercises the merged sponge band on multi-block (`> 136`-byte) messages.
/// The default full-proof fixtures use the single-block input `b"abc"`; this
/// test covers cross-block state, invocation seams, overshoot lanes, padding,
/// and final squeezing through both constraint and bus-balance checks.
#[test]
fn merged_chunk_node_sponge_multi_block_checks_and_balances() {
    let mut rng = StdRng::seed_from_u64(0xc0de_5b09);
    // 136..144: every padding byte offset after the rate boundary (pad in block 2).
    // 271: rate boundary − 1 across two blocks. 300, 407: overshoot variety.
    for len in (136usize..144).chain([271, 300, 407]) {
        let input: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let traces = keccak_session_traces(&input);
        // Inspect the production merged band rather than inferring activity from the input. This
        // fails if trace construction silently truncates the sponge invocation.
        let merged = traces.mains()[0];
        let active_sponge_rows = merged
            .values
            .chunks_exact(merged.width)
            .filter(|row| row[SPONGE_COL_OFFSET + SPONGE_COL_ACT] == Felt::ONE)
            .count();
        assert!(
            active_sponge_rows > SPONGE_PERIOD,
            "case len={len} must activate more than one sponge block, got {active_sponge_rows} rows"
        );
        traces.check();
        assert_session_balanced(&traces, &mut rng);
    }
}

/// The generic chunk and Eidos AIRs do not interpret the CHUNKS frame. The Keccak-node owner binds
/// its claimed chunk count into both the Eidos initial CV and the consumed `(head, tail, digest)`
/// relation. This mutant changes only that owner-supplied count. It remains locally admissible for
/// a single invocation, but cannot balance against the unchanged chunk and Eidos traces.
#[test]
fn keccak_node_chunk_count_is_bound_by_cross_air_relations() {
    let traces = keccak_session_traces(&[0xa5; 33]);
    let mains = traces.mains();
    let n_chunks_col = NODE_COL_OFFSET + NODE_COL_N_CHUNKS;

    let challenges = Challenges::new(
        QuadFelt::from_u64(101),
        QuadFelt::from_u64(103),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    assert_eq!(mains[0].values[n_chunks_col], Felt::from_u8(2));

    for forged_count in [Felt::ZERO, Felt::from_u8(3), -Felt::ONE] {
        let mut forged = mains[0].clone();
        forged.values[n_chunks_col] = forged_count;

        // There is one active Keccak-node row, so changing its count does not violate the owner's
        // row-to-row layout constraints. Soundness comes from its cross-AIR frame and span
        // messages.
        crate::tests::check_local(ChunkNodeSpongeAir, &forged);

        let residual = session_stack_residual(&mains, &[(0, &forged)], &challenges);
        assert!(
            !residual.is_empty(),
            "forged CHUNKS count {forged_count} must unbalance the bus"
        );
    }
}

/// The output relation must bind both ends of an Eidos chain. A tail-only relation cannot
/// distinguish the last Keccak owner claiming the digest of the chain immediately before its own:
/// setting its chunk count to zero makes its derived tail `head - 1`. This test isolates that
/// decisive relation seam; it does not reproduce every coordinated mutation needed by a
/// tail-only interface.
#[test]
fn chain_head_distinguishes_a_crossed_terminal_digest_request() {
    let mut session = Session::new();
    let (_, first_claim) = session.keccak(&[0x11; 33]);
    let (_, second_claim) = session.keccak(&[0xa5; 33]);
    let root = session.assert_and_fold([first_claim, second_claim]);
    let traces = session.finish(root);
    let mains = traces.mains();

    let owner = mains[0];
    let owner_width = owner.width;
    let active_rows: Vec<_> = owner
        .values
        .chunks_exact(owner_width)
        .enumerate()
        .filter_map(|(row_idx, row)| {
            (row[NODE_COL_OFFSET + NODE_COL_ACT] == Felt::ONE).then_some(row_idx)
        })
        .collect();
    assert_eq!(active_rows.len(), 2);

    let second_row_idx = active_rows[1];
    let second_row =
        &owner.values[second_row_idx * owner_width..(second_row_idx + 1) * owner_width];
    let new_head = second_row[NODE_COL_OFFSET + NODE_COL_ABSORPTION_ID_CHUNKS];
    let new_head_idx = new_head.as_canonical_u64() as usize;
    assert!(new_head_idx > 0);
    let old_tail = new_head - Felt::ONE;

    let compression = mains[1];
    let old_tail_idx = new_head_idx - 1;
    let old_head = compression.values
        [old_tail_idx * EIDOS_COMPRESSION_CYCLE_LEN * EIDOS_NUM_MAIN_COLS + COL_CHAIN_HEAD_ID];
    let old_footer = (old_tail_idx + 1) * EIDOS_COMPRESSION_CYCLE_LEN - 1;
    let old_digest = core::array::from_fn(|idx| {
        compression.values[old_footer * EIDOS_NUM_MAIN_COLS + footer_digest_col(idx)]
    });
    assert_eq!(old_head, old_tail, "the preceding chain must be a one-block chain");
    assert_ne!(new_head, old_head);

    let challenges = Challenges::new(
        QuadFelt::from_u64(101),
        QuadFelt::from_u64(103),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let previous_provider = EidosOutMsg {
        chain_head_id: old_head,
        compression_id: old_tail,
        digest: old_digest,
    }
    .encode(&challenges);
    let crossed_request = EidosOutMsg {
        chain_head_id: new_head,
        compression_id: old_tail,
        digest: old_digest,
    }
    .encode(&challenges);
    let tail_only_previous = [old_tail, old_digest[0], old_digest[1], old_digest[2], old_digest[3]];
    let tail_only_crossed =
        [new_head - Felt::ONE, old_digest[0], old_digest[1], old_digest[2], old_digest[3]];
    assert_eq!(
        tail_only_crossed, tail_only_previous,
        "a tail-only relation would alias the crossed request with the previous provider",
    );
    assert_ne!(
        crossed_request, previous_provider,
        "the chain head must distinguish the crossed request from the previous provider",
    );

    let mut forged_owner = owner.clone();
    let forged_row =
        &mut forged_owner.values[second_row_idx * owner_width..(second_row_idx + 1) * owner_width];
    forged_row[NODE_COL_OFFSET + NODE_COL_N_CHUNKS] = Felt::ZERO;
    forged_row[NODE_COL_OFFSET + COL_H_INPUT_CHUNKS_BEGIN
        ..NODE_COL_OFFSET + COL_H_INPUT_CHUNKS_BEGIN + old_digest.len()]
        .copy_from_slice(&old_digest);

    // This is the final active owner row, so neither mutation violates its local layout. The
    // full relation set rejects it. The direct comparison above isolates the head field; this
    // integration check also confirms that the composed trace does not accept the malformed owner.
    crate::tests::check_local(ChunkNodeSpongeAir, &forged_owner);
    let residual = session_stack_residual(&mains, &[(0, &forged_owner)], &challenges);
    assert!(!residual.is_empty(), "the crossed terminal digest must not balance");
}

/// Chunk contents are locally unconstrained because their two consumers authenticate them: the
/// downstream sponge fixes Memory64 order, while EidosBlock fixes physical compression order.
/// Swapping two blocks therefore preserves the owner AIR's local equations but must break the
/// cross-AIR relations.
#[test]
fn reordering_chunks_within_an_eidos_chain_unbalances_the_bus() {
    let traces = keccak_session_traces(&[0xa5; 33]);
    let mains = traces.mains();
    let mut forged = mains[0].clone();
    let width = forged.width;

    assert_ne!(
        &forged.values[CHUNK_COL_F_BEGIN..CHUNK_COL_F_END],
        &forged.values[width + CHUNK_COL_F_BEGIN..width + CHUNK_COL_F_END],
        "the two input chunks must differ for the reorder mutant"
    );
    for col in CHUNK_COL_F_BEGIN..CHUNK_COL_F_END {
        forged.values.swap(col, width + col);
    }

    crate::tests::check_local(ChunkNodeSpongeAir, &forged);

    let challenges = Challenges::new(
        QuadFelt::from_u64(101),
        QuadFelt::from_u64(103),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let residual = session_stack_residual(&mains, &[(0, &forged)], &challenges);
    assert!(!residual.is_empty(), "reordered chunks must unbalance the bus");
}

/// Explicit full prove+verify of a multi-block Keccak session — the
/// end-to-end counterpart to the fast check/balance guard above, closing
/// the merged-AIR multi-block gap through the real STARK path.
#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn prove_deferred_state_round_trips_for_multi_block_keccak() {
    let synthetic = synthetic_keccak_state(&(0u8..200).collect::<Vec<u8>>());
    let proof = prove_fixture(&synthetic.state, DEFAULT_HASH_FUNCTION)
        .expect("multi-block keccak session should prove");
    verify_deferred(&proof, synthetic.vm_root).expect("multi-block keccak session should verify");
}
