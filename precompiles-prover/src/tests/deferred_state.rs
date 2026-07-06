use std::{format, string::String, sync::Arc, vec, vec::Vec};

use k256::{ProjectivePoint, elliptic_curve::sec1::ToEncodedPoint};
use miden_core::{
    Felt,
    deferred::{
        DeferredState, DeferredStateWire, Digest, Node as VmNode, PrecompileRegistry,
        TRUE_DIGEST as VM_TRUE_DIGEST, TRUE_INDEX, Tag, WireEntry,
    },
    proof::{DeferredProof, HashFunction},
};
use miden_precompiles::{
    CurveId, CurvePrecompile, Keccak256Precompile, UintDomain, UintPrecompile,
};

use crate::{
    deferred::{DeferredSession, session_from_deferred_state},
    hash::keccak::sponge::trace::keccak_oracle,
    math::{U256, from_hex, to_limbs32},
    prove_deferred_state,
    session::{Session, SessionTraces, verify_deferred},
    transcript::poseidon2::P2Digest,
};

/// A VM synthetic Keccak-only deferred state and the prover-typed view of its root.
#[derive(Debug)]
struct SyntheticKeccakDeferredState {
    state: DeferredState,
    input_digest: Digest,
    expected_digest: Digest,
    assertion_digest: Digest,
    vm_root: Digest,
    root: P2Digest,
}

/// Builds the Keccak-only VM deferred state for `input`:
/// `AND(TRUE_DIGEST, Keccak256Assert(chunks(input), chunks(keccak256(input))))`.
fn synthetic_keccak_state(input: &[u8]) -> SyntheticKeccakDeferredState {
    let registry =
        Arc::new(PrecompileRegistry::new().with_precompile(Keccak256Precompile::default()));
    let mut state = DeferredState::new(registry, usize::MAX)
        .expect("Keccak-only VM deferred state should initialize");

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
        .expect("VM Keccak assertion should evaluate to TRUE");

    let vm_root = state
        .log_statement(assertion_digest)
        .expect("true Keccak assertion should log into the deferred root");
    debug_assert_eq!(vm_root, VmNode::and(VM_TRUE_DIGEST, assertion_digest).digest());
    debug_assert_eq!(state.root(), vm_root);

    SyntheticKeccakDeferredState {
        state,
        input_digest,
        expected_digest,
        assertion_digest,
        vm_root,
        root: P2Digest::from(vm_root),
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
    u32::try_from(input.len()).expect("Keccak MVP inputs fit in a VM u32 length tag")
}

fn register_keccak_assertion(state: &mut DeferredState, input: &[u8]) -> Digest {
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

fn register_uint_value(state: &mut DeferredState, domain: UintDomain, value: U256) -> Digest {
    state
        .register(UintPrecompile::value_node(domain, to_limbs32(value)))
        .expect("register uint value node")
}

fn register_uint_op(state: &mut DeferredState, op_id: u64, lhs: Digest, rhs: Digest) -> Digest {
    state
        .register(VmNode::join(UintPrecompile::op_tag(op_id), lhs, rhs).expect("uint op tag"))
        .expect("register uint op node")
}

fn register_curve_point(state: &mut DeferredState, curve: CurveId, x: U256, y: U256) -> Digest {
    let x_digest = register_uint_value(state, curve.base_domain(), x);
    let y_digest = register_uint_value(state, curve.base_domain(), y);
    state
        .register(CurvePrecompile::affine_node_from_digests(curve, x_digest, y_digest))
        .expect("register curve point value node")
}

fn register_curve_identity(state: &mut DeferredState, curve: CurveId) -> Digest {
    state
        .register(CurvePrecompile::identity_node(curve))
        .expect("register curve identity node")
}

fn register_curve_generator(state: &mut DeferredState, curve: CurveId) -> Digest {
    state
        .register(CurvePrecompile::generator_node(curve))
        .expect("register curve generator node")
}

fn register_curve_op(state: &mut DeferredState, op_id: u64, lhs: Digest, rhs: Digest) -> Digest {
    state
        .register(VmNode::join(CurvePrecompile::op_tag(op_id), lhs, rhs).expect("curve op tag"))
        .expect("register curve op node")
}

fn register_curve_msm(state: &mut DeferredState, pairs: Vec<(Digest, Digest)>) -> Digest {
    state
        .register(
            VmNode::try_pair_list(CurvePrecompile::msm_tag(), pairs)
                .expect("curve msm pair list is non-empty"),
        )
        .expect("register curve msm node")
}

fn be_to_u256(bytes: impl AsRef<[u8]>) -> U256 {
    let hex: String = bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    from_hex(&hex)
}

fn k256_coords(point: &ProjectivePoint) -> (U256, U256) {
    let enc = point.to_affine().to_encoded_point(false);
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

fn all_node_vm_state() -> DeferredState {
    let mut state = DeferredState::new(Arc::new(miden_precompiles::registry()), usize::MAX)
        .expect("full precompile registry initializes");

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

fn translated_traces_check(state: &DeferredState) {
    let DeferredSession { session, root } = session_from_deferred_state(state).unwrap();
    assert_eq!(root.hash(), P2Digest::from(state.root()));
    let traces = session.finish(root);
    traces.check();
}

fn uint_value_entry(domain: UintDomain, value: U256) -> WireEntry {
    WireEntry::Data {
        tag: UintPrecompile::value_tag(domain),
        chunks: vec![to_limbs32(value).map(Felt::from_u32)],
    }
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
    assert_eq!(synthetic.root, P2Digest::from(synthetic.vm_root));
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
    let state = all_node_vm_state();
    let DeferredSession { session, root } = session_from_deferred_state(&state).unwrap();

    assert_eq!(root.hash(), P2Digest::from(state.root()));
    let traces = session.finish(root);
    traces.check();
}

#[test]
fn empty_deferred_state_translates_to_true_root() {
    let state = DeferredState::new(Arc::new(miden_precompiles::registry()), usize::MAX)
        .expect("full precompile registry initializes");

    translated_traces_check(&state);
}

#[test]
fn prove_deferred_state_returns_empty_for_true_root() {
    let state = DeferredState::new(Arc::new(miden_precompiles::registry()), usize::MAX)
        .expect("full precompile registry initializes");

    let proof = prove_deferred_state(&state, HashFunction::Blake3_256).unwrap();

    assert_eq!(proof, DeferredProof::Empty);
}

#[test]
fn deferred_session_translates_curve_claims_for_all_fixed_curves() {
    let mut state = DeferredState::new(Arc::new(miden_precompiles::registry()), usize::MAX)
        .expect("full precompile registry initializes");

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
fn deferred_session_translates_arbitrary_non_log_spine_truthy_root() {
    let wire = DeferredStateWire {
        entries: vec![
            WireEntry::Join {
                tag: Tag::AND,
                lhs: TRUE_INDEX,
                rhs: TRUE_INDEX,
            },
            WireEntry::Join { tag: Tag::AND, lhs: 1, rhs: 1 },
        ],
    };
    let state =
        DeferredState::from_wire(Arc::new(miden_precompiles::registry()), &wire, usize::MAX)
            .expect("AND-only wire state rehydrates");

    translated_traces_check(&state);
}

#[test]
fn deferred_session_translates_shared_uint_intermediate() {
    let domain = UintDomain::U256;
    let wire = DeferredStateWire {
        entries: vec![
            uint_value_entry(domain, U256::from(5u8)),
            uint_value_entry(domain, U256::from(7u8)),
            WireEntry::Join {
                tag: UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID),
                lhs: 1,
                rhs: 2,
            },
            uint_value_entry(domain, U256::from(12u8)),
            WireEntry::Join {
                tag: UintPrecompile::op_tag(UintPrecompile::EQ_OP_ID),
                lhs: 3,
                rhs: 4,
            },
            WireEntry::Join { tag: Tag::AND, lhs: 5, rhs: 5 },
        ],
    };
    let state =
        DeferredState::from_wire(Arc::new(miden_precompiles::registry()), &wire, usize::MAX)
            .expect("shared uint wire state rehydrates");

    translated_traces_check(&state);
}

#[test]
fn trailing_zero_input_changes_root() {
    let abc = synthetic_keccak_state(b"abc");
    let abc_zero = synthetic_keccak_state(b"abc\0");

    // Generic chunk nodes are lengthless: these inputs pack to the same single zero-padded chunk.
    // The Keccak assertion tag's `len_bytes` and digest child are what distinguish them.
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
fn keccak_deferred_state_root_proves_and_verifies() {
    let input = b"abc";
    let synthetic = synthetic_keccak_state(input);
    let DeferredSession { session, root } = session_from_deferred_state(&synthetic.state).unwrap();
    assert_eq!(root.hash(), synthetic.root);
    let traces = session.finish(root);
    assert_eq!(traces.public_root(), synthetic.root);

    let proof = traces.prove();
    let Some((_, public_root)) = proof.as_stark() else {
        panic!("precompile session should produce a deferred STARK proof");
    };
    assert_eq!(P2Digest::from(public_root), synthetic.root);
    verify_deferred(&proof).expect("Keccak deferred-state proof should verify");
}

#[test]
fn prove_deferred_state_proves_non_empty_root() {
    let synthetic = synthetic_keccak_state(b"abc");

    let proof = prove_deferred_state(&synthetic.state, HashFunction::Blake3_256)
        .expect("Keccak deferred state should prove");
    let Some((_, public_root)) = proof.as_stark() else {
        panic!("non-empty deferred state should produce a STARK-backed proof");
    };

    assert_eq!(P2Digest::from(public_root), synthetic.root);
    verify_deferred(&proof).expect("Keccak deferred-state proof should verify");
}
