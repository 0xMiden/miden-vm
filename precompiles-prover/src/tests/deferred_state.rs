use std::sync::Arc;

use k256::{ProjectivePoint, elliptic_curve::sec1::ToEncodedPoint};
use miden_core::{
    Felt,
    deferred::{DeferredState, Digest, Node as VmNode, TRUE_DIGEST as VM_TRUE_DIGEST},
};
use miden_precompiles::{
    CurveId, CurvePrecompile, Keccak256Precompile, UintDomain, UintPrecompile,
};

use crate::{
    deferred::synthetic_keccak_state,
    hash::keccak::sponge::trace::keccak_oracle,
    math::{U256, from_hex, to_limbs32},
    session::{Session, SessionTraces},
    transcript::poseidon2::P2Digest,
};

fn keccak_session_traces(input: &[u8]) -> SessionTraces {
    let mut session = Session::new();
    let (_, claim) = session.keccak(input);
    let root = session.assert_and_fold([claim]);
    session.finish(root)
}

fn keccak_digest_chunks(input: &[u8]) -> Vec<[Felt; 8]> {
    vec![keccak_oracle(input).to_u32s().map(Felt::from_u32)]
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

fn all_node_vm_root() -> Digest {
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

    state.root()
}

fn all_node_session_traces() -> SessionTraces {
    let curve = CurveId::Secp256k1;
    let fp = curve.base_domain().bound_ptr();
    let group_ptr = curve.group_ptr();
    let sn = curve.scalar_domain().bound_ptr();
    let [(gx, gy), (g2x, g2y), (g3x, g3y)] = k1_points();

    let mut session = Session::new();
    let mut claims = Vec::new();

    let (_, keccak_claim) = session.keccak(b"all-node synthetic dag");
    claims.push(keccak_claim);

    let u11 = session.uint_leaf(U256::from(11u8), fp);
    let u7 = session.uint_leaf(U256::from(7u8), fp);

    let add = session.uint_add(&u11, &u7);
    let add_expected = session.uint_leaf(U256::from(18u8), fp);
    claims.push(session.uint_is(&add, &add_expected));

    let sub = session.uint_sub(&u11, &u7);
    let sub_expected = session.uint_leaf(U256::from(4u8), fp);
    claims.push(session.uint_is(&sub, &sub_expected));

    let mul = session.uint_mul(&u11, &u7);
    let mul_expected = session.uint_leaf(U256::from(77u8), fp);
    claims.push(session.uint_is(&mul, &mul_expected));

    let inf = session.ec_pai(group_ptr);
    claims.push(session.ec_is(&inf, &inf));

    let create = |session: &mut Session, x: U256, y: U256| {
        let x_node = session.uint_leaf(x, fp);
        let y_node = session.uint_leaf(y, fp);
        session.ec_create(group_ptr, &x_node, &y_node)
    };

    let g_pt = create(&mut session, gx, gy);
    let g2_pt = create(&mut session, g2x, g2y);
    let g3_pt = create(&mut session, g3x, g3y);

    let add_pt = session.ec_add(&g_pt, &g2_pt);
    claims.push(session.ec_is(&add_pt, &g3_pt));

    let sub_pt = session.ec_sub(&g3_pt, &g_pt);
    claims.push(session.ec_is(&sub_pt, &g2_pt));

    let g_expr = session.msm_intro(&g_pt);
    let g2_expr = session.msm_intro(&g2_pt);
    let expr = session.msm_combine(g_expr, g2_expr);
    let one = session.uint_leaf(from_hex("1"), sn);
    let msm_value = session.ec_msm(expr, &[(g_pt, one), (g2_pt, one)]);
    claims.push(session.ec_is(&msm_value, &g3_pt));

    let root = session.assert_and_fold(claims);
    session.finish(root)
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
    let vm_root = all_node_vm_root();
    let traces = all_node_session_traces();

    assert_eq!(traces.public_root(), P2Digest::from(vm_root));
    traces.check();
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
    let traces = keccak_session_traces(input);
    assert_eq!(traces.public_root(), synthetic.root);

    let proof = traces.prove();
    assert_eq!(proof.public_root(), synthetic.root);
    proof.verify().expect("Keccak deferred-state proof should verify");
}
