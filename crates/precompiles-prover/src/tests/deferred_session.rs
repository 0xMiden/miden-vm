use alloc::{vec, vec::Vec};

use miden_core::{
    Felt,
    deferred::{DEFERRED_AND_FRAME, Node, PrecompileWitness, TRUE_DIGEST},
    serde::{ByteWriter, Deserializable, Serializable},
};
use miden_crypto::hash::{keccak::Keccak256, sha2::Sha512};
use miden_precompiles::{
    CurveId, CurvePoint, CurvePrecompile, Keccak256Precompile, Sha512Precompile, UintDomain,
    UintPrecompile,
};

use crate::{
    deferred::session::session_from_witnesses,
    math::{U256, from_hex, to_limbs32},
    session::SessionTraces,
    tests::batch_witness::WitnessFixture,
    transcript::eval::{COL_ACT, COL_IS_AND, COL_OUT_MULT},
};

fn state() -> WitnessFixture {
    WitnessFixture::new()
}

fn limbs(value: u32) -> [u32; 8] {
    let mut limbs = [0; 8];
    limbs[0] = value;
    limbs
}

#[test]
fn deferred_session_binds_full_sha512_digests_in_a_mixed_hash_session() {
    let mut state = state();
    // [1] and [1,0] share raw zero-padded CHUNKS but have different lengths/digests. Repeating
    // [1] exercises multiplicities, and 112 bytes requires a second SHA padding block.
    for input in [vec![1], vec![1, 0], vec![1], vec![0xa5; 112]] {
        let preimage = state.register(Node::chunks_from_bytes(&input)).unwrap();
        let expected = state
            .register(Node::chunks_from_bytes(Sha512::hash(&input).as_bytes()))
            .unwrap();
        let assertion = state
            .register(Sha512Precompile::assert_node(input.len() as u32, preimage, expected))
            .unwrap();
        state.log_statement(assertion).unwrap();
    }
    // Keccak must remain able to reuse the raw Eidos span without sharing SHA's block IDs.
    let preimage = state.register(Node::chunks_from_bytes(&[1])).unwrap();
    let expected = state
        .register(Node::chunks_from_bytes(Keccak256::hash(&[1]).as_bytes()))
        .unwrap();
    let assertion =
        state.register(Keccak256Precompile::assert_node(1, preimage, expected)).unwrap();
    state.log_statement(assertion).unwrap();

    let imported = session_from_witnesses(vec![state.witness()])
        .expect("SHA-512 assertions must lower with their exact 64-byte expected digest");
    imported.finish().check();
}

#[test]
fn deferred_session_lowers_shared_uint_dag_from_wire() {
    let mut state = state();
    let zero = state
        .register(UintPrecompile::value_node(UintDomain::U256, limbs(0)))
        .expect("zero must register");
    let mut current = zero;
    // Only 24 operation nodes, but an uncached traversal expands over 16 million leaves.
    // Every expression evaluates to zero while retaining a distinct structural digest.
    for depth in 0..24 {
        let op = [UintPrecompile::ADD_OP_ID, UintPrecompile::SUB_OP_ID, UintPrecompile::MUL_OP_ID]
            [depth % 3];
        let node = Node::join(UintPrecompile::op_frame(op), current, current).unwrap();
        current = state.register(node).expect("shared uint expression must register");
    }
    let eq = Node::join(UintPrecompile::op_frame(UintPrecompile::EQ_OP_ID), current, zero).unwrap();
    let eq = state.register(eq).expect("equality must register");
    state.log_statement(eq).unwrap();
    state.log_statement(eq).unwrap();
    check_wire_session(state);
}

#[test]
fn deferred_session_lowers_shared_ec_dag_from_wire() {
    let mut state = state();
    let identity = state
        .register(CurvePrecompile::identity_node(CurveId::Secp256k1))
        .expect("identity must register");
    let mut current = identity;
    for depth in 0..24 {
        let op = [CurvePrecompile::ADD_OP_ID, CurvePrecompile::SUB_OP_ID][depth % 2];
        let node = Node::join(CurvePrecompile::op_frame(op), current, current).unwrap();
        current = state.register(node).expect("shared EC expression must register");
    }
    let eq = Node::join(CurvePrecompile::op_frame(CurvePrecompile::EQ_OP_ID), current, identity)
        .unwrap();
    let eq = state.register(eq).expect("equality must register");
    state.log_statement(eq).unwrap();
    state.log_statement(eq).unwrap();
    check_wire_session(state);
}

#[test]
fn deferred_session_lowers_exponential_and_dag_from_raw_wire() {
    for depth in [1_u32, 2, 4, 64] {
        // Start from untrusted bytes, not an in-memory state or private wire fields.
        let mut bytes = Vec::new();
        bytes.write_u8(PrecompileWitness::WIRE_VERSION);
        bytes.write_usize(depth as usize);
        for previous_index in 0..depth {
            bytes.write_u8(1); // Join entry
            DEFERRED_AND_FRAME.as_word().write_into(&mut bytes);
            bytes.write_u32(previous_index);
            bytes.write_u32(previous_index);
        }
        let witness = PrecompileWitness::read_from_bytes(&bytes).unwrap();
        assert_eq!(witness.to_bytes(), bytes);
        let traces = session_from_witnesses(vec![witness]).unwrap().finish();
        traces.check();
        let eval = traces.mains()[4];
        let rows = eval.values.chunks_exact(eval.width).collect::<Vec<_>>();
        assert_eq!(rows.iter().filter(|row| row[COL_ACT] == Felt::ONE).count(), depth as usize + 1);
        assert_eq!(rows.iter().filter(|row| row[COL_IS_AND] == Felt::ONE).count(), depth as usize);
        assert_eq!(rows[0][COL_OUT_MULT], Felt::ZERO);
        for row in rows.iter().skip(1).filter(|row| row[COL_ACT] == Felt::ONE) {
            assert_eq!(row[COL_OUT_MULT], Felt::from_u32(2));
        }
    }
}

fn check_wire_session(state: WitnessFixture) -> SessionTraces {
    let witness = state.witness();
    let witness =
        PrecompileWitness::read_from_bytes(&witness.to_bytes()).expect("witness must decode");
    assert_eq!(witness.root_unchecked(), state.root());
    let traces = session_from_witnesses(vec![witness]).expect("shared DAG must lower").finish();
    traces.check();
    traces
}

#[test]
fn deferred_session_lowers_uint_equality_assertion() {
    let mut state = state();
    let one = UintPrecompile::value_node(UintDomain::U256, limbs(1));
    let two = UintPrecompile::value_node(UintDomain::U256, limbs(2));
    let three = UintPrecompile::value_node(UintDomain::U256, limbs(3));

    state.register(one.clone()).expect("one must register");
    state.register(two.clone()).expect("two must register");
    state.register(three.clone()).expect("three must register");

    let sum =
        Node::join(UintPrecompile::op_frame(UintPrecompile::ADD_OP_ID), one.digest(), two.digest())
            .expect("frame is uint-owned");
    let sum = state.register(sum).expect("sum must register");
    let eq = Node::join(UintPrecompile::op_frame(UintPrecompile::EQ_OP_ID), three.digest(), sum)
        .expect("frame is uint-owned");
    let eq = state.register(eq).expect("equality must register");
    state.log_statement(eq).expect("equality must log");

    session_from_witnesses(vec![state.witness()])
        .expect("uint equality should lower into a session");
}

#[test]
fn deferred_session_lowers_curve_equality_assertion() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let identity = CurvePrecompile::identity_node(curve);

    state.register(identity.clone()).expect("identity must register");
    state.register(generator.clone()).expect("generator must register");

    let sum = Node::join(
        CurvePrecompile::op_frame(CurvePrecompile::ADD_OP_ID),
        identity.digest(),
        generator.digest(),
    )
    .expect("frame is curve-owned");
    let sum = state.register(sum).expect("sum must register");
    let eq =
        Node::join(CurvePrecompile::op_frame(CurvePrecompile::EQ_OP_ID), generator.digest(), sum)
            .expect("frame is curve-owned");
    let eq = state.register(eq).expect("equality must register");
    state.log_statement(eq).expect("equality must log");

    session_from_witnesses(vec![state.witness()])
        .expect("curve equality should lower into a session");
}

fn register_curve_equality(state: &mut WitnessFixture, lhs: Node, rhs: Node) {
    let lhs = state.register(lhs).expect("lhs must register");
    let rhs = state.register(rhs).expect("rhs must register");
    let eq = Node::join(CurvePrecompile::op_frame(CurvePrecompile::EQ_OP_ID), lhs, rhs)
        .expect("frame is curve-owned");
    let eq = state.register(eq).expect("equality must register");
    state.log_statement(eq).expect("equality must log");
}

fn curve_msm_node(pairs: Vec<(Node, Node)>) -> Node {
    let n_pairs = u32::try_from(pairs.len()).expect("test MSM pair count fits in u32");
    let pairs = pairs.into_iter().map(|(point, scalar)| (point.digest(), scalar.digest()));
    let pairs = pairs.collect::<Vec<_>>();
    Node::try_pair_list(CurvePrecompile::msm_frame(n_pairs), pairs).expect("frame is curve-owned")
}

#[test]
fn deferred_session_lowers_nested_one_term_msm() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let one = UintPrecompile::value_node(curve.scalar_domain(), limbs(1));
    state.register(generator.clone()).expect("generator must register");
    state.register(one.clone()).expect("scalar must register");

    let inner = curve_msm_node(vec![(generator.clone(), one.clone())]);
    state.register(inner.clone()).expect("inner MSM must register");
    let outer = curve_msm_node(vec![(inner, one)]);
    state.register(outer.clone()).expect("outer MSM must register");
    register_curve_equality(&mut state, outer, generator);

    let imported =
        session_from_witnesses(vec![state.witness()]).expect("nested MSM claims should lower");
    imported.finish().check();
}

#[test]
fn deferred_session_reuses_identical_msm_claim_in_trace() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let one = UintPrecompile::value_node(curve.scalar_domain(), limbs(1));
    state.register(generator.clone()).expect("generator must register");
    state.register(one.clone()).expect("scalar must register");

    let msm = curve_msm_node(vec![(generator, one)]);
    register_curve_equality(&mut state, msm.clone(), msm);

    let imported =
        session_from_witnesses(vec![state.witness()]).expect("repeated MSM claim should lower");
    imported.finish().check();
}

fn register_affine_curve_value(
    state: &mut WitnessFixture,
    curve: CurveId,
    point: CurvePoint,
) -> Node {
    let CurvePoint::Affine { x, y } = point else {
        panic!("expected affine point");
    };
    let x = UintPrecompile::value_node(curve.base_domain(), x);
    let y = UintPrecompile::value_node(curve.base_domain(), y);
    state.register(x.clone()).expect("x coordinate must register");
    state.register(y.clone()).expect("y coordinate must register");
    let point = CurvePrecompile::affine_node_from_digests(curve, x.digest(), y.digest());
    state.register(point.clone()).expect("point must register");
    point
}

#[test]
fn deferred_session_proves_ed25519_msm_with_mixed_torsion() {
    let mut state = state();
    let curve = CurveId::Ed25519;
    // (486662/3, 0) is the short-Weierstrass image of the order-two point. The
    // prime subgroup order l must preserve it: [l](B+T)=T, rather than the identity.
    let torsion = curve
        .point_from_affine(
            to_limbs32(from_hex(
                "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad2451",
            )),
            limbs(0),
        )
        .unwrap();
    let mixed = curve.add(curve.generator(), torsion).unwrap();
    let mixed = register_affine_curve_value(&mut state, curve, mixed);
    let torsion = register_affine_curve_value(&mut state, curve, torsion);
    let subgroup_order = UintPrecompile::value_node(
        UintDomain::Ed25519Order,
        to_limbs32(from_hex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")),
    );
    state.register(subgroup_order.clone()).unwrap();
    let msm = curve_msm_node(vec![(mixed.clone(), subgroup_order)]);
    state.register(msm.clone()).unwrap();
    register_curve_equality(&mut state, msm, torsion);

    // [8l-1]P+P=0 also exercises scalar reduction modulo the full order and the
    // group-law exceptional cases reached by a mixed-torsion MSM ladder.
    let order_minus_one = UintPrecompile::value_node(
        UintDomain::Ed25519Order,
        to_limbs32(from_hex("80000000000000000000000000000000a6f7cef517bce6b2c09318d2e7ae9f67")),
    );
    state.register(order_minus_one.clone()).unwrap();
    let negative = curve_msm_node(vec![(mixed.clone(), order_minus_one)]);
    state.register(negative.clone()).unwrap();
    let sum = Node::join(
        CurvePrecompile::op_frame(CurvePrecompile::ADD_OP_ID),
        negative.digest(),
        mixed.digest(),
    )
    .unwrap();
    register_curve_equality(&mut state, sum, CurvePrecompile::identity_node(curve));

    let imported = session_from_witnesses(vec![state.witness()])
        .expect("Ed25519 MSMs must lower under the full group order");
    imported.finish().check();
}

#[test]
fn deferred_session_lowers_zero_scalar_msm() {
    // 0·P = 𝒪: a single zero-scalar term registers and lowers to a session
    // whose resolved value is the point at infinity.
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let zero = UintPrecompile::value_node(curve.scalar_domain(), limbs(0));
    state.register(generator.clone()).expect("generator must register");
    state.register(zero.clone()).expect("zero scalar must register");

    let msm = curve_msm_node(vec![(generator, zero)]);
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_witnesses(vec![state.witness()]).expect("zero-scalar MSM should lower");
}

#[test]
fn deferred_session_lowers_duplicate_base_msm() {
    // a·P + b·P = (a + b)·P: two terms naming the same generator lower
    // (via the term-preserving fallback path) into one session.
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let two = UintPrecompile::value_node(curve.scalar_domain(), limbs(2));
    let three = UintPrecompile::value_node(curve.scalar_domain(), limbs(3));
    state.register(generator.clone()).expect("generator must register");
    state.register(two.clone()).expect("scalar must register");
    state.register(three.clone()).expect("scalar must register");

    let msm = curve_msm_node(vec![(generator.clone(), two), (generator, three)]);
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_witnesses(vec![state.witness()]).expect("duplicate-base MSM should lower");
}

#[test]
fn deferred_session_lowers_mixed_zero_and_nonzero_msm() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let two_g = register_affine_curve_value(
        &mut state,
        curve,
        curve
            .mul_scalar(curve.generator(), limbs(2))
            .expect("valid scalar multiplication"),
    );
    let zero = UintPrecompile::value_node(curve.scalar_domain(), limbs(0));
    let three = UintPrecompile::value_node(curve.scalar_domain(), limbs(3));
    state.register(generator.clone()).expect("generator must register");
    state.register(zero.clone()).expect("zero scalar must register");
    state.register(three.clone()).expect("scalar must register");

    let msm = curve_msm_node(vec![(generator, zero), (two_g, three)]);
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_witnesses(vec![state.witness()]).expect("mixed zero/nonzero MSM should lower");
}

#[test]
fn deferred_session_lowers_all_zero_msm_with_multiple_terms() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let two_g = register_affine_curve_value(
        &mut state,
        curve,
        curve
            .mul_scalar(curve.generator(), limbs(2))
            .expect("valid scalar multiplication"),
    );
    let zero = UintPrecompile::value_node(curve.scalar_domain(), limbs(0));
    state.register(generator.clone()).expect("generator must register");
    state.register(zero.clone()).expect("zero scalar must register");

    let msm = curve_msm_node(vec![(generator, zero.clone()), (two_g, zero)]);
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_witnesses(vec![state.witness()]).expect("all-zero MSM should lower");
}

#[test]
fn deferred_session_lowers_repeated_base_coefficients_that_cancel() {
    // A repeated base whose scalars sum to the curve order mod n cancels to
    // the identity: k·P + (n − k)·P = n·P = 𝒪.
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let k = limbs(7);
    let order = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    let n_minus_k = to_limbs32(order - U256::from(7u64));
    let k_node = UintPrecompile::value_node(curve.scalar_domain(), k);
    let n_minus_k_node = UintPrecompile::value_node(curve.scalar_domain(), n_minus_k);
    state.register(generator.clone()).expect("generator must register");
    state.register(k_node.clone()).expect("scalar must register");
    state.register(n_minus_k_node.clone()).expect("scalar must register");

    let msm = curve_msm_node(vec![(generator.clone(), k_node), (generator, n_minus_k_node)]);
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_witnesses(vec![state.witness()])
        .expect("cancelling repeated-base MSM should lower");
}

#[test]
fn deferred_session_lowers_structurally_different_nodes_at_the_same_canonical_point() {
    // `G` and `identity + G` are structurally different DAG nodes that both
    // evaluate to the generator — the same repeated-canonical-base path as
    // `deferred_session_lowers_duplicate_base_msm`, reached structurally.
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let identity = CurvePrecompile::identity_node(curve);
    state.register(generator.clone()).expect("generator must register");
    state.register(identity.clone()).expect("identity must register");
    let generator_via_add = Node::join(
        CurvePrecompile::op_frame(CurvePrecompile::ADD_OP_ID),
        identity.digest(),
        generator.digest(),
    )
    .expect("frame is curve-owned");
    let generator_via_add =
        state.register(generator_via_add).expect("identity + generator must register");

    let two = UintPrecompile::value_node(curve.scalar_domain(), limbs(2));
    let three = UintPrecompile::value_node(curve.scalar_domain(), limbs(3));
    state.register(two.clone()).expect("scalar must register");
    state.register(three.clone()).expect("scalar must register");

    let pairs = vec![(generator.digest(), two.digest()), (generator_via_add, three.digest())];
    let msm =
        Node::try_pair_list(CurvePrecompile::msm_frame(2), pairs).expect("frame is curve-owned");
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_witnesses(vec![state.witness()])
        .expect("MSM over structurally different same-point nodes should lower");
}

#[test]
fn deferred_session_inputs_reject_identity_base_msm() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let identity = CurvePrecompile::identity_node(curve);
    let generator = CurvePrecompile::generator_node(curve);
    let one = UintPrecompile::value_node(curve.scalar_domain(), limbs(17));
    let two = UintPrecompile::value_node(curve.scalar_domain(), limbs(2));
    state.register(identity.clone()).expect("identity must register");
    state.register(generator.clone()).expect("generator must register");
    state.register(one.clone()).expect("scalar must register");
    state.register(two.clone()).expect("scalar must register");

    let msm = curve_msm_node(vec![(identity, one), (generator, two)]);
    let root = state.register(msm).unwrap();
    state.log_statement(root).unwrap();
    let error = session_from_witnesses(vec![state.witness()]).err().unwrap();
    assert!(matches!(
        error,
        crate::SessionInputError::Invalid {
            reason: "MSM identity bases are unsupported",
            ..
        }
    ));
}

#[test]
fn deferred_session_lowers_large_msm_without_panicking() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let one = UintPrecompile::value_node(curve.scalar_domain(), limbs(1));
    state.register(one.clone()).expect("scalar must register");

    let pairs = (1..=17)
        .map(|scalar| {
            let point = curve
                .mul_scalar(curve.generator(), limbs(scalar))
                .expect("generator multiple must be valid");
            (register_affine_curve_value(&mut state, curve, point), one.clone())
        })
        .collect::<Vec<_>>();
    let msm = curve_msm_node(pairs);
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_witnesses(vec![state.witness()]).expect("large MSM should lower");
}

fn run_on_small_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(f)
        .expect("thread spawn must succeed")
        .join()
        .expect("thread must not panic");
}

#[test]
fn translate_truthy_deep_and_spine_does_not_stackoverflow() {
    run_on_small_stack(|| {
        let mut state = WitnessFixture::new();
        for _ in 0..512 {
            state.log_statement(TRUE_DIGEST).unwrap();
        }
        session_from_witnesses(vec![state.witness()])
            .expect("deep AND spine must lower without stack overflow");
    });
}

#[test]
fn translate_uint_deep_add_chain_does_not_stackoverflow() {
    run_on_small_stack(|| {
        let mut state = state();
        let curve = CurveId::Secp256k1;
        let one = UintPrecompile::value_node(curve.scalar_domain(), limbs(1));
        state.register(one.clone()).expect("scalar leaf must register");
        let mut current = one.clone();
        for _ in 0..512 {
            let next = Node::join(
                UintPrecompile::op_frame(UintPrecompile::ADD_OP_ID),
                current.digest(),
                one.digest(),
            )
            .expect("add node must construct");
            state.register(next.clone()).expect("add node must register");
            current = next;
        }
        let generator = CurvePrecompile::generator_node(curve);
        state.register(generator.clone()).expect("generator must register");
        let msm = curve_msm_node(vec![(generator, current)]);
        state.register(msm.clone()).expect("MSM must register");
        register_curve_equality(&mut state, msm.clone(), msm);
        session_from_witnesses(vec![state.witness()])
            .expect("deep uint add chain must lower without stack overflow");
    });
}

#[test]
fn translate_ec_deep_nested_msm_does_not_stackoverflow() {
    run_on_small_stack(|| {
        let mut state = state();
        let curve = CurveId::Secp256k1;
        let scalar2 = UintPrecompile::value_node(curve.scalar_domain(), limbs(2));
        state.register(scalar2.clone()).expect("scalar must register");
        let generator = CurvePrecompile::generator_node(curve);
        state.register(generator.clone()).expect("generator must register");
        let mut current = curve_msm_node(vec![(generator, scalar2.clone())]);
        state.register(current.clone()).expect("first MSM must register");
        for _ in 1..512 {
            let next = curve_msm_node(vec![(current.clone(), scalar2.clone())]);
            state.register(next.clone()).expect("nested MSM must register");
            current = next;
        }
        register_curve_equality(&mut state, current.clone(), current);
        session_from_witnesses(vec![state.witness()])
            .expect("deep nested MSM must lower without stack overflow");
    });
}
