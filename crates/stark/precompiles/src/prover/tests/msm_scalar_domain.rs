//! MSM claim scalars must live in the curve's scalar domain.

use alloc::vec;

use miden_core::{Felt, deferred::Node};
use miden_precompiles::{CurveId, CurvePoint, CurvePrecompile, UintDomain, UintPrecompile};
use miden_stark::ProverError;

use crate::prover::{
    PrecompileProvingError, ProveError,
    deferred::session::{SessionInputError, session_from_witnesses},
    math::{U256, from_limbs32},
    session::{EcNode, Session, SessionTraces, UintNode},
    stark_config::DEFAULT_HASH_FUNCTION,
    tests::{SessionTracesTestExt, batch_witness::WitnessFixture, verify_deferred},
    transcript::{
        eidos::EidosDigest,
        eval::{COL_BOUND_PTR, COL_IS_EC_MSM, COL_MSM_IDX},
    },
};

fn generator(session: &mut Session, curve: CurveId) -> EcNode {
    let CurvePoint::Affine { x, y } = curve.generator() else {
        unreachable!()
    };
    let x = session.uint_leaf(from_limbs32(&x), curve.base_domain().bound_ptr());
    let y = session.uint_leaf(from_limbs32(&y), curve.base_domain().bound_ptr());
    session.ec_create(curve.group_ptr(), &x, &y)
}

fn assert_rejected(traces: SessionTraces) {
    let root = traces.public_root().as_array().into();
    match traces.prove_stark(DEFAULT_HASH_FUNCTION) {
        Ok(proof) => assert!(
            verify_deferred(&(proof, root)).is_err(),
            "verifier accepted a proof with a mismatched scalar domain"
        ),
        Err(ProveError::Prover(ProverError::ExternalAssertionFailed { assertion: 0 })) => (),
        Err(error) => panic!("unexpected proving failure: {error}"),
    }
}

/// `MSM[(G, 1 as U256)] == G` on secp256k1: the reference evaluator rejects the scalar's declared
/// U256 domain, so a proof for the same root must not verify even though the integer value is one.
#[test]
fn msm_intro_scalar_outside_scalar_domain_is_rejected() {
    let curve = CurveId::Secp256k1;
    let wrong = UintDomain::U256;
    let CurvePoint::Affine { x, y } = curve.generator() else {
        unreachable!()
    };

    let mut state = WitnessFixture::new();
    let gx = UintPrecompile::value_node(curve.base_domain(), x);
    let gy = UintPrecompile::value_node(curve.base_domain(), y);
    state.register(gx.clone()).unwrap();
    state.register(gy.clone()).unwrap();
    let g = CurvePrecompile::affine_node_from_digests(curve, gx.digest(), gy.digest());
    state.register(g.clone()).unwrap();
    let mut one_limbs = [0u32; 8];
    one_limbs[0] = 1;
    let one = UintPrecompile::value_node(wrong, one_limbs);
    state.register(one.clone()).unwrap();
    let msm = Node::try_pair_list(CurvePrecompile::msm_frame(1), vec![(g.digest(), one.digest())])
        .unwrap();
    let msm = state.register(msm).unwrap();
    let g = state.register(g).unwrap();
    let eq = Node::join(CurvePrecompile::op_frame(CurvePrecompile::EQ_OP_ID), msm, g).unwrap();
    let eq = state.register(eq).unwrap();
    state.log_statement(eq).unwrap();
    let err = session_from_witnesses(vec![state.witness()])
        .err()
        .expect("reference must reject");
    assert!(
        matches!(
            err,
            PrecompileProvingError::Input(SessionInputError::Invalid {
                reason: "MSM scalar uses the wrong domain",
                ..
            })
        ),
        "unexpected reference rejection: {err}"
    );

    // Same DAG, with the intro row laid out under the U256 bound.
    let mut s = Session::new();
    let bound = curve.base_domain().bound_ptr();
    let gx = s.uint_leaf(from_limbs32(&x), bound);
    let gy = s.uint_leaf(from_limbs32(&y), bound);
    let gp = s.ec_create(curve.group_ptr(), &gx, &gy);
    let one = s.uint_leaf(U256::from(1u64), wrong.bound_ptr());
    let expr = s.msm_intro_with_scalar(&gp, &one, curve.group_ptr());
    let r = s.ec_msm(expr, &[(gp, one)]);
    let claim = s.ec_is(&r, &gp);
    // The VM statement log is AND(TRUE, claim); the importer lowers TRUE to `zero()`.
    let t = s.zero();
    let root = s.assert_and(t, claim);
    let traces = s.finish(root);
    assert_eq!(traces.public_root(), EidosDigest::from(state.root()));
    assert_rejected(traces);
}

#[test]
fn msm_intro_header_must_name_the_actual_base_curve() {
    let mut s = Session::new();
    let point = generator(&mut s, CurveId::Secp256k1);
    let foreign_curve = CurveId::P256;
    let one = s.uint_leaf(U256::from(1u64), foreign_curve.scalar_domain().bound_ptr());
    // The header and scalar both name the other curve. Only the base-point lookup exposes
    // that this is actually a secp256k1 point, so pinning the header alone is insufficient.
    let expr = s.msm_intro_with_scalar(&point, &one, foreign_curve.group_ptr());
    let result = s.ec_msm(expr, &[(point, one)]);
    let claim = s.ec_is(&result, &point);
    assert_rejected(s.finish(claim));
}

#[test]
fn msm_nested_claim_checks_the_declared_domain_of_zero() {
    let curve = CurveId::Secp256k1;
    let mut s = Session::new();
    let point = generator(&mut s, curve);
    let correct = s.uint_leaf(U256::ZERO, curve.scalar_domain().bound_ptr());
    let foreign = s.uint_leaf(U256::ZERO, UintDomain::U256.bound_ptr());
    assert_ne!(correct.ptr, foreign.ptr, "the builder separates scalar domains");
    assert_ne!(correct.hash(), foreign.hash(), "the committed domains remain distinct");

    let leaf = s.msm_intro_zero(&point);
    let pair = s.msm_combine_terms_preserving(leaf, leaf);
    let triple = s.msm_combine_terms_preserving(pair, leaf);
    // Bypass the builder's checks while retaining the foreign node's committed hash/id.
    // The resulting claim must be rejected even though all three coefficients equal zero.
    let unchecked = UintNode {
        ptr: correct.ptr,
        bound_ptr: correct.bound_ptr,
        ..foreign
    };
    let result = s.ec_msm(triple, &[(point, correct), (point, unchecked), (point, correct)]);
    let identity = s.ec_pai(curve.group_ptr());
    let claim = s.ec_is(&result, &identity);
    let mut traces = s.finish(claim);
    let eval = traces.eval_main_mut();
    let width = eval.width;
    let mut changed = 0;
    for row in eval.values.chunks_exact_mut(width) {
        if row[COL_IS_EC_MSM] == Felt::ONE && row[COL_MSM_IDX] == Felt::ONE {
            row[COL_BOUND_PTR] = Felt::from(UintDomain::U256.bound_ptr());
            changed += 1;
        }
    }
    assert_eq!(changed, 1, "only the interior scalar binding has the wrong domain");
    assert_rejected(traces);
}

#[test]
fn msm_claim_lookup_distinguishes_domains_for_the_same_zero_pointer() {
    use std::collections::HashMap;

    use miden_core::field::QuadFelt;
    use miden_stark::lookup::Challenges;

    use crate::prover::{
        ec::msm::{EcMsmAir, MsmClaimTermMsg},
        logup::LookupMessage,
        relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
        tests::{bus_balance::fold_balance, transcript_eval_main},
        transcript::eval::TranscriptEvalAir,
    };

    let curve = CurveId::Secp256k1;
    let mut session = Session::new();
    let point = generator(&mut session, curve);
    let zero = session.uint_leaf(U256::ZERO, curve.scalar_domain().bound_ptr());
    let expr = session.msm_intro_zero(&point);
    let result = session.ec_msm(expr, &[(point, zero)]);
    let identity = session.ec_pai(curve.group_ptr());
    let claim = session.ec_is(&result, &identity);
    let traces = session.finish(claim);
    let msm = traces.mains()[9];
    let mut eval = transcript_eval_main(&traces);
    let challenges = Challenges::new(
        QuadFelt::new([Felt::from(17u32), Felt::from(23u32)]),
        QuadFelt::new([Felt::from(31u32), Felt::from(37u32)]),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let term = MsmClaimTermMsg {
        expr_ptr: Felt::from(expr.addr()),
        base_ptr: Felt::from(point.point.addr()),
        scalar_ptr: Felt::from(zero.ptr.addr()),
        scalar_bound_ptr: Felt::from(curve.scalar_domain().bound_ptr()),
    };
    let correct_key = term.encode(&challenges);
    let other_bound = Felt::from(UintDomain::U256.bound_ptr());
    let other_key = MsmClaimTermMsg { scalar_bound_ptr: other_bound, ..term }.encode(&challenges);
    assert_ne!(correct_key, other_key);

    let mut net = HashMap::new();
    fold_balance(&EcMsmAir, msm, &challenges, &mut net);
    fold_balance(&TranscriptEvalAir, &eval, &challenges, &mut net);
    assert_eq!(net[&correct_key].0, Felt::ZERO);

    let mut rows = eval
        .values
        .chunks_exact_mut(eval.width)
        .filter(|row| row[COL_IS_EC_MSM] == Felt::ONE);
    let row = rows.next().expect("one MSM term");
    assert!(rows.next().is_none());
    row[COL_BOUND_PTR] = other_bound;

    // Inspect the claim-term keys directly: a separate scalar-binding mismatch cannot satisfy
    // these assertions. The expression, point, and scalar pointers are unchanged.
    net.clear();
    fold_balance(&EcMsmAir, msm, &challenges, &mut net);
    fold_balance(&TranscriptEvalAir, &eval, &challenges, &mut net);
    assert_eq!(net[&correct_key].0, -Felt::ONE);
    assert_eq!(net[&other_key].0, Felt::ONE);
}

#[test]
fn msm_correctly_typed_zero_one_and_two_verify_on_all_curves() {
    for curve in CurveId::ALL {
        let mut s = Session::new();
        let point = generator(&mut s, curve);
        let bound = curve.scalar_domain().bound_ptr();
        let zero = s.uint_leaf(U256::ZERO, bound);
        let one = s.uint_leaf(U256::from(1u64), bound);
        let two = s.uint_leaf(U256::from(2u64), bound);
        let zero_expr = s.msm_intro_zero(&point);
        let one_expr = s.msm_intro(&point);
        let two_expr = s.msm_combine(one_expr, one_expr);
        let zero_result = s.ec_msm(zero_expr, &[(point, zero)]);
        let one_result = s.ec_msm(one_expr, &[(point, one)]);
        let two_result = s.ec_msm(two_expr, &[(point, two)]);
        let identity = s.ec_pai(curve.group_ptr());
        let doubled = s.ec_add(&point, &point);
        let claims = [
            s.ec_is(&zero_result, &identity),
            s.ec_is(&one_result, &point),
            s.ec_is(&two_result, &doubled),
        ];
        let root = s.assert_and_fold(claims);
        verify_deferred(&s.finish(root).prove()).expect("correct scalar domains verify");
    }
}

#[test]
fn msm_plain_intro_preserves_identity_base_support() {
    let curve = CurveId::Secp256k1;
    let mut s = Session::new();
    let identity = s.ec_pai(curve.group_ptr());
    let one = s.uint_leaf(U256::from(1u64), curve.scalar_domain().bound_ptr());
    let expr = s.msm_intro(&identity);
    let result = s.ec_msm(expr, &[(identity, one)]);
    let claim = s.ec_is(&result, &identity);
    verify_deferred(&s.finish(claim).prove()).expect("internal identity introduction verifies");
}
