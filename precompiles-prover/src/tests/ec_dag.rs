use k256::{ProjectivePoint, elliptic_curve::sec1::ToEncodedPoint};
use miden_precompiles::UintDomain;

use crate::{
    math::{U256, from_hex},
    session::{Session, SessionTraces},
    transcript::eval::trace::EcNode,
    uint::trace::UintPtr,
};

const FP: u32 = 1;
const A_PTR: u32 = 2;
const B_PTR: u32 = 3;

fn be_to_u256(bytes: impl AsRef<[u8]>) -> U256 {
    let hex: String = bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    from_hex(&hex)
}

fn k256_coords(p: &ProjectivePoint) -> (U256, U256) {
    let encoded = p.to_affine().to_encoded_point(false);
    (
        be_to_u256(encoded.x().expect("finite point")),
        be_to_u256(encoded.y().expect("finite point")),
    )
}

fn init_k256(session: &mut Session) -> (UintPtr, UintPtr, UintPtr) {
    let bound = session.pin_domain(FP, UintDomain::K1Base);
    let a = session.pin_uint_value(A_PTR, U256::ZERO, bound);
    let b = session.pin_uint_value(B_PTR, U256::from(7u64), bound);
    (bound, a, b)
}

fn create_point(
    session: &mut Session,
    bound: UintPtr,
    a: UintPtr,
    b: UintPtr,
    p: &ProjectivePoint,
) -> EcNode {
    let (x, y) = k256_coords(p);
    let x = session.uint_leaf(x, bound);
    let y = session.uint_leaf(y, bound);
    session.ec_create(a, b, &x, &y)
}

fn ec_dag_add_traces() -> SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let mut session = Session::new();
    let (bound, a, b) = init_k256(&mut session);

    let g_pt = create_point(&mut session, bound, a, b, &g);
    let g2_pt = create_point(&mut session, bound, a, b, &(g + g));
    let sum = session.ec_add(&g_pt, &g2_pt);
    let expected = create_point(&mut session, bound, a, b, &(g + g + g));

    let claim = session.ec_is(&sum, &expected);
    let root = session.assert_and_fold([claim]);
    session.finish(root)
}

#[test]
fn ec_dag_add_matches_k256() {
    ec_dag_add_traces().check();
}

#[test]
fn ec_dag_neg_sub_match_k256() {
    let g = ProjectivePoint::GENERATOR;
    let mut session = Session::new();
    let (bound, a, b) = init_k256(&mut session);

    let g_pt = create_point(&mut session, bound, a, b, &g);
    let neg_g = session.ec_neg(&g_pt);
    let expected_neg = create_point(&mut session, bound, a, b, &(-g));
    let neg_claim = session.ec_is(&neg_g, &expected_neg);

    let g3_pt = create_point(&mut session, bound, a, b, &(g + g + g));
    let diff = session.ec_sub(&g3_pt, &g_pt);
    let expected_diff = create_point(&mut session, bound, a, b, &(g + g));
    let sub_claim = session.ec_is(&diff, &expected_diff);

    let root = session.assert_and_fold([neg_claim, sub_claim]);
    session.finish(root).check();
}

#[test]
fn ec_dag_pai_passthroughs_hold() {
    let g = ProjectivePoint::GENERATOR;
    let mut session = Session::new();
    let (bound, a, b) = init_k256(&mut session);

    let inf = session.ec_pai(a, b, bound);
    let g_pt = create_point(&mut session, bound, a, b, &g);
    let g2_pt = create_point(&mut session, bound, a, b, &(g + g));

    let c1 = {
        let sum = session.ec_add(&inf, &g_pt);
        session.ec_is(&sum, &g_pt)
    };
    let c2 = {
        let sum = session.ec_add(&g2_pt, &inf);
        session.ec_is(&sum, &g2_pt)
    };
    let c3 = {
        let sum = session.ec_add(&inf, &inf);
        session.ec_is(&sum, &inf)
    };

    let root = session.assert_and_fold([c1, c2, c3]);
    session.finish(root).check();
}

#[test]
fn ec_dag_double_matches_k256() {
    let g = ProjectivePoint::GENERATOR;
    let mut session = Session::new();
    let (bound, a, b) = init_k256(&mut session);

    let g_pt = create_point(&mut session, bound, a, b, &g);
    let dbl = session.ec_add(&g_pt, &g_pt);
    let expected = create_point(&mut session, bound, a, b, &(g + g));

    let claim = session.ec_is(&dbl, &expected);
    session.finish(claim).check();
}
