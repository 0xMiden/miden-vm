//! Prove a small ECDSA verification shape with the current EC DAG session API.
//!
//! ECDSA verification checks a relation shaped like `R = u1 * G + u2 * Q`.
//! This example uses tiny fixed scalars and lays the two scalar products with
//! repeated EC DAG addition. It is intentionally not the efficient MSM path:
//! the canonical Curve MSM transcript node is a later review unit.

use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use miden_precompiles::UintDomain;
use miden_precompiles_prover::{
    math::{U256, from_hex},
    session::Session,
    transcript::eval::trace::EcNode,
    uint::trace::UintPtr,
};

const FP: u32 = 1;
const A_PTR: u32 = 2;
const B_PTR: u32 = 3;

fn be_to_u256(bytes: impl AsRef<[u8]>) -> U256 {
    let hex: String = bytes.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
    from_hex(&hex)
}

fn coords(point: &ProjectivePoint) -> (U256, U256) {
    let encoded = point.to_affine().to_encoded_point(false);
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
    point: &ProjectivePoint,
) -> EcNode {
    let (x, y) = coords(point);
    let x = session.uint_leaf(x, bound);
    let y = session.uint_leaf(y, bound);
    session.ec_create(a, b, &x, &y)
}

fn scalar_mul(session: &mut Session, base: &EcNode, scalar: u64) -> EcNode {
    assert!(scalar > 0, "scalar must be non-zero");

    let bit_len = u64::BITS - scalar.leading_zeros();
    let mut acc = *base;
    for bit in (0..bit_len - 1).rev() {
        acc = session.ec_add(&acc, &acc);
        if ((scalar >> bit) & 1) == 1 {
            acc = session.ec_add(&acc, base);
        }
    }
    acc
}

fn main() {
    let g = ProjectivePoint::GENERATOR;
    let q = g * Scalar::from(11u64);
    let u1 = 5u64;
    let u2 = 7u64;
    let expected = g * Scalar::from(u1) + q * Scalar::from(u2);

    let mut session = Session::new();
    let (bound, a, b) = init_k256(&mut session);

    let g_node = create_point(&mut session, bound, a, b, &g);
    let q_node = create_point(&mut session, bound, a, b, &q);
    let expected_node = create_point(&mut session, bound, a, b, &expected);

    let g_term = scalar_mul(&mut session, &g_node, u1);
    let q_term = scalar_mul(&mut session, &q_node, u2);
    let actual = session.ec_add(&g_term, &q_term);
    let claim = session.ec_is(&actual, &expected_node);
    let root = session.assert_and_fold([claim]);

    let traces = session.finish(root);
    traces.check();
    let proof = traces.prove();
    proof.verify().expect("proof must verify");

    println!("proved R = {u1} * G + {u2} * Q for Q = 11 * G");
    println!("public root: {:?}", traces.public_root().as_array());
}
