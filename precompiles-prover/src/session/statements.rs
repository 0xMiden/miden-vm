//! Reusable example statements over the [`Session`] facade.
//!
//! The constructions here are *statements*, not chiplets: pure drivers of
//! the public DAG surface, shared between the test suite and the
//! `src/bin/` benches so a construction is written (and audited) once.

use crate::{
    math::U256,
    session::{Session, UintNode},
};

/// Build `P(−x)` by two different DAG shapes over the modulus pinned at
/// `bound_ptr` and return the two accumulators — equal in value (so
/// canonical interning lands them on one ptr and
/// [`uint_is`](Session::uint_is) closes), distinct in hash (genuinely
/// different DAGs).
///
/// `coeffs` is `c₀ ‥ c_N` (little-endian by degree), `N = coeffs.len() − 1
/// ≥ 1`; every value must already be reduced below the modulus.
///
/// - **Path A** subtracts from a typed zero: `n = 0 − x`, then the plain Horner `(((c_N)·n +
///   c_{N−1})·n + …)·n + c₀` — `1` sub, `N` muls, `N` adds.
/// - **Path B** sign-flips the odd coefficients instead, absorbing every negation into a
///   subtraction: Horner over `x` itself with `A_i = x·A_{i+1} ± c_i` (`+` for even `i`, `−` for
///   odd), and an odd *leading* coefficient folded into the first step (`A_{N−1} = c_{N−1} −
///   c_N·x`) so no negation is ever needed — `N` muls, `N` adds/subs.
///
/// Per degree, the statement costs `2N` `UintMul` and `2N + 1` `UintAdd`
/// relation ops (plus the `N + 3` value leaves and the closing `Is`),
/// which is what makes it a uint-throughput workload: arithmetic
/// dominates, keccak chiplets stay empty. The paths' accumulators
/// coincide in *value* at every even step (path A holds `(−1)^i·A_i`),
/// so roughly half of path B's intermediates dedup onto path A's store
/// blocks — canonical interning exercised mid-chain, not just at the
/// ends.
pub fn horner_sign_paths(
    session: &mut Session,
    x: U256,
    coeffs: &[U256],
    bound_ptr: u32,
) -> (UintNode, UintNode) {
    let n = coeffs.len() - 1;
    assert!(n >= 1, "horner_sign_paths needs degree ≥ 1");

    let x_leaf = session.uint_leaf(x, bound_ptr);
    let c: Vec<UintNode> = coeffs.iter().map(|&v| session.uint_leaf(v, bound_ptr)).collect();

    // Path A: Horner over 0 − x with the original coefficients.
    let zero = session.uint_leaf(U256::ZERO, bound_ptr);
    let neg_x = session.uint_sub(&zero, &x_leaf);
    let mut acc_a = c[n];
    for i in (0..n).rev() {
        let m = session.uint_mul(&acc_a, &neg_x);
        acc_a = session.uint_add(&m, &c[i]);
    }

    // Path B: the subtractions carry the flipped signs.
    let (mut acc_b, rest) = if n.is_multiple_of(2) {
        (c[n], n)
    } else {
        let t = session.uint_mul(&c[n], &x_leaf);
        (session.uint_sub(&c[n - 1], &t), n - 1)
    };
    for i in (0..rest).rev() {
        let m = session.uint_mul(&acc_b, &x_leaf);
        acc_b = if i % 2 == 0 {
            session.uint_add(&m, &c[i])
        } else {
            session.uint_sub(&m, &c[i])
        };
    }

    (acc_a, acc_b)
}
