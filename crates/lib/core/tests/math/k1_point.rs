//! Tests for `k1_point` affine secp256k1 point arithmetic. Covers point_negate,
//! point_double, point_add, decompress, scalar_mul, and double_scalar_mul.

use miden_utils_testing::proptest::prelude::*;
use num::{BigUint, Zero};

use super::u256_mod::{
    assert_stack_words, boundary_biased_u32, push_masm_felt_sequence, secp256k1_base_prime,
    secp256k1_scalar_order,
};

// REFERENCE AFFINE POINT ARITHMETIC OVER P_K1
// ================================================================================================

/// Affine secp256k1 point: either a finite (x, y) or the point at infinity.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AffinePoint {
    x: BigUint,
    y: BigUint,
    is_infinity: bool,
}

impl AffinePoint {
    fn infinity() -> Self {
        Self {
            x: BigUint::zero(),
            y: BigUint::zero(),
            is_infinity: true,
        }
    }

    fn finite(x: BigUint, y: BigUint) -> Self {
        Self { x, y, is_infinity: false }
    }

    /// secp256k1 generator G.
    fn generator() -> Self {
        let x = BigUint::parse_bytes(
            b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            16,
        )
        .unwrap();
        let y = BigUint::parse_bytes(
            b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            16,
        )
        .unwrap();
        Self::finite(x, y)
    }

    /// `[2]G`, included as an independent reference vector.
    fn two_g() -> Self {
        let x = BigUint::parse_bytes(
            b"C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
            16,
        )
        .unwrap();
        let y = BigUint::parse_bytes(
            b"1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
            16,
        )
        .unwrap();
        Self::finite(x, y)
    }

    fn negate(&self, p: &BigUint) -> Self {
        if self.is_infinity {
            return Self::infinity();
        }
        let neg_y = if self.y.is_zero() { BigUint::zero() } else { p - &self.y };
        Self::finite(self.x.clone(), neg_y)
    }

    fn double(&self, p: &BigUint) -> Self {
        if self.is_infinity || self.y.is_zero() {
            return Self::infinity();
        }
        // Slope m = (3*x^2) / (2*y) mod p.
        let three_x2 = (BigUint::from(3u32) * &self.x * &self.x) % p;
        let two_y = (BigUint::from(2u32) * &self.y) % p;
        let inv_two_y = modinv(&two_y, p).expect("2y must be invertible for a curve point");
        let m = (three_x2 * inv_two_y) % p;

        // x3 = m^2 - 2*x
        let m2 = (&m * &m) % p;
        let two_x = (BigUint::from(2u32) * &self.x) % p;
        let x3 = sub_mod(&m2, &two_x, p);

        // y3 = m*(x - x3) - y
        let diff = sub_mod(&self.x, &x3, p);
        let prod = (&m * &diff) % p;
        let y3 = sub_mod(&prod, &self.y, p);

        Self::finite(x3, y3)
    }
}

fn sub_mod(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    if a >= b { (a - b) % p } else { (p - ((b - a) % p)) % p }
}

/// Modular inverse via Fermat (only used in tests so the cost doesn't matter).
fn modinv(a: &BigUint, p: &BigUint) -> Option<BigUint> {
    if a.is_zero() {
        None
    } else {
        Some(a.modpow(&(p - BigUint::from(2u32)), p))
    }
}

/// Convert a `BigUint` to 8 little-endian u32 limbs, padded with zeros.
fn bn_to_u32_limbs(v: &BigUint) -> [u32; 8] {
    let digits = v.to_u32_digits();
    let mut out = [0u32; 8];
    for (i, &d) in digits.iter().enumerate().take(8) {
        out[i] = d;
    }
    out
}

/// Render a MASM `push.X` sequence that lands the 17-felt encoding of a point on top of the
/// operand stack with X[0] topmost, then Y, then the is_infinity flag deepest. The flag and
/// 16 coordinate limbs total 17 felts, which exceeds the test harness's 16-felt input-stack
/// cap, so we push them via the source instead of via `&operands`.
fn point_pushes(pt: &AffinePoint) -> String {
    let x = bn_to_u32_limbs(&pt.x);
    let y = bn_to_u32_limbs(&pt.y);
    let mut v = Vec::with_capacity(17);
    v.extend(x.iter().map(|&l| l as u64));
    v.extend(y.iter().map(|&l| l as u64));
    v.push(if pt.is_infinity { 1 } else { 0 });
    push_masm_felt_sequence(&v)
}

/// Build the MASM `assert_stack_words` sequence that checks the top of the operand stack
/// matches the 20-felt encoding of `expected` (X word-low, X word-high, Y word-low, Y word-high,
/// flag word [flag, 0, 0, 0]).
fn expected_point_assertions(expected: &AffinePoint) -> String {
    let x = bn_to_u32_limbs(&expected.x);
    let y = bn_to_u32_limbs(&expected.y);
    let flag = if expected.is_infinity { 1 } else { 0 };
    let mut limbs: Vec<u64> = Vec::with_capacity(20);
    limbs.extend(x.iter().map(|&l| l as u64));
    limbs.extend(y.iter().map(|&l| l as u64));
    limbs.extend([flag as u64, 0, 0, 0]);
    assert_stack_words(&limbs)
}

// PRECOMPUTED CONSTANTS
// ================================================================================================

#[test]
fn phi_g_x_constant_matches_runtime() {
    // verify_glv_hinted hardcodes φ(G).x = β·G_x mod p as a constant pushed onto the stack.
    // This test recomputes that value in Rust and asserts the limbs match what's in the .masm.
    let p = bn_p();
    let g_x_limbs: [u32; 8] = [
        0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb, 0xce870b07, 0x55a06295, 0xf9dcbbac,
        0x79be667e,
    ];
    let beta_limbs: [u32; 8] = [
        0x719501ee, 0xc1396c28, 0x12f58995, 0x9cf04975, 0xac3434e9, 0x6e64479e, 0x657c0710,
        0x7ae96a2b,
    ];
    let g_x = BigUint::from_slice(&g_x_limbs);
    let beta = BigUint::from_slice(&beta_limbs);
    let phi_g_x = (&beta * &g_x) % &p;

    let mut got = [0u32; 8];
    let bytes = phi_g_x.to_bytes_le();
    for (i, chunk) in bytes.chunks(4).enumerate() {
        let mut buf = [0u8; 4];
        buf[..chunk.len()].copy_from_slice(chunk);
        got[i] = u32::from_le_bytes(buf);
    }

    // The pinned constant in `k1_point.masm::verify_glv_hinted` (low to high u32 limbs).
    let pinned: [u32; 8] = [
        0x00b88fcb, 0xa7bba044, 0x7f15e98d, 0x87284406, 0x96902325, 0xab0102b6, 0x9da01887,
        0xbcace2e9,
    ];
    assert_eq!(
        got, pinned,
        "φ(G).x recomputation mismatch; if β or G_x changed in the .masm, update the constant \
         and this pin to {got:#x?}"
    );
}

#[test]
fn lut3_constants_match_runtime() {
    // Recomputes the 4 LUT[3] = (±G) + (±φ(G)) constants from (G_x, G_y, β, p_k1) and
    // asserts limb-equality with the hardcoded values in `k1_point.masm::msm_4_128_glv_k1`.
    let p = bn_p();
    let beta = BigUint::parse_bytes(
        b"7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE",
        16,
    )
    .unwrap();
    let g = AffinePoint::generator();
    let phi_g_x = (&beta * &g.x) % &p;
    let phi_g = AffinePoint::finite(phi_g_x, g.y.clone());
    // A = G + φ(G), B = G - φ(G); the other two cases are negations.
    let a = affine_add(&g, &phi_g, &p);
    let b = affine_add(&g, &phi_g.negate(&p), &p);
    let neg_a = a.negate(&p);
    let neg_b = b.negate(&p);

    fn to_le_limbs(v: &BigUint) -> [u32; 8] {
        let digits = v.to_u32_digits();
        let mut out = [0u32; 8];
        for (i, &d) in digits.iter().enumerate().take(8) {
            out[i] = d;
        }
        out
    }

    let cases: [(&str, [u32; 8], [u32; 8]); 4] = [
        (
            "+A = G + φ(G)  (sa=0, sb=0)",
            [
                0xe84f50fb, 0xfe51de5e, 0x531bed98, 0x763bbf1e, 0x9ae8d1d3, 0xff5e9ab3, 0x68832bcb,
                0xc994b697,
            ],
            [
                0x04ef2777, 0x63b82f6f, 0x597aabe6, 0x02e84bb7, 0xf1eef757, 0xa25b0403, 0xd95c3b9a,
                0xb7c52588,
            ],
        ),
        (
            "+B = G - φ(G)  (sa=0, sb=1)",
            [
                0x415a87b0, 0xea6eadae, 0x596e21f2, 0xe5015022, 0x2325ba6c, 0x9f2b0aa7, 0x4cc437be,
                0x93c4d65b,
            ],
            [
                0x03706352, 0x50730fbc, 0x625309ca, 0x5d419b1b, 0x92bd956f, 0x77e94036, 0x1778d37f,
                0xde87653b,
            ],
        ),
        (
            "-A = -(G + φ(G))  (sa=1, sb=1)",
            [
                0xe84f50fb, 0xfe51de5e, 0x531bed98, 0x763bbf1e, 0x9ae8d1d3, 0xff5e9ab3, 0x68832bcb,
                0xc994b697,
            ],
            [
                0xfb10d4b8, 0x9c47d08f, 0xa6855419, 0xfd17b448, 0x0e1108a8, 0x5da4fbfc, 0x26a3c465,
                0x483ada77,
            ],
        ),
        (
            "-B = -(G - φ(G))  (sa=1, sb=0)",
            [
                0x415a87b0, 0xea6eadae, 0x596e21f2, 0xe5015022, 0x2325ba6c, 0x9f2b0aa7, 0x4cc437be,
                0x93c4d65b,
            ],
            [
                0xfc8f98dd, 0xaf8cf042, 0x9dacf635, 0xa2be64e4, 0x6d426a90, 0x8816bfc9, 0xe8872c80,
                0x21789ac4,
            ],
        ),
    ];
    let actuals = [(&a.x, &a.y), (&b.x, &b.y), (&neg_a.x, &neg_a.y), (&neg_b.x, &neg_b.y)];

    for ((label, expected_x, expected_y), (ax, ay)) in cases.iter().zip(actuals.iter()) {
        let got_x = to_le_limbs(ax);
        let got_y = to_le_limbs(ay);
        assert_eq!(
            &got_x, expected_x,
            "{label}: X mismatch; update LUT[3] constants in k1_point.masm to X = {got_x:#x?}"
        );
        assert_eq!(
            &got_y, expected_y,
            "{label}: Y mismatch; update LUT[3] constants in k1_point.masm to Y = {got_y:#x?}"
        );
    }
}

// POINT NEGATION
// ================================================================================================

#[test]
fn k1_point_negate_generator() {
    let p = bn_p();
    let g = AffinePoint::generator();
    assert_point_negate(&g, &g.negate(&p));
}

#[test]
fn k1_point_negate_infinity() {
    let inf = AffinePoint::infinity();
    assert_point_negate(&inf, &inf);
}

#[test]
fn k1_point_negate_infinity_with_non_canonical_y_does_not_trap() {
    // Pins the is_infinity branch in point_negate: identity with Y = 2^256 - 1 (above p_k1)
    // must skip the f_k1::neg(Y) call.
    let source = "
        use miden::core::math::k1_point

        @locals(40)
        proc test_wrapper_negate_identity_garbage_y
            # Lay out an identity-flagged point at mem[0..20] with Y = u256::MAX
            # (non-canonical; > p_k1) and X = 0.
            push.0.0.0.0  loc_storew_le.0   dropw          # X[0..4] = 0
            push.0.0.0.0  loc_storew_le.4   dropw          # X[4..8] = 0
            push.0xffffffff.0xffffffff.0xffffffff.0xffffffff
            loc_storew_le.8  dropw                          # Y[0..4] = u32::MAX
            push.0xffffffff.0xffffffff.0xffffffff.0xffffffff
            loc_storew_le.12 dropw                          # Y[4..8] = u32::MAX
            push.0.0.0.1  loc_storew_le.16 dropw            # flag word = [1, 0, 0, 0]

            # point_negate(out=locaddr.20, p=locaddr.0).
            locaddr.0  locaddr.20
            exec.k1_point::point_negate

            # Read the output flag at mem[36] (= locaddr.20 + 16). For identity input the
            # output must also be identity.
            loc_load.36
        end

        begin
            exec.test_wrapper_negate_identity_garbage_y
            push.1  assert_eq.err=\"output should be identity\"
        end
    ";
    build_test!(source, &[]).execute().unwrap();
}

fn assert_point_negate(input: &AffinePoint, expected: &AffinePoint) {
    let source = format!(
        "
        use miden::core::math::k1_point

        @locals(40)
        proc test_wrapper_negate
            # Stack at entry: [X[0..8], Y[0..8], flag, ...]
            loc_storew_le.0  dropw                       # mem[0..4] = X[0..4]
            loc_storew_le.4  dropw                       # mem[4..8] = X[4..8]
            loc_storew_le.8  dropw                       # mem[8..12] = Y[0..4]
            loc_storew_le.12 dropw                       # mem[12..16] = Y[4..8]
            loc_store.16                                 # mem[16] = flag

            locaddr.0  locaddr.20
            exec.k1_point::point_negate

            # Read mem[20..40] (the output point) back to the operand stack.
            # Load in reverse address order so that mem[20..24] (X[0..4]) ends up on top.
            padw loc_loadw_le.36
            padw loc_loadw_le.32
            padw loc_loadw_le.28
            padw loc_loadw_le.24
            padw loc_loadw_le.20
        end

        begin
            {pushes}
            exec.test_wrapper_negate
            {asserts}
        end",
        pushes = point_pushes(input),
        asserts = expected_point_assertions(expected),
    );
    build_test!(&source, &[]).execute().unwrap();
}

// POINT DOUBLING
// ================================================================================================

#[test]
fn k1_point_double_generator() {
    let g = AffinePoint::generator();
    let two_g = AffinePoint::two_g();
    assert_point_double(&g, &two_g);
}

#[test]
fn k1_point_double_two_g_matches_reference_doubling() {
    let p = bn_p();
    let two_g = AffinePoint::two_g();
    assert_point_double(&two_g, &two_g.double(&p));
}

#[test]
fn k1_point_double_infinity() {
    let inf = AffinePoint::infinity();
    assert_point_double(&inf, &inf);
}

/// Pre-fills the output point's reserved-padding felts (mem[+17..+20] of the flag word) with
/// non-zero sentinels before calling `point_double`, then asserts the full flag word reads back
/// as `[0, 0, 0, 0]`. Guards the point-representation contract documented at the top of
/// `k1_point.masm`: procs that produce a finite result must write the reserved felts as zero.
#[test]
fn k1_point_double_finite_overwrites_reserved_padding() {
    let g = AffinePoint::generator();
    let two_g = AffinePoint::two_g();
    let source = format!(
        "
        use miden::core::math::k1_point

        @locals(40)
        proc test_wrapper_double_reserved_taint
            loc_storew_le.0  dropw
            loc_storew_le.4  dropw
            loc_storew_le.8  dropw
            loc_storew_le.12 dropw
            loc_store.16

            # Taint the output's reserved padding (mem[37..40]) with non-zero sentinels so we
            # can verify that point_double overwrites them.
            push.0xdeadbeef loc_store.37
            push.0xcafebabe loc_store.38
            push.0xfeedface loc_store.39

            locaddr.0  locaddr.20
            exec.k1_point::point_double

            # Load in reverse address order so that mem[20..24] (X[0..4]) ends up on top.
            padw loc_loadw_le.36
            padw loc_loadw_le.32
            padw loc_loadw_le.28
            padw loc_loadw_le.24
            padw loc_loadw_le.20
        end

        begin
            {pushes}
            exec.test_wrapper_double_reserved_taint
            {asserts}
        end",
        pushes = point_pushes(&g),
        asserts = expected_point_assertions(&two_g),
    );
    build_test!(&source, &[]).execute().unwrap();
}

fn assert_point_double(input: &AffinePoint, expected: &AffinePoint) {
    let source = format!(
        "
        use miden::core::math::k1_point

        @locals(40)
        proc test_wrapper_double
            loc_storew_le.0  dropw
            loc_storew_le.4  dropw
            loc_storew_le.8  dropw
            loc_storew_le.12 dropw
            loc_store.16

            locaddr.0  locaddr.20
            exec.k1_point::point_double

            # Load in reverse address order so that mem[20..24] (X[0..4]) ends up on top.
            padw loc_loadw_le.36
            padw loc_loadw_le.32
            padw loc_loadw_le.28
            padw loc_loadw_le.24
            padw loc_loadw_le.20
        end

        begin
            {pushes}
            exec.test_wrapper_double
            {asserts}
        end",
        pushes = point_pushes(input),
        asserts = expected_point_assertions(expected),
    );
    build_test!(&source, &[]).execute().unwrap();
}

// POINT ADDITION
// ================================================================================================

#[test]
fn k1_point_add_g_plus_g_doubles() {
    let g = AffinePoint::generator();
    let two_g = AffinePoint::two_g();
    assert_point_add(&g, &g, &two_g);
}

#[test]
fn k1_point_add_g_plus_neg_g_is_infinity() {
    let p = bn_p();
    let g = AffinePoint::generator();
    let neg_g = g.negate(&p);
    assert_point_add(&g, &neg_g, &AffinePoint::infinity());
}

#[test]
fn k1_point_add_g_plus_two_g_is_three_g() {
    let p = bn_p();
    let g = AffinePoint::generator();
    let two_g = AffinePoint::two_g();
    let three_g = affine_add(&g, &two_g, &p);
    assert_point_add(&g, &two_g, &three_g);
}

#[test]
fn k1_point_add_g_plus_infinity() {
    let g = AffinePoint::generator();
    let inf = AffinePoint::infinity();
    assert_point_add(&g, &inf, &g);
}

#[test]
fn k1_point_add_infinity_plus_g() {
    let g = AffinePoint::generator();
    let inf = AffinePoint::infinity();
    assert_point_add(&inf, &g, &g);
}

#[test]
fn k1_point_add_infinity_plus_infinity() {
    let inf = AffinePoint::infinity();
    assert_point_add(&inf, &inf, &inf);
}

fn assert_point_add(p1: &AffinePoint, p2: &AffinePoint, expected: &AffinePoint) {
    let source = format!(
        "
        use miden::core::math::k1_point

        @locals(60)
        proc test_wrapper_add
            # Stack at entry (top to deep): [P1 (17 felts), P2 (17 felts), ...]
            # P1 -> mem[0..20], P2 -> mem[20..40], output -> mem[40..60].
            loc_storew_le.0  dropw
            loc_storew_le.4  dropw
            loc_storew_le.8  dropw
            loc_storew_le.12 dropw
            loc_store.16

            loc_storew_le.20 dropw
            loc_storew_le.24 dropw
            loc_storew_le.28 dropw
            loc_storew_le.32 dropw
            loc_store.36

            # Stack convention for point_add: [out_addr, p1_addr, p2_addr, ...].
            # Push deepest first.
            locaddr.20  locaddr.0  locaddr.40
            exec.k1_point::point_add

            # Read mem[40..60] in reverse address order so X[0..4] ends up on top.
            padw loc_loadw_le.56
            padw loc_loadw_le.52
            padw loc_loadw_le.48
            padw loc_loadw_le.44
            padw loc_loadw_le.40
        end

        begin
            {pushes_p2}
            {pushes_p1}
            exec.test_wrapper_add
            {asserts}
        end",
        pushes_p1 = point_pushes(p1),
        pushes_p2 = point_pushes(p2),
        asserts = expected_point_assertions(expected),
    );
    build_test!(&source, &[]).execute().unwrap();
}

// POINT DECOMPRESSION
// ================================================================================================

#[test]
fn k1_point_decompress_generator_even_parity() {
    // Gy = 0x...D4B8: low byte 0xB8 -> parity 0.
    let g = AffinePoint::generator();
    assert_point_decompress(&g.x, 0, &g);
}

#[test]
fn k1_point_decompress_generator_odd_parity_yields_neg_g() {
    // Asking for the odd-parity root of Gx returns -G (since Gy is even, p-Gy is odd).
    let p = bn_p();
    let g = AffinePoint::generator();
    let neg_g = g.negate(&p);
    assert_point_decompress(&g.x, 1, &neg_g);
}

#[test]
fn k1_point_decompress_two_g_even_parity() {
    // 2Gy = 0x...E52A: low byte 0x2A -> parity 0.
    let two_g = AffinePoint::two_g();
    assert_point_decompress(&two_g.x, 0, &two_g);
}

fn assert_point_decompress(x: &BigUint, parity: u8, expected: &AffinePoint) {
    let x_limbs = bn_to_u32_limbs(x);
    let mut encoded: Vec<u64> = Vec::with_capacity(9);
    encoded.extend(x_limbs.iter().map(|&l| l as u64));
    encoded.push(parity as u64);

    let source = format!(
        "
        use miden::core::math::k1_point

        @locals(40)
        proc test_wrapper_decompress
            # Stack at entry: [encoded (9 felts), ...] with X[0] on top.
            loc_storew_le.0  dropw                       # X[0..4]
            loc_storew_le.4  dropw                       # X[4..8]
            loc_store.8                                  # parity

            # Stack convention for decompress: [out_addr, encoded_addr, ...].
            locaddr.0  locaddr.20
            exec.k1_point::decompress

            # Read mem[20..40] in reverse address order so X[0..4] ends up on top.
            padw loc_loadw_le.36
            padw loc_loadw_le.32
            padw loc_loadw_le.28
            padw loc_loadw_le.24
            padw loc_loadw_le.20
        end

        begin
            {pushes}
            exec.test_wrapper_decompress
            {asserts}
        end",
        pushes = push_masm_felt_sequence(&encoded),
        asserts = expected_point_assertions(expected),
    );
    build_test!(&source, &[]).execute().unwrap();
}

// SCALAR MULTIPLICATION
// ================================================================================================

#[test]
fn k1_scalar_mul_zero_yields_identity() {
    let g = AffinePoint::generator();
    assert_scalar_mul(&BigUint::zero(), &g, &AffinePoint::infinity());
}

#[test]
fn k1_scalar_mul_one_yields_p() {
    let g = AffinePoint::generator();
    assert_scalar_mul(&BigUint::from(1u32), &g, &g);
}

fn assert_scalar_mul(k: &BigUint, p: &AffinePoint, expected: &AffinePoint) {
    // Stack at the wrapper's entry should be [P (17 felts), scalar (8 felts), ...] with
    // P[0] on top. push_masm_felt_sequence places array[0] on top, so concatenate P then k.
    let mut stack: Vec<u64> = Vec::with_capacity(25);
    let x = bn_to_u32_limbs(&p.x);
    let y = bn_to_u32_limbs(&p.y);
    stack.extend(x.iter().map(|&l| l as u64));
    stack.extend(y.iter().map(|&l| l as u64));
    stack.push(if p.is_infinity { 1 } else { 0 });
    let k_limbs = bn_to_u32_limbs(k);
    stack.extend(k_limbs.iter().map(|&l| l as u64));

    let source = format!(
        "
        use miden::core::math::k1_point

        @locals(60)
        proc test_wrapper_scalar_mul
            # Stack at entry: [P (17 felts), scalar (8 felts), ...] with P[0] on top.
            loc_storew_le.0  dropw
            loc_storew_le.4  dropw
            loc_storew_le.8  dropw
            loc_storew_le.12 dropw
            loc_store.16

            loc_storew_le.20 dropw
            loc_storew_le.24 dropw

            # Stack convention: [out_addr, scalar_addr, p_addr, ...].
            locaddr.0  locaddr.20  locaddr.32
            exec.k1_point::scalar_mul

            # Read mem[32..52] in reverse address order.
            padw loc_loadw_le.48
            padw loc_loadw_le.44
            padw loc_loadw_le.40
            padw loc_loadw_le.36
            padw loc_loadw_le.32
        end

        begin
            {pushes}
            exec.test_wrapper_scalar_mul
            {asserts}
        end",
        pushes = push_masm_felt_sequence(&stack),
        asserts = expected_point_assertions(expected),
    );
    build_test!(&source, &[]).execute().unwrap();
}

// DOUBLE SCALAR MULTIPLICATION (SHAMIR)
// ================================================================================================

#[test]
fn k1_double_scalar_mul_only_k1_active() {
    let p = bn_p();
    let g = AffinePoint::generator();
    let two_g = AffinePoint::two_g();
    let expected = scalar_mul_reference(&g, &BigUint::from(5u32), &p);
    assert_double_scalar_mul(&BigUint::from(5u32), &BigUint::zero(), &g, &two_g, &expected);
}

#[test]
fn k1_double_scalar_mul_only_k2_active() {
    let p = bn_p();
    let g = AffinePoint::generator();
    let two_g = AffinePoint::two_g();
    let expected = scalar_mul_reference(&two_g, &BigUint::from(7u32), &p);
    assert_double_scalar_mul(&BigUint::zero(), &BigUint::from(7u32), &g, &two_g, &expected);
}

#[test]
fn k1_double_scalar_mul_both_small() {
    let p = bn_p();
    let g = AffinePoint::generator();
    let two_g = AffinePoint::two_g();
    let k1 = BigUint::from(5u32);
    let k2 = BigUint::from(7u32);
    // expected = 5*G + 7*(2G) = 5*G + 14*G = 19*G.
    let term1 = scalar_mul_reference(&g, &k1, &p);
    let term2 = scalar_mul_reference(&two_g, &k2, &p);
    let expected = affine_add(&term1, &term2, &p);
    assert_double_scalar_mul(&k1, &k2, &g, &two_g, &expected);
}

fn assert_double_scalar_mul(
    k1: &BigUint,
    k2: &BigUint,
    p1: &AffinePoint,
    p2: &AffinePoint,
    expected: &AffinePoint,
) {
    // Stack at wrapper entry: [P1 (17), P2 (17), k1 (8), k2 (8), ...] with P1[0] on top.
    let mut stack: Vec<u64> = Vec::with_capacity(50);
    let p1_x = bn_to_u32_limbs(&p1.x);
    let p1_y = bn_to_u32_limbs(&p1.y);
    stack.extend(p1_x.iter().map(|&l| l as u64));
    stack.extend(p1_y.iter().map(|&l| l as u64));
    stack.push(if p1.is_infinity { 1 } else { 0 });
    let p2_x = bn_to_u32_limbs(&p2.x);
    let p2_y = bn_to_u32_limbs(&p2.y);
    stack.extend(p2_x.iter().map(|&l| l as u64));
    stack.extend(p2_y.iter().map(|&l| l as u64));
    stack.push(if p2.is_infinity { 1 } else { 0 });
    let k1_limbs = bn_to_u32_limbs(k1);
    stack.extend(k1_limbs.iter().map(|&l| l as u64));
    let k2_limbs = bn_to_u32_limbs(k2);
    stack.extend(k2_limbs.iter().map(|&l| l as u64));

    let source = format!(
        "
        use miden::core::math::k1_point

        @locals(96)
        proc test_wrapper_double_scalar_mul
            # Save P1 to mem[0..20].
            loc_storew_le.0  dropw
            loc_storew_le.4  dropw
            loc_storew_le.8  dropw
            loc_storew_le.12 dropw
            loc_store.16

            # Save P2 to mem[20..40].
            loc_storew_le.20 dropw
            loc_storew_le.24 dropw
            loc_storew_le.28 dropw
            loc_storew_le.32 dropw
            loc_store.36

            # Save k1 to mem[40..48].
            loc_storew_le.40 dropw
            loc_storew_le.44 dropw

            # Save k2 to mem[48..56].
            loc_storew_le.48 dropw
            loc_storew_le.52 dropw

            # Stack convention: [out_addr, k1_addr, k2_addr, p1_addr, p2_addr, ...].
            # Push deepest (p2) first.
            locaddr.20  locaddr.0  locaddr.48  locaddr.40  locaddr.60
            exec.k1_point::double_scalar_mul

            # Read mem[60..80] in reverse address order.
            padw loc_loadw_le.76
            padw loc_loadw_le.72
            padw loc_loadw_le.68
            padw loc_loadw_le.64
            padw loc_loadw_le.60
        end

        begin
            {pushes}
            exec.test_wrapper_double_scalar_mul
            {asserts}
        end",
        pushes = push_masm_felt_sequence(&stack),
        asserts = expected_point_assertions(expected),
    );
    build_test!(&source, &[]).execute().unwrap();
}

// MSM(4, 128) — specialized GLV variant
// ================================================================================================

/// secp256k1 endomorphism: φ((x, y)) = (β·x mod p, y).
fn phi(pt: &AffinePoint, p: &BigUint) -> AffinePoint {
    if pt.is_infinity {
        return AffinePoint::infinity();
    }
    let beta = BigUint::parse_bytes(
        b"7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE",
        16,
    )
    .unwrap();
    let x = (&beta * &pt.x) % p;
    AffinePoint::finite(x, pt.y.clone())
}

#[test]
fn k1_msm_4_128_all_zero_scalars_yields_identity() {
    let p = bn_p();
    let g = AffinePoint::generator();
    let phi_g = phi(&g, &p);
    let two_g = AffinePoint::two_g();
    assert_msm_4_128_glv(
        &g,
        &phi_g,
        &g,
        &two_g,
        0,
        0,
        0,
        &BigUint::zero(),
        &BigUint::zero(),
        &BigUint::zero(),
        &BigUint::zero(),
        &AffinePoint::infinity(),
    );
}

#[test]
fn k1_msm_4_128_sign_pair_00_recovers_g_plus_phi_g() {
    let p = bn_p();
    let g = AffinePoint::generator();
    let phi_g = phi(&g, &p);
    let expected = affine_add(&g, &phi_g, &p);
    // LUT[3] dispatch test. k3 = k4 = 0, so LUT[12] is built but not selected.
    assert_msm_4_128_glv(
        &g,
        &phi_g,
        &g,
        &phi_g,
        0,
        0,
        1,
        &BigUint::from(1u32),
        &BigUint::from(1u32),
        &BigUint::zero(),
        &BigUint::zero(),
        &expected,
    );
}

#[test]
fn k1_msm_4_128_sign_pair_01_recovers_g_minus_phi_g() {
    let p = bn_p();
    let g = AffinePoint::generator();
    let phi_g = phi(&g, &p);
    let neg_phi_g = phi_g.negate(&p);
    let expected = affine_add(&g, &neg_phi_g, &p);
    // LUT[3] dispatch test. lut12_endo = 0 (general point_add for LUT[12]).
    assert_msm_4_128_glv(
        &g,
        &neg_phi_g,
        &g,
        &phi_g,
        0,
        1,
        0,
        &BigUint::from(1u32),
        &BigUint::from(1u32),
        &BigUint::zero(),
        &BigUint::zero(),
        &expected,
    );
}

#[test]
fn k1_msm_4_128_sign_pair_10_recovers_neg_g_plus_phi_g() {
    let p = bn_p();
    let g = AffinePoint::generator();
    let phi_g = phi(&g, &p);
    let neg_g = g.negate(&p);
    let expected = affine_add(&neg_g, &phi_g, &p);
    // LUT[3] dispatch test. lut12_endo = 0 (general point_add for LUT[12]).
    assert_msm_4_128_glv(
        &neg_g,
        &phi_g,
        &g,
        &phi_g,
        1,
        0,
        0,
        &BigUint::from(1u32),
        &BigUint::from(1u32),
        &BigUint::zero(),
        &BigUint::zero(),
        &expected,
    );
}

#[test]
fn k1_msm_4_128_sign_pair_11_recovers_neg_g_minus_phi_g() {
    let p = bn_p();
    let g = AffinePoint::generator();
    let phi_g = phi(&g, &p);
    let neg_g = g.negate(&p);
    let neg_phi_g = phi_g.negate(&p);
    let expected = affine_add(&neg_g, &neg_phi_g, &p);
    // LUT[3] dispatch test. k3 = k4 = 0, so LUT[12] is built but not selected.
    assert_msm_4_128_glv(
        &neg_g,
        &neg_phi_g,
        &g,
        &phi_g,
        1,
        1,
        1,
        &BigUint::from(1u32),
        &BigUint::from(1u32),
        &BigUint::zero(),
        &BigUint::zero(),
        &expected,
    );
}

#[test]
fn k1_msm_4_128_lut12_endo_recovers_q_plus_phi_q() {
    // Selects LUT[12] in the final iteration: k3 = k4 = 1 and k1 = k2 = 0.
    // Q = 7G keeps this independent of the hardcoded G + φ(G) constants.
    let p = bn_p();
    let g = AffinePoint::generator();
    let phi_g = phi(&g, &p);
    let q = scalar_mul_reference(&g, &BigUint::from(7u32), &p);
    let phi_q = phi(&q, &p);
    let expected = affine_add(&q, &phi_q, &p);
    assert_msm_4_128_glv(
        &g,
        &phi_g,
        &q,
        &phi_q,
        0,
        0,
        1,
        &BigUint::zero(),
        &BigUint::zero(),
        &BigUint::from(1u32),
        &BigUint::from(1u32),
        &expected,
    );
}

#[test]
fn k1_msm_4_128_lut12_endo_recovers_neg_q_minus_phi_q() {
    // Same LUT[12] check for the negative same-sign case.
    let p = bn_p();
    let g = AffinePoint::generator();
    let phi_g = phi(&g, &p);
    let q = scalar_mul_reference(&g, &BigUint::from(7u32), &p);
    let phi_q = phi(&q, &p);
    let neg_q = q.negate(&p);
    let neg_phi_q = phi_q.negate(&p);
    let expected = affine_add(&neg_q, &neg_phi_q, &p);
    assert_msm_4_128_glv(
        &g,
        &phi_g,
        &neg_q,
        &neg_phi_q,
        0,
        0,
        1,
        &BigUint::zero(),
        &BigUint::zero(),
        &BigUint::from(1u32),
        &BigUint::from(1u32),
        &expected,
    );
}

#[test]
fn k1_msm_4_128_full_128_bit_scalars() {
    let p = bn_p();
    let g = AffinePoint::generator();
    let phi_g = phi(&g, &p);
    let three_g = scalar_mul_reference(&g, &BigUint::from(3u32), &p);
    let four_g = scalar_mul_reference(&g, &BigUint::from(4u32), &p);
    let k1 = BigUint::parse_bytes(b"deadbeef12345678cafebabe9abcdef0", 16).unwrap();
    let k2 = BigUint::parse_bytes(b"feedface5678912334567890abcdefab", 16).unwrap();
    let k3 = BigUint::parse_bytes(b"00000000000000010203040506070809", 16).unwrap();
    let k4 = BigUint::parse_bytes(b"ffffffffffffffffffffffffffffffff", 16).unwrap();
    let r1 = scalar_mul_reference(&g, &k1, &p);
    let r2 = scalar_mul_reference(&phi_g, &k2, &p);
    let r3 = scalar_mul_reference(&three_g, &k3, &p);
    let r4 = scalar_mul_reference(&four_g, &k4, &p);
    let expected = affine_add(&affine_add(&r1, &r2, &p), &affine_add(&r3, &r4, &p), &p);
    // P_3, P_4 not endo-related → lut12_endo = 0.
    assert_msm_4_128_glv(&g, &phi_g, &three_g, &four_g, 0, 0, 0, &k1, &k2, &k3, &k4, &expected);
}

#[allow(clippy::too_many_arguments)]
fn assert_msm_4_128_glv(
    p1: &AffinePoint,
    p2: &AffinePoint,
    p3: &AffinePoint,
    p4: &AffinePoint,
    sign_a_u1: u8,
    sign_b_u1: u8,
    lut12_endo: u8,
    k1: &BigUint,
    k2: &BigUint,
    k3: &BigUint,
    k4: &BigUint,
    expected: &AffinePoint,
) {
    // Each scalar is at most 128 bits. Reject test inputs that don't fit.
    for (label, k) in [("k1", k1), ("k2", k2), ("k3", k3), ("k4", k4)] {
        assert!(k.bits() <= 128, "{label} must fit in 128 bits, got {} bits", k.bits());
    }
    assert!(lut12_endo <= 1, "lut12_endo is a u1; got {lut12_endo}");

    // Stack at wrapper entry (top to deep, 84 felts):
    //   [P1 (17), P2 (17), P3 (17), P4 (17), k1 (4), k2 (4), k3 (4), k4 (4), ...]
    let mut stack: Vec<u64> = Vec::with_capacity(84);
    for pt in [p1, p2, p3, p4] {
        let x = bn_to_u32_limbs(&pt.x);
        let y = bn_to_u32_limbs(&pt.y);
        stack.extend(x.iter().map(|&l| l as u64));
        stack.extend(y.iter().map(|&l| l as u64));
        stack.push(if pt.is_infinity { 1 } else { 0 });
    }
    for k in [k1, k2, k3, k4] {
        let limbs = bn_to_u32_limbs(k);
        stack.extend(limbs.iter().take(4).map(|&l| l as u64));
    }

    let source = format!(
        "
        use miden::core::math::k1_point

        @locals(120)
        proc test_wrapper_msm_4_128_glv_k1
            # Save P1 (17 felts) to mem[0..20].
            loc_storew_le.0  dropw
            loc_storew_le.4  dropw
            loc_storew_le.8  dropw
            loc_storew_le.12 dropw
            loc_store.16

            # Save P2 to mem[20..40].
            loc_storew_le.20 dropw
            loc_storew_le.24 dropw
            loc_storew_le.28 dropw
            loc_storew_le.32 dropw
            loc_store.36

            # Save P3 to mem[40..60].
            loc_storew_le.40 dropw
            loc_storew_le.44 dropw
            loc_storew_le.48 dropw
            loc_storew_le.52 dropw
            loc_store.56

            # Save P4 to mem[60..80].
            loc_storew_le.60 dropw
            loc_storew_le.64 dropw
            loc_storew_le.68 dropw
            loc_storew_le.72 dropw
            loc_store.76

            # Save k1..k4 (4 u32 limbs each) to mem[80..96].
            loc_storew_le.80 dropw
            loc_storew_le.84 dropw
            loc_storew_le.88 dropw
            loc_storew_le.92 dropw

            # Stack convention: [sign_a_u1, sign_b_u1, out_addr, k4_addr, k3_addr, k2_addr,
            #                    k1_addr, P4_addr, P3_addr, P2_addr, P1_addr, lut12_endo, ...].
            # Push deepest (lut12_endo) first.
            push.{lut12_endo}
            locaddr.0   locaddr.20  locaddr.40  locaddr.60
            locaddr.80  locaddr.84  locaddr.88  locaddr.92
            locaddr.96
            push.{sign_b_u1}
            push.{sign_a_u1}
            exec.k1_point::msm_4_128_glv_k1

            # Read mem[96..116] in reverse address order so X[0..4] ends on top.
            padw loc_loadw_le.112
            padw loc_loadw_le.108
            padw loc_loadw_le.104
            padw loc_loadw_le.100
            padw loc_loadw_le.96
        end

        begin
            {pushes}
            exec.test_wrapper_msm_4_128_glv_k1
            {asserts}
        end",
        pushes = push_masm_felt_sequence(&stack),
        asserts = expected_point_assertions(expected),
    );
    build_test!(&source, &[]).execute().unwrap();
}

// VERIFY_GLV_HINTED
// ================================================================================================

#[test]
fn k1_verify_glv_hinted_u1_one_u2_zero() {
    // R = 1*G + 0*Q = G.
    let g = AffinePoint::generator();
    let q = scalar_mul_reference(&g, &BigUint::from(7u32), &bn_p());
    let u1 = BigUint::from(1u32);
    let u2 = BigUint::zero();
    assert_verify_glv_hinted(&q, &u1, &u2, &g);
}

#[test]
fn k1_verify_glv_hinted_u1_zero_u2_one() {
    // R = 0*G + 1*Q = Q.
    let g = AffinePoint::generator();
    let q = scalar_mul_reference(&g, &BigUint::from(7u32), &bn_p());
    assert_verify_glv_hinted(&q, &BigUint::zero(), &BigUint::from(1u32), &q);
}

#[test]
fn k1_verify_glv_hinted_small_combination() {
    // R = 3*G + 5*Q where Q = 7G; so R = 3G + 35G = 38G.
    let p = bn_p();
    let g = AffinePoint::generator();
    let q = scalar_mul_reference(&g, &BigUint::from(7u32), &p);
    let u1 = BigUint::from(3u32);
    let u2 = BigUint::from(5u32);
    let expected = scalar_mul_reference(&g, &BigUint::from(38u32), &p);
    assert_verify_glv_hinted(&q, &u1, &u2, &expected);
}

#[test]
fn k1_verify_glv_hinted_full_256_bit_scalars() {
    let p = bn_p();
    let n = BigUint::from_slice(&secp256k1_scalar_order().to_le_u32_limbs());
    let g = AffinePoint::generator();
    let q = scalar_mul_reference(&g, &BigUint::from(0xdeadbeef_u32), &p);
    let u1 = BigUint::parse_bytes(
        b"5e3a1b3a8c00c5d6c0a4afde7f8e0c5b9a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e",
        16,
    )
    .unwrap()
        % &n;
    let u2 = BigUint::parse_bytes(
        b"7f8e9d0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8e9d0a1b2c3d4e5f6a7b8c",
        16,
    )
    .unwrap()
        % &n;
    let expected_g = scalar_mul_reference(&g, &u1, &p);
    let expected_q = scalar_mul_reference(&q, &u2, &p);
    let expected = affine_add(&expected_g, &expected_q, &p);
    assert_verify_glv_hinted(&q, &u1, &u2, &expected);
}

fn assert_verify_glv_hinted(q: &AffinePoint, u1: &BigUint, u2: &BigUint, expected: &AffinePoint) {
    let n = BigUint::from_slice(&secp256k1_scalar_order().to_le_u32_limbs());
    assert!(u1 < &n, "u1 must be < n");
    assert!(u2 < &n, "u2 must be < n");

    // Stack at wrapper entry (top to deep, 33 felts):
    //   [Q (17), u_1 (8), u_2 (8), ...]
    let mut stack: Vec<u64> = Vec::with_capacity(33);
    let q_x = bn_to_u32_limbs(&q.x);
    let q_y = bn_to_u32_limbs(&q.y);
    stack.extend(q_x.iter().map(|&l| l as u64));
    stack.extend(q_y.iter().map(|&l| l as u64));
    stack.push(if q.is_infinity { 1 } else { 0 });
    let u1_limbs = bn_to_u32_limbs(u1);
    stack.extend(u1_limbs.iter().map(|&l| l as u64));
    let u2_limbs = bn_to_u32_limbs(u2);
    stack.extend(u2_limbs.iter().map(|&l| l as u64));

    let source = format!(
        "
        use miden::core::math::k1_point

        @locals(60)
        proc test_wrapper_verify_glv_hinted
            # Save Q (17 felts) to mem[0..20].
            loc_storew_le.0  dropw
            loc_storew_le.4  dropw
            loc_storew_le.8  dropw
            loc_storew_le.12 dropw
            loc_store.16

            # Save u_1 (8 felts) to mem[20..28] and u_2 (8 felts) to mem[28..36].
            loc_storew_le.20 dropw
            loc_storew_le.24 dropw
            loc_storew_le.28 dropw
            loc_storew_le.32 dropw

            # Stack convention: [out_addr, q_addr, u_2_addr, u_1_addr, ...]. Push deepest first.
            locaddr.20  locaddr.28  locaddr.0  locaddr.36
            exec.k1_point::verify_glv_hinted

            # Read mem[36..56] (the result) in reverse address order so X[0..4] ends on top.
            padw loc_loadw_le.52
            padw loc_loadw_le.48
            padw loc_loadw_le.44
            padw loc_loadw_le.40
            padw loc_loadw_le.36
        end

        begin
            {pushes}
            exec.test_wrapper_verify_glv_hinted
            {asserts}
        end",
        pushes = push_masm_felt_sequence(&stack),
        asserts = expected_point_assertions(expected),
    );
    build_test!(&source, &[]).execute().unwrap();
}

// PROPTESTS
// ================================================================================================

proptest! {
    /// Random scalar k -> compute P = k*G with the affine reference doubling +
    /// addition), then test that MASM's point_double matches the reference doubling on P.
    #[test]
    fn k1_point_double_proptest(k_lo in 1u64..1_000_000) {
        let p = bn_p();
        let pt = scalar_mul_reference(&AffinePoint::generator(), &BigUint::from(k_lo), &p);
        let expected = pt.double(&p);
        assert_point_double(&pt, &expected);
    }

    /// Random small scalars k1, k2 -> P1 = k1*G, P2 = k2*G via reference scalar mul. Test that
    /// MASM's point_add(P1, P2) matches the reference addition. Covers many input shapes;
    /// the smaller k1 and k2 ranges keep test runtime down (each MASM execution is ~1 inv +
    /// a few muls, all routed through SZ Horner modmul which is the slow part).
    #[test]
    fn k1_point_add_proptest(
        k1_lo in 1u64..10_000,
        k2_lo in 1u64..10_000,
    ) {
        let p = bn_p();
        let g = AffinePoint::generator();
        let p1 = scalar_mul_reference(&g, &BigUint::from(k1_lo), &p);
        let p2 = scalar_mul_reference(&g, &BigUint::from(k2_lo), &p);
        let expected = affine_add(&p1, &p2, &p);
        assert_point_add(&p1, &p2, &expected);
    }

    /// Small scalar k. We compute k*G in Rust and check that MASM's scalar_mul matches.
    /// Range is tight (k <= 1000) because the full 256-bit scalar mul scans all 256 bits
    /// even for small k; keeping k small means most leading bits are zero so the
    /// short-circuiting fast paths dominate.
    #[test]
    fn k1_scalar_mul_proptest(k_lo in 0u64..1_000) {
        let p = bn_p();
        let g = AffinePoint::generator();
        let expected = scalar_mul_reference(&g, &BigUint::from(k_lo), &p);
        assert_scalar_mul(&BigUint::from(k_lo), &g, &expected);
    }

    /// Random small scalars k1, k2 with P1 = G, P2 = 2G. Tight upper bounds on k1, k2 keep
    /// most bit-pairs at (0, 0), letting the inner short-circuit dominate; the joint scan
    /// loop still runs all 256 bits per call.
    #[test]
    fn k1_double_scalar_mul_proptest(
        k1_lo in 0u64..500,
        k2_lo in 0u64..500,
    ) {
        let p = bn_p();
        let g = AffinePoint::generator();
        let two_g = AffinePoint::two_g();
        let term1 = scalar_mul_reference(&g, &BigUint::from(k1_lo), &p);
        let term2 = scalar_mul_reference(&two_g, &BigUint::from(k2_lo), &p);
        let expected = affine_add(&term1, &term2, &p);
        assert_double_scalar_mul(
            &BigUint::from(k1_lo),
            &BigUint::from(k2_lo),
            &g,
            &two_g,
            &expected,
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    /// Low-count integration property test for the optimized ECDSA MSM core: random `u_1`,
    /// `u_2`, and valid `Q`, checked against the affine reference equation `u_1*G + u_2*Q`.
    #[test]
    fn k1_verify_glv_hinted_proptest(
        q_scalar in 1u64..10_000,
        u1_limbs in prop::array::uniform8(boundary_biased_u32()),
        u2_limbs in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let p = bn_p();
        let n = BigUint::from_slice(&secp256k1_scalar_order().to_le_u32_limbs());
        let g = AffinePoint::generator();
        let q = scalar_mul_reference(&g, &BigUint::from(q_scalar), &p);
        let u1 = BigUint::from_slice(&u1_limbs) % &n;
        let u2 = BigUint::from_slice(&u2_limbs) % &n;

        let expected_g = scalar_mul_reference(&g, &u1, &p);
        let expected_q = scalar_mul_reference(&q, &u2, &p);
        let expected = affine_add(&expected_g, &expected_q, &p);

        assert_verify_glv_hinted(&q, &u1, &u2, &expected);
    }
}

/// Reference scalar multiplication using affine doubling/addition. NOT wired through MASM; this
/// is purely for test-vector generation.
fn scalar_mul_reference(p_pt: &AffinePoint, k: &BigUint, p: &BigUint) -> AffinePoint {
    let mut acc = AffinePoint::infinity();
    let bits = k.bits();
    for i in (0..bits).rev() {
        acc = acc.double(p);
        if k.bit(i) {
            acc = affine_add(&acc, p_pt, p);
        }
    }
    acc
}

/// Reference affine addition (handles the ±P / infinity cases). Only used by
/// `scalar_mul_reference`; MASM's `point_add` is the subject of step 4b.
fn affine_add(a: &AffinePoint, b: &AffinePoint, p: &BigUint) -> AffinePoint {
    if a.is_infinity {
        return b.clone();
    }
    if b.is_infinity {
        return a.clone();
    }
    if a.x == b.x {
        if a.y == b.y {
            return a.double(p);
        }
        return AffinePoint::infinity();
    }
    let m = {
        let num = sub_mod(&b.y, &a.y, p);
        let den = sub_mod(&b.x, &a.x, p);
        let inv_den = modinv(&den, p).expect("x_b - x_a must be invertible");
        (num * inv_den) % p
    };
    let m2 = (&m * &m) % p;
    let x3 = sub_mod(&sub_mod(&m2, &a.x, p), &b.x, p);
    let diff = sub_mod(&a.x, &x3, p);
    let prod = (&m * &diff) % p;
    let y3 = sub_mod(&prod, &a.y, p);
    AffinePoint::finite(x3, y3)
}

fn bn_p() -> BigUint {
    BigUint::from_slice(&secp256k1_base_prime().to_le_u32_limbs())
}

// VERIFY_PRECOMP PROPTESTS
// ================================================================================================
//
// Each case builds the 176,128-entry precomputed-key cache and runs `verify_precomp` through
// the MASM proc, so cases are deliberately few. The intent is to give random coverage over
// the bit-buffer + leaf-index path -- the four hand-picked
// boundary cases above (zero/identity scalars, small combinations, full 256-bit) cover the
// algebraic edges; this proptest covers everything in between.

/// Strategy that generates a secp256k1 scalar in `[1, n)`. Built from a uniform 32-byte
/// buffer reduced mod n; zero is clamped to one so the resulting point is never the identity.
fn arb_scalar_lt_n() -> impl Strategy<Value = BigUint> {
    any::<[u8; 32]>().prop_map(|bytes| {
        let n = BigUint::from_slice(&secp256k1_scalar_order().to_le_u32_limbs());
        (BigUint::from_bytes_be(&bytes) % &n).max(BigUint::from(1u32))
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn k1_verify_precomp_proptest(
        q_scalar in arb_scalar_lt_n(),
        u1 in arb_scalar_lt_n(),
        u2 in arb_scalar_lt_n(),
    ) {
        let p = bn_p();
        let g = AffinePoint::generator();
        let q = scalar_mul_reference(&g, &q_scalar, &p);
        let expected_g = scalar_mul_reference(&g, &u1, &p);
        let expected_q = scalar_mul_reference(&q, &u2, &p);
        let expected = affine_add(&expected_g, &expected_q, &p);
        assert_verify_precomp(&q, &u1, &u2, &expected);
    }
}

// STREAMING-HASH SANITY CHECK
// ================================================================================================

/// Streaming N felts from the advice stack via `adv_pipe + hperm` must produce the same
/// digest as Rust-side `Poseidon2::hash_elements`. Pins the digest-extraction tail used by
/// `verify_precomp` so a subtle stack-shuffle change (e.g. wrong drop ordering) gets
/// caught directly.
#[test]
fn k1_streaming_hash_sanity_16_felts() {
    use miden_core::{Felt, crypto::hash::Poseidon2};

    let elements: Vec<Felt> = (1u64..=16).map(Felt::new_unchecked).collect();
    let expected = *Poseidon2::hash_elements(&elements);
    let expected_u64: [u64; 4] = std::array::from_fn(|i| expected[i].as_canonical_u64());

    let advice: Vec<u64> = elements.iter().map(|f| f.as_canonical_u64()).collect();
    let source = "
        use miden::core::crypto::hashes::poseidon2

        begin
            push.0xE0050000
            padw padw padw
            repeat.2
                adv_pipe exec.poseidon2::permute
            end
            # Stack: [R0, R1, C, ptr_end, <16 init zeros>]. Keep R0; drop the rest.
            swapw dropw      # drop R1
            swapw dropw      # drop C
            movup.4 drop     # drop ptr_end (sits below R0 now)
            swapdw dropw dropw  # drop trailing init zeros to satisfy stack-depth cap
        end";
    build_test!(source, &[], &advice).expect_stack(&expected_u64);
}

// VERIFY_PRECOMP -- joint-comb scalar mult driver
// ================================================================================================

#[test]
fn k1_verify_precomp_u1_one_u2_zero() {
    // R = 1*G + 0*Q = G.
    let g = AffinePoint::generator();
    let q = scalar_mul_reference(&g, &BigUint::from(7u32), &bn_p());
    assert_verify_precomp(&q, &BigUint::from(1u32), &BigUint::zero(), &g);
}

#[test]
fn k1_verify_precomp_u1_zero_u2_one() {
    // R = 0*G + 1*Q = Q.
    let g = AffinePoint::generator();
    let q = scalar_mul_reference(&g, &BigUint::from(7u32), &bn_p());
    assert_verify_precomp(&q, &BigUint::zero(), &BigUint::from(1u32), &q);
}

#[test]
fn k1_verify_precomp_small_combination() {
    // R = 3*G + 5*Q where Q = 7G; so R = 3G + 35G = 38G.
    let p = bn_p();
    let g = AffinePoint::generator();
    let q = scalar_mul_reference(&g, &BigUint::from(7u32), &p);
    let expected = scalar_mul_reference(&g, &BigUint::from(38u32), &p);
    assert_verify_precomp(&q, &BigUint::from(3u32), &BigUint::from(5u32), &expected);
}

#[test]
fn k1_verify_precomp_full_256_bit_scalars() {
    let p = bn_p();
    let n = BigUint::from_slice(&secp256k1_scalar_order().to_le_u32_limbs());
    let g = AffinePoint::generator();
    let q = scalar_mul_reference(&g, &BigUint::from(0xdeadbeef_u32), &p);
    let u1 = BigUint::parse_bytes(
        b"5e3a1b3a8c00c5d6c0a4afde7f8e0c5b9a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e",
        16,
    )
    .unwrap()
        % &n;
    let u2 = BigUint::parse_bytes(
        b"7f8e9d0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8e9d0a1b2c3d4e5f6a7b8c",
        16,
    )
    .unwrap()
        % &n;
    let expected_g = scalar_mul_reference(&g, &u1, &p);
    let expected_q = scalar_mul_reference(&q, &u2, &p);
    let expected = affine_add(&expected_g, &expected_q, &p);
    assert_verify_precomp(&q, &u1, &u2, &expected);
}

fn assert_verify_precomp(q: &AffinePoint, u1: &BigUint, u2: &BigUint, expected: &AffinePoint) {
    use miden_core::advice::AdviceInputs;
    use miden_core_lib::handlers::comb_k1::{AffinePoint as HandlerPoint, PrecomputedK1PubKey};

    let n = BigUint::from_slice(&secp256k1_scalar_order().to_le_u32_limbs());
    assert!(u1 < &n, "u1 must be < n");
    assert!(u2 < &n, "u2 must be < n");

    let g_handler = HandlerPoint {
        x: AffinePoint::generator().x,
        y: AffinePoint::generator().y,
        is_infinity: false,
    };
    let q_handler = HandlerPoint {
        x: q.x.clone(),
        y: q.y.clone(),
        is_infinity: q.is_infinity,
    };
    let precomputed_pk = PrecomputedK1PubKey::new(&g_handler, &q_handler);
    let root = precomputed_pk.merkle_root();
    let (entry_advice, store) = precomputed_pk.advice_for_windows(u1, u2);

    // Stack at wrapper entry (top to deep, 20 felts):
    //   [u_1 (8), u_2 (8), merkle_root (4), ...]
    let mut stack: Vec<u64> = Vec::with_capacity(20);
    stack.extend(bn_to_u32_limbs(u1).iter().map(|&l| l as u64));
    stack.extend(bn_to_u32_limbs(u2).iter().map(|&l| l as u64));
    for f in root.iter() {
        stack.push(f.as_canonical_u64());
    }

    let source = format!(
        "
        use miden::core::math::k1_point

        @locals(48)
        proc test_wrapper_verify_precomp
            # Save u_1 (8 felts) to mem[0..8] and u_2 (8 felts) to mem[8..16].
            loc_storew_le.0  dropw
            loc_storew_le.4  dropw
            loc_storew_le.8  dropw
            loc_storew_le.12 dropw

            # Save merkle_root (4 felts) to mem[16..20].
            loc_storew_le.16 dropw

            # Stack convention: [out_addr, u_2_addr, u_1_addr, merkle_root_addr, ...].
            locaddr.16  locaddr.0  locaddr.8  locaddr.20
            exec.k1_point::verify_precomp

            # Read result at mem[20..40] in reverse address order so X[0..4] ends on top.
            padw loc_loadw_le.36
            padw loc_loadw_le.32
            padw loc_loadw_le.28
            padw loc_loadw_le.24
            padw loc_loadw_le.20
        end

        begin
            {pushes}
            exec.test_wrapper_verify_precomp
            {asserts}
        end",
        pushes = push_masm_felt_sequence(&stack),
        asserts = expected_point_assertions(expected),
    );

    let mut test = build_test!(&source, &[]);
    test.advice_inputs = AdviceInputs::default().with_stack(entry_advice).with_merkle_store(store);
    test.execute().unwrap();
}

// CYCLE BENCHMARKS
// ================================================================================================

#[test]
#[ignore = "benchmark; run with --ignored to print cycle count"]
fn point_double_cycles() {
    use miden_core::Felt;
    use miden_processor::ContextId;

    // Match the working `assert_point_double` wrapper pattern: input is on the stack at
    // entry, get stored to local mem, then point_double is called.
    let g = AffinePoint::generator();
    let pushes = point_pushes(&g);
    let source = format!(
        "
        use miden::core::math::k1_point
        use miden::core::sys

        @locals(40)
        proc bench
            loc_storew_le.0  dropw
            loc_storew_le.4  dropw
            loc_storew_le.8  dropw
            loc_storew_le.12 dropw
            loc_store.16

            clk
            locaddr.0  locaddr.20
            exec.k1_point::point_double
            clk

            swap sub
            push.5000 mem_store
        end

        begin
            {pushes}
            exec.bench
            exec.sys::truncate_stack
        end
        "
    );
    let source = source.as_str();
    let test = build_debug_test!(source, &[]);
    let (output, _) = test.execute_for_output().unwrap();
    let cycles = output
        .memory
        .read_element(ContextId::root(), Felt::from_u32(5000))
        .unwrap()
        .as_canonical_u64();
    eprintln!("point_double cycles: {cycles}");
}

#[test]
#[ignore = "benchmark; run with --ignored to print cycle count"]
fn point_add_cycles() {
    use miden_core::Felt;
    use miden_processor::ContextId;

    let source = "
        use miden::core::math::k1_point
        use miden::core::sys

        @locals(60)
        proc bench
            # P1 = G at mem[0..20].
            push.0x029BFCDB.0x2DCE28D9.0x59F2815B.0x16F81798  loc_storew_le.0  dropw
            push.0x79BE667E.0xF9DCBBAC.0x55A06295.0xCE870B07  loc_storew_le.4  dropw
            push.0xFD17B448.0xA6855419.0x9C47D08F.0xFB10D4B8  loc_storew_le.8  dropw
            push.0x483ADA77.0x26A3C465.0x5DA4FBFC.0x0E1108A8  loc_storew_le.12 dropw
            padw  loc_storew_le.16 dropw

            # P2 = 2G at mem[20..40] (precomputed affine doubling of G).
            push.0x9075b4ee.0x5c75a31f.0x7ce670b4.0xc6047f94  loc_storew_le.20 dropw
            push.0x6cb91068.0xe51b3f87.0x95c707a6.0x1ae168fe  loc_storew_le.24 dropw
            push.0xf9dcbbac.0x55a06295.0xce870b07.0x029bfcdb  loc_storew_le.28 dropw
            push.0xa6855419.0x9c47d08f.0xfb10d4b8.0xfd17b448  loc_storew_le.32 dropw
            padw  loc_storew_le.36 dropw

            clk
            # point_add signature: [out_addr, p1_addr, p2_addr, ...]; push deepest first.
            locaddr.20  locaddr.0  locaddr.40
            exec.k1_point::point_add
            clk

            swap sub
            push.5000 mem_store
        end

        begin
            exec.bench
            exec.sys::truncate_stack
        end
    ";
    let test = build_debug_test!(source, &[]);
    let (output, _) = test.execute_for_output().unwrap();
    let cycles = output
        .memory
        .read_element(ContextId::root(), Felt::from_u32(5000))
        .unwrap()
        .as_canonical_u64();
    eprintln!("point_add cycles (G + 2G): {cycles}");
}

#[test]
#[ignore = "benchmark; run with --ignored to print cycle count"]
fn msm_4_128_glv_k1_cycles() {
    use miden_core::Felt;
    use miden_processor::ContextId;

    let source = "
        use miden::core::math::k1_point
        use miden::core::sys

        @locals(120)
        proc bench
            # P_1 = G at mem[0..20].
            push.0x029BFCDB.0x2DCE28D9.0x59F2815B.0x16F81798  loc_storew_le.0  dropw
            push.0x79BE667E.0xF9DCBBAC.0x55A06295.0xCE870B07  loc_storew_le.4  dropw
            push.0xFD17B448.0xA6855419.0x9C47D08F.0xFB10D4B8  loc_storew_le.8  dropw
            push.0x483ADA77.0x26A3C465.0x5DA4FBFC.0x0E1108A8  loc_storew_le.12 dropw
            push.0  loc_store.16

            # P_2 = φ(G) at mem[20..40]; φ(G).y = G_y.
            push.0x87284406.0x7f15e98d.0xa7bba044.0x00b88fcb  loc_storew_le.20 dropw
            push.0xbcace2e9.0x9da01887.0xab0102b6.0x96902325  loc_storew_le.24 dropw
            push.0xFD17B448.0xA6855419.0x9C47D08F.0xFB10D4B8  loc_storew_le.28 dropw
            push.0x483ADA77.0x26A3C465.0x5DA4FBFC.0x0E1108A8  loc_storew_le.32 dropw
            push.0  loc_store.36

            # P_3 = G again at mem[40..60] (arbitrary valid point).
            push.0x029BFCDB.0x2DCE28D9.0x59F2815B.0x16F81798  loc_storew_le.40 dropw
            push.0x79BE667E.0xF9DCBBAC.0x55A06295.0xCE870B07  loc_storew_le.44 dropw
            push.0xFD17B448.0xA6855419.0x9C47D08F.0xFB10D4B8  loc_storew_le.48 dropw
            push.0x483ADA77.0x26A3C465.0x5DA4FBFC.0x0E1108A8  loc_storew_le.52 dropw
            push.0  loc_store.56

            # P_4 = 2G at mem[60..80].
            push.0x9075b4ee.0x5c75a31f.0x7ce670b4.0xc6047f94  loc_storew_le.60 dropw
            push.0x6cb91068.0xe51b3f87.0x95c707a6.0x1ae168fe  loc_storew_le.64 dropw
            push.0xf9dcbbac.0x55a06295.0xce870b07.0x029bfcdb  loc_storew_le.68 dropw
            push.0xa6855419.0x9c47d08f.0xfb10d4b8.0xfd17b448  loc_storew_le.72 dropw
            push.0  loc_store.76

            # k_1..k_4: 4-limb 128-bit scalars at mem[80..96].
            push.0xdeadbeef.0x12345678.0xcafebabe.0x9abcdef0  loc_storew_le.80 dropw
            push.0xfeedface.0x56789123.0x34567890.0xabcdefab  loc_storew_le.84 dropw
            push.0x00000000.0x00000001.0x02030405.0x06070809  loc_storew_le.88 dropw
            push.0xffffffff.0xffffffff.0xffffffff.0xffffffff  loc_storew_le.92 dropw

            clk
            # Stack: [sign_a_u1, sign_b_u1, out_addr, k_4_addr, k_3_addr, k_2_addr,
            #         k_1_addr, P_4_addr, P_3_addr, P_2_addr, P_1_addr, lut12_endo, ...].
            push.0  # lut12_endo (P_3 = G, P_4 = 2G — no endo relation; force point_add path)
            locaddr.0   locaddr.20  locaddr.40  locaddr.60
            locaddr.80  locaddr.84  locaddr.88  locaddr.92
            locaddr.96
            push.0  # sign_b_u1
            push.0  # sign_a_u1
            exec.k1_point::msm_4_128_glv_k1
            clk

            swap sub
            push.5000 mem_store
        end

        begin
            exec.bench
            exec.sys::truncate_stack
        end
    ";
    let test = build_debug_test!(source, &[]);
    let (output, _) = test.execute_for_output().unwrap();
    let cycles = output
        .memory
        .read_element(ContextId::root(), Felt::from_u32(5000))
        .unwrap()
        .as_canonical_u64();
    eprintln!("msm_4_128_glv_k1 cycles (sa=0, sb=0, full 128-bit scalars): {cycles}");
}

#[test]
#[ignore = "benchmark; run with --ignored to print cycle count"]
fn verify_glv_hinted_cycles() {
    use miden_core::Felt;
    use miden_processor::ContextId;

    let source = "
        use miden::core::math::k1_point
        use miden::core::sys

        @locals(80)
        proc bench
            # u_1 at mem[0..8] (256-bit scalar).
            push.0xdeadbeef.0x12345678.0xcafebabe.0x9abcdef0  loc_storew_le.0 dropw
            push.0x11111111.0x22222222.0x33333333.0x12345678  loc_storew_le.4 dropw

            # u_2 at mem[8..16].
            push.0xfeedface.0x56789123.0x34567890.0xabcdefab  loc_storew_le.8  dropw
            push.0x55443322.0x11ffeedd.0xccbbaa99.0x88776655  loc_storew_le.12 dropw

            # Q = 2G at mem[16..36] (an on-curve point).
            push.0x9075b4ee.0x5c75a31f.0x7ce670b4.0xc6047f94  loc_storew_le.16 dropw
            push.0x6cb91068.0xe51b3f87.0x95c707a6.0x1ae168fe  loc_storew_le.20 dropw
            push.0xf9dcbbac.0x55a06295.0xce870b07.0x029bfcdb  loc_storew_le.24 dropw
            push.0xa6855419.0x9c47d08f.0xfb10d4b8.0xfd17b448  loc_storew_le.28 dropw
            push.0  loc_store.32

            clk
            # verify_glv_hinted signature: [out_addr, q_addr, u_2_addr, u_1_addr, ...].
            # Push deepest first.
            locaddr.0  locaddr.8  locaddr.16  locaddr.36
            exec.k1_point::verify_glv_hinted
            clk

            swap sub
            push.5000 mem_store
        end

        begin
            exec.bench
            exec.sys::truncate_stack
        end
    ";
    let test = build_debug_test!(source, &[]);
    let (output, _) = test.execute_for_output().unwrap();
    let cycles = output
        .memory
        .read_element(ContextId::root(), Felt::from_u32(5000))
        .unwrap()
        .as_canonical_u64();
    eprintln!("verify_glv_hinted cycles: {cycles}");
}
