//! Ed25519 parameters for the fixed curve precompile.

use miden_core::deferred::{DeferredError, PrecompileError};

use super::{CurvePoint, CurveSpec, ShortWeierstrassSpec, short_weierstrass};
use crate::math::{
    ed25519_base::Ed25519Base,
    ed25519_order::Ed25519Order,
    uint::{Limbs, UintSpec, ZERO_LIMBS},
};

const ONE_LIMBS: Limbs = [1, 0, 0, 0, 0, 0, 0, 0];

// Edwards `d = -121665 / 121666 mod p`, represented in the birational model's base field.
const ED25519_D: Limbs = [
    0x1359_78a3,
    0x75eb_4dca,
    0x4141_d8ab,
    0x0070_0a4d,
    0x7779_e898,
    0x8cc7_4079,
    0x2b6f_fe73,
    0x5203_6cee,
];

// Square root of -1 modulo p, used by the p ≡ 5 (mod 8) square-root method.
const SQRT_MINUS_ONE: Limbs = [
    0x4a0e_a0b0,
    0xc4ee_1b27,
    0xad2f_e478,
    0x2f43_1806,
    0x3dfb_d7a7,
    0x2b4d_0099,
    0x4fc1_df0b,
    0x2b83_2480,
];

// (p + 3) / 8 for p = 2^255 - 19.
const SQRT_EXPONENT: Limbs = [
    0xffff_fffe,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0x0fff_ffff,
];

/// Decodes the affine Edwards x-coordinate from a compressed RFC 8032 Ed25519 point.
///
/// This is a coordinate helper for the signature precompile. It validates canonical `y`, solves
/// `x² = (y² - 1) / (d*y² + 1)` in the Ed25519 base field, and applies the encoded x parity bit.
/// The returned value is the canonical Edwards x witness; no compressed bytes are retained in
/// graph nodes. The caller can then apply the fixed birational map to obtain SW coordinates.
pub fn ed25519_decompress_x(encoded: [u8; 32]) -> Result<Limbs, PrecompileError> {
    let sign = encoded[31] >> 7;
    let mut y_bytes = encoded;
    y_bytes[31] &= 0x7f;
    let y = core::array::from_fn(|index| {
        u32::from_le_bytes([
            y_bytes[index * 4],
            y_bytes[index * 4 + 1],
            y_bytes[index * 4 + 2],
            y_bytes[index * 4 + 3],
        ])
    });
    if !Ed25519Base::is_canonical(&y) {
        return Err(DeferredError::InvalidPayload.into());
    }

    let y_squared = Ed25519Base::mul(y, y);
    let numerator = Ed25519Base::sub(y_squared, ONE_LIMBS);
    let denominator = Ed25519Base::add(Ed25519Base::mul(ED25519_D, y_squared), ONE_LIMBS);
    let denominator_inv = Ed25519Base::inv(denominator)
        .ok_or(DeferredError::InvalidPayload)
        .map_err(PrecompileError::from)?;
    let x_squared = Ed25519Base::mul(numerator, denominator_inv);

    let mut x = pow_base_field(x_squared, SQRT_EXPONENT);
    if Ed25519Base::mul(x, x) != x_squared {
        x = Ed25519Base::mul(x, SQRT_MINUS_ONE);
    }
    if Ed25519Base::mul(x, x) != x_squared {
        return Err(DeferredError::InvalidPayload.into());
    }

    if (x[0] & 1) != u32::from(sign) {
        if x == ZERO_LIMBS {
            return Err(DeferredError::InvalidPayload.into());
        }
        x = Ed25519Base::sub(ZERO_LIMBS, x);
    }
    Ok(x)
}

fn pow_base_field(base: Limbs, exponent: Limbs) -> Limbs {
    let mut result = ONE_LIMBS;
    for bit in (0..256).rev() {
        result = Ed25519Base::mul(result, result);
        if (exponent[bit / 32] >> (bit % 32)) & 1 == 1 {
            result = Ed25519Base::mul(result, base);
        }
    }
    result
}

/// Stable local curve selector for Ed25519.
pub const ED25519_ID: miden_core::Felt = miden_core::Felt::new_unchecked(2);

/// Ed25519's birational short-Weierstrass generator x-coordinate, little-endian u32 limbs.
pub const ED25519_GENERATOR_X: Limbs = [
    0xaaad_245a,
    0xaaaa_aaaa,
    0xaaaa_aaaa,
    0xaaaa_aaaa,
    0xaaaa_aaaa,
    0xaaaa_aaaa,
    0xaaaa_aaaa,
    0x2aaa_aaaa,
];

/// Ed25519's birational short-Weierstrass generator y-coordinate, little-endian u32 limbs.
pub const ED25519_GENERATOR_Y: Limbs = [
    0x8131_2c14,
    0xd616_3a5d,
    0x9283_9e4d,
    0x6dc2_b281,
    0x88b7_2eb3,
    0x1fe1_22d3,
    0x475f_794b,
    0x5f51_e65e,
];

/// Marker type for the Ed25519 birational short-Weierstrass curve.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519;

impl CurveSpec for Ed25519 {
    const ID: miden_core::Felt = ED25519_ID;

    type BaseField = Ed25519Base;
    // The complete group order is required so MSM annihilates mixed-torsion points.
    type ScalarField = Ed25519Order;

    const GENERATOR_X: Limbs = ED25519_GENERATOR_X;
    const GENERATOR_Y: Limbs = ED25519_GENERATOR_Y;

    fn point_from_affine(x: Limbs, y: Limbs) -> Result<CurvePoint, PrecompileError> {
        short_weierstrass::point_from_affine::<Self>(x, y)
    }

    fn add(lhs: CurvePoint, rhs: CurvePoint) -> Result<CurvePoint, PrecompileError> {
        short_weierstrass::add::<Self>(lhs, rhs)
    }

    fn neg(point: CurvePoint) -> Result<CurvePoint, PrecompileError> {
        Ok(short_weierstrass::neg::<Self>(point))
    }

    fn mul_scalar(point: CurvePoint, scalar: Limbs) -> Result<CurvePoint, PrecompileError> {
        short_weierstrass::mul_scalar::<Self>(point, scalar)
    }
}

impl ShortWeierstrassSpec for Ed25519 {
    /// Birational SW coefficient `A` from RFC 7748 section 4.1.
    const A: Limbs = [
        0x4914_a144,
        0xaaaa_aa98,
        0xaaaa_aaaa,
        0xaaaa_aaaa,
        0xaaaa_aaaa,
        0xaaaa_aaaa,
        0xaaaa_aaaa,
        0x2aaa_aaaa,
    ];

    /// Birational SW coefficient `B` from RFC 7748 section 4.1.
    const B: Limbs = [
        0x7710_c864,
        0x260b_5e9c,
        0x5ed0_97b4,
        0xed09_7b42,
        0xd097_b425,
        0x097b_425e,
        0x97b4_25ed,
        0x7b42_5ed0,
    ];
}
