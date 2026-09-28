//! P-256 parameters for the fixed curve precompile.

use miden_core::deferred::PrecompileError;

use super::{CurvePoint, CurveSpec, ShortWeierstrassSpec, short_weierstrass};
use crate::math::{p256_base::P256Base, p256_scalar::P256Scalar, uint::Limbs};

/// Stable local curve selector for P-256.
pub const P256_ID: miden_core::Felt = miden_core::Felt::new_unchecked(3);

/// Standard P-256 generator x-coordinate, little-endian u32 limbs.
pub const P256_GENERATOR_X: Limbs = [
    0xd898_c296,
    0xf4a1_3945,
    0x2deb_33a0,
    0x7703_7d81,
    0x63a4_40f2,
    0xf8bc_e6e5,
    0xe12c_4247,
    0x6b17_d1f2,
];

/// Standard P-256 generator y-coordinate, little-endian u32 limbs.
pub const P256_GENERATOR_Y: Limbs = [
    0x37bf_51f5,
    0xcbb6_4068,
    0x6b31_5ece,
    0x2bce_3357,
    0x7c0f_9e16,
    0x8ee7_eb4a,
    0xfe1a_7f9b,
    0x4fe3_42e2,
];

/// Marker type for the P-256 curve.
#[derive(Debug, Default, Clone, Copy)]
pub struct P256;

impl CurveSpec for P256 {
    /// Stable local curve selector retained for host-side metadata.
    const ID: miden_core::Felt = P256_ID;

    type BaseField = P256Base;
    type ScalarField = P256Scalar;

    /// Standard P-256 generator x-coordinate, little-endian u32 limbs.
    const GENERATOR_X: Limbs = P256_GENERATOR_X;

    /// Standard P-256 generator y-coordinate, little-endian u32 limbs.
    const GENERATOR_Y: Limbs = P256_GENERATOR_Y;

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

impl ShortWeierstrassSpec for P256 {
    /// Coefficient `A = p - 3` for `y^2 = x^3 - 3x + B`.
    const A: Limbs = [
        0xffff_fffc,
        0xffff_ffff,
        0xffff_ffff,
        0x0000_0000,
        0x0000_0000,
        0x0000_0000,
        0x0000_0001,
        0xffff_ffff,
    ];

    /// Coefficient `B` for `y^2 = x^3 - 3x + B`.
    const B: Limbs = [
        0x27d2_604b,
        0x3bce_3c3e,
        0xcc53_b0f6,
        0x651d_06b0,
        0x7698_86bc,
        0xb3eb_bd55,
        0xaa3a_93e7,
        0x5ac6_35d8,
    ];
}
