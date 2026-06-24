//! secp256r1 parameters for the fixed curve precompile.

use miden_core::deferred::PrecompileError;

use super::{CurvePoint, CurveSpec, ShortWeierstrassSpec, short_weierstrass};
use crate::math::{r1_base::R1Base, r1_scalar::R1Scalar, uint::Limbs};

/// Marker type for the secp256r1 curve.
#[derive(Debug, Default, Clone, Copy)]
pub struct Secp256r1;

impl CurveSpec for Secp256r1 {
    /// Stable local curve selector used by host-side metadata.
    const ID: miden_core::Felt = miden_precompiles_codegen::SECP256R1_ID;

    type BaseField = R1Base;
    type ScalarField = R1Scalar;

    /// Standard secp256r1 generator x-coordinate, little-endian u32 limbs.
    const GENERATOR_X: Limbs = miden_precompiles_codegen::SECP256R1_GENERATOR_X;

    /// Standard secp256r1 generator y-coordinate, little-endian u32 limbs.
    const GENERATOR_Y: Limbs = miden_precompiles_codegen::SECP256R1_GENERATOR_Y;

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

impl ShortWeierstrassSpec for Secp256r1 {
    /// Coefficient `A = -3 mod p` for the secp256r1 curve.
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

    /// Coefficient `B` for the secp256r1 curve.
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
