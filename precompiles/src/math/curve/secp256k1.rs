//! secp256k1 parameters for the fixed curve precompile.

use miden_core::deferred::PrecompileError;

use super::{CurvePoint, CurveSpec, ShortWeierstrassSpec, short_weierstrass};
use crate::math::{k1_base::K1Base, k1_scalar::K1Scalar, uint::Limbs};

/// Marker type for the secp256k1 curve.
#[derive(Debug, Default, Clone, Copy)]
pub struct Secp256k1;

impl CurveSpec for Secp256k1 {
    /// Stable local curve selector carried in curve precompile tags.
    const ID: miden_core::Felt = miden_precompiles_codegen::SECP256K1_ID;

    type BaseField = K1Base;
    type ScalarField = K1Scalar;

    /// Standard secp256k1 generator x-coordinate, little-endian u32 limbs.
    const GENERATOR_X: Limbs = miden_precompiles_codegen::SECP256K1_GENERATOR_X;

    /// Standard secp256k1 generator y-coordinate, little-endian u32 limbs.
    const GENERATOR_Y: Limbs = miden_precompiles_codegen::SECP256K1_GENERATOR_Y;

    fn point_from_affine(x: Limbs, y: Limbs) -> Result<CurvePoint, PrecompileError> {
        short_weierstrass::point_from_affine::<Self>(x, y)
    }

    fn add(lhs: CurvePoint, rhs: CurvePoint) -> Result<CurvePoint, PrecompileError> {
        short_weierstrass::add::<Self>(lhs, rhs)
    }

    fn neg(point: CurvePoint) -> Result<CurvePoint, PrecompileError> {
        Ok(short_weierstrass::neg::<Self>(point))
    }
}

impl ShortWeierstrassSpec for Secp256k1 {
    /// Coefficient `A = 0` for `y^2 = x^3 + 7`.
    const A: Limbs = [0; 8];

    /// Coefficient `B = 7` for `y^2 = x^3 + 7`.
    const B: Limbs = [7, 0, 0, 0, 0, 0, 0, 0];
}
