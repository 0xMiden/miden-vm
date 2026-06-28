//! secp256k1 parameters for the fixed curve precompile.

use miden_core::{Felt, deferred::PrecompileError};

use super::{CurvePoint, CurveSpec, ShortWeierstrassSpec, short_weierstrass};
use crate::math::{k1_base::K1Base, k1_scalar::K1Scalar, uint::Limbs};

/// Marker type for the secp256k1 curve.
#[derive(Debug, Default, Clone, Copy)]
pub struct Secp256k1;

impl CurveSpec for Secp256k1 {
    /// Stable local curve selector carried in curve precompile tags.
    const ID: Felt = Felt::new_unchecked(1);

    type BaseField = K1Base;
    type ScalarField = K1Scalar;

    /// Standard secp256k1 generator x-coordinate, little-endian u32 limbs.
    const GENERATOR_X: Limbs = [
        0x16f8_1798,
        0x59f2_815b,
        0x2dce_28d9,
        0x029b_fcdb,
        0xce87_0b07,
        0x55a0_6295,
        0xf9dc_bbac,
        0x79be_667e,
    ];

    /// Standard secp256k1 generator y-coordinate, little-endian u32 limbs.
    const GENERATOR_Y: Limbs = [
        0xfb10_d4b8,
        0x9c47_d08f,
        0xa685_5419,
        0xfd17_b448,
        0x0e11_08a8,
        0x5da4_fbfc,
        0x26a3_c465,
        0x483a_da77,
    ];

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
