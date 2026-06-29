//! Ed25519 parameters for the fixed curve precompile.

use miden_core::deferred::PrecompileError;

use super::{CurvePoint, CurveSpec, TwistedEdwardsSpec, twisted_edwards};
use crate::math::{ed25519_base::Ed25519Base, ed25519_scalar::Ed25519Scalar, uint::Limbs};

/// Marker type for the Ed25519 curve.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519;

impl CurveSpec for Ed25519 {
    /// Stable local curve selector carried in curve precompile tags.
    const ID: miden_core::Felt = miden_precompiles_codegen::ED25519_ID;

    type BaseField = Ed25519Base;
    type ScalarField = Ed25519Scalar;

    /// Standard Ed25519 generator x-coordinate, little-endian u32 limbs.
    const GENERATOR_X: Limbs = miden_precompiles_codegen::ED25519_GENERATOR_X;

    /// Standard Ed25519 generator y-coordinate, little-endian u32 limbs.
    const GENERATOR_Y: Limbs = miden_precompiles_codegen::ED25519_GENERATOR_Y;

    fn point_from_affine(x: Limbs, y: Limbs) -> Result<CurvePoint, PrecompileError> {
        twisted_edwards::point_from_affine::<Self>(x, y)
    }

    fn add(lhs: CurvePoint, rhs: CurvePoint) -> Result<CurvePoint, PrecompileError> {
        twisted_edwards::add::<Self>(lhs, rhs)
    }

    fn neg(point: CurvePoint) -> Result<CurvePoint, PrecompileError> {
        Ok(twisted_edwards::neg::<Self>(point))
    }
}

impl TwistedEdwardsSpec for Ed25519 {
    /// Edwards parameter `d = -121665 / 121666 mod p`, little-endian u32 limbs.
    const D: Limbs = [
        0x1359_78a3,
        0x75eb_4dca,
        0x4141_d8ab,
        0x0070_0a4d,
        0x7779_e898,
        0x8cc7_4079,
        0x2b6f_fe73,
        0x5203_6cee,
    ];
}
