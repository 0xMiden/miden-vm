//! Ed25519-SW parameters for the fixed curve precompile.
//!
//! `Ed25519Sw` is the short-Weierstrass model birationally equivalent to Ed25519 over
//! `p = 2^255 - 19`. Starting from the Montgomery form `v^2 = u^3 + 486662*u^2 + u`,
//! this uses the map `X = u + 486662/3`, `Y = v`.

use miden_core::deferred::PrecompileError;

use super::{CurvePoint, CurveSpec, ShortWeierstrassSpec, short_weierstrass};
use crate::math::{ed25519_base::Ed25519Base, ed25519_scalar::Ed25519Scalar, uint::Limbs};

/// Marker type for the Ed25519 short-Weierstrass curve model.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Sw;

impl CurveSpec for Ed25519Sw {
    /// Stable local curve selector used by host-side metadata.
    const ID: miden_core::Felt = miden_precompiles_codegen::ED25519_SW_ID;

    type BaseField = Ed25519Base;
    type ScalarField = Ed25519Scalar;

    /// Ed25519 base point mapped to short-Weierstrass `X`, little-endian u32 limbs.
    const GENERATOR_X: Limbs = miden_precompiles_codegen::ED25519_SW_GENERATOR_X;

    /// Ed25519 base point mapped to short-Weierstrass `Y`, little-endian u32 limbs.
    const GENERATOR_Y: Limbs = miden_precompiles_codegen::ED25519_SW_GENERATOR_Y;

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

impl ShortWeierstrassSpec for Ed25519Sw {
    /// Coefficient `A = 1 - 486662^2 / 3 mod p` for the mapped short-Weierstrass model.
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

    /// Coefficient `B = 2*486662^3 / 27 - 486662 / 3 mod p` for the mapped model.
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
