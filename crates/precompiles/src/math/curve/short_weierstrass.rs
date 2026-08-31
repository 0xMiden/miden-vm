//! Slow affine short-Weierstrass formulas used by fixed curve specs.

use miden_core::deferred::{DeferredError, PrecompileError};

use super::{CurvePoint, ShortWeierstrassSpec};
use crate::math::uint::{Limbs, UintSpec, ZERO_LIMBS};

const ONE_LIMBS: Limbs = [1, 0, 0, 0, 0, 0, 0, 0];

/// Checked affine boundary for short-Weierstrass coordinates.
///
/// Validates that the limbs are canonical base-field elements satisfying the curve equation before
/// returning a trusted point.
pub(super) fn point_from_affine<C: ShortWeierstrassSpec>(
    x: Limbs,
    y: Limbs,
) -> Result<CurvePoint, PrecompileError> {
    if !affine_coordinates_on_curve::<C>(x, y) {
        return Err(DeferredError::InvalidPayload.into());
    }

    Ok(CurvePoint::Affine { x, y })
}

/// Trusted negation over a canonical valid point, without using division.
///
/// Callers must not pass arbitrary coordinates: release builds rely on the checked boundary and do
/// not revalidate curve membership here.
pub(super) fn neg<C: ShortWeierstrassSpec>(point: CurvePoint) -> CurvePoint {
    debug_assert!(C::is_on_curve(&point));

    match point {
        CurvePoint::Identity => CurvePoint::Identity,
        CurvePoint::Affine { x, y } => {
            CurvePoint::Affine { x, y: C::BaseField::sub(ZERO_LIMBS, y) }
        },
    }
}

/// Trusted addition over canonical valid affine/identity points using slow generic formulas.
///
/// Callers must not pass arbitrary coordinates: release builds rely on the checked boundary and do
/// not revalidate curve membership here.
pub(super) fn add<C: ShortWeierstrassSpec>(
    lhs: CurvePoint,
    rhs: CurvePoint,
) -> Result<CurvePoint, PrecompileError> {
    debug_assert!(C::is_on_curve(&lhs));
    debug_assert!(C::is_on_curve(&rhs));

    match (lhs, rhs) {
        (CurvePoint::Identity, point) | (point, CurvePoint::Identity) => Ok(point),
        (CurvePoint::Affine { x: x1, y: y1 }, CurvePoint::Affine { x: x2, y: y2 }) => {
            if x1 == x2 && (y1 != y2 || y1 == ZERO_LIMBS) {
                return Ok(CurvePoint::Identity);
            }

            let numerator = if x1 == x2 {
                // λ = (3*x1^2 + A) / (2*y1)
                let x1_squared = C::BaseField::mul(x1, x1);
                let two_x1_squared = C::BaseField::add(x1_squared, x1_squared);
                C::BaseField::add(C::BaseField::add(two_x1_squared, x1_squared), C::A)
            } else {
                // λ = (y2 - y1) / (x2 - x1)
                C::BaseField::sub(y2, y1)
            };

            let denominator = if x1 == x2 {
                C::BaseField::add(y1, y1)
            } else {
                C::BaseField::sub(x2, x1)
            };
            let denominator_inv =
                C::BaseField::inv(denominator).ok_or(DeferredError::InvalidPayload)?;
            let lambda = C::BaseField::mul(numerator, denominator_inv);

            let lambda_squared = C::BaseField::mul(lambda, lambda);
            let x3 = C::BaseField::sub(C::BaseField::sub(lambda_squared, x1), x2);
            let x1_minus_x3 = C::BaseField::sub(x1, x3);
            let y3 = C::BaseField::sub(C::BaseField::mul(lambda, x1_minus_x3), y1);

            let point = CurvePoint::Affine { x: x3, y: y3 };
            debug_assert!(C::is_on_curve(&point));
            Ok(point)
        },
    }
}

/// Trusted scalar multiplication over a canonical valid point using Jacobian coordinates.
///
/// Performs a single field inversion (in the final affine conversion) rather than one per point
/// operation. Callers must not pass arbitrary coordinates: release builds rely on the checked
/// boundary and do not revalidate curve membership here.
pub(super) fn mul_scalar<C: ShortWeierstrassSpec>(
    point: CurvePoint,
    scalar: Limbs,
) -> Result<CurvePoint, PrecompileError> {
    debug_assert!(C::is_on_curve(&point));
    debug_assert!(C::ScalarField::is_canonical(&scalar));

    let Some(highest_limb) = scalar.iter().rposition(|&limb| limb != 0) else {
        return Ok(CurvePoint::Identity);
    };
    let highest_bit =
        highest_limb * 32 + (u32::BITS - 1 - scalar[highest_limb].leading_zeros()) as usize;

    let (x, y) = match point {
        CurvePoint::Identity => return Ok(CurvePoint::Identity),
        CurvePoint::Affine { x, y } => (x, y),
    };

    // Left-to-right double-and-add with mixed (Jacobian + affine) additions of the fixed base.
    let mut acc = JACOBIAN_IDENTITY;
    for bit_index in (0..=highest_bit).rev() {
        acc = jacobian_double::<C>(acc);
        if ((scalar[bit_index / 32] >> (bit_index % 32)) & 1) == 1 {
            acc = jacobian_add_affine::<C>(acc, x, y);
        }
    }

    let result = jacobian_to_affine::<C>(acc)?;
    debug_assert!(C::is_on_curve(&result));
    Ok(result)
}

/// Jacobian point `(X : Y : Z)` representing affine `(X / Z^2, Y / Z^3)`; `Z = 0` is the identity.
type JacobianPoint = (Limbs, Limbs, Limbs);

const JACOBIAN_IDENTITY: JacobianPoint = (ONE_LIMBS, ONE_LIMBS, ZERO_LIMBS);

/// Jacobian doubling using the curve-generic `dbl-2007-bl` formulas (valid for any coefficient
/// `A`).
fn jacobian_double<C: ShortWeierstrassSpec>(point: JacobianPoint) -> JacobianPoint {
    let (x1, y1, z1) = point;
    if z1 == ZERO_LIMBS || y1 == ZERO_LIMBS {
        return JACOBIAN_IDENTITY;
    }

    let xx = C::BaseField::mul(x1, x1);
    let yy = C::BaseField::mul(y1, y1);
    let yyyy = C::BaseField::mul(yy, yy);
    let zz = C::BaseField::mul(z1, z1);

    // S = 2 * ((X1 + YY)^2 - XX - YYYY)
    let x1_plus_yy = C::BaseField::add(x1, yy);
    let s_inner =
        C::BaseField::sub(C::BaseField::sub(C::BaseField::mul(x1_plus_yy, x1_plus_yy), xx), yyyy);
    let s = C::BaseField::add(s_inner, s_inner);

    // M = 3 * XX + A * ZZ^2
    let zzzz = C::BaseField::mul(zz, zz);
    let a_zzzz = C::BaseField::mul(C::A, zzzz);
    let three_xx = C::BaseField::add(C::BaseField::add(xx, xx), xx);
    let m = C::BaseField::add(three_xx, a_zzzz);

    // X3 = M^2 - 2 * S
    let x3 = C::BaseField::sub(C::BaseField::mul(m, m), C::BaseField::add(s, s));

    // Y3 = M * (S - X3) - 8 * YYYY
    let two_yyyy = C::BaseField::add(yyyy, yyyy);
    let four_yyyy = C::BaseField::add(two_yyyy, two_yyyy);
    let eight_yyyy = C::BaseField::add(four_yyyy, four_yyyy);
    let y3 = C::BaseField::sub(C::BaseField::mul(m, C::BaseField::sub(s, x3)), eight_yyyy);

    // Z3 = 2 * Y1 * Z1
    let y1z1 = C::BaseField::mul(y1, z1);
    let z3 = C::BaseField::add(y1z1, y1z1);

    (x3, y3, z3)
}

/// Mixed Jacobian + affine addition using the `madd-2007-bl` formulas.
fn jacobian_add_affine<C: ShortWeierstrassSpec>(
    point: JacobianPoint,
    x2: Limbs,
    y2: Limbs,
) -> JacobianPoint {
    let (x1, y1, z1) = point;
    if z1 == ZERO_LIMBS {
        return (x2, y2, ONE_LIMBS);
    }

    let zz = C::BaseField::mul(z1, z1);
    let u2 = C::BaseField::mul(x2, zz);
    let s2 = C::BaseField::mul(C::BaseField::mul(y2, z1), zz);

    if u2 == x1 {
        return if s2 == y1 {
            jacobian_double::<C>(point)
        } else {
            JACOBIAN_IDENTITY
        };
    }

    let h = C::BaseField::sub(u2, x1);
    let hh = C::BaseField::mul(h, h);
    let two_hh = C::BaseField::add(hh, hh);
    let i = C::BaseField::add(two_hh, two_hh);
    let j = C::BaseField::mul(h, i);
    let s2_minus_y1 = C::BaseField::sub(s2, y1);
    let r = C::BaseField::add(s2_minus_y1, s2_minus_y1);
    let v = C::BaseField::mul(x1, i);

    // X3 = r^2 - J - 2 * V
    let x3 =
        C::BaseField::sub(C::BaseField::sub(C::BaseField::mul(r, r), j), C::BaseField::add(v, v));
    // Y3 = r * (V - X3) - 2 * Y1 * J
    let y1j = C::BaseField::mul(y1, j);
    let y3 = C::BaseField::sub(
        C::BaseField::mul(r, C::BaseField::sub(v, x3)),
        C::BaseField::add(y1j, y1j),
    );
    // Z3 = (Z1 + H)^2 - ZZ - HH
    let z1_plus_h = C::BaseField::add(z1, h);
    let z3 = C::BaseField::sub(C::BaseField::sub(C::BaseField::mul(z1_plus_h, z1_plus_h), zz), hh);

    (x3, y3, z3)
}

/// Converts a Jacobian point back to affine with a single field inversion.
fn jacobian_to_affine<C: ShortWeierstrassSpec>(
    point: JacobianPoint,
) -> Result<CurvePoint, PrecompileError> {
    let (x, y, z) = point;
    if z == ZERO_LIMBS {
        return Ok(CurvePoint::Identity);
    }

    let z_inv = C::BaseField::inv(z).ok_or(DeferredError::InvalidPayload)?;
    let z_inv2 = C::BaseField::mul(z_inv, z_inv);
    let z_inv3 = C::BaseField::mul(z_inv2, z_inv);
    Ok(CurvePoint::Affine {
        x: C::BaseField::mul(x, z_inv2),
        y: C::BaseField::mul(y, z_inv3),
    })
}

fn affine_coordinates_on_curve<C: ShortWeierstrassSpec>(x: Limbs, y: Limbs) -> bool {
    if !C::BaseField::is_canonical(&x) || !C::BaseField::is_canonical(&y) {
        return false;
    }

    let y2 = C::BaseField::mul(y, y);
    let x2 = C::BaseField::mul(x, x);
    let x3 = C::BaseField::mul(x2, x);
    let ax = C::BaseField::mul(C::A, x);
    let rhs = C::BaseField::add(C::BaseField::add(x3, ax), C::B);

    y2 == rhs
}
