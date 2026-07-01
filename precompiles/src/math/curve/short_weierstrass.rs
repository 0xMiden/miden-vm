//! Slow affine short-Weierstrass formulas used by fixed curve specs.

use miden_core::deferred::{DeferredError, PrecompileError};

use super::{CurvePoint, ShortWeierstrassSpec};
use crate::math::uint::{Limbs, UintSpec, ZERO_LIMBS};

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
