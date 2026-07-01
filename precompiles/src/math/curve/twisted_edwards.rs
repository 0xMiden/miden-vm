//! Slow affine twisted-Edwards formulas for curves with `a = -1`.

use miden_core::deferred::{DeferredError, PrecompileError};

use super::{CurvePoint, TwistedEdwardsSpec};
use crate::math::uint::{Limbs, UintSpec, ZERO_LIMBS};

const ONE_LIMBS: Limbs = [1, 0, 0, 0, 0, 0, 0, 0];

/// Checked affine boundary for twisted-Edwards coordinates.
///
/// Validates canonical base-field coordinates satisfying `-x^2 + y^2 = 1 + d*x^2*y^2`.
/// The affine identity `(0, 1)` is canonicalized to [`CurvePoint::Identity`].
pub(super) fn point_from_affine<C: TwistedEdwardsSpec>(
    x: Limbs,
    y: Limbs,
) -> Result<CurvePoint, PrecompileError> {
    if !affine_coordinates_on_curve::<C>(x, y) {
        return Err(DeferredError::InvalidPayload.into());
    }

    Ok(canonical_affine(x, y))
}

/// Trusted negation over a canonical valid point.
///
/// For curves with `a = -1`, `-(x, y) = (-x, y)`.
pub(super) fn neg<C: TwistedEdwardsSpec>(point: CurvePoint) -> CurvePoint {
    debug_assert!(C::is_on_curve(&point));

    match point {
        CurvePoint::Identity => CurvePoint::Identity,
        CurvePoint::Affine { x, y } => canonical_affine(C::BaseField::sub(ZERO_LIMBS, x), y),
    }
}

/// Trusted addition over canonical valid affine/identity points.
///
/// Uses the complete affine addition law for twisted Edwards curves with `a = -1`:
///
/// `x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)`
/// `y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)`
pub(super) fn add<C: TwistedEdwardsSpec>(
    lhs: CurvePoint,
    rhs: CurvePoint,
) -> Result<CurvePoint, PrecompileError> {
    debug_assert!(C::is_on_curve(&lhs));
    debug_assert!(C::is_on_curve(&rhs));

    match (lhs, rhs) {
        (CurvePoint::Identity, point) | (point, CurvePoint::Identity) => Ok(point),
        (CurvePoint::Affine { x: x1, y: y1 }, CurvePoint::Affine { x: x2, y: y2 }) => {
            let x1x2 = C::BaseField::mul(x1, x2);
            let y1y2 = C::BaseField::mul(y1, y2);
            let dxxyy = C::BaseField::mul(C::D, C::BaseField::mul(x1x2, y1y2));

            let x_numerator =
                C::BaseField::add(C::BaseField::mul(x1, y2), C::BaseField::mul(y1, x2));
            let x_denominator = C::BaseField::add(ONE_LIMBS, dxxyy);
            let x_denominator_inv =
                C::BaseField::inv(x_denominator).ok_or(DeferredError::InvalidPayload)?;
            let x3 = C::BaseField::mul(x_numerator, x_denominator_inv);

            let y_numerator = C::BaseField::add(y1y2, x1x2);
            let y_denominator = C::BaseField::sub(ONE_LIMBS, dxxyy);
            let y_denominator_inv =
                C::BaseField::inv(y_denominator).ok_or(DeferredError::InvalidPayload)?;
            let y3 = C::BaseField::mul(y_numerator, y_denominator_inv);

            let point = canonical_affine(x3, y3);
            debug_assert!(C::is_on_curve(&point));
            Ok(point)
        },
    }
}

fn canonical_affine(x: Limbs, y: Limbs) -> CurvePoint {
    if x == ZERO_LIMBS && y == ONE_LIMBS {
        CurvePoint::Identity
    } else {
        CurvePoint::Affine { x, y }
    }
}

fn affine_coordinates_on_curve<C: TwistedEdwardsSpec>(x: Limbs, y: Limbs) -> bool {
    if !C::BaseField::is_canonical(&x) || !C::BaseField::is_canonical(&y) {
        return false;
    }

    let x2 = C::BaseField::mul(x, x);
    let y2 = C::BaseField::mul(y, y);
    let lhs = C::BaseField::sub(y2, x2);
    let rhs = C::BaseField::add(ONE_LIMBS, C::BaseField::mul(C::D, C::BaseField::mul(x2, y2)));

    lhs == rhs
}
