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

/// Trusted scalar multiplication over a canonical valid point using extended twisted-Edwards
/// coordinates (`a = -1`).
///
/// Performs a single field inversion (in the final affine conversion) rather than two per point
/// operation. Callers must not pass arbitrary coordinates: release builds rely on the checked
/// boundary and do not revalidate curve membership here.
pub(super) fn mul_scalar<C: TwistedEdwardsSpec>(
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
    // Affine base in extended form has `Z2 = 1` and `T2 = x * y`. Precompute `d * T2` once for the
    // mixed additions of the fixed base.
    let t2 = C::BaseField::mul(x, y);
    let d_t2 = C::BaseField::mul(C::D, t2);

    // The twisted-Edwards (a = -1) addition and doubling formulas are complete, so no operand needs
    // special-casing inside the loop.
    let mut acc = EXTENDED_IDENTITY;
    for bit_index in (0..=highest_bit).rev() {
        acc = extended_double::<C>(acc);
        if ((scalar[bit_index / 32] >> (bit_index % 32)) & 1) == 1 {
            acc = extended_add_affine::<C>(acc, x, y, d_t2);
        }
    }

    extended_to_affine::<C>(acc)
}

/// Extended twisted-Edwards point `(X : Y : Z : T)` with `x = X/Z`, `y = Y/Z`, and `x*y = T/Z`.
type ExtendedPoint = (Limbs, Limbs, Limbs, Limbs);

const EXTENDED_IDENTITY: ExtendedPoint = (ZERO_LIMBS, ONE_LIMBS, ONE_LIMBS, ZERO_LIMBS);

/// Doubling using the `dbl-2008-hwcd` formulas specialized to `a = -1`.
fn extended_double<C: TwistedEdwardsSpec>(point: ExtendedPoint) -> ExtendedPoint {
    let (x1, y1, z1, _t1) = point;

    let aa = C::BaseField::mul(x1, x1);
    let bb = C::BaseField::mul(y1, y1);
    let zz = C::BaseField::mul(z1, z1);
    let cc = C::BaseField::add(zz, zz); // C = 2 * Z1^2
    let d = C::BaseField::sub(ZERO_LIMBS, aa); // D = a * AA = -AA
    // E = (X1 + Y1)^2 - AA - BB
    let x1_plus_y1 = C::BaseField::add(x1, y1);
    let e = C::BaseField::sub(C::BaseField::sub(C::BaseField::mul(x1_plus_y1, x1_plus_y1), aa), bb);
    let g = C::BaseField::add(d, bb); // G = D + BB
    let f = C::BaseField::sub(g, cc); // F = G - CC
    let h = C::BaseField::sub(d, bb); // H = D - BB

    (
        C::BaseField::mul(e, f), // X3 = E * F
        C::BaseField::mul(g, h), // Y3 = G * H
        C::BaseField::mul(f, g), // Z3 = F * G
        C::BaseField::mul(e, h), // T3 = E * H
    )
}

/// Mixed extended + affine addition using the `madd-2008-hwcd` formulas specialized to `a = -1`,
/// taking the precomputed `d * T2` for the affine base.
fn extended_add_affine<C: TwistedEdwardsSpec>(
    point: ExtendedPoint,
    x2: Limbs,
    y2: Limbs,
    d_t2: Limbs,
) -> ExtendedPoint {
    let (x1, y1, z1, t1) = point;

    let a = C::BaseField::mul(x1, x2);
    let b = C::BaseField::mul(y1, y2);
    let c = C::BaseField::mul(t1, d_t2); // C = T1 * (d * T2)
    let d = z1; // D = Z1 * Z2 = Z1 (Z2 = 1)
    // E = (X1 + Y1) * (x2 + y2) - A - B
    let e = C::BaseField::sub(
        C::BaseField::sub(
            C::BaseField::mul(C::BaseField::add(x1, y1), C::BaseField::add(x2, y2)),
            a,
        ),
        b,
    );
    let f = C::BaseField::sub(d, c); // F = D - C
    let g = C::BaseField::add(d, c); // G = D + C
    let h = C::BaseField::add(b, a); // H = B - a*A = B + A

    (
        C::BaseField::mul(e, f), // X3 = E * F
        C::BaseField::mul(g, h), // Y3 = G * H
        C::BaseField::mul(f, g), // Z3 = F * G
        C::BaseField::mul(e, h), // T3 = E * H
    )
}

/// Converts an extended point back to affine with a single field inversion.
fn extended_to_affine<C: TwistedEdwardsSpec>(
    point: ExtendedPoint,
) -> Result<CurvePoint, PrecompileError> {
    let (x, y, z, _t) = point;
    let z_inv = C::BaseField::inv(z).ok_or(DeferredError::InvalidPayload)?;
    Ok(canonical_affine(C::BaseField::mul(x, z_inv), C::BaseField::mul(y, z_inv)))
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
