//! Fixed environment loaded by verifier boundary consumes, not transcript claims.
//!
//! This is deterministic protocol data. The prover installs fixed uints in the uint store,
//! preseeds fixed curve groups in the EC group table, and records external `UintVal` / `EcGroup`
//! demands. Matching positive consumes are injected by `ChipletMultiAir::eval_external`.

use miden_core::{
    Felt,
    field::{Field, PrimeCharacteristicRing, QuadFelt},
};
use miden_precompiles::{CurveId, Limbs, UintDomain};
use miden_stark::air::ReductionError;

use crate::precompile::{
    ec::EcGroupMsg,
    logup::{Challenges, LookupMessage, lookup_challenges_from_slice},
    uint::UintValMsg,
};

/// Fixed uints in dependency order: modulus/bound self-pins first, then coefficients under those
/// bounds.
pub fn fixed_uints() -> impl Iterator<Item = (u32, u32, Limbs)> {
    UintDomain::ALL
        .into_iter()
        .map(|domain| {
            let ptr = domain.bound_ptr();
            (ptr, ptr, domain.minus_one())
        })
        .chain(CurveId::ALL.into_iter().flat_map(|curve| {
            let bound_ptr = curve.base_domain().bound_ptr();
            [
                (curve.a_ptr(), bound_ptr, curve.a_value()),
                (curve.b_ptr(), bound_ptr, curve.b_value()),
            ]
        }))
        .chain(CurveId::ALL.into_iter().flat_map(|curve| {
            let base_bound_ptr = curve.base_domain().bound_ptr();
            let scalar_bound_ptr = curve.scalar_domain().bound_ptr();
            curve.endomorphism().into_iter().flat_map(move |endo| {
                [
                    (endo.beta_ptr, base_bound_ptr, endo.beta),
                    (endo.lambda_ptr, scalar_bound_ptr, endo.lambda),
                ]
            })
        }))
}

/// Verifier-side `UintVal` consumes for the fixed uint environment.
pub fn fixed_uintval_msgs() -> impl Iterator<Item = UintValMsg<Felt>> {
    fixed_uints().map(|(ptr, bound_ptr, limbs)| UintValMsg {
        ptr: Felt::from(ptr),
        bound_ptr: Felt::from(bound_ptr),
        limbs: core::array::from_fn(|i| Felt::from(limbs[i])),
    })
}

/// Verifier-side `EcGroup` consumes for the fixed curve groups.
pub fn fixed_ecgroup_msgs() -> impl Iterator<Item = EcGroupMsg<Felt>> {
    CurveId::ALL.into_iter().map(|curve| {
        let (beta_ptr, lambda_ptr) = match curve.endomorphism() {
            Some(endo) => (endo.beta_ptr, endo.lambda_ptr),
            None => (0, 0),
        };
        EcGroupMsg {
            group_ptr: Felt::from(curve.group_ptr()),
            a_ptr: Felt::from(curve.a_ptr()),
            b_ptr: Felt::from(curve.b_ptr()),
            bound_ptr: Felt::from(curve.base_domain().bound_ptr()),
            scalar_bound_ptr: Felt::from(curve.scalar_domain().bound_ptr()),
            beta_ptr: Felt::from(beta_ptr),
            lambda_ptr: Felt::from(lambda_ptr),
        }
    })
}

/// The one-time LogUp contribution of the fixed uint and curve-group environment.
///
/// The relation statement adds this contribution to the trace-length-weighted AIR residues.
pub fn fixed_boundary_correction(challenges: &[QuadFelt]) -> Result<QuadFelt, ReductionError> {
    let lookup_challenges = lookup_challenges_from_slice(challenges);
    Ok(boundary_correction(
        &lookup_challenges,
        fixed_uintval_msgs(),
        "fixed UintVal boundary denominator was zero",
    )? + boundary_correction(
        &lookup_challenges,
        fixed_ecgroup_msgs(),
        "fixed EcGroup boundary denominator was zero",
    )?)
}

fn boundary_correction<M>(
    challenges: &Challenges<QuadFelt>,
    messages: impl IntoIterator<Item = M>,
    zero_denominator: &'static str,
) -> Result<QuadFelt, ReductionError>
where
    M: LookupMessage<Felt, QuadFelt>,
{
    let mut correction = QuadFelt::ZERO;
    for msg in messages {
        let Some(inv) = msg.encode(challenges).try_inverse() else {
            return Err(zero_denominator.into());
        };
        correction += inv;
    }
    Ok(correction)
}
