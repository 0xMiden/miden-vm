//! Fixed environment loaded by verifier boundary consumes, not transcript claims.
//!
//! This is deterministic protocol data: [`Session`](super::Session) installs fixed uints in the
//! uint store, preseeds fixed curve groups in the EC group table, and records external `UintVal`
//! / `EcGroup` demands. Matching positive consumes are injected by
//! `ChipletMultiAir::eval_external`.

use miden_core::Felt;
use miden_precompiles::{CurveId, Limbs, UintDomain};

use crate::{ec::EcGroupMsg, uint::UintValMsg};

/// Fixed uints in dependency order: modulus/bound self-pins first, then coefficients under those
/// bounds.
pub(crate) fn fixed_uints() -> impl Iterator<Item = (u32, u32, Limbs)> {
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
}

/// Verifier-side `UintVal` consumes for the fixed uint environment.
pub(crate) fn fixed_uintval_msgs() -> impl Iterator<Item = UintValMsg<Felt>> {
    fixed_uints().flat_map(|(ptr, bound_ptr, limbs)| {
        (0..2).map(move |offset| {
            let start = offset * 4;
            UintValMsg {
                ptr: Felt::from(ptr),
                bound_ptr: Felt::from(bound_ptr),
                offset: Felt::from(offset as u32),
                limbs: core::array::from_fn(|i| Felt::from(limbs[start + i])),
            }
        })
    })
}

/// Verifier-side `EcGroup` consumes for the fixed curve groups.
pub(crate) fn fixed_ecgroup_msgs() -> impl Iterator<Item = EcGroupMsg<Felt>> {
    CurveId::ALL.into_iter().map(|curve| EcGroupMsg {
        group_ptr: Felt::from(curve.group_ptr()),
        a_ptr: Felt::from(curve.a_ptr()),
        b_ptr: Felt::from(curve.b_ptr()),
        bound_ptr: Felt::from(curve.base_domain().bound_ptr()),
        scalar_bound_ptr: Felt::from(curve.scalar_domain().bound_ptr()),
    })
}
