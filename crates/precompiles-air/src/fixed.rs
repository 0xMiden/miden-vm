//! Fixed environment loaded by verifier boundary consumes, not transcript claims.
//!
//! This is deterministic protocol data. The prover installs fixed uints in the uint store,
//! preseeds fixed curve groups in the EC group table, and records external `UintVal` / `EcGroup`
//! demands. Matching positive consumes are injected by `ChipletMultiAir::eval_external`.

use miden_core::Felt;
use miden_precompiles::Limbs;
pub use miden_precompiles::{CurveId, UintDomain};

use crate::{ec::EcGroupMsg, uint::UintValMsg};

/// Semantic identity of an unsigned integer in the fixed environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedUintKind {
    /// Self-pinned upper bound of an arithmetic domain.
    Bound(UintDomain),
    /// Short-Weierstrass coefficient A, including converted curve models.
    CoefficientA(CurveId),
    /// Short-Weierstrass coefficient B, including converted curve models.
    CoefficientB(CurveId),
    /// Base-field factor of a GLV endomorphism.
    GlvBeta(CurveId),
    /// Scalar-field eigenvalue of a GLV endomorphism.
    GlvLambda(CurveId),
}

/// Fixed unsigned integer installed by the prover and consumed at the verifier boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FixedUint {
    /// Identity retained for consumers that need to describe the entry.
    pub kind: FixedUintKind,
    /// Address of the value in the fixed environment.
    pub ptr: u32,
    /// Address of its inclusive upper bound; equal to `ptr` for a self-pinned bound.
    pub bound_ptr: u32,
    /// Little-endian 32-bit limbs of the value.
    pub limbs: Limbs,
}

/// Fixed uint records in dependency order: self-pinned bounds first, then their dependents.
pub fn fixed_uint_records() -> impl Iterator<Item = FixedUint> {
    UintDomain::ALL
        .into_iter()
        .map(|domain| {
            let ptr = domain.bound_ptr();
            FixedUint {
                kind: FixedUintKind::Bound(domain),
                ptr,
                bound_ptr: ptr,
                limbs: domain.minus_one(),
            }
        })
        .chain(CurveId::ALL.into_iter().flat_map(|curve| {
            let bound_ptr = curve.base_domain().bound_ptr();
            [
                FixedUint {
                    kind: FixedUintKind::CoefficientA(curve),
                    ptr: curve.a_ptr(),
                    bound_ptr,
                    limbs: curve.a_value(),
                },
                FixedUint {
                    kind: FixedUintKind::CoefficientB(curve),
                    ptr: curve.b_ptr(),
                    bound_ptr,
                    limbs: curve.b_value(),
                },
            ]
        }))
        .chain(CurveId::ALL.into_iter().flat_map(|curve| {
            let base_bound_ptr = curve.base_domain().bound_ptr();
            let scalar_bound_ptr = curve.scalar_domain().bound_ptr();
            curve.endomorphism().into_iter().flat_map(move |endo| {
                [
                    FixedUint {
                        kind: FixedUintKind::GlvBeta(curve),
                        ptr: endo.beta_ptr,
                        bound_ptr: base_bound_ptr,
                        limbs: endo.beta,
                    },
                    FixedUint {
                        kind: FixedUintKind::GlvLambda(curve),
                        ptr: endo.lambda_ptr,
                        bound_ptr: scalar_bound_ptr,
                        limbs: endo.lambda,
                    },
                ]
            })
        }))
}

/// Fixed uints in dependency order: modulus/bound self-pins first, then coefficients under those
/// bounds. Each tuple contains the value's address, bound address, and little-endian limbs.
pub fn fixed_uints() -> impl Iterator<Item = (u32, u32, Limbs)> {
    fixed_uint_records().map(|entry| (entry.ptr, entry.bound_ptr, entry.limbs))
}

/// Verifier-side `UintVal` consumes for the fixed uint environment.
pub fn fixed_uintval_msgs() -> impl Iterator<Item = UintValMsg<Felt>> {
    fixed_uints().map(|(ptr, bound_ptr, limbs)| UintValMsg {
        ptr: Felt::from(ptr),
        bound_ptr: Felt::from(bound_ptr),
        limbs: core::array::from_fn(|i| Felt::from(limbs[i])),
    })
}

/// Fixed curve identity and its verifier-side group message.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FixedEcGroup {
    /// Curve whose short-Weierstrass parameters the message identifies.
    pub curve: CurveId,
    /// Boundary consume containing the fixed-environment parameter pointers.
    pub message: EcGroupMsg<Felt>,
}

/// Fixed curve records in native initialization order.
pub fn fixed_ecgroup_records() -> impl Iterator<Item = FixedEcGroup> {
    CurveId::ALL.into_iter().map(|curve| {
        let (beta_ptr, lambda_ptr) = match curve.endomorphism() {
            Some(endo) => (endo.beta_ptr, endo.lambda_ptr),
            None => (0, 0),
        };
        FixedEcGroup {
            curve,
            message: EcGroupMsg {
                group_ptr: Felt::from(curve.group_ptr()),
                a_ptr: Felt::from(curve.a_ptr()),
                b_ptr: Felt::from(curve.b_ptr()),
                bound_ptr: Felt::from(curve.base_domain().bound_ptr()),
                scalar_bound_ptr: Felt::from(curve.scalar_domain().bound_ptr()),
                beta_ptr: Felt::from(beta_ptr),
                lambda_ptr: Felt::from(lambda_ptr),
            },
        }
    })
}

/// Verifier-side `EcGroup` consumes for the fixed curve groups.
pub fn fixed_ecgroup_msgs() -> impl Iterator<Item = EcGroupMsg<Felt>> {
    fixed_ecgroup_records().map(|entry| entry.message)
}
