//! Fixed uints loaded by the verifier boundary, not transcript bootstrap claims.
//!
//! The manifest is deterministic protocol data. [`Session`](super::Session) installs these uints in
//! the store by default and records one external `UintVal` demand for each full value; the matching
//! positive consumes are injected by `ChipletMultiAir::eval_external`.

use miden_precompiles::{Limbs, UintDomain, curve_coefficients};

/// One fixed uint at a VM-owned store pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FixedUint {
    pub ptr: u32,
    pub bound_ptr: u32,
    pub value: Limbs,
}

const NUM_CURVE_COEFFICIENTS: usize = 6;

/// Number of fixed uints installed by default: all domain bounds plus all curve coefficients.
pub(crate) const FIXED_UINT_COUNT: usize = UintDomain::ALL.len() + NUM_CURVE_COEFFICIENTS;

/// Fixed uint manifest in dependency order: modulus/bound self-pins first, then coefficients under
/// those bounds.
pub(crate) fn fixed_uint_manifest() -> Vec<FixedUint> {
    let mut fixed = Vec::with_capacity(FIXED_UINT_COUNT);

    for domain in UintDomain::ALL {
        let ptr = domain.bound_ptr();
        fixed.push(FixedUint {
            ptr,
            bound_ptr: ptr,
            value: domain.minus_one(),
        });
    }

    fixed.extend(curve_coefficients().into_iter().map(|coefficient| FixedUint {
        ptr: coefficient.ptr,
        bound_ptr: coefficient.bound_ptr,
        value: coefficient.value,
    }));

    debug_assert_eq!(fixed.len(), FIXED_UINT_COUNT);
    fixed
}
