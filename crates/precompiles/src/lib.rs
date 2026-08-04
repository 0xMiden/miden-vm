#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use miden_core::deferred::PrecompileRegistry;

mod codec;
mod hash;
mod math;

pub use codec::{chunks_to_bytes_exact, n_chunks};
pub use hash::{HashAssertNode, HashFunction, HashPrecompile, keccak256::Keccak256Precompile};
pub use math::{
    curve::{
        CurveCoefficient, CurveId, CurveNodeRef, CurvePoint, CurvePrecompile, CurveSpec, K1_A_PTR,
        K1_B_PTR, K1_GROUP_PTR, SECP256K1_GENERATOR_X, SECP256K1_GENERATOR_Y, SECP256K1_ID,
        ShortWeierstrassSpec, curve_coefficients,
    },
    k1_base::K1Base,
    k1_scalar::K1Scalar,
    u256::U256,
    uint::{
        K1_BASE_BOUND_PTR, K1_SCALAR_BOUND_PTR, Limbs, ONE_LIMBS, TWO_LIMBS, U256_BOUND_PTR,
        UintDomain, UintNodeRef, UintPrecompile, UintSpec, ZERO_LIMBS,
    },
};

// REGISTRY
// ================================================================================================

/// Returns a [`PrecompileRegistry`] containing the precompiles provided by this crate.
///
/// TODO: If constructing the official registry becomes measurable overhead, consider a
/// cached/shared registry for default processor initialization.
pub fn registry() -> PrecompileRegistry {
    PrecompileRegistry::new()
        .with_precompile(Keccak256Precompile::default())
        .with_precompile(UintPrecompile)
        .with_precompile(CurvePrecompile)
}
