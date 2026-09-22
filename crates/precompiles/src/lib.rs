#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use miden_core::deferred::{
    MAX_DEFERRED_ELEMENTS, Node, PrecompileLimits, PrecompileRegistry, Tag, WorkClass, WorkLimit,
};

mod codec;
mod hash;
mod math;

pub use codec::{chunks_to_bytes_exact, n_chunks};
pub use hash::{HashAssertNode, HashFunction, HashPrecompile, keccak256::Keccak256Precompile};
pub use math::{
    curve::{
        CurveBinaryOp, CurveCoefficient, CurveId, CurveNodeRef, CurveOp, CurvePoint,
        CurvePrecompile, CurveSpec, K1_A_PTR, K1_B_PTR, K1_GROUP_PTR, SECP256K1_BETA,
        SECP256K1_GENERATOR_X, SECP256K1_GENERATOR_Y, SECP256K1_ID, SECP256K1_LAMBDA,
        ShortWeierstrassSpec, curve_coefficients, glv_decompose, phi_generator, scalar_mul_mod_n,
    },
    k1_base::K1Base,
    k1_scalar::K1Scalar,
    u256::U256,
    uint::{
        K1_BASE_BOUND_PTR, K1_SCALAR_BOUND_PTR, Limbs, ONE_LIMBS, TWO_LIMBS, U256_BOUND_PTR,
        UintBinaryOp, UintDomain, UintNodeRef, UintOp, UintPrecompile, UintSpec, ZERO_LIMBS,
    },
};

// WORK ACCOUNTING
// ================================================================================================

/// Work class shared by every supported hash assertion.
pub const HASH_WORK: WorkClass = WorkClass::new("hash");
/// Work class shared by all uint domains and operations.
pub const UINT_WORK: WorkClass = WorkClass::new("uint");
/// Work class shared by non-MSM curve operations.
pub const CURVE_WORK: WorkClass = WorkClass::new("curve");
/// Work class for multi-scalar multiplication, sized by term count.
pub const MSM_WORK: WorkClass = WorkClass::new("msm");

/// Conservative maximum number of terms in one MSM admitted by default.
pub const DEFAULT_MAX_MSM_TERMS: u32 = 4_096;
/// Conservative maximum total MSM terms in one witness admitted by default.
pub const DEFAULT_MAX_TOTAL_MSM_TERMS: u64 = 16 * DEFAULT_MAX_MSM_TERMS as u64;

/// Returns the canonical per-witness precompile admission policy.
pub fn default_precompile_limits() -> PrecompileLimits {
    let min_node_elements =
        Tag::AND.as_word().len() + Node::PACKED_BYTES_PER_CHUNK / size_of::<u32>();
    let max_operations = (MAX_DEFERRED_ELEMENTS / min_node_elements) as u64;
    let max_hash_bytes = (MAX_DEFERRED_ELEMENTS * size_of::<u32>()) as u64;

    PrecompileLimits::new(MAX_DEFERRED_ELEMENTS as u64)
        .with_class(UINT_WORK, WorkLimit::new(max_operations, max_operations, 1))
        .with_class(CURVE_WORK, WorkLimit::new(max_operations, max_operations, 1))
        .with_class(
            HASH_WORK,
            WorkLimit::new(max_operations, max_hash_bytes, max_hash_bytes as u32),
        )
        .with_class(
            MSM_WORK,
            WorkLimit::new(max_operations, DEFAULT_MAX_TOTAL_MSM_TERMS, DEFAULT_MAX_MSM_TERMS),
        )
}

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
