#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub use miden_core::deferred::PvmAirVariant;
use miden_core::deferred::{PrecompileLimits, PrecompileRegistry, WorkClass, WorkLimit};

mod codec;
mod hash;
mod math;

pub use codec::{chunks_to_bytes_exact, n_chunks};
pub use hash::{
    HashAssertNode, HashFunction, HashPrecompile, keccak256::Keccak256Precompile,
    sha256::Sha256Precompile, sha512::Sha512Precompile,
};
pub use math::{
    curve::{
        CurveBinaryOp, CurveCoefficient, CurveId, CurveNodeRef, CurveOp, CurvePoint,
        CurvePrecompile, CurveSpec, ED25519_A_PTR, ED25519_B_PTR, ED25519_GENERATOR_X,
        ED25519_GENERATOR_Y, ED25519_GROUP_PTR, ED25519_ID, K1_A_PTR, K1_B_PTR, K1_GROUP_PTR,
        P256_A_PTR, P256_B_PTR, P256_GENERATOR_X, P256_GENERATOR_Y, P256_GROUP_PTR, P256_ID,
        SECP256K1_BETA, SECP256K1_GENERATOR_X, SECP256K1_GENERATOR_Y, SECP256K1_ID,
        SECP256K1_LAMBDA, ShortWeierstrassSpec, curve_coefficients, ed25519_decompress_x,
        glv_decompose, phi_generator, scalar_mul_mod_n,
    },
    ed25519_base::Ed25519Base,
    ed25519_order::Ed25519Order,
    ed25519_scalar::Ed25519Scalar,
    k1_base::K1Base,
    k1_scalar::K1Scalar,
    p256_base::P256Base,
    p256_scalar::P256Scalar,
    u256::U256,
    uint::{
        ED25519_BASE_BOUND_PTR, ED25519_ORDER_BOUND_PTR, ED25519_SCALAR_BOUND_PTR,
        K1_BASE_BOUND_PTR, K1_SCALAR_BOUND_PTR, Limbs, ONE_LIMBS, P256_BASE_BOUND_PTR,
        P256_SCALAR_BOUND_PTR, TWO_LIMBS, U256_BOUND_PTR, UintBinaryOp, UintDomain, UintDomainKind,
        UintNodeRef, UintOp, UintPrecompile, UintSpec, ZERO_LIMBS,
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

/// Maximum number of terms in one MSM admitted by the default policy.
///
/// This is an operator admission limit, not a supported-input ceiling of the proving relation.
pub const DEFAULT_MAX_MSM_TERMS: u32 = 32;
/// Maximum total MSM terms in one accounting scope admitted by the default policy.
pub const DEFAULT_MAX_TOTAL_MSM_TERMS: u64 = 256;

// Admission policy is independent of the hard transport/allocation ceiling, even though their
// structural element limits currently have the same value.
const DEFAULT_MAX_ELEMENTS: u64 = 1_048_576;
const DEFAULT_MAX_UINT_OPERATIONS: u64 = 4_096;
const DEFAULT_MAX_CURVE_OPERATIONS: u64 = 512;
const DEFAULT_MAX_HASH_CALLS: u64 = 256;
const DEFAULT_MAX_HASH_INPUT_BYTES: u32 = 128 * 1024;
const DEFAULT_MAX_TOTAL_HASH_INPUT_BYTES: u64 = 256 * 1024;
const DEFAULT_MAX_MSM_CALLS: u64 = 64;

// Uint and non-MSM curve operations each declare one unit of work.
const FIXED_OPERATION_WORK_SIZE: u32 = 1;

/// Returns the default policy for guest-induced deferred work during execution.
pub fn default_execution_precompile_limits() -> PrecompileLimits {
    default_precompile_limits()
}

/// Returns the default policy for one final root-reachable witness during verification.
pub fn default_verification_precompile_limits() -> PrecompileLimits {
    default_precompile_limits()
}

/// Builds the currently shared default policy for execution and verification.
///
/// Execution charges guest registration attempts, including duplicates; verification charges the
/// unique final root-reachable witness. Equal numerical defaults do not equate these scopes.
/// These configurable admission bounds neither define algorithm-specific supported-input ceilings
/// nor guarantee that a witness or batch fits the independently checked proving-memory budget.
fn default_precompile_limits() -> PrecompileLimits {
    PrecompileLimits::new(DEFAULT_MAX_ELEMENTS)
        .with_class(
            UINT_WORK,
            WorkLimit {
                max_count: DEFAULT_MAX_UINT_OPERATIONS,
                max_total_size: DEFAULT_MAX_UINT_OPERATIONS,
                max_size: FIXED_OPERATION_WORK_SIZE,
            },
        )
        .with_class(
            CURVE_WORK,
            WorkLimit {
                max_count: DEFAULT_MAX_CURVE_OPERATIONS,
                max_total_size: DEFAULT_MAX_CURVE_OPERATIONS,
                max_size: FIXED_OPERATION_WORK_SIZE,
            },
        )
        .with_class(
            HASH_WORK,
            WorkLimit {
                max_count: DEFAULT_MAX_HASH_CALLS,
                max_total_size: DEFAULT_MAX_TOTAL_HASH_INPUT_BYTES,
                max_size: DEFAULT_MAX_HASH_INPUT_BYTES,
            },
        )
        .with_class(
            MSM_WORK,
            WorkLimit {
                max_count: DEFAULT_MAX_MSM_CALLS,
                max_total_size: DEFAULT_MAX_TOTAL_MSM_TERMS,
                max_size: DEFAULT_MAX_MSM_TERMS,
            },
        )
}

// REGISTRY
// ================================================================================================

/// Returns a [`PrecompileRegistry`] containing the precompiles provided by this crate.
///
/// TODO: If constructing the official registry becomes measurable overhead, consider a
/// cached/shared registry for default processor initialization.
pub fn registry() -> PrecompileRegistry {
    registry_for(PvmAirVariant::ALL)
}

/// Returns the uint and curve precompiles together with the selected hash precompiles.
pub fn registry_for(variant: PvmAirVariant) -> PrecompileRegistry {
    let mut registry = PrecompileRegistry::new();
    if variant.contains(PvmAirVariant::KECCAK) {
        registry = registry.with_precompile(Keccak256Precompile::default());
    }
    if variant.contains(PvmAirVariant::SHA512) {
        registry = registry.with_precompile(Sha512Precompile::default());
    }
    if variant.contains(PvmAirVariant::SHA256) {
        registry = registry.with_precompile(Sha256Precompile::default());
    }
    registry.with_precompile(UintPrecompile).with_precompile(CurvePrecompile)
}

#[cfg(test)]
mod tests {
    use alloc::{sync::Arc, vec};

    use miden_core::deferred::{
        DeferredState, Node, NodeType, PrecompileError, PrecompileLimitError,
    };

    use super::*;
    use crate::hash::keccak256::Keccak256Hash;

    #[test]
    fn variant_registry_rejects_disabled_hash_frames() {
        for variant in PvmAirVariant::ALL_VARIANTS {
            let registry = registry_for(variant);
            for (required, frame) in [
                (PvmAirVariant::KECCAK, Keccak256Precompile::assert_frame(0)),
                (PvmAirVariant::SHA256, Sha256Precompile::assert_frame(0)),
                (PvmAirVariant::SHA512, Sha512Precompile::assert_frame(0)),
            ] {
                let result = registry.decode_precompile_frame(frame);
                if variant.contains(required) {
                    assert_eq!(result.unwrap(), NodeType::Join);
                } else {
                    assert!(result.is_err());
                }
            }
            assert!(
                registry
                    .decode_precompile_frame(CurvePrecompile::value_frame(CurveId::Secp256k1))
                    .is_ok()
            );
            assert!(
                registry
                    .decode_precompile_frame(UintPrecompile::value_frame(UintDomain::U256))
                    .is_ok()
            );
        }
    }

    #[test]
    fn default_execution_limits_charge_repeated_registrations() {
        use PrecompileLimitError::{Count, ItemSize, TotalSize};

        for (class, size, repetitions, expected) in [
            (
                UINT_WORK,
                1,
                4_096,
                Count {
                    class: UINT_WORK,
                    actual: 4_097,
                    max: 4_096,
                },
            ),
            (CURVE_WORK, 1, 512, Count { class: CURVE_WORK, actual: 513, max: 512 }),
            (HASH_WORK, 0, 256, Count { class: HASH_WORK, actual: 257, max: 256 }),
            (
                HASH_WORK,
                128 * 1024,
                2,
                TotalSize {
                    class: HASH_WORK,
                    actual: 384 * 1024,
                    max: 256 * 1024,
                },
            ),
            (
                HASH_WORK,
                128 * 1024 + 1,
                0,
                ItemSize {
                    class: HASH_WORK,
                    actual: 128 * 1024 + 1,
                    max: 128 * 1024,
                },
            ),
            (MSM_WORK, 4, 64, Count { class: MSM_WORK, actual: 65, max: 64 }),
            (MSM_WORK, 32, 8, TotalSize { class: MSM_WORK, actual: 288, max: 256 }),
            (MSM_WORK, 33, 0, ItemSize { class: MSM_WORK, actual: 33, max: 32 }),
        ] {
            let mut state =
                DeferredState::new(Arc::new(registry()), default_execution_precompile_limits())
                    .unwrap();
            let curve = CurveId::Secp256k1;
            let node = if class == HASH_WORK {
                let input = vec![0; size as usize];
                let preimage = state.register(Node::chunks_from_bytes(&input)).unwrap();
                let expected =
                    state.register(Node::chunks_from_bytes(&Keccak256Hash::hash(&input))).unwrap();
                Keccak256Precompile::assert_node(size, preimage, expected)
            } else if class == MSM_WORK {
                let generator = CurvePrecompile::generator_node(curve).digest();
                let zero = UintPrecompile::value_node(curve.scalar_domain(), ZERO_LIMBS).digest();
                Node::try_pair_list(
                    CurvePrecompile::msm_frame(size),
                    vec![(generator, zero); size as usize],
                )
                .unwrap()
            } else if class == UINT_WORK {
                UintPrecompile::value_node(UintDomain::U256, ZERO_LIMBS)
            } else {
                CurvePrecompile::identity_node(curve)
            };
            for _ in 0..repetitions {
                state.register(node.clone()).unwrap();
            }
            let error = state.register(node.clone()).unwrap_err();
            assert!(
                matches!(error.root(), PrecompileError::Limit(actual) if *actual == expected),
                "unexpected admission error for {class}: {error:?}",
            );
            if matches!(expected, ItemSize { class: HASH_WORK, .. }) {
                // A valid input above the default remains supported when the operator raises
                // only the individual admission allowance.
                state
                    .set_execution_limits(default_execution_precompile_limits().with_class(
                        HASH_WORK,
                        WorkLimit {
                            max_count: DEFAULT_MAX_HASH_CALLS,
                            max_total_size: DEFAULT_MAX_TOTAL_HASH_INPUT_BYTES,
                            max_size: size,
                        },
                    ))
                    .unwrap();
                state.register(node).unwrap();
            }
        }
    }
}
