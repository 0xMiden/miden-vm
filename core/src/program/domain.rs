//! Eidos domains maintained by `miden-vm`.
//!
//! Numeric tags use the `miden-vm` namespace allocated by `miden-crypto`. MAST control nodes keep
//! their opcode-based framing; those tags are below 256 and therefore disjoint from every
//! registered domain tag.

pub use miden_crypto::hash::eidos::DomainTag;
#[cfg(test)]
use miden_crypto::hash::eidos::domains::MidenCryptoDomainRegistry;
use miden_crypto::hash::eidos::{
    Custom, DomainVersion, FeltSequence, Transcript, domain::EidosDomain, namespace,
};

use crate::Felt;

/// Number of Felts in the Falcon product-check transcript payload.
pub const FALCON_PRODUCT_CHECK_PAYLOAD_LEN: u32 = 8 + 512 + 1024;

miden_crypto::eidos_domain_registry! {
    /// Domains maintained by `miden-vm`.
    pub registry MidenVmDomainRegistry {
        namespace: namespace::MIDEN_VM;
        domains: {
            pub KERNEL_COMMITMENT: KernelCommitmentDomain {
                local_id: 0x0000,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Miden VM kernel commitment.",
                schema: "param0 = number of Felts; param1 = 0; param2 = 0; payload = procedure digests in canonical order",
            }
            pub EXECUTION_CLAIM: ExecutionClaimDomain {
                local_id: 0x0001,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Miden VM execution-claim commitment.",
                schema: "param0 = 40; param1 = 0; param2 = 0; payload = program root || kernel commitment || stack inputs || stack outputs",
            }
            pub PROOF_REQUEST: ProofRequestDomain {
                local_id: 0x0002,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Miden VM recursive-proof request key.",
                schema: "param0 = 8; param1 = 0; param2 = 0; payload = claim commitment || verifier root",
            }
            pub DEFERRED_AND: DeferredAndDomain {
                local_id: 0x0003,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Deferred AND node and rolling-root fold.",
                schema: "param0 = 8; param1 = 0; param2 = 0; payload = left digest || right digest",
            }
            pub DEFERRED_CHUNKS: DeferredChunksDomain {
                local_id: 0x0004,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Deferred framework chunk-list node.",
                schema: "param0 = number of payload Felts; param1 = 0; param2 = 0; payload = one or more complete 8-Felt chunks",
            }
            pub STARK_TRANSCRIPT: StarkTranscriptDomain {
                local_id: 0x0005,
                version: DomainVersion::numbered(1),
                encoding: Transcript,
                description: "Miden VM and Precompile VM STARK transcript.",
                schema: "params = [0, 0, 0]; absorb the relation digest before sampling transcript challenges",
            }
            pub KECCAK256_PRECOMPILE: Keccak256PrecompileDomain {
                local_id: 0x0006,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Keccak-256 deferred precompile nodes.",
                schema: "param0 = payload length in Felts; param1/param2 = node tag arguments; payload = complete 8-Felt chunks",
            }
            pub UINT256_PRECOMPILE: Uint256PrecompileDomain {
                local_id: 0x0007,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Uint256 deferred precompile nodes.",
                schema: "param0 = payload length in Felts; param1/param2 = node tag arguments; payload = complete 8-Felt chunks",
            }
            pub CURVE_PRECOMPILE: CurvePrecompileDomain {
                local_id: 0x0008,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Elliptic-curve deferred precompile nodes.",
                schema: "param0 = payload length in Felts; param1/param2 = node tag arguments; payload = complete 8-Felt chunks",
            }
            pub PVM_UINT_PIN_CLAIM: PvmUintPinClaimDomain {
                local_id: 0x0009,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Precompile VM uint pin claim.",
                schema: "param0 = payload length in Felts; param1 = uint bound pointer; param2 = pin pointer; payload = complete 8-Felt chunks",
            }
            pub FALCON_PRODUCT_CHECK: FalconProductCheckDomain {
                local_id: 0x000a,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Falcon512-Eidos polynomial product-check transcript.",
                schema: "param0 = 1544; param1 = 0; param2 = 0; payload = public-key commitment || zero word || 512 s2 coefficients || 1024 product coefficients",
            }
        }
    }
}

/// Returns the field-element representation of a typed Eidos domain.
pub const fn domain_tag<D: EidosDomain>(_: D) -> Felt {
    D::TAG.as_felt()
}

/// Parses a structurally valid Eidos domain tag.
pub(crate) fn parse_domain_tag(value: Felt) -> Option<DomainTag> {
    let value = u32::try_from(value.as_canonical_u64()).ok()?;
    DomainTag::from_u32(value)
}

/// Returns whether `tag` is assigned to a deferred precompile in the VM registry.
pub(crate) fn is_vm_precompile_domain(tag: DomainTag) -> bool {
    tag == Keccak256PrecompileDomain::TAG
        || tag == Uint256PrecompileDomain::TAG
        || tag == CurvePrecompileDomain::TAG
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_and_vm_registries_are_disjoint() {
        for crypto in MidenCryptoDomainRegistry::domains() {
            assert!(MidenVmDomainRegistry::resolve(crypto.tag).is_none());
        }
        for vm in MidenVmDomainRegistry::domains() {
            assert!(MidenCryptoDomainRegistry::resolve(vm.tag).is_none());
        }
    }

    #[test]
    fn mast_opcodes_are_disjoint_from_registered_tags() {
        for domain in MidenVmDomainRegistry::domains() {
            assert!(domain.tag.as_u32() > u8::MAX as u32);
        }
    }
}
