//! Eidos domains maintained by `miden-crypto`.
//!
//! This is the owner-local registry for namespace `0x00`. Numeric tags are consensus-visible;
//! names and descriptions make the assignments auditable and generate matching MASM constants.

use super::domain::{ByteString, Custom, DomainVersion, FeltSequence, namespace};

crate::eidos_domain_registry! {
    /// Domains maintained by `miden-crypto`.
    pub registry MidenCryptoDomainRegistry {
        namespace: namespace::MIDEN_CRYPTO;
        domains: {
            pub SMT_BUCKET_LEAF: SmtBucketLeafDomain {
                local_id: 0x0001,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Reserved domain for sparse Merkle tree bucket-leaf commitments.",
                schema: "param0 = number of entries; param1 = 0; param2 = 0; payload = sorted key/value pairs",
            }
            pub MMR_PEAKS: MmrPeaksDomain {
                local_id: 0x0002,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Reserved domain for Merkle mountain range peak commitments.",
                schema: "param0/param1 = low/high u32 limbs of num_leaves; param2 = 0; payload = canonical padded peak vector",
            }
            pub GENERIC_BYTE_STRING: GenericByteStringDomain {
                local_id: 0x0003,
                version: DomainVersion::numbered(1),
                encoding: ByteString,
                description: "Generic exact-length byte string.",
                schema: "param0 = number of bytes; param1 = 0; param2 = 0; zero-pad one final 64-byte block",
            }
            pub FALCON_HASH_TO_POINT: FalconHashToPointDomain {
                local_id: 0x0004,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Falcon512-Eidos hash-to-point construction.",
                schema: "params = [0, 0, 0]; absorb the eight-Felt nonce, then the four-Felt message padded with four zeros; repeat 128 times: compress an all-zero block, continue the chain from the Eidos CV without Falcon-field reduction, and emit its four Felts reduced modulo 12289 in order; 2^63 mod 12289 = 2832",
            }
            pub FALCON_PUBLIC_KEY: FalconPublicKeyDomain {
                local_id: 0x0005,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Falcon512-Eidos public-key commitment.",
                schema: "param0 = coefficient count; param1 = 0; param2 = 0; payload = 512 Falcon public-key coefficients",
            }
            pub AEAD_CTR_KEY: AeadCtrKeyDomain {
                local_id: 0x0006,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Eidos AEAD counter-mode key derivation.",
                schema: "params = [0, 0, 0]; one fixed key || nonce block",
            }
            pub AEAD_MAC_KEY: AeadMacKeyDomain {
                local_id: 0x0007,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Eidos AEAD polynomial-MAC key derivation.",
                schema: "params = [0, 0, 0]; one fixed key || nonce block",
            }
            pub RANDOM_COIN_STATE: RandomCoinStateDomain {
                local_id: 0x0008,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Eidos random-coin state derivation and reseeding.",
                schema: "param0 = 4 for initialization or 10 for reseeding; param1 = 0; param2 = 0; initialization payload = four-Felt seed; reseed payload = four-Felt coin state, low/high u32 next-block-counter limbs, and four-Felt reseed data",
            }
            pub RANDOM_COIN_OUTPUT: RandomCoinOutputDomain {
                local_id: 0x0009,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Eidos random-coin counter-mode output generation.",
                schema: "param0 = 6; param1 = 0; param2 = 0; payload = four-Felt coin state followed by low/high u32 next-block-counter limbs",
            }
            pub GENERIC_FELT_SEQUENCE: GenericFeltSequenceDomain {
                local_id: 0x000a,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Generic exact-length sequence of Goldilocks field elements.",
                schema: "param0 = number of Felts; param1 = 0; param2 = 0; zero-pad one final block",
            }
            pub LMCS_LEAF: LmcsLeafDomain {
                local_id: 0x000b,
                version: DomainVersion::numbered(1),
                encoding: Custom,
                description: "Canonical Eidos LMCS leaf hashing.",
                schema: "param0 = sum of matrix-row and salt widths after each is independently padded to 8 Felts; param1 = 0; param2 = 0; absorb rows in commitment order; the verifier fixes the row boundaries and widths",
            }
        }
    }
}
