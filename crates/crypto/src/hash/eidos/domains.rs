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
                version: DomainVersion::numbered(2),
                encoding: Custom,
                description: "Falcon512-Eidos hash-to-point construction.",
                schema: "params = [0, 0, 0]; absorb the eight-Felt nonce, then the four-Felt message padded with four zeros to derive a fixed seed; for counters 0 through 127, compress [counter, 0, 0, 0, 0, 0, 0, 0] under that seed and emit its four Felts reduced modulo 12289 in order; 2^63 mod 12289 = 2832",
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
                version: DomainVersion::numbered(2),
                encoding: Custom,
                description: "Eidos AEAD counter-mode key derivation.",
                schema: "params = [0, 0, 0]; one fixed key || nonce block",
            }
            pub AEAD_MAC_KEY: AeadMacKeyDomain {
                local_id: 0x0007,
                version: DomainVersion::numbered(2),
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
                schema: "param0 = sum of matrix-row and salt widths after each is independently padded to 8 Felts; param1 = 0; param2 = 0; absorb rows in commitment order; an empty leaf returns the unmasked initial CV; the verifier fixes the row boundaries and widths",
            }
            pub ECGFP5_SEAL_KEY: Ecgfp5SealKeyDomain {
                local_id: 0x000c,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "EcGFp5-Eidos single-message key expansion; four-Felt output.",
                schema: "param0 = 8; param1 = 0; param2 = 0; payload = extracted secret(4), context digest(4)",
            }
            pub ECGFP5_SEAL_NONCE: Ecgfp5SealNonceDomain {
                local_id: 0x000d,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "EcGFp5-Eidos single-message nonce expansion; four-Felt output.",
                schema: "param0 = 8; param1 = 0; param2 = 0; payload = extracted secret(4), context digest(4)",
            }
            pub ECGFP5_SEAL_CONTEXT: Ecgfp5SealContextDomain {
                local_id: 0x000e,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "EcGFp5-Eidos application-context commitment.",
                schema: "param0 = context length in Felts; param1 = 0; param2 = 0; payload = application context",
            }
            pub ECGFP5_SEAL_EXTRACT: Ecgfp5SealExtractDomain {
                local_id: 0x000f,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "EcGFp5-Eidos single-message DH extraction; four-Felt output.",
                schema: "param0 = 24; param1 = 0; param2 = 0; payload = shared point S(5), zero(3), ephemeral point R(5), zero(3), recipient point Q(5), zero(3)",
            }
            pub ECGFP5_PUBLIC_KEY: Ecgfp5PublicKeyDomain {
                local_id: 0x0010,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "EcGFp5 public-key commitment.",
                schema: "param0 = 5; param1 = 0; param2 = 0; payload = canonical point encoding in increasing coefficient order",
            }
            pub ECGFP5_PREPROCESSED_PUBLIC_KEY: Ecgfp5PreprocessedPublicKeyDomain {
                local_id: 0x0011,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "EcGFp5 preprocessed public-key commitment.",
                schema: "param0 = 80; param1 = 0; param2 = 0; payload = twenty ordered Merkle roots of paired 16-bit multiplication tables",
            }
            pub ECGFP5_SEAL_BYTE_CONTEXT: Ecgfp5SealByteContextDomain {
                local_id: 0x0012,
                version: DomainVersion::numbered(1),
                encoding: ByteString,
                description: "EcGFp5-Eidos byte-message application-context commitment.",
                schema: "param0 = context length in bytes; param1 = 0; param2 = 0; payload = application context",
            }
        }
    }
}
