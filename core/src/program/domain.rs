//! Registered domain selectors for protocol-visible hash commitments.
//!
//! Consensus-critical domains use registered numeric identifiers packed as
//!
//! ```text
//! selector = (domain_id << 8) | version
//! ```
//!
//! with `domain_id` a registered 24-bit integer (`>= 1`) and `version` an 8-bit per-domain
//! version (`>= 1`). Eidos incorporates the selector and exact input length into its initial
//! Eidos chaining value through `hash_elements_in_domain`.
//!
//! # Registry entries
//!
//! The `0x010000..0x01ffff` range is allocated to miden-vm. This module defines the following
//! entries within that range:
//!
//! | domain_id  | version | domain |
//! |------------|---------|-------------------------------------------|
//! | `0x010000` | 1       | kernel commitment ([`KERNEL_DOMAIN_TAG`](super::KERNEL_DOMAIN_TAG)) |
//! | `0x010001` | 1       | execution claim ([`CLAIM_DOMAIN_TAG`](super::CLAIM_DOMAIN_TAG)) |
//! | `0x010002` | 1       | proof request key ([`PROOF_REQUEST_DOMAIN_TAG`](super::PROOF_REQUEST_DOMAIN_TAG)) |
//! | `0x010003` | 1       | deferred AND/root fold |
//! | `0x010004` | 1       | deferred framework CHUNKS node |
//! | `0x010006` | 1       | Keccak-256 deferred precompile |
//! | `0x010007` | 1       | uint256 deferred precompile |
//! | `0x010008` | 1       | curve deferred precompile |
//! | `0x010009` | 1       | PVM uint pin claim |
//!
//! Selectors share one Eidos domain namespace with the `merge_in_domain` values used for MAST
//! control-block hashing. Those are opcode-sized (`< 256`) while every registered selector is
//! `>= 257` (`domain_id >= 1`), so those two ranges cannot collide. Distinctness among registered
//! selectors is the registry's responsibility: each `domain_id` is allocated once within its
//! maintainer's range, and the entries defined here are pinned distinct by
//! `registry_entries_are_valid_and_distinct_selectors`.

use crate::Felt;

/// Registered domain id for the kernel commitment.
pub const KERNEL_COMMITMENT_DOMAIN_ID: u32 = 0x010000;

/// Registered domain id for the execution-claim commitment.
pub const EXECUTION_CLAIM_DOMAIN_ID: u32 = 0x010001;

/// Registered domain id for the proof-request key.
pub const PROOF_REQUEST_DOMAIN_ID: u32 = 0x010002;

/// Registered domain id for deferred AND nodes and rolling-root folds.
pub const DEFERRED_AND_DOMAIN_ID: u32 = 0x010003;

/// Registered domain id for framework-owned deferred CHUNKS nodes.
pub const DEFERRED_CHUNKS_DOMAIN_ID: u32 = 0x010004;

/// Registered domain id for the Keccak-256 deferred precompile.
pub const KECCAK256_PRECOMPILE_DOMAIN_ID: u32 = 0x010006;

/// Registered domain id for the uint256 deferred precompile.
pub const UINT256_PRECOMPILE_DOMAIN_ID: u32 = 0x010007;

/// Registered domain id for the curve deferred precompile.
pub const CURVE_PRECOMPILE_DOMAIN_ID: u32 = 0x010008;

/// Registered domain id for PVM uint pin claims.
pub const PVM_UINT_PIN_CLAIM_DOMAIN_ID: u32 = 0x010009;

/// Largest selector or selector-defined parameter accepted by Eidos framing.
pub(crate) const MAX_EIDOS_INIT_VALUE: u32 = u32::MAX;

/// Returns whether `selector` has the domain-selector encoding.
pub(crate) fn has_domain_selector_encoding(selector: Felt) -> bool {
    let selector = selector.as_canonical_u64();
    selector <= u64::from(MAX_EIDOS_INIT_VALUE) && selector >> 8 != 0 && selector & 0xff != 0
}

/// Registered selector for the Keccak-256 deferred precompile.
pub const KECCAK256_PRECOMPILE_SELECTOR: Felt = domain_selector(KECCAK256_PRECOMPILE_DOMAIN_ID, 1);

/// Registered selector for the uint256 deferred precompile.
pub const UINT256_PRECOMPILE_SELECTOR: Felt = domain_selector(UINT256_PRECOMPILE_DOMAIN_ID, 1);

/// Registered selector for the curve deferred precompile.
pub const CURVE_PRECOMPILE_SELECTOR: Felt = domain_selector(CURVE_PRECOMPILE_DOMAIN_ID, 1);

/// Registered selector for PVM uint pin claims.
pub const PVM_UINT_PIN_CLAIM_SELECTOR: Felt = domain_selector(PVM_UINT_PIN_CLAIM_DOMAIN_ID, 1);

/// Packs a registered domain id and per-domain version into a domain selector.
///
/// The result is a u32 (`domain_id << 8 | version`), used as the domain element of
/// `hash_elements_in_domain`.
pub const fn domain_selector(domain_id: u32, version: u8) -> Felt {
    assert!(
        domain_id >= 1 && domain_id < (1 << 24),
        "domain_id must be a registered 24-bit id"
    );
    assert!(version >= 1, "per-domain versions start at 1");
    Felt::new_unchecked(((domain_id as u64) << 8) | version as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_entries_are_valid_and_distinct_selectors() {
        use crate::{
            crypto::dsa::falcon512_eidos::{
                FALCON_HASH_TO_POINT_DOMAIN_ID, FALCON_HASH_TO_POINT_SELECTOR,
                FALCON_PRODUCT_CHECK_DOMAIN_ID, FALCON_PRODUCT_CHECK_SELECTOR,
            },
            deferred::{DEFERRED_AND_DOMAIN, DEFERRED_CHUNKS_DOMAIN},
            program::{CLAIM_DOMAIN_TAG, KERNEL_DOMAIN_TAG, PROOF_REQUEST_DOMAIN_TAG},
        };

        let entries = [
            (FALCON_HASH_TO_POINT_DOMAIN_ID, Felt::from_u32(FALCON_HASH_TO_POINT_SELECTOR)),
            (FALCON_PRODUCT_CHECK_DOMAIN_ID, Felt::from_u32(FALCON_PRODUCT_CHECK_SELECTOR)),
            (KERNEL_COMMITMENT_DOMAIN_ID, KERNEL_DOMAIN_TAG),
            (EXECUTION_CLAIM_DOMAIN_ID, CLAIM_DOMAIN_TAG),
            (PROOF_REQUEST_DOMAIN_ID, PROOF_REQUEST_DOMAIN_TAG),
            (DEFERRED_AND_DOMAIN_ID, DEFERRED_AND_DOMAIN),
            (DEFERRED_CHUNKS_DOMAIN_ID, DEFERRED_CHUNKS_DOMAIN),
            (KECCAK256_PRECOMPILE_DOMAIN_ID, KECCAK256_PRECOMPILE_SELECTOR),
            (UINT256_PRECOMPILE_DOMAIN_ID, UINT256_PRECOMPILE_SELECTOR),
            (CURVE_PRECOMPILE_DOMAIN_ID, CURVE_PRECOMPILE_SELECTOR),
            (PVM_UINT_PIN_CLAIM_DOMAIN_ID, PVM_UINT_PIN_CLAIM_SELECTOR),
        ];
        for (i, (id, tag)) in entries.iter().enumerate() {
            assert!(*id >= 1 && *id < (1 << 24), "domain id out of the registered range");
            assert_eq!(
                tag.as_canonical_u64(),
                (u64::from(*id) << 8) | 1,
                "tag is not the packed selector"
            );
            for (other_id, other_tag) in entries.iter().skip(i + 1) {
                assert_ne!(id, other_id, "registered domain ids must be unique");
                assert_ne!(tag, other_tag, "registered tags must be unique");
            }
        }
    }

    #[test]
    #[should_panic(expected = "domain_id must be a registered 24-bit id")]
    fn domain_selector_rejects_values_outside_eidos_domain_range() {
        let _ = domain_selector(1 << 24, 1);
    }

    #[test]
    fn domain_selectors_have_nonzero_domain_and_version() {
        assert!(has_domain_selector_encoding(domain_selector(1, 1)));
        assert!(has_domain_selector_encoding(Felt::from_u32(u32::MAX)));

        for selector in [0, 1, 0xff, 0x100] {
            assert!(!has_domain_selector_encoding(Felt::from_u32(selector)));
        }
        assert!(!has_domain_selector_encoding(Felt::new_unchecked(u64::from(u32::MAX) + 1)));
    }
}
