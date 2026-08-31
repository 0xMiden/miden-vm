//! Registered domain selectors for protocol-visible hash commitments.
//!
//! This module follows the Miden domain-separation RFC
//! (<https://github.com/0xMiden/crypto/pull/1026>): consensus-critical domains use **registered
//! numeric identifiers** rather than hashed strings, packed as
//!
//! ```text
//! selector = (domain_id << 8) | version
//! ```
//!
//! with `domain_id` a registered 24-bit integer (`>= 1`) and `version` an 8-bit per-domain
//! version (`>= 1`). The selector rides in the second capacity element of the Poseidon2 sponge
//! (`hash_elements_in_domain`); the first capacity element carries the padding rule, and the third
//! marks empty input. The fourth capacity element is zero in the initial framing state.
//!
//! # Provisional registry entries
//!
//! The RFC's draft registry allocates `0x010000..0x01ffff` to miden-vm, with concrete entries
//! delegated to this repository. These are the range's first entries, to be migrated into the
//! machine-readable registry when it lands:
//!
//! | domain_id  | version | domain |
//! |------------|---------|-------------------------------------------|
//! | `0x010000` | 1       | kernel commitment ([`KERNEL_DOMAIN_TAG`](super::KERNEL_DOMAIN_TAG)) |
//! | `0x010001` | 1       | execution claim ([`CLAIM_DOMAIN_TAG`](super::CLAIM_DOMAIN_TAG)) |
//! | `0x010002` | 1       | proof request key ([`PROOF_REQUEST_DOMAIN_TAG`](super::PROOF_REQUEST_DOMAIN_TAG)) |
//!
//! Selectors share one capacity namespace with the `merge_in_domain` values used for MAST
//! control-block hashing. Those are opcode-sized (`< 256`) while every registered selector is
//! `>= 257` (`domain_id >= 1`), so those two ranges cannot collide. Distinctness among registered
//! selectors is the registry's responsibility: each `domain_id` is allocated once within its
//! maintainer's range, and the three defined here are pinned distinct by
//! `registry_entries_are_valid_and_distinct_selectors`.

use crate::Felt;

/// Registered domain id for the kernel commitment.
pub const KERNEL_COMMITMENT_DOMAIN_ID: u32 = 0x010000;

/// Registered domain id for the execution-claim commitment.
pub const EXECUTION_CLAIM_DOMAIN_ID: u32 = 0x010001;

/// Registered domain id for the proof-request key.
pub const PROOF_REQUEST_DOMAIN_ID: u32 = 0x010002;

/// Packs a registered domain id and per-domain version into a domain selector.
///
/// The result is a small integer (`domain_id << 8 | version`), used as the domain element of
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
        use crate::program::{CLAIM_DOMAIN_TAG, KERNEL_DOMAIN_TAG, PROOF_REQUEST_DOMAIN_TAG};

        let entries = [
            (KERNEL_COMMITMENT_DOMAIN_ID, KERNEL_DOMAIN_TAG),
            (EXECUTION_CLAIM_DOMAIN_ID, CLAIM_DOMAIN_TAG),
            (PROOF_REQUEST_DOMAIN_ID, PROOF_REQUEST_DOMAIN_TAG),
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
}
