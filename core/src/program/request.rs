//! Content-addressing for recursive proof packages.

use super::domain::{PROOF_REQUEST_DOMAIN_ID, domain_selector};
use crate::{Felt, Word, ZERO, chiplets::hasher};

/// Domain tag for proof-request keys: the registered selector
/// `(PROOF_REQUEST_DOMAIN_ID << 8) | 1` (see the [`domain`](super::domain) module).
pub const PROOF_REQUEST_DOMAIN_TAG: Felt = domain_selector(PROOF_REQUEST_DOMAIN_ID, 1);

/// Returns the advice-map key addressing a proof package for `claim_commitment` under the
/// verifier identified by `verifier_root`.
///
/// The key is `H_tag(claim_commitment ‖ verifier_root)` (one rate block, domain-separated). It
/// is a lookup address, not a trust anchor: the verifier re-checks the retrieved package against
/// its statement, so a wrong package fails verification. Both inputs are values the requester owns
/// rather than values taken from advice.
pub fn proof_request_key(verifier_root: Word, claim_commitment: Word) -> Word {
    // Absorb claim_commitment first so the MASM mirror needs a single word-swap to place the
    // rate; the order is otherwise arbitrary (a domain-separated hash of the two words).
    let mut preimage = [ZERO; 2 * 4];
    preimage[0..4].copy_from_slice(claim_commitment.as_elements());
    preimage[4..8].copy_from_slice(verifier_root.as_elements());
    hasher::hash_elements_in_domain(&preimage, PROOF_REQUEST_DOMAIN_TAG)
}
