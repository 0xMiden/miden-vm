use miden_crypto::{ZERO, hash::poseidon2::Poseidon2};

use super::{DeferredTag, Digest, Payload};
use crate::{Felt, Word};

/// Hashes a node `(tag, payload)` into its canonical 4-felt digest using Poseidon2.
///
/// The 12-felt sponge state is laid out as `[payload[0..8] || tag[0..4]]`: the 8-felt payload
/// occupies the rate, the 4-felt tag occupies the capacity. A single permutation produces the
/// digest from the first 4 state elements. This matches the layout MASM uses when computing the
/// same digest with one `hperm` instruction.
pub fn hash_node(tag: DeferredTag, payload: &Payload) -> Digest {
    let tag_felts = tag.to_felts();
    let payload_felts = payload.as_felts();

    let mut state: [Felt; 12] = [ZERO; 12];
    state[0..8].copy_from_slice(payload_felts);
    state[8..12].copy_from_slice(&tag_felts);

    Poseidon2::apply_permutation(&mut state);

    Word::new([state[0], state[1], state[2], state[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(seed: u64) -> Payload {
        Payload::new([
            Felt::new_unchecked(seed),
            Felt::new_unchecked(seed.wrapping_add(1)),
            Felt::new_unchecked(seed.wrapping_add(2)),
            Felt::new_unchecked(seed.wrapping_add(3)),
            Felt::new_unchecked(seed.wrapping_add(4)),
            Felt::new_unchecked(seed.wrapping_add(5)),
            Felt::new_unchecked(seed.wrapping_add(6)),
            Felt::new_unchecked(seed.wrapping_add(7)),
        ])
    }

    #[test]
    fn deterministic() {
        let p = payload(42);
        let a = hash_node(DeferredTag::Field0Leaf, &p);
        let b = hash_node(DeferredTag::Field0Leaf, &p);
        assert_eq!(a, b);
    }

    #[test]
    fn tag_changes_digest() {
        let p = payload(7);
        let leaf = hash_node(DeferredTag::Field0Leaf, &p);
        let add = hash_node(DeferredTag::Field0Add, &p);
        assert_ne!(leaf, add);
    }

    #[test]
    fn payload_changes_digest() {
        let a = hash_node(DeferredTag::Field0Leaf, &payload(0));
        let b = hash_node(DeferredTag::Field0Leaf, &payload(1));
        assert_ne!(a, b);
    }
}
