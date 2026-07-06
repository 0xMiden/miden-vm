use miden_core::{Felt, ONE, ZERO};
use miden_core_vm::deferred::Tag as VmTag;
use miden_precompiles_vm::Keccak256Precompile as VmKeccak256Precompile;

use crate::transcript::deferred_tags;

fn local_word_u64(word: [Felt; 4]) -> [u64; 4] {
    word.map(|felt| felt.as_canonical_u64())
}

#[test]
fn framework_tags_match_vm_source_of_truth() {
    assert_eq!(
        local_word_u64(deferred_tags::chunks()),
        VmTag::CHUNKS.as_word().map(|felt| felt.as_canonical_u64()),
    );
    assert_eq!(
        local_word_u64(deferred_tags::and()),
        VmTag::AND.as_word().map(|felt| felt.as_canonical_u64()),
    );

    assert_eq!(
        deferred_tags::chunks(),
        [Felt::from_u32(2), ZERO, ZERO, ZERO]
    );
    assert_eq!(deferred_tags::and(), [ONE, ZERO, ZERO, ZERO]);
}

#[test]
fn keccak_assert_tags_match_vm_source_of_truth() {
    for len in [0, 1, 31, 32, 33, 135, 136, 137] {
        assert_eq!(
            local_word_u64(deferred_tags::keccak_assert(len)),
            VmKeccak256Precompile::assert_tag(len)
                .as_word()
                .map(|felt| felt.as_canonical_u64()),
        );
    }
}

#[test]
fn keccak_assert_tag_layout_is_id_discriminant_len_zero() {
    assert_eq!(VmKeccak256Precompile::ASSERT_TAG_ID, 0);

    for len in [0, 1, 31, 32, 33, 135, 136, 137] {
        let tag = deferred_tags::keccak_assert(len);
        assert_eq!(
            tag[0].as_canonical_u64(),
            VmKeccak256Precompile::id().as_canonical_u64()
        );
        assert_eq!(tag[1], Felt::from_u32(VmKeccak256Precompile::ASSERT_TAG_ID));
        assert_eq!(tag[2], Felt::from_u32(len));
        assert_eq!(tag[3], ZERO);
    }
}
