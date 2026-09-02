use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use miden_core::FMP_INIT_VALUE;
use miden_core_lib::{CoreLibrary, handlers::aead_eidos::AEAD_EIDOS_DECRYPT_EMPTY_AD_EVENT_NAME};
use miden_crypto::{
    Felt, Word,
    aead::aead_eidos::expanded::{
        auth_tag_expanded, derive_ctr_key, derive_mac_key, encrypt_felts_expanded,
    },
};
use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventHandler},
};

const SRC_PTR: u64 = 1000;
const DST_PTR: u64 = 2000;
const SCRATCH_PTR: u64 = 3000;
const COUNTER: u64 = 0;
const SRC_PTR_PLUS_ONE_WORD: u64 = SRC_PTR + 4;
const DST_PTR_PLUS_ONE_WORD: u64 = DST_PTR + 4;
const DST_PTR_PLUS_TWO_WORDS: u64 = DST_PTR + 8;
const SRC_PTR_PLUS_TWO_WORDS: u64 = SRC_PTR + 8;
const DST_PTR_PLUS_THREE_WORDS: u64 = DST_PTR + 12;
const DST_PTR_PLUS_FOUR_WORDS: u64 = DST_PTR + 16;
const THREE_BLOCKS: u64 = 3;
const SRC_PTR_PLUS_THREE_WORDS: u64 = SRC_PTR + 12;
const SRC_PTR_PLUS_FOUR_WORDS: u64 = SRC_PTR + 16;
const SRC_PTR_PLUS_FIVE_WORDS: u64 = SRC_PTR + 20;
const SRC_PTR_PLUS_SIX_WORDS: u64 = SRC_PTR + 24;
const DST_PTR_PLUS_FIVE_WORDS: u64 = DST_PTR + 20;
const DST_PTR_PLUS_TWELVE_WORDS: u64 = DST_PTR + 48;
const COUNTER_PLUS_THREE: u64 = COUNTER + 3;
const SIX_BLOCKS: u64 = 6;
const U32_ADDRESS_SPACE_END: u64 = 1_u64 << 32;
const FIRST_UNSUPPORTED_AUTH_CIPHERTEXT_LEN: u64 = (1 << 28) - 5;
const FIRST_UNSUPPORTED_AUTH_BLOCK_COUNT: u64 = 1 << 25;
const FIRST_UNSUPPORTED_AUTH_PLAINTEXT_LEN: u64 = (1 << 27) - 2;

#[test]
fn derive_ctr_key_matches_reference() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let key_elements = key.into_elements();
    let nonce_elements = nonce.into_elements();
    let ctr_key_elements = derive_ctr_key(key, nonce).into_elements();

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{nonce_elements:?}
        push.{key_elements:?}
        exec.aead_eidos::derive_ctr_key

        push.{ctr_key_elements:?}
        assert_eqw.err=\"derive_ctr_key must match Rust reference\"
    end
    "
    );

    build_test!(source.as_str(), &[]).expect_stack(&[]);
}

#[test]
fn derive_mac_key_matches_reference() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let key_elements = key.into_elements();
    let nonce_elements = nonce.into_elements();
    let mac_key_elements = derive_mac_key(key, nonce).into_elements();

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{nonce_elements:?}
        push.{key_elements:?}
        exec.aead_eidos::derive_mac_key

        push.{mac_key_elements:?}
        assert_eqw.err=\"derive_mac_key must match Rust reference\"
    end
    "
    );

    build_test!(source.as_str(), &[]).expect_stack(&[]);
}

#[test]
fn auth_empty_ad_zero_ciphertext_matches_reference_vector() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let nonce_elements = nonce.into_elements();
    let mac_key_elements = derive_mac_key(key, nonce).into_elements();
    let expected_tag = auth_tag_expanded(key, nonce, &[], &[]);
    let expected_tag_0 = expected_tag[0].as_canonical_u64();
    let expected_tag_1 = expected_tag[1].as_canonical_u64();

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.0
        push.{DST_PTR}
        push.{nonce_elements:?}
        push.{mac_key_elements:?}

        exec.aead_eidos::auth_empty_ad_expanded

        push.{expected_tag_0}
        assert_eq.err=\"tag0 must match Rust reference\"
        push.{expected_tag_1}
        assert_eq.err=\"tag1 must match Rust reference\"
    end
    "
    );

    let test = build_test!(source.as_str(), &[]);
    test.check_constraints();
    test.expect_stack(&[]);
}

#[test]
fn auth_empty_ad_one_block_matches_reference_vector() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let nonce_elements = nonce.into_elements();
    let plaintext = [
        Felt::ZERO,
        Felt::new_unchecked(1 << 63),
        Felt::new(Felt::ORDER - 1).unwrap(),
        Felt::new_unchecked(0x0123_4567_89ab_cdef),
    ];

    let mac_key_elements = derive_mac_key(key, nonce).into_elements();
    let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
    let ciphertext_0 = &ciphertext[..4];
    let ciphertext_1 = &ciphertext[4..];
    let expected_tag = auth_tag_expanded(key, nonce, &[], &ciphertext);
    let expected_tag_0 = expected_tag[0].as_canonical_u64();
    let expected_tag_1 = expected_tag[1].as_canonical_u64();

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{ciphertext_0:?}
        push.{DST_PTR}
        mem_storew_le
        dropw
        push.{ciphertext_1:?}
        push.{DST_PTR_PLUS_ONE_WORD}
        mem_storew_le
        dropw

        push.1
        push.{DST_PTR}
        push.{nonce_elements:?}
        push.{mac_key_elements:?}

        exec.aead_eidos::auth_empty_ad_expanded

        push.{expected_tag_0}
        assert_eq.err=\"tag0 must match Rust reference\"
        push.{expected_tag_1}
        assert_eq.err=\"tag1 must match Rust reference\"
    end
    "
    );

    let test = build_test!(source.as_str(), &[]);
    test.check_constraints();
    test.expect_stack(&[]);
}

#[test]
fn encrypt_blocks_stream_zero_is_noop() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let ctr_key_elements = derive_ctr_key(key, nonce).into_elements();
    let dst_sentinel = [
        Felt::new_unchecked(91),
        Felt::new_unchecked(92),
        Felt::new_unchecked(93),
        Felt::new_unchecked(94),
    ];
    let expected_memory = felts_to_u64(&dst_sentinel);

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{dst_sentinel:?}
        push.{DST_PTR}
        mem_storew_le
        dropw

        push.0
        push.{COUNTER}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{ctr_key_elements:?}

        exec.aead_eidos::encrypt_blocks_stream

        push.{ctr_key_elements:?}
        assert_eqw.err=\"K_CTR must be preserved for zero stream blocks\"
        push.{SRC_PTR}
        assert_eq.err=\"src_ptr must not advance for zero stream blocks\"
        push.{DST_PTR}
        assert_eq.err=\"dst_ptr must not advance for zero stream blocks\"
        push.{COUNTER}
        assert_eq.err=\"counter must not advance for zero stream blocks\"
    end
    "
    );

    let test = build_test!(source.as_str(), &[]);
    test.check_constraints();
    test.expect_stack_and_memory(&[], DST_PTR as u32, &expected_memory);
}

#[test]
fn encrypt_blocks_stream_after_u32and_matches_three_block_reference_vector() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let plaintext = stream_plaintext_three_blocks();

    let ctr_key = derive_ctr_key(key, nonce);
    let ctr_key_elements = ctr_key.into_elements();
    let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
    let expected_memory = felts_to_u64(&ciphertext);
    let plaintext_0 = &plaintext[..4];
    let plaintext_1 = &plaintext[4..8];
    let plaintext_2 = &plaintext[8..12];
    let plaintext_3 = &plaintext[12..16];
    let plaintext_4 = &plaintext[16..20];
    let plaintext_5 = &plaintext[20..];

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{plaintext_0:?}
        push.{SRC_PTR}
        mem_storew_le
        dropw
        push.{plaintext_1:?}
        push.{SRC_PTR_PLUS_ONE_WORD}
        mem_storew_le
        dropw
        push.{plaintext_2:?}
        push.{SRC_PTR_PLUS_TWO_WORDS}
        mem_storew_le
        dropw
        push.{plaintext_3:?}
        push.{SRC_PTR_PLUS_THREE_WORDS}
        mem_storew_le
        dropw
        push.{plaintext_4:?}
        push.{SRC_PTR_PLUS_FOUR_WORDS}
        mem_storew_le
        dropw
        push.{plaintext_5:?}
        push.{SRC_PTR_PLUS_FIVE_WORDS}
        mem_storew_le
        dropw

        push.{THREE_BLOCKS}
        push.{COUNTER}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{ctr_key_elements:?}

        # Record a normal bitwise row before the stream entries. The bitwise trace writer must
        # keep the following period-8 stream entries phase-aligned.
        push.1 push.1 u32and drop

        exec.aead_eidos::encrypt_blocks_stream

        push.{ctr_key_elements:?}
        assert_eqw.err=\"K_CTR must be preserved by stream path\"
        push.{SRC_PTR_PLUS_SIX_WORDS}
        assert_eq.err=\"stream src_ptr must advance by num plaintext words\"
        push.{DST_PTR_PLUS_TWELVE_WORDS}
        assert_eq.err=\"stream dst_ptr must advance by num ciphertext double-words\"
        push.{COUNTER_PLUS_THREE}
        assert_eq.err=\"stream counter must advance by num blocks\"
    end
    "
    );

    let test = build_test!(source.as_str(), &[]);
    test.check_constraints();
    test.expect_stack_and_memory(&[], DST_PTR as u32, &expected_memory);
}

#[test]
fn encrypt_blocks_stream_unrolled_block_counts_match_reference() {
    for num_blocks in [1_u64, 2, 4, 5, 7, 8, 13, 16] {
        let key = word([1, 2, 3, 4]);
        let nonce = word([0x10, 0x20, 0x30, 0x40]);
        let ctr_key = derive_ctr_key(key, nonce);
        let ctr_key_elements = ctr_key.into_elements();
        let plaintext = stream_plaintext_blocks(num_blocks as usize);
        let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
        let expected_memory = felts_to_u64(&ciphertext);

        let mut stores = String::new();
        for (word_idx, word) in plaintext.chunks(4).enumerate() {
            let ptr = SRC_PTR + (word_idx as u64) * 4;
            stores.push_str(&format!(
                "
        push.{word:?}
        push.{ptr}
        mem_storew_le
        dropw
"
            ));
        }

        let expected_src = SRC_PTR + 8 * num_blocks;
        let expected_dst = DST_PTR + 16 * num_blocks;
        let expected_counter = COUNTER + num_blocks;
        let source = format!(
            "
    use miden::core::crypto::aead_eidos

    begin
        {stores}

        push.{num_blocks}
        push.{COUNTER}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{ctr_key_elements:?}

        exec.aead_eidos::encrypt_blocks_stream

        push.{ctr_key_elements:?}
        assert_eqw.err=\"K_CTR must be preserved by unrolled stream path\"
        push.{expected_src}
        assert_eq.err=\"stream src_ptr must advance by num plaintext words\"
        push.{expected_dst}
        assert_eq.err=\"stream dst_ptr must advance by num ciphertext double-words\"
        push.{expected_counter}
        assert_eq.err=\"stream counter must advance by num blocks\"
    end
    "
        );

        let test = build_test!(source.as_str(), &[]);
        test.check_constraints();
        test.expect_stack_and_memory(&[], DST_PTR as u32, &expected_memory);
    }
}

#[test]
fn encrypt_felts_expanded_matches_reference_for_exact_lengths() {
    for num_felts in [0_u64, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 16, 17] {
        let key = word([1, 2, 3, 4]);
        let nonce = word([0x10, 0x20, 0x30, 0x40]);
        let ctr_key = derive_ctr_key(key, nonce);
        let ctr_key_elements = ctr_key.into_elements();
        let plaintext = stream_plaintext_felts(num_felts as usize);
        let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
        let expected_counter = COUNTER + num_felts.div_ceil(8);
        let expected_src = SRC_PTR + num_felts;
        let expected_dst = DST_PTR + 2 * num_felts;

        let stores = store_felts(SRC_PTR, &plaintext);
        let expected_memory = if num_felts == 0 {
            vec![91, 92, 93, 94]
        } else {
            felts_to_u64(&ciphertext)
        };
        let zero_memory_setup = if num_felts == 0 {
            "
        push.[91, 92, 93, 94]
        push.2000
        mem_storew_le
        dropw
"
        } else {
            ""
        };

        let source = format!(
            "
    use miden::core::crypto::aead_eidos

    begin
        {zero_memory_setup}
        {stores}

        push.{num_felts}
        push.{COUNTER}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{ctr_key_elements:?}

        exec.aead_eidos::encrypt_felts_expanded

        push.{ctr_key_elements:?}
        assert_eqw.err=\"K_CTR must be preserved by exact-length stream path\"
        push.{expected_src}
        assert_eq.err=\"exact stream src_ptr must advance by num plaintext felts\"
        push.{expected_dst}
        assert_eq.err=\"exact stream dst_ptr must advance by logical ciphertext limbs\"
        push.{expected_counter}
        assert_eq.err=\"exact stream counter must advance by used stream blocks\"
    end
    "
        );

        let test = build_test!(source.as_str(), &[]);
        test.check_constraints();
        test.expect_stack_and_memory(&[], DST_PTR as u32, &expected_memory);
    }
}

#[test]
fn encrypt_entry_points_reject_cross_block_overlap() {
    // The first block sees adjacent ranges, but its output would overwrite the next input block.
    assert_encrypt_rejected(
        "encrypt_blocks_stream cross-block overlap",
        "encrypt_blocks_stream",
        1000,
        1008,
        2,
    );

    // The aligned prefix would overwrite the ninth Felt before the tail path reads it.
    assert_encrypt_rejected(
        "encrypt_felts_expanded cross-block overlap",
        "encrypt_felts_expanded",
        1000,
        1008,
        9,
    );
}

#[test]
fn encrypt_entry_points_accept_adjacent_and_empty_ranges() {
    // source [1000, 1016), destination [1016, 1048)
    assert_encrypt_blocks_accepts_layout(1000, 1016, 2);
    // source [1000, 1012), destination [1012, 1036)
    assert_encrypt_felts_accepts_layout(1000, 1012, 12);

    // Empty source and destination ranges may begin at the same address.
    assert_encrypt_blocks_accepts_layout(1000, 1000, 0);
    assert_encrypt_felts_accepts_layout(1000, 1000, 0);
    let local_memory_start = FMP_INIT_VALUE.as_canonical_u64();
    assert_encrypt_blocks_accepts_layout(local_memory_start, local_memory_start, 0);
    assert_encrypt_felts_accepts_layout(local_memory_start, local_memory_start, 0);
}

#[test]
fn encrypt_entry_points_reject_local_memory_aliases() {
    let local_memory_start = FMP_INIT_VALUE.as_canonical_u64();

    for (procedure, count) in [("encrypt_blocks_stream", 1), ("encrypt_felts_expanded", 4)] {
        assert_encrypt_rejected(
            "source aliases procedure-local memory",
            procedure,
            local_memory_start,
            1000,
            count,
        );
        assert_encrypt_local_frame_rejected(procedure, 1000, local_memory_start, count);
    }
}

#[test]
fn encrypt_entry_points_reject_expanded_length_overflow() {
    assert_encrypt_rejected(
        "encrypt_blocks_stream ciphertext length overflow",
        "encrypt_blocks_stream",
        1000,
        2000,
        1_u64 << 28,
    );
    assert_encrypt_rejected(
        "encrypt_felts_expanded ciphertext length overflow",
        "encrypt_felts_expanded",
        1000,
        2000,
        1_u64 << 31,
    );
}

#[test]
fn encrypt_entry_points_validate_counter_schedule() {
    let max_counter = u64::from(u32::MAX);

    assert_encrypt_counter_accepts("encrypt_blocks_stream", max_counter, 1, 8, 16);
    assert_encrypt_counter_rejected(
        "encrypt_blocks_stream counter range",
        "encrypt_blocks_stream",
        max_counter,
        2,
    );

    assert_encrypt_counter_accepts("encrypt_felts_expanded", max_counter, 1, 1, 2);
    assert_encrypt_counter_rejected(
        "encrypt_felts_expanded counter range",
        "encrypt_felts_expanded",
        max_counter,
        9,
    );
}

#[test]
fn auth_empty_ad_expanded_with_scratch_matches_reference_for_exact_lengths() {
    for num_felts in [0_usize, 1, 2, 4, 5, 8, 9, 13, 16, 24, 31, 64] {
        let key = word([1, 2, 3, 4]);
        let nonce = word([0x10, 0x20, 0x30, 0x40]);
        let nonce_elements = nonce.into_elements();
        let mac_key_elements = derive_mac_key(key, nonce).into_elements();
        let plaintext = stream_plaintext_felts(num_felts);
        let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
        let stores = store_felts(DST_PTR, &ciphertext);
        let expected_tag = auth_tag_expanded(key, nonce, &[], &ciphertext);
        let expected_tag_0 = expected_tag[0].as_canonical_u64();
        let expected_tag_1 = expected_tag[1].as_canonical_u64();

        let source = format!(
            "
    use miden::core::crypto::aead_eidos

    begin
        {stores}

        push.{SCRATCH_PTR}
        push.{ciphertext_len}
        push.{DST_PTR}
        push.{nonce_elements:?}
        push.{mac_key_elements:?}

        exec.aead_eidos::auth_empty_ad_expanded_with_scratch

        push.{expected_tag_0}
        assert_eq.err=\"tag0 must match exact expanded MAC reference\"
        push.{expected_tag_1}
        assert_eq.err=\"tag1 must match exact expanded MAC reference\"
    end
    ",
            ciphertext_len = ciphertext.len()
        );

        let test = build_test!(source.as_str(), &[]);
        test.check_constraints();
        test.expect_stack(&[]);
    }
}

#[test]
fn auth_empty_ad_expanded_rejects_invalid_ranges() {
    let cases = [
        ("misaligned ciphertext", 1001, 0),
        ("ciphertext pointer exceeds u32", U32_ADDRESS_SPACE_END, 0),
        ("block count exceeds u32", 1000, U32_ADDRESS_SPACE_END),
        (
            "authentication input exceeds the supported length",
            1000,
            FIRST_UNSUPPORTED_AUTH_BLOCK_COUNT,
        ),
        ("ciphertext end overflows", U32_ADDRESS_SPACE_END - 4, 1),
    ];

    for (case, ct_ptr, num_blocks) in cases {
        assert_block_auth_rejected(case, ct_ptr, num_blocks);
    }
}

#[test]
fn auth_empty_ad_expanded_accepts_zero_blocks() {
    assert_block_auth_accepts(1000, 0);
    assert_block_auth_accepts(FMP_INIT_VALUE.as_canonical_u64(), 0);
}

#[test]
fn auth_empty_ad_expanded_rejects_local_memory_alias() {
    assert_block_auth_rejected(
        "ciphertext aliases procedure-local memory",
        FMP_INIT_VALUE.as_canonical_u64(),
        1,
    );
}

#[test]
fn decrypt_empty_ad_accepts_valid_ciphertext_for_exact_lengths() {
    for num_felts in [0_usize, 1, 5, 8, 13, 16, 32, 64] {
        let key = word([1, 2, 3, 4]);
        let nonce = word([0x10, 0x20, 0x30, 0x40]);
        let key_elements = key.into_elements();
        let nonce_elements = nonce.into_elements();
        let plaintext = stream_plaintext_felts(num_felts);
        let mut ciphertext_and_tag = encrypt_felts_expanded(key, nonce, &plaintext);
        let tag = auth_tag_expanded(key, nonce, &[], &ciphertext_and_tag);
        ciphertext_and_tag.extend(tag);

        let input_stores = store_felts(SRC_PTR, &ciphertext_and_tag);
        let expected_memory = if num_felts == 0 {
            vec![91, 92, 93, 94]
        } else {
            felts_to_u64(&plaintext)
        };
        let zero_memory_setup = if num_felts == 0 {
            "
        push.[91, 92, 93, 94]
        push.2000
        mem_storew_le
        dropw
"
        } else {
            ""
        };

        let source = format!(
            "
    use miden::core::crypto::aead_eidos

    begin
        {zero_memory_setup}
        {input_stores}

        push.{SCRATCH_PTR}
        push.{num_felts}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}

        exec.aead_eidos::decrypt_empty_ad
    end
    "
        );

        let test = build_test!(source.as_str(), &[]);
        test.check_constraints();
        test.expect_stack_and_memory(&[], DST_PTR as u32, &expected_memory);
    }
}

#[test]
fn decrypt_empty_ad_rejects_overlapping_regions_before_event() {
    let cases = [
        ("source and destination are identical", 1000, 1000, 3000),
        ("destination starts inside source", 1000, 1004, 3000),
        ("destination overlaps only the source tag", 1000, 1016, 3000),
        ("source starts inside destination", 1000, 996, 3000),
        ("source and workspace are identical", 1000, 2000, 1000),
        ("workspace starts inside source", 1000, 2000, 1004),
        ("workspace overlaps only the source tag", 1000, 2000, 1016),
        ("source starts inside workspace", 1000, 2000, 996),
        ("destination and workspace are identical", 1000, 2000, 2000),
        ("workspace starts inside destination", 1000, 2000, 2004),
        ("destination starts inside workspace", 1000, 2000, 1996),
    ];

    for (case, src_ptr, dst_ptr, scratch_ptr) in cases {
        assert_decrypt_rejected_before_event(case, src_ptr, dst_ptr, 8, scratch_ptr);
    }
}

#[test]
fn decrypt_empty_ad_accepts_adjacent_regions() {
    // workspace [984, 1000), source [1000, 1012), destination [1012, 1017)
    assert_decrypt_accepts_layout(1000, 1012, 5, 984);

    // destination [2000, 2008), workspace [2008, 2024)
    assert_decrypt_accepts_layout(1000, 2000, 8, 2008);
}

#[test]
fn decrypt_empty_ad_rejects_local_memory_aliases() {
    let local_memory_start = FMP_INIT_VALUE.as_canonical_u64();

    assert_decrypt_rejected_before_event(
        "source aliases procedure-local memory",
        local_memory_start,
        1000,
        1,
        2000,
    );

    assert_decrypt_rejected_before_event(
        "destination aliases procedure-local memory",
        1000,
        local_memory_start,
        1,
        2000,
    );
    assert_decrypt_rejected_before_event(
        "workspace aliases procedure-local memory",
        1000,
        2000,
        1,
        local_memory_start,
    );
}

#[test]
fn decrypt_empty_ad_handles_empty_destination_range() {
    // The source still covers the two-Felt tag when num_felts is zero. The empty destination may
    // begin inside either non-empty region without overlapping it.
    assert_decrypt_accepts_layout(1000, 1000, 0, 2000);
    assert_decrypt_accepts_layout(1000, 2000, 0, 2000);
    assert_decrypt_accepts_layout(1000, FMP_INIT_VALUE.as_canonical_u64(), 0, 2000);

    assert_decrypt_rejected_before_event(
        "zero-length plaintext still has a source tag",
        1000,
        2000,
        0,
        1000,
    );
}

#[test]
fn decrypt_empty_ad_rejects_invalid_ranges_before_event() {
    let cases = [
        ("misaligned source", 1001, 2000, 8, 3000),
        ("misaligned destination", 1000, 2001, 8, 3000),
        ("misaligned workspace", 1000, 2000, 8, 3001),
        ("source pointer exceeds u32", U32_ADDRESS_SPACE_END, 2000, 0, 3000),
        ("destination pointer exceeds u32", 1000, U32_ADDRESS_SPACE_END, 0, 3000),
        ("workspace pointer exceeds u32", 1000, 2000, 0, U32_ADDRESS_SPACE_END),
        ("plaintext length exceeds u32", 1000, 2000, U32_ADDRESS_SPACE_END, 3000),
        (
            "authentication input exceeds the supported length",
            1000,
            2000,
            FIRST_UNSUPPORTED_AUTH_PLAINTEXT_LEN,
            3000,
        ),
        ("source end overflows", U32_ADDRESS_SPACE_END - 4, 1000, 2, 2000),
        ("destination end overflows", 1000, U32_ADDRESS_SPACE_END - 4, 8, 2000),
        ("workspace end overflows", 1000, 2000, 1, U32_ADDRESS_SPACE_END - 4),
    ];

    for (case, src_ptr, dst_ptr, num_felts, scratch_ptr) in cases {
        assert_decrypt_rejected_before_event(case, src_ptr, dst_ptr, num_felts, scratch_ptr);
    }
}

#[test]
fn auth_empty_ad_expanded_with_scratch_rejects_overlapping_regions() {
    let cases = [
        ("ciphertext and workspace are identical", 1000, 8, 1000),
        ("workspace starts inside ciphertext", 1000, 8, 1004),
        ("ciphertext starts inside workspace", 1000, 8, 996),
    ];

    for (case, ct_ptr, ciphertext_len, scratch_ptr) in cases {
        assert_auth_rejected(case, ct_ptr, ciphertext_len, scratch_ptr);
    }
}

#[test]
fn auth_empty_ad_expanded_with_scratch_accepts_adjacent_and_empty_ranges() {
    // workspace [984, 1000), ciphertext [1000, 1008)
    assert_auth_accepts(1000, 8, 984);
    // ciphertext [1000, 1008), workspace [1008, 1024)
    assert_auth_accepts(1000, 8, 1008);
    // An empty ciphertext region may begin inside the non-empty workspace.
    assert_auth_accepts(1000, 0, 1000);
    assert_auth_accepts(FMP_INIT_VALUE.as_canonical_u64(), 0, 1000);
}

#[test]
fn auth_empty_ad_expanded_with_scratch_rejects_local_memory_aliases() {
    let local_memory_start = FMP_INIT_VALUE.as_canonical_u64();

    assert_auth_rejected("ciphertext aliases procedure-local memory", local_memory_start, 4, 1000);
    assert_auth_local_frame_rejected(1000, 4, local_memory_start);
}

#[test]
fn auth_empty_ad_expanded_with_scratch_rejects_invalid_ranges() {
    let cases = [
        ("misaligned ciphertext", 1001, 8, 2000),
        ("misaligned workspace", 1000, 8, 2001),
        ("ciphertext pointer exceeds u32", U32_ADDRESS_SPACE_END, 0, 2000),
        ("workspace pointer exceeds u32", 1000, 0, U32_ADDRESS_SPACE_END),
        ("ciphertext length exceeds u32", 1000, U32_ADDRESS_SPACE_END, 2000),
        (
            "authentication input exceeds the supported length",
            1000,
            FIRST_UNSUPPORTED_AUTH_CIPHERTEXT_LEN,
            2000,
        ),
        ("ciphertext end overflows", U32_ADDRESS_SPACE_END - 4, 8, 2000),
        ("workspace end overflows", 1000, 8, U32_ADDRESS_SPACE_END - 4),
    ];

    for (case, ct_ptr, ciphertext_len, scratch_ptr) in cases {
        assert_auth_rejected(case, ct_ptr, ciphertext_len, scratch_ptr);
    }
}

#[test]
fn decrypt_empty_ad_rejects_forged_ciphertext() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let key_elements = key.into_elements();
    let nonce_elements = nonce.into_elements();
    let plaintext = stream_plaintext_felts(5);
    let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
    let tag = auth_tag_expanded(key, nonce, &[], &ciphertext);

    let mut forged = ciphertext;
    forged[0] += Felt::ONE;
    forged.extend(tag);

    let input_stores = store_felts(SRC_PTR, &forged);
    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        {input_stores}

        push.{SCRATCH_PTR}
        push.5
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}

        exec.aead_eidos::decrypt_empty_ad
    end
    "
    );

    let test = build_test!(source.as_str(), &[]);
    assert!(test.execute().is_err());
}

#[test]
fn decrypt_empty_ad_rejects_forged_plaintext_advice() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let key_elements = key.into_elements();
    let nonce_elements = nonce.into_elements();
    let plaintext = stream_plaintext_felts(5);
    let mut ciphertext_and_tag = encrypt_felts_expanded(key, nonce, &plaintext);
    let tag = auth_tag_expanded(key, nonce, &[], &ciphertext_and_tag);
    ciphertext_and_tag.extend(tag);

    let input_stores = store_felts(SRC_PTR, &ciphertext_and_tag);
    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        {input_stores}

        push.{SCRATCH_PTR}
        push.5
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}

        exec.aead_eidos::decrypt_empty_ad
    end
    "
    );

    let core_lib = CoreLibrary::default();
    let mut forged_plaintext = plaintext;
    forged_plaintext[0] += Felt::ONE;
    let test = miden_utils_testing::build_test_by_mode!(false, source.as_str(), &[])
        .with_library(core_lib.package())
        .with_event_handler(
            AEAD_EIDOS_DECRYPT_EMPTY_AD_EVENT_NAME,
            PlaintextHandler(forged_plaintext),
        );
    assert!(test.execute().is_err());
}

#[test]
fn decrypt_empty_ad_rejects_forged_tag() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let key_elements = key.into_elements();
    let nonce_elements = nonce.into_elements();
    let plaintext = stream_plaintext_felts(5);
    let mut ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
    let mut tag = auth_tag_expanded(key, nonce, &[], &ciphertext);
    tag[0] += Felt::ONE;
    ciphertext.extend(tag);

    let input_stores = store_felts(SRC_PTR, &ciphertext);
    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        {input_stores}

        push.{SCRATCH_PTR}
        push.5
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}

        exec.aead_eidos::decrypt_empty_ad
    end
    "
    );

    let core_lib = CoreLibrary::default();
    let test = miden_utils_testing::build_test_by_mode!(false, source.as_str(), &[])
        .with_library(core_lib.package())
        .with_event_handler(AEAD_EIDOS_DECRYPT_EMPTY_AD_EVENT_NAME, PlaintextHandler(plaintext));
    assert!(test.execute().is_err());
}

#[test]
fn auth_empty_ad_three_blocks_matches_reference_vector() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let nonce_elements = nonce.into_elements();
    let plaintext = [
        Felt::ZERO,
        Felt::new_unchecked(1 << 63),
        Felt::new(Felt::ORDER - 1).unwrap(),
        Felt::new_unchecked(0x0123_4567_89ab_cdef),
        Felt::new_unchecked(42),
        Felt::new_unchecked(0x1020_3040_5060_7080),
        Felt::new_unchecked(0xffff_ffff),
        Felt::new_unchecked(0xffff_ffff_0000_0000),
        Felt::new_unchecked(0x2222_3333_4444_5555),
        Felt::new_unchecked(0x7777_8888_9999_aaaa),
        Felt::new_unchecked(17),
        Felt::new_unchecked(0x8000_0000),
    ];

    let mac_key_elements = derive_mac_key(key, nonce).into_elements();
    let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
    let ciphertext_0 = &ciphertext[..4];
    let ciphertext_1 = &ciphertext[4..8];
    let ciphertext_2 = &ciphertext[8..12];
    let ciphertext_3 = &ciphertext[12..16];
    let ciphertext_4 = &ciphertext[16..20];
    let ciphertext_5 = &ciphertext[20..24];
    let expected_tag = auth_tag_expanded(key, nonce, &[], &ciphertext);
    let expected_tag_0 = expected_tag[0].as_canonical_u64();
    let expected_tag_1 = expected_tag[1].as_canonical_u64();

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{ciphertext_0:?}
        push.{DST_PTR}
        mem_storew_le
        dropw
        push.{ciphertext_1:?}
        push.{DST_PTR_PLUS_ONE_WORD}
        mem_storew_le
        dropw
        push.{ciphertext_2:?}
        push.{DST_PTR_PLUS_TWO_WORDS}
        mem_storew_le
        dropw
        push.{ciphertext_3:?}
        push.{DST_PTR_PLUS_THREE_WORDS}
        mem_storew_le
        dropw
        push.{ciphertext_4:?}
        push.{DST_PTR_PLUS_FOUR_WORDS}
        mem_storew_le
        dropw
        push.{ciphertext_5:?}
        push.{DST_PTR_PLUS_FIVE_WORDS}
        mem_storew_le
        dropw

        push.{THREE_BLOCKS}
        push.{DST_PTR}
        push.{nonce_elements:?}
        push.{mac_key_elements:?}

        exec.aead_eidos::auth_empty_ad_expanded

        push.{expected_tag_0}
        assert_eq.err=\"tag0 must match Rust reference\"
        push.{expected_tag_1}
        assert_eq.err=\"tag1 must match Rust reference\"
    end
    "
    );

    let test = build_test!(source.as_str(), &[]);
    test.check_constraints();
    test.expect_stack(&[]);
}

#[test]
fn encrypt_stream_then_auth_empty_ad_matches_reference_vector() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let key_elements = key.into_elements();
    let nonce_elements = nonce.into_elements();
    let plaintext = stream_plaintext_three_blocks();

    let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
    let expected_memory = felts_to_u64(&ciphertext);
    let expected_tag = auth_tag_expanded(key, nonce, &[], &ciphertext);
    let expected_tag_0 = expected_tag[0].as_canonical_u64();
    let expected_tag_1 = expected_tag[1].as_canonical_u64();
    let plaintext_0 = &plaintext[..4];
    let plaintext_1 = &plaintext[4..8];
    let plaintext_2 = &plaintext[8..12];
    let plaintext_3 = &plaintext[12..16];
    let plaintext_4 = &plaintext[16..20];
    let plaintext_5 = &plaintext[20..];

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{plaintext_0:?}
        push.{SRC_PTR}
        mem_storew_le
        dropw
        push.{plaintext_1:?}
        push.{SRC_PTR_PLUS_ONE_WORD}
        mem_storew_le
        dropw
        push.{plaintext_2:?}
        push.{SRC_PTR_PLUS_TWO_WORDS}
        mem_storew_le
        dropw
        push.{plaintext_3:?}
        push.{SRC_PTR_PLUS_THREE_WORDS}
        mem_storew_le
        dropw
        push.{plaintext_4:?}
        push.{SRC_PTR_PLUS_FOUR_WORDS}
        mem_storew_le
        dropw
        push.{plaintext_5:?}
        push.{SRC_PTR_PLUS_FIVE_WORDS}
        mem_storew_le
        dropw

        push.{THREE_BLOCKS}
        push.{COUNTER}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}
        exec.aead_eidos::derive_ctr_key
        exec.aead_eidos::encrypt_blocks_stream
        dropw drop drop drop

        push.{SIX_BLOCKS}
        push.{DST_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}
        exec.aead_eidos::derive_mac_key
        push.{nonce_elements:?}
        swapw
        exec.aead_eidos::auth_empty_ad_expanded

        push.{expected_tag_0}
        assert_eq.err=\"tag0 must match Rust reference\"
        push.{expected_tag_1}
        assert_eq.err=\"tag1 must match Rust reference\"
    end
    "
    );

    let test = build_test!(source.as_str(), &[]);
    test.check_constraints();
    test.expect_stack_and_memory(&[], DST_PTR as u32, &expected_memory);
}

fn word(values: [u64; 4]) -> Word {
    Word::new(values.map(Felt::new_unchecked))
}

fn felts_to_u64(values: &[Felt]) -> Vec<u64> {
    values.iter().map(Felt::as_canonical_u64).collect()
}

fn stream_plaintext_three_blocks() -> [Felt; 24] {
    [
        Felt::ZERO,
        Felt::new_unchecked(1 << 63),
        Felt::new(Felt::ORDER - 1).unwrap(),
        Felt::new_unchecked(0x0123_4567_89ab_cdef),
        Felt::new_unchecked(42),
        Felt::new_unchecked(0x1020_3040_5060_7080),
        Felt::new_unchecked(0xffff_ffff),
        Felt::new_unchecked(0xffff_ffff_0000_0000),
        Felt::new_unchecked(0x2222_3333_4444_5555),
        Felt::new_unchecked(0x7777_8888_9999_aaaa),
        Felt::new_unchecked(17),
        Felt::new_unchecked(0x8000_0000),
        Felt::new_unchecked(0x0102_0304_0506_0708),
        Felt::new_unchecked(0x1112_1314_1516_1718),
        Felt::new_unchecked(0x2122_2324_2526_2728),
        Felt::new_unchecked(0x3132_3334_3536_3738),
        Felt::new_unchecked(0x4142_4344_4546_4748),
        Felt::new_unchecked(0x5152_5354_5556_5758),
        Felt::new_unchecked(0x6162_6364_6566_6768),
        Felt::new_unchecked(0x7172_7374_7576_7778),
        Felt::new_unchecked(0x8182_8384_8586_8788),
        Felt::new_unchecked(0x9192_9394_9596_9798),
        Felt::new_unchecked(0xa1a2_a3a4_a5a6_a7a8),
        Felt::new_unchecked(0xb1b2_b3b4_b5b6_b7b8),
    ]
}

fn stream_plaintext_blocks(num_blocks: usize) -> Vec<Felt> {
    let base = stream_plaintext_three_blocks();
    (0..num_blocks * 8)
        .map(|i| base[i % base.len()] + Felt::new_unchecked((i / base.len()) as u64))
        .collect()
}

fn stream_plaintext_felts(num_felts: usize) -> Vec<Felt> {
    let base = stream_plaintext_three_blocks();
    (0..num_felts)
        .map(|i| base[i % base.len()] + Felt::new_unchecked((i / base.len()) as u64))
        .collect()
}

fn store_felts(ptr: u64, values: &[Felt]) -> String {
    let mut stores = String::new();
    let (chunks, remainder) = values.as_chunks::<4>();

    for (word_idx, word) in chunks.iter().enumerate() {
        let ptr = ptr + (word_idx as u64) * 4;
        stores.push_str(&format!(
            "
        push.{word:?}
        push.{ptr}
        mem_storew_le
        dropw
"
        ));
    }

    let tail_start = ptr + ((values.len() / 4) as u64) * 4;
    for (offset, felt) in remainder.iter().enumerate() {
        let value = felt.as_canonical_u64();
        let ptr = tail_start + offset as u64;
        stores.push_str(&format!(
            "
        push.{value}
        push.{ptr}
        mem_store
"
        ));
    }

    stores
}

fn assert_decrypt_accepts_layout(src_ptr: u64, dst_ptr: u64, num_felts: usize, scratch_ptr: u64) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let key_elements = key.into_elements();
    let nonce_elements = nonce.into_elements();
    let plaintext = stream_plaintext_felts(num_felts);
    let mut ciphertext_and_tag = encrypt_felts_expanded(key, nonce, &plaintext);
    let tag = auth_tag_expanded(key, nonce, &[], &ciphertext_and_tag);
    ciphertext_and_tag.extend(tag);
    let input_stores = store_felts(src_ptr, &ciphertext_and_tag);

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        {input_stores}

        push.{scratch_ptr}
        push.{num_felts}
        push.{dst_ptr}
        push.{src_ptr}
        push.{nonce_elements:?}
        push.{key_elements:?}

        exec.aead_eidos::decrypt_empty_ad
    end
    "
    );

    let test = build_test!(source.as_str(), &[]);
    if plaintext.is_empty() {
        test.expect_stack(&[]);
    } else {
        test.expect_stack_and_memory(&[], dst_ptr as u32, &felts_to_u64(&plaintext));
    }
}

fn assert_encrypt_blocks_accepts_layout(src_ptr: u64, dst_ptr: u64, num_blocks: usize) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let ctr_key_elements = derive_ctr_key(key, nonce).into_elements();
    let plaintext = stream_plaintext_blocks(num_blocks);
    let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
    let stores = store_felts(src_ptr, &plaintext);
    let expected_src = src_ptr + 8 * num_blocks as u64;
    let expected_dst = dst_ptr + 16 * num_blocks as u64;
    let expected_counter = COUNTER + num_blocks as u64;

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        {stores}

        push.{num_blocks}
        push.{COUNTER}
        push.{dst_ptr}
        push.{src_ptr}
        push.{ctr_key_elements:?}

        exec.aead_eidos::encrypt_blocks_stream

        push.{ctr_key_elements:?}
        assert_eqw.err=\"K_CTR must be preserved\"
        push.{expected_src}
        assert_eq.err=\"source pointer must advance by the plaintext length\"
        push.{expected_dst}
        assert_eq.err=\"destination pointer must advance by the ciphertext length\"
        push.{expected_counter}
        assert_eq.err=\"counter must advance by the block count\"
    end
    "
    );

    let test = build_test!(source.as_str(), &[]);
    if ciphertext.is_empty() {
        test.expect_stack(&[]);
    } else {
        test.expect_stack_and_memory(&[], dst_ptr as u32, &felts_to_u64(&ciphertext));
    }
}

fn assert_encrypt_felts_accepts_layout(src_ptr: u64, dst_ptr: u64, num_felts: usize) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let ctr_key_elements = derive_ctr_key(key, nonce).into_elements();
    let plaintext = stream_plaintext_felts(num_felts);
    let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
    let stores = store_felts(src_ptr, &plaintext);
    let expected_src = src_ptr + num_felts as u64;
    let expected_dst = dst_ptr + 2 * num_felts as u64;
    let expected_counter = COUNTER + (num_felts as u64).div_ceil(8);

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        {stores}

        push.{num_felts}
        push.{COUNTER}
        push.{dst_ptr}
        push.{src_ptr}
        push.{ctr_key_elements:?}

        exec.aead_eidos::encrypt_felts_expanded

        push.{ctr_key_elements:?}
        assert_eqw.err=\"K_CTR must be preserved\"
        push.{expected_src}
        assert_eq.err=\"source pointer must advance by the plaintext length\"
        push.{expected_dst}
        assert_eq.err=\"destination pointer must advance by the ciphertext length\"
        push.{expected_counter}
        assert_eq.err=\"counter must advance by the used stream blocks\"
    end
    "
    );

    let test = build_test!(source.as_str(), &[]);
    if ciphertext.is_empty() {
        test.expect_stack(&[]);
    } else {
        test.expect_stack_and_memory(&[], dst_ptr as u32, &felts_to_u64(&ciphertext));
    }
}

fn assert_encrypt_rejected(case: &str, procedure: &str, src_ptr: u64, dst_ptr: u64, count: u64) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let ctr_key_elements = derive_ctr_key(key, nonce).into_elements();
    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{count}
        push.{COUNTER}
        push.{dst_ptr}
        push.{src_ptr}
        push.{ctr_key_elements:?}

        exec.aead_eidos::{procedure}
    end
    "
    );

    assert!(build_test!(source.as_str(), &[]).execute().is_err(), "{case} must be rejected");
}

fn assert_encrypt_local_frame_rejected(procedure: &str, src_ptr: u64, dst_ptr: u64, count: u64) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let ctr_key_elements = derive_ctr_key(key, nonce).into_elements();
    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{count}
        push.{COUNTER}
        push.{dst_ptr}
        push.{src_ptr}
        push.{ctr_key_elements:?}

        exec.aead_eidos::{procedure}
    end
    "
    );

    let test = build_test!(source.as_str(), &[]);
    expect_assert_error_code_from_msg!(test, "AEAD memory ranges must stay below the local frame");
}

fn assert_encrypt_counter_accepts(
    procedure: &str,
    counter: u64,
    count: u64,
    src_advance: u64,
    dst_advance: u64,
) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let ctr_key_elements = derive_ctr_key(key, nonce).into_elements();
    let expected_src = SRC_PTR + src_advance;
    let expected_dst = DST_PTR + dst_advance;
    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{count}
        push.{counter}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{ctr_key_elements:?}

        exec.aead_eidos::{procedure}

        push.{ctr_key_elements:?}
        assert_eqw.err=\"K_CTR must be preserved\"
        push.{expected_src}
        assert_eq.err=\"source pointer must advance by the plaintext length\"
        push.{expected_dst}
        assert_eq.err=\"destination pointer must advance by the ciphertext length\"
        push.{U32_ADDRESS_SPACE_END}
        assert_eq.err=\"the returned counter may be one past u32::MAX\"
    end
    "
    );

    build_test!(source.as_str(), &[]).expect_stack(&[]);
}

fn assert_encrypt_counter_rejected(case: &str, procedure: &str, counter: u64, count: u64) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let ctr_key_elements = derive_ctr_key(key, nonce).into_elements();
    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{count}
        push.{counter}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{ctr_key_elements:?}

        exec.aead_eidos::{procedure}
    end
    "
    );

    assert!(build_test!(source.as_str(), &[]).execute().is_err(), "{case} must be rejected");
}

fn assert_decrypt_rejected_before_event(
    case: &str,
    src_ptr: u64,
    dst_ptr: u64,
    num_felts: u64,
    scratch_ptr: u64,
) {
    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{scratch_ptr}
        push.{num_felts}
        push.{dst_ptr}
        push.{src_ptr}
        push.[16, 32, 48, 64]
        push.[1, 2, 3, 4]

        exec.aead_eidos::decrypt_empty_ad
    end
    "
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let core_lib = CoreLibrary::default();
    let test = miden_utils_testing::build_test_by_mode!(false, source.as_str(), &[])
        .with_library(core_lib.package())
        .with_event_handler(
            AEAD_EIDOS_DECRYPT_EMPTY_AD_EVENT_NAME,
            CountingHandler(Arc::clone(&calls)),
        );

    assert!(test.execute().is_err(), "{case} must be rejected");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "{case} must be rejected before the plaintext event"
    );
}

fn assert_auth_accepts(ct_ptr: u64, ciphertext_len: usize, scratch_ptr: u64) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let nonce_elements = nonce.into_elements();
    let mac_key_elements = derive_mac_key(key, nonce).into_elements();
    let ciphertext = vec![Felt::ZERO; ciphertext_len];
    let expected_tag = auth_tag_expanded(key, nonce, &[], &ciphertext);
    let expected_tag_0 = expected_tag[0].as_canonical_u64();
    let expected_tag_1 = expected_tag[1].as_canonical_u64();

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{scratch_ptr}
        push.{ciphertext_len}
        push.{ct_ptr}
        push.{nonce_elements:?}
        push.{mac_key_elements:?}

        exec.aead_eidos::auth_empty_ad_expanded_with_scratch

        push.{expected_tag_0}
        assert_eq.err=\"tag0 must match for valid memory ranges\"
        push.{expected_tag_1}
        assert_eq.err=\"tag1 must match for valid memory ranges\"
    end
    "
    );

    build_test!(source.as_str(), &[]).expect_stack(&[]);
}

fn assert_block_auth_accepts(ct_ptr: u64, num_blocks: usize) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let nonce_elements = nonce.into_elements();
    let mac_key_elements = derive_mac_key(key, nonce).into_elements();
    let ciphertext = vec![Felt::ZERO; 8 * num_blocks];
    let expected_tag = auth_tag_expanded(key, nonce, &[], &ciphertext);
    let expected_tag_0 = expected_tag[0].as_canonical_u64();
    let expected_tag_1 = expected_tag[1].as_canonical_u64();

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{num_blocks}
        push.{ct_ptr}
        push.{nonce_elements:?}
        push.{mac_key_elements:?}

        exec.aead_eidos::auth_empty_ad_expanded

        push.{expected_tag_0}
        assert_eq.err=\"tag0 must match for a valid block range\"
        push.{expected_tag_1}
        assert_eq.err=\"tag1 must match for a valid block range\"
    end
    "
    );

    build_test!(source.as_str(), &[]).expect_stack(&[]);
}

fn assert_block_auth_rejected(case: &str, ct_ptr: u64, num_blocks: u64) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([16, 32, 48, 64]);
    let nonce_elements = nonce.into_elements();
    let mac_key_elements = derive_mac_key(key, nonce).into_elements();

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{num_blocks}
        push.{ct_ptr}
        push.{nonce_elements:?}
        push.{mac_key_elements:?}

        exec.aead_eidos::auth_empty_ad_expanded
    end
    "
    );

    assert!(build_test!(source.as_str(), &[]).execute().is_err(), "{case} must be rejected");
}

fn assert_auth_rejected(case: &str, ct_ptr: u64, ciphertext_len: u64, scratch_ptr: u64) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([16, 32, 48, 64]);
    let nonce_elements = nonce.into_elements();
    let mac_key_elements = derive_mac_key(key, nonce).into_elements();

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{scratch_ptr}
        push.{ciphertext_len}
        push.{ct_ptr}
        push.{nonce_elements:?}
        push.{mac_key_elements:?}

        exec.aead_eidos::auth_empty_ad_expanded_with_scratch
    end
    "
    );

    assert!(build_test!(source.as_str(), &[]).execute().is_err(), "{case} must be rejected");
}

fn assert_auth_local_frame_rejected(ct_ptr: u64, ciphertext_len: u64, scratch_ptr: u64) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([16, 32, 48, 64]);
    let nonce_elements = nonce.into_elements();
    let mac_key_elements = derive_mac_key(key, nonce).into_elements();

    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.{scratch_ptr}
        push.{ciphertext_len}
        push.{ct_ptr}
        push.{nonce_elements:?}
        push.{mac_key_elements:?}

        exec.aead_eidos::auth_empty_ad_expanded_with_scratch
    end
    "
    );

    let test = build_test!(source.as_str(), &[]);
    expect_assert_error_code_from_msg!(test, "AEAD memory ranges must stay below the local frame");
}

struct PlaintextHandler(Vec<Felt>);

impl EventHandler for PlaintextHandler {
    fn on_event(&self, _process: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(vec![AdviceMutation::extend_advice_stack_with(self.0.clone())])
    }
}

struct CountingHandler(Arc<AtomicUsize>);

impl EventHandler for CountingHandler {
    fn on_event(&self, _process: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }
}
