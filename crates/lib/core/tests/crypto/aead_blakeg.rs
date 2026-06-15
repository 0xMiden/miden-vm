use miden_core::chiplets::blakeg;
use miden_crypto::{
    Felt, Word,
    hash::eidos::aead_ref::{
        auth_tag_expanded, derive_ctr_key, derive_mac_key, encrypt_felts_expanded,
    },
};
use miden_utils_testing::AdviceStackBuilder;

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

#[test]
fn derive_ctr_key_matches_reference() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let key_elements = key.into_elements();
    let nonce_elements = nonce.into_elements();
    let ctr_key_elements = derive_ctr_key(key, nonce).into_elements();

    let source = format!(
        "
    use miden::core::crypto::aead_blakeg

    begin
        push.{nonce_elements:?}
        push.{key_elements:?}
        exec.aead_blakeg::derive_ctr_key

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
    use miden::core::crypto::aead_blakeg

    begin
        push.{nonce_elements:?}
        push.{key_elements:?}
        exec.aead_blakeg::derive_mac_key

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
    use miden::core::crypto::aead_blakeg

    begin
        push.0
        push.{DST_PTR}
        push.{nonce_elements:?}
        push.{mac_key_elements:?}

        exec.aead_blakeg::auth_empty_ad_expanded

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
    use miden::core::crypto::aead_blakeg

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

        exec.aead_blakeg::auth_empty_ad_expanded

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
    use miden::core::crypto::aead_blakeg

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

        exec.aead_blakeg::encrypt_blocks_stream

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
fn encrypt_blocks_stream_three_blocks_matches_reference_vector() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let plaintext = stream_plaintext_three_blocks();

    let ctr_key = derive_ctr_key(key, nonce);
    let ctr_key_elements = ctr_key.into_elements();
    let ciphertext = encrypt_felts_expanded_xof(ctr_key, &plaintext);
    let expected_memory = felts_to_u64(&ciphertext);
    let plaintext_0 = &plaintext[..4];
    let plaintext_1 = &plaintext[4..8];
    let plaintext_2 = &plaintext[8..12];
    let plaintext_3 = &plaintext[12..16];
    let plaintext_4 = &plaintext[16..20];
    let plaintext_5 = &plaintext[20..];

    let source = format!(
        "
    use miden::core::crypto::aead_blakeg

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

        exec.aead_blakeg::encrypt_blocks_stream

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
        let ciphertext = encrypt_felts_expanded_xof(ctr_key, &plaintext);
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
    use miden::core::crypto::aead_blakeg

    begin
        {stores}

        push.{num_blocks}
        push.{COUNTER}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{ctr_key_elements:?}

        exec.aead_blakeg::encrypt_blocks_stream

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
        let ciphertext = encrypt_felts_expanded_xof(ctr_key, &plaintext);
        let expected_counter = COUNTER + (num_felts + 7) / 8;
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
    use miden::core::crypto::aead_blakeg

    begin
        {zero_memory_setup}
        {stores}

        push.{num_felts}
        push.{COUNTER}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{ctr_key_elements:?}

        exec.aead_blakeg::encrypt_felts_expanded

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
fn auth_empty_ad_expanded_with_scratch_matches_reference_for_exact_lengths() {
    for num_felts in [0_usize, 1, 2, 4, 5, 8, 9, 13, 16, 24, 31, 64] {
        let key = word([1, 2, 3, 4]);
        let nonce = word([0x10, 0x20, 0x30, 0x40]);
        let nonce_elements = nonce.into_elements();
        let mac_key_elements = derive_mac_key(key, nonce).into_elements();
        let plaintext = stream_plaintext_felts(num_felts);
        let ctr_key = derive_ctr_key(key, nonce);
        let ciphertext = encrypt_felts_expanded_xof(ctr_key, &plaintext);
        let stores = store_felts(DST_PTR, &ciphertext);
        let expected_tag = auth_tag_expanded(key, nonce, &[], &ciphertext);
        let expected_tag_0 = expected_tag[0].as_canonical_u64();
        let expected_tag_1 = expected_tag[1].as_canonical_u64();

        let source = format!(
            "
    use miden::core::crypto::aead_blakeg

    begin
        {stores}

        push.{SCRATCH_PTR}
        push.{ciphertext_len}
        push.{DST_PTR}
        push.{nonce_elements:?}
        push.{mac_key_elements:?}

        exec.aead_blakeg::auth_empty_ad_expanded_with_scratch

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
fn decrypt_empty_ad_accepts_valid_ciphertext_for_exact_lengths() {
    for num_felts in [0_usize, 1, 5, 8, 13, 16, 32, 64] {
        let key = word([1, 2, 3, 4]);
        let nonce = word([0x10, 0x20, 0x30, 0x40]);
        let key_elements = key.into_elements();
        let nonce_elements = nonce.into_elements();
        let plaintext = stream_plaintext_felts(num_felts);
        let ctr_key = derive_ctr_key(key, nonce);
        let mut ciphertext_and_tag = encrypt_felts_expanded_xof(ctr_key, &plaintext);
        let tag = auth_tag_expanded(key, nonce, &[], &ciphertext_and_tag);
        ciphertext_and_tag.extend(tag);

        let input_stores = store_felts(SRC_PTR, &ciphertext_and_tag);
        let advice_stack = advice_stack_for_memory_load(&plaintext);
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
    use miden::core::crypto::aead_blakeg

    begin
        {zero_memory_setup}
        {input_stores}

        push.{SCRATCH_PTR}
        push.{num_felts}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}

        exec.aead_blakeg::decrypt_empty_ad
    end
    "
        );

        let test = build_test!(source.as_str(), &[], &advice_stack);
        test.check_constraints();
        test.expect_stack_and_memory(&[], DST_PTR as u32, &expected_memory);
    }
}

#[test]
fn decrypt_empty_ad_rejects_forged_ciphertext() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let key_elements = key.into_elements();
    let nonce_elements = nonce.into_elements();
    let plaintext = stream_plaintext_felts(5);
    let ctr_key = derive_ctr_key(key, nonce);
    let ciphertext = encrypt_felts_expanded_xof(ctr_key, &plaintext);
    let tag = auth_tag_expanded(key, nonce, &[], &ciphertext);

    let mut forged = ciphertext;
    forged[0] += Felt::ONE;
    forged.extend(tag);

    let input_stores = store_felts(SRC_PTR, &forged);
    let advice_stack = advice_stack_for_memory_load(&plaintext);
    let source = format!(
        "
    use miden::core::crypto::aead_blakeg

    begin
        {input_stores}

        push.{SCRATCH_PTR}
        push.5
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}

        exec.aead_blakeg::decrypt_empty_ad
    end
    "
    );

    let test = build_test!(source.as_str(), &[], &advice_stack);
    assert!(test.execute().is_err());
}

#[test]
fn decrypt_empty_ad_rejects_forged_plaintext_advice() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let key_elements = key.into_elements();
    let nonce_elements = nonce.into_elements();
    let plaintext = stream_plaintext_felts(5);
    let ctr_key = derive_ctr_key(key, nonce);
    let mut ciphertext_and_tag = encrypt_felts_expanded_xof(ctr_key, &plaintext);
    let tag = auth_tag_expanded(key, nonce, &[], &ciphertext_and_tag);
    ciphertext_and_tag.extend(tag);

    let mut forged_plaintext = plaintext;
    forged_plaintext[0] += Felt::ONE;
    let input_stores = store_felts(SRC_PTR, &ciphertext_and_tag);
    let advice_stack = advice_stack_for_memory_load(&forged_plaintext);
    let source = format!(
        "
    use miden::core::crypto::aead_blakeg

    begin
        {input_stores}

        push.{SCRATCH_PTR}
        push.5
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}

        exec.aead_blakeg::decrypt_empty_ad
    end
    "
    );

    let test = build_test!(source.as_str(), &[], &advice_stack);
    assert!(test.execute().is_err());
}

#[test]
fn decrypt_empty_ad_rejects_forged_tag() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let key_elements = key.into_elements();
    let nonce_elements = nonce.into_elements();
    let plaintext = stream_plaintext_felts(5);
    let ctr_key = derive_ctr_key(key, nonce);
    let mut ciphertext = encrypt_felts_expanded_xof(ctr_key, &plaintext);
    let mut tag = auth_tag_expanded(key, nonce, &[], &ciphertext);
    tag[0] += Felt::ONE;
    ciphertext.extend(tag);

    let input_stores = store_felts(SRC_PTR, &ciphertext);
    let advice_stack = advice_stack_for_memory_load(&plaintext);
    let source = format!(
        "
    use miden::core::crypto::aead_blakeg

    begin
        {input_stores}

        push.{SCRATCH_PTR}
        push.5
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}

        exec.aead_blakeg::decrypt_empty_ad
    end
    "
    );

    let test = build_test!(source.as_str(), &[], &advice_stack);
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
    use miden::core::crypto::aead_blakeg

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

        exec.aead_blakeg::auth_empty_ad_expanded

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

    let ctr_key = derive_ctr_key(key, nonce);
    let ciphertext = encrypt_felts_expanded_xof(ctr_key, &plaintext);
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
    use miden::core::crypto::aead_blakeg

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
        exec.aead_blakeg::derive_ctr_key
        exec.aead_blakeg::encrypt_blocks_stream
        dropw drop drop drop

        push.{SIX_BLOCKS}
        push.{DST_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}
        exec.aead_blakeg::derive_mac_key
        push.{nonce_elements:?}
        swapw
        exec.aead_blakeg::auth_empty_ad_expanded

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
    values.iter().map(|felt| felt.as_canonical_u64()).collect()
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
    let mut chunks = values.chunks_exact(4);

    for (word_idx, word) in chunks.by_ref().enumerate() {
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
    for (offset, felt) in chunks.remainder().iter().enumerate() {
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

fn advice_stack_for_memory_load(values: &[Felt]) -> Vec<u64> {
    let mut builder = AdviceStackBuilder::new();
    builder.push_elements(values.iter().copied());
    builder.build_vec_u64()
}

fn encrypt_felts_expanded_xof(ctr_key: Word, plaintext: &[Felt]) -> Vec<Felt> {
    let ctr_key = ctr_key.into_elements();
    let mut ciphertext = Vec::with_capacity(plaintext.len() * 2);

    for (counter, chunk) in plaintext.chunks(8).enumerate() {
        let state = [
            Felt::from_u32(counter as u32),
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            ctr_key[0],
            ctr_key[1],
            ctr_key[2],
            ctr_key[3],
        ];
        let keystream = blakeg::compress_raw_xof_lanes(&state);
        for (i, felt) in chunk.iter().enumerate() {
            let value = felt.as_canonical_u64();
            let lo = value as u32;
            let hi = (value >> 32) as u32;
            ciphertext.push(Felt::from_u32(lo ^ keystream[2 * i]));
            ciphertext.push(Felt::from_u32(hi ^ keystream[2 * i + 1]));
        }
    }

    ciphertext
}
