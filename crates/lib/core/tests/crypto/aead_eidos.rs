use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use miden_core::{FMP_INIT_VALUE, program::StackOutputs};
use miden_core_lib::{CoreLibrary, handlers::aead_eidos::AEAD_EIDOS_DECRYPT_EVENT_NAME};
use miden_crypto::{
    Felt, Word,
    aead::aead_eidos::expanded::{
        auth_tag_expanded, derive_ctr_key, derive_mac_key, encrypt_felts_expanded,
    },
};
use miden_processor::{
    ExecutionError, ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventHandler},
    operation::OperationError,
};
use miden_utils_testing::Test;

const SRC_PTR: u64 = 1000;
const DST_PTR: u64 = 2000;
const SCRATCH_PTR: u64 = 3000;
const COUNTER: u64 = 0;
const U32_ADDRESS_SPACE_END: u64 = 1_u64 << 32;
const FIRST_UNSUPPORTED_AUTH_PLAINTEXT_LEN: u64 = (1 << 27) - 2;

#[test]
fn authenticated_round_trips_match_rust() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([16, 32, 48, 64]);
    for pt_len in (0..=9).chain([65]) {
        for ad_len in (0..=9).chain([70]) {
            let plaintext = stream_plaintext_felts(pt_len);
            let ad = stream_plaintext_felts(ad_len);
            let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
            let [t0, t1] = auth_tag_expanded(key, nonce, &ad, &ciphertext);
            // Exercise both empty-AD wrappers and the explicit empty-AD interface.
            let empty_wrapper = ad_len == 0 && pt_len % 2 == 0;
            let encrypt_args = if empty_wrapper {
                format!("push.2000.{pt_len}.1000")
            } else {
                format!("push.2000.{ad_len}.4000.{pt_len}.1000")
            };
            let decrypt_args = if empty_wrapper {
                format!("push.{t1}.{t0}.3000.{pt_len}.5000.2000")
            } else {
                format!("push.{t1}.{t0}.{ad_len}.4000.3000.{pt_len}.5000.2000")
            };
            let suffix = if empty_wrapper { "" } else { "_with_ad" };
            let source = format!(
                "use miden::core::crypto::aead_eidos
                begin
                    {}{}
                    push.91.92.93.94
                    {encrypt_args} push.{nonce:?} push.{key:?}
                    exec.aead_eidos::encrypt{suffix}
                    push.{t0} assert_eq push.{t1} assert_eq
                    {decrypt_args} push.{nonce:?} push.{key:?}
                    exec.aead_eidos::decrypt{suffix}
                    push.91.92.93.94 assert_eqw
                end",
                store_felts(1000, &plaintext),
                store_felts(4000, &ad),
                nonce = nonce.into_elements(),
                key = key.into_elements(),
            );
            let test = build_test!(&source, &[]);
            let (output, _) = test.execute_for_output().unwrap();
            assert_eq!(output.stack.get_num_elements(16), &[Felt::ZERO; 16]);
            for (ptr, expected) in [(2000, &ciphertext), (5000, &plaintext), (4000, &ad)] {
                for (i, &value) in expected.iter().enumerate() {
                    assert_eq!(
                        output
                            .memory
                            .read_element(0_u32.into(), Felt::from_u32(ptr + i as u32))
                            .unwrap(),
                        value,
                        "pt_len={pt_len}, ad_len={ad_len}, address={}",
                        ptr + i as u32
                    );
                }
            }
            if (pt_len, ad_len) == (9, 7) {
                test.check_constraints();
                test.prove_and_verify(vec![], false);
            }
        }
    }
}

#[test]
fn decrypt_rejects_modified_authenticated_inputs_before_event() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([16, 32, 48, 64]);
    let plaintext = stream_plaintext_felts(9);
    let original_ad = stream_plaintext_felts(7);
    let original_ct = encrypt_felts_expanded(key, nonce, &plaintext);
    let original_tag = auth_tag_expanded(key, nonce, &original_ad, &original_ct);
    for changed in ["key", "nonce", "ad", "ad length", "ciphertext", "tag0", "tag1"] {
        let mut key = key.into_elements();
        let mut nonce = nonce.into_elements();
        let mut ad = original_ad.clone();
        let mut ct = original_ct.clone();
        let mut tag = original_tag;
        match changed {
            "key" => key[0] += Felt::ONE,
            "nonce" => nonce[0] += Felt::ONE,
            "ad" => ad[0] += Felt::ONE,
            "ad length" => ad.push(Felt::ZERO),
            "ciphertext" => ct[0] += Felt::ONE,
            "tag0" => tag[0] += Felt::ONE,
            "tag1" => tag[1] += Felt::ONE,
            _ => unreachable!(),
        }
        let source = format!(
            "use miden::core::crypto::aead_eidos
            begin
                {}{}
                push.{}.{}.{}.4000.3000.9.2000.1000
                push.{nonce:?} push.{key:?}
                exec.aead_eidos::decrypt_with_ad
            end",
            store_felts(1000, &ct),
            store_felts(4000, &ad),
            tag[1],
            tag[0],
            ad.len(),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let test = miden_utils_testing::build_test_by_mode!(false, source.as_str(), &[])
            .with_library(CoreLibrary::default().package())
            .with_event_handler(AEAD_EIDOS_DECRYPT_EVENT_NAME, CountingHandler(Arc::clone(&calls)));
        assert_aead_error(changed, &test, "AEAD tag mismatch");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "{changed}");
    }
}

#[test]
fn aead_public_surface_contains_only_authenticated_operations() {
    let package = CoreLibrary::default().package();
    for name in ["encrypt", "encrypt_with_ad", "decrypt", "decrypt_with_ad"] {
        assert!(
            package
                .get_procedure_root_by_path(
                    format!("::miden::core::crypto::aead_eidos::{name}").as_str()
                )
                .is_some()
        );
    }
    for name in [
        "derive_ctr_key",
        "derive_mac_key",
        "encrypt_felts_expanded",
        "encrypt_blocks_stream",
        "auth_expanded_exact",
        "auth_empty_ad_expanded_exact",
        "auth_empty_ad_expanded",
        "decrypt_empty_ad",
    ] {
        assert!(
            package
                .get_procedure_root_by_path(
                    format!("::miden::core::crypto::aead_eidos::{name}").as_str()
                )
                .is_none()
        );
    }
    assert!(
        package
            .manifest
            .get_module(miden_assembly::Path::new("::miden::core::crypto::aead_eidos::primitives"))
            .is_none()
    );
}

#[test]
fn authenticated_operations_reject_invalid_ad_before_event() {
    let frame = FMP_INIT_VALUE.as_canonical_u64();
    for (ad_ptr, ad_len, message) in [
        (4001, 0, "AEAD pointer must be word-aligned"),
        (1 << 32, 0, "AEAD pointer must fit in a u32"),
        (4000, 1_u64 << 32, "AEAD associated-data length must fit in a u32"),
        (4000, (1 << 28) - 21, "AEAD authentication input exceeds its supported length"),
        (frame, 1, "AEAD memory ranges must stay below the local frame"),
        ((1_u64 << 32) - 4, 8, "AEAD memory range exceeds the u32 address space"),
        (2000, 1, "AEAD memory ranges must not overlap"),
        (1996, 8, "AEAD memory ranges must not overlap"),
    ] {
        for (procedure, arguments) in [
            ("encrypt_with_ad", format!("push.2000.{ad_len}.{ad_ptr}.8.1000")),
            ("decrypt_with_ad", format!("push.0.0.{ad_len}.{ad_ptr}.3000.8.2000.1000")),
        ] {
            let source = format!(
                "use miden::core::crypto::aead_eidos
                begin
                    {arguments} push.[16,32,48,64] push.[1,2,3,4]
                    exec.aead_eidos::{procedure}
                end"
            );
            let calls = Arc::new(AtomicUsize::new(0));
            let test = miden_utils_testing::build_test_by_mode!(false, source.as_str(), &[])
                .with_library(CoreLibrary::default().package())
                .with_event_handler(
                    AEAD_EIDOS_DECRYPT_EVENT_NAME,
                    CountingHandler(Arc::clone(&calls)),
                );
            assert_aead_error(procedure, &test, message);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
    let source = "use miden::core::crypto::aead_eidos
        begin
            push.0.0.1.3000.3000.8.2000.1000 push.[16,32,48,64] push.[1,2,3,4]
            exec.aead_eidos::decrypt_with_ad
        end";
    assert_aead_error(
        "AD overlaps scratch",
        &build_test!(source, &[]),
        "AEAD memory ranges must not overlap",
    );
}

#[test]
fn associated_data_may_overlap_read_only_input() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([16, 32, 48, 64]);
    let plaintext = stream_plaintext_felts(8);
    let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
    let encryption_tag = auth_tag_expanded(key, nonce, &plaintext[..3], &ciphertext);
    let decryption_tag = auth_tag_expanded(key, nonce, &ciphertext[..3], &ciphertext);
    let source = format!(
        "use miden::core::crypto::aead_eidos
        begin
            {}
            push.2000.3.1000.8.1000 push.{nonce:?} push.{key:?}
            exec.aead_eidos::encrypt_with_ad
            push.{} assert_eq push.{} assert_eq
            push.{}.{}.3.2000.3000.8.5000.2000 push.{nonce:?} push.{key:?}
            exec.aead_eidos::decrypt_with_ad
        end",
        store_felts(1000, &plaintext),
        encryption_tag[0],
        encryption_tag[1],
        decryption_tag[1],
        decryption_tag[0],
        nonce = nonce.into_elements(),
        key = key.into_elements(),
    );
    build_test!(&source, &[]).expect_stack_and_memory(&[], 5000, &felts_to_u64(&plaintext));
}

#[test]
fn auth_general_ad_matches_rust_across_segment_boundaries() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let mac_key = derive_mac_key(key, nonce).into_elements();
    let nonce_elements = nonce.into_elements();
    let mac_frame = FMP_INIT_VALUE.as_canonical_u64();
    let check_caller = (1..=32)
        .rev()
        .map(|value| format!("push.{value} assert_eq.err=\"caller stack\"\n"))
        .collect::<String>();
    // Every residue modulo eight, plus enough data to exercise the unrolled stream loop.
    for ad_len in (0..=9).chain([70]) {
        // Completing the nonce/AD batch advances the ciphertext by three, two, or one Felts.
        // Include 7/8/9 remaining Felts at each unaligned bulk-entry boundary; shorter lengths
        // are already covered by the common cases.
        let boundary_lengths: &[u32] = match ad_len {
            1 => &[10, 11, 12],
            2 => &[10, 11],
            3 => &[10],
            _ => &[],
        };
        for ct_len in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 70]
            .into_iter()
            .chain(boundary_lengths.iter().copied())
        {
            let ad = stream_plaintext_felts(ad_len);
            let ct: Vec<_> = (0..ct_len).map(|i| Felt::from_u32(i * 31)).collect();
            let [t0, t1] = auth_tag_expanded(key, nonce, &ad, &ct);
            let stores = format!(
                "{}{}{}{}",
                store_felts(SRC_PTR, &ad),
                store_sentinels(SRC_PTR + ad_len as u64, 501),
                store_felts(DST_PTR, &ct),
                store_sentinels(DST_PTR + u64::from(ct_len), 601),
            );
            let source = format!(
                "use test::aead_primitives
                begin
                    {stores}
                    # The pending-batch buffer can contain data from an earlier call.
                    push.777.777.777.777
                    push.{mac_frame} add.8 mem_storew_le
                    push.{mac_frame} add.12 mem_storew_le dropw
                    push.1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16
                    push.17.18.19.20.21.22.23.24.25.26.27.28.29.30.31.32
                    push.{ct_len}.{DST_PTR}.{ad_len}.{SRC_PTR}
                    push.{nonce_elements:?} push.{mac_key:?}
                    exec.aead_primitives::auth_expanded_exact
                    push.{t0} assert_eq push.{t1} assert_eq
                    {check_caller}

                    push.{mac_frame}
                    repeat.4
                        padw dup.4 mem_loadw_le padw
                        assert_eqw.err=\"MAC locals must be cleared\"
                        add.4
                    end
                    drop
                end"
            );
            let trace = build_primitives_test(&source).execute().unwrap();
            assert_eq!(trace.last_stack_state(), StackOutputs::default());
            if (ad_len, ct_len) == (7, 9) {
                miden_vm_stark::debug::check_constraints(&trace);
            }
        }
    }
}

#[test]
fn key_derivations_match_reference() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([16, 32, 48, 64]);
    for (procedure, expected) in [
        ("derive_ctr_key", derive_ctr_key(key, nonce)),
        ("derive_mac_key", derive_mac_key(key, nonce)),
    ] {
        let source = format!(
            "use test::aead_primitives
            begin
                push.{:?} push.{:?}
                exec.aead_primitives::{procedure}
                push.{:?} assert_eqw
            end",
            nonce.into_elements(),
            key.into_elements(),
            expected.into_elements(),
        );
        build_primitives_test(&source).expect_stack(&[]);
    }
}

#[test]
fn auth_empty_ad_binds_the_final_coefficient_to_the_evaluation_point() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let nonce_elements = nonce.into_elements();
    let mac_key_elements = derive_mac_key(key, nonce).into_elements();

    // These inputs have the same padded length. Their encoded streams agree until the final
    // extension coefficient, which changes from (0, 0) to (0, 10).
    let extended_ciphertext = [
        Felt::from_u32(1),
        Felt::from_u32(2),
        Felt::from_u32(3),
        Felt::from_u32(4),
        Felt::ZERO,
        Felt::from_u32(4),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];
    let stores = store_felts(DST_PTR, &extended_ciphertext);

    let source = format!(
        "
    use test::aead_primitives

    begin
        {stores}

        push.4
        push.{DST_PTR}
        push.{nonce_elements:?}
        push.{mac_key_elements:?}

        exec.aead_primitives::auth_empty_ad_expanded_exact

        push.10
        push.{DST_PTR}
        push.{nonce_elements:?}
        push.{mac_key_elements:?}

        exec.aead_primitives::auth_empty_ad_expanded_exact

        dup.2
        eq
        movup.2
        drop
        movup.2
        add.10
        movup.2
        eq
        and
        assertz.err=\"the final MAC coefficient must be multiplied by the evaluation point\"
    end
    "
    );

    build_primitives_test(&source).expect_stack(&[]);
}

#[test]
fn stream_encryption_matches_rust_at_block_and_tail_boundaries() {
    // Include every tail length and the unrolled loop's short and long block counts.
    for num_felts in (0..=9).chain([13, 16, 17, 32, 40, 56, 64, 104, 128]) {
        assert_stream_encryption(num_felts, "");
    }
}

#[test]
fn stream_encryption_after_u32and_matches_reference() {
    // A bitwise row before the stream must not disturb its period-eight trace alignment.
    assert_stream_encryption(24, "push.1 push.1 u32and drop");
}

#[test]
fn stream_encryption_reject_cross_block_overlap() {
    // The first block sees adjacent ranges, but its output would overwrite the next input block.
    assert_encrypt_rejected(1000, 1008, 16, "AEAD memory ranges must not overlap");

    // The aligned prefix would overwrite the ninth Felt before the tail path reads it.
    assert_encrypt_rejected(1000, 1008, 9, "AEAD memory ranges must not overlap");
}

#[test]
fn stream_encryption_accept_adjacent_and_empty_ranges() {
    // source [1000, 1016), destination [1016, 1048)
    assert_encrypt_felts_accepts_layout(1000, 1016, 16);
    // source [1000, 1012), destination [1012, 1036)
    assert_encrypt_felts_accepts_layout(1000, 1012, 12);

    // Empty source and destination ranges may begin at the same address.
    assert_encrypt_felts_accepts_layout(1000, 1000, 0);
    let local_memory_start = FMP_INIT_VALUE.as_canonical_u64();
    assert_encrypt_felts_accepts_layout(local_memory_start, local_memory_start, 0);
}

#[test]
fn stream_encryption_reject_local_memory_aliases() {
    let local_memory_start = FMP_INIT_VALUE.as_canonical_u64();

    for count in [8, 4] {
        assert_encrypt_rejected(
            local_memory_start,
            1000,
            count,
            "AEAD memory ranges must stay below the local frame",
        );
        assert_encrypt_rejected(
            1000,
            local_memory_start,
            count,
            "AEAD memory ranges must stay below the local frame",
        );
    }
}

#[test]
fn encryption_rejects_invalid_ranges_and_lengths() {
    for (src, dst, len, error) in [
        (1001, 2000, 0, "AEAD pointer must be word-aligned"),
        (1000, 2001, 0, "AEAD pointer must be word-aligned"),
        (U32_ADDRESS_SPACE_END, 2000, 0, "AEAD pointer must fit in a u32"),
        (1000, U32_ADDRESS_SPACE_END, 0, "AEAD pointer must fit in a u32"),
        (1000, 2000, U32_ADDRESS_SPACE_END, "AEAD plaintext length must fit in a u32"),
        (
            1000,
            2000,
            1_u64 << 31,
            "AEAD authentication input exceeds its supported length",
        ),
        (
            1000,
            2000,
            FIRST_UNSUPPORTED_AUTH_PLAINTEXT_LEN,
            "AEAD authentication input exceeds its supported length",
        ),
        (
            U32_ADDRESS_SPACE_END - 4,
            1000,
            5,
            "AEAD memory range exceeds the u32 address space",
        ),
        (
            1000,
            U32_ADDRESS_SPACE_END - 4,
            3,
            "AEAD memory range exceeds the u32 address space",
        ),
    ] {
        assert_encrypt_rejected(src, dst, len, error);
    }
}

#[test]
fn internal_stream_advances_past_last_counter() {
    let max_counter = u64::from(u32::MAX);
    assert_encrypt_exhausts_counter(max_counter, 1, 1, 2);
    assert_encrypt_exhausts_counter(max_counter, 8, 8, 16);
}

#[test]
fn auth_empty_ad_expanded_exact_matches_reference_for_exact_lengths() {
    // Expanded ciphertext has even length. Cover each tail with and without middle batches.
    for ciphertext_len in (0_usize..=20).step_by(2).chain([24, 26, 32, 48, 62, 64, 128]) {
        let key = word([1, 2, 3, 4]);
        let nonce = word([0x10, 0x20, 0x30, 0x40]);
        let nonce_elements = nonce.into_elements();
        let mac_key_elements = derive_mac_key(key, nonce).into_elements();
        let plaintext = stream_plaintext_felts(ciphertext_len / 2);
        let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
        // Nonzero sentinels ensure the MAC excludes values read past the ciphertext tail.
        let mut stores = store_felts(DST_PTR, &ciphertext);
        stores.push_str(&store_sentinels(DST_PTR + ciphertext_len as u64, 1001));
        let expected_tag = auth_tag_expanded(key, nonce, &[], &ciphertext);
        let expected_tag_0 = expected_tag[0].as_canonical_u64();
        let expected_tag_1 = expected_tag[1].as_canonical_u64();

        let source = format!(
            "
    use test::aead_primitives

    begin
        {stores}

        push.{ciphertext_len}
        push.{DST_PTR}
        push.{nonce_elements:?}
        push.{mac_key_elements:?}

        exec.aead_primitives::auth_empty_ad_expanded_exact

        push.{expected_tag_0}
        assert_eq.err=\"tag0 must match exact expanded MAC reference\"
        push.{expected_tag_1}
        assert_eq.err=\"tag1 must match exact expanded MAC reference\"
    end
    ",
            ciphertext_len = ciphertext.len()
        );

        let trace = build_primitives_test(&source).execute().unwrap();
        assert_eq!(trace.last_stack_state(), StackOutputs::default());
        miden_vm_stark::debug::check_constraints(&trace);
    }
}

#[test]
fn decrypt_empty_ad_accepts_valid_ciphertext_for_exact_lengths() {
    // Ciphertext lengths 2 * num_felts cover every even MAC tail with and without middle batches.
    for num_felts in [0_usize, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 16, 32, 64] {
        let key = word([1, 2, 3, 4]);
        let nonce = word([0x10, 0x20, 0x30, 0x40]);
        let key_elements = key.into_elements();
        let nonce_elements = nonce.into_elements();
        let plaintext = stream_plaintext_felts(num_felts);
        let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
        let tag = auth_tag_expanded(key, nonce, &[], &ciphertext);

        let mut input_stores = store_felts(SRC_PTR, &ciphertext);
        // The output must stop at the plaintext length, including for an empty plaintext.
        input_stores.push_str(&store_sentinels(DST_PTR + num_felts as u64, 3001));
        let mut expected_memory = felts_to_u64(&plaintext);
        expected_memory.extend(3001..3001 + SENTINEL_CELLS);

        let [tag0, tag1] = tag;
        let source = format!(
            "
    use miden::core::crypto::aead_eidos

    begin
        {input_stores}

        push.[91, 92, 93, 94]
        push.{tag1}.{tag0}
        push.{SCRATCH_PTR}
        push.{num_felts}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}

        exec.aead_eidos::decrypt

        push.[91, 92, 93, 94]
        assert_eqw.err=\"decrypt must preserve the caller's stack\"
    end
    "
        );

        let test = build_test!(&source, &[]);
        test.check_constraints();
        test.expect_stack_and_memory(&[], DST_PTR as u32, &expected_memory);
    }
}

#[test]
fn decrypt_empty_ad_rejects_overlapping_regions_before_event() {
    let cases = [
        ("source and destination are identical", 1000, 1000, 3000),
        ("destination starts inside source", 1000, 1004, 3000),
        ("source starts inside destination", 1000, 996, 3000),
        ("source and workspace are identical", 1000, 2000, 1000),
        ("workspace starts inside source", 1000, 2000, 1004),
        ("source starts inside workspace", 1000, 2000, 996),
        ("destination and workspace are identical", 1000, 2000, 2000),
        ("workspace starts inside destination", 1000, 2000, 2004),
        ("destination starts inside workspace", 1000, 2000, 1996),
    ];

    for (case, src_ptr, dst_ptr, scratch_ptr) in cases {
        assert_decrypt_rejected_before_event(
            case,
            src_ptr,
            dst_ptr,
            8,
            scratch_ptr,
            "AEAD memory ranges must not overlap",
        );
    }
}

#[test]
fn decrypt_empty_ad_accepts_adjacent_regions() {
    // workspace [984, 994), source [1000, 1010), destination [1012, 1017)
    assert_decrypt_accepts_layout(1000, 1012, 5, 984);

    // destination [2000, 2008), workspace [2008, 2024)
    assert_decrypt_accepts_layout(1000, 2000, 8, 2008);
}

#[test]
fn decrypt_empty_ad_rejects_local_memory_aliases() {
    let local_memory_start = FMP_INIT_VALUE.as_canonical_u64();
    let cases = [
        ("source aliases procedure-local memory", local_memory_start, 1000, 2000),
        ("destination aliases procedure-local memory", 1000, local_memory_start, 2000),
        ("workspace aliases procedure-local memory", 1000, 2000, local_memory_start),
    ];

    for (case, src_ptr, dst_ptr, scratch_ptr) in cases {
        assert_decrypt_rejected_before_event(
            case,
            src_ptr,
            dst_ptr,
            1,
            scratch_ptr,
            "AEAD memory ranges must stay below the local frame",
        );
    }
}

#[test]
fn decrypt_empty_ad_handles_empty_destination_range() {
    // All three memory ranges are empty; the authentication tag is supplied on the stack.
    assert_decrypt_accepts_layout(1000, 1000, 0, 2000);
    assert_decrypt_accepts_layout(1000, 2000, 0, 2000);
    assert_decrypt_accepts_layout(1000, 2000, 0, 1000);
    assert_decrypt_accepts_layout(1000, FMP_INIT_VALUE.as_canonical_u64(), 0, 2000);
}

#[test]
fn decrypt_empty_ad_rejects_invalid_ranges_before_event() {
    let cases = [
        ("misaligned source", 1001, 2000, 8, 3000, "AEAD pointer must be word-aligned"),
        (
            "misaligned destination",
            1000,
            2001,
            8,
            3000,
            "AEAD pointer must be word-aligned",
        ),
        ("misaligned workspace", 1000, 2000, 8, 3001, "AEAD pointer must be word-aligned"),
        (
            "source pointer exceeds u32",
            U32_ADDRESS_SPACE_END,
            2000,
            0,
            3000,
            "AEAD pointer must fit in a u32",
        ),
        (
            "destination pointer exceeds u32",
            1000,
            U32_ADDRESS_SPACE_END,
            0,
            3000,
            "AEAD pointer must fit in a u32",
        ),
        (
            "workspace pointer exceeds u32",
            1000,
            2000,
            0,
            U32_ADDRESS_SPACE_END,
            "AEAD pointer must fit in a u32",
        ),
        (
            "plaintext length exceeds u32",
            1000,
            2000,
            U32_ADDRESS_SPACE_END,
            3000,
            "AEAD plaintext length must fit in a u32",
        ),
        (
            "authentication input exceeds the supported length",
            1000,
            2000,
            FIRST_UNSUPPORTED_AUTH_PLAINTEXT_LEN,
            3000,
            "AEAD authentication input exceeds its supported length",
        ),
        (
            "source end overflows",
            U32_ADDRESS_SPACE_END - 4,
            1000,
            3,
            2000,
            "AEAD memory range exceeds the u32 address space",
        ),
        (
            "destination end overflows",
            1000,
            U32_ADDRESS_SPACE_END - 4,
            8,
            2000,
            "AEAD memory range exceeds the u32 address space",
        ),
        (
            "workspace end overflows",
            1000,
            2000,
            8,
            U32_ADDRESS_SPACE_END - 4,
            "AEAD memory range exceeds the u32 address space",
        ),
    ];

    for (case, src_ptr, dst_ptr, num_felts, scratch_ptr, expected_error) in cases {
        assert_decrypt_rejected_before_event(
            case,
            src_ptr,
            dst_ptr,
            num_felts,
            scratch_ptr,
            expected_error,
        );
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

    let input_stores = store_felts(SRC_PTR, &forged);
    let [tag0, tag1] = tag;
    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        {input_stores}

        push.{tag1}.{tag0}
        push.{SCRATCH_PTR}
        push.5
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}

        exec.aead_eidos::decrypt
    end
    "
    );

    let test = build_test!(&source, &[]);
    assert_aead_error("forged ciphertext", &test, "AEAD tag mismatch");
}

#[test]
fn decrypt_empty_ad_rejects_forged_plaintext_advice() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let key_elements = key.into_elements();
    let nonce_elements = nonce.into_elements();
    let core_lib = CoreLibrary::default();

    for num_felts in [1_u64, 2, 3, 4, 7, 8, 9, 16, 17] {
        let plaintext: Vec<_> =
            (0..num_felts).map(|i| Felt::new(((i + 1) << 32) | (i + 17)).unwrap()).collect();
        let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
        let tag = auth_tag_expanded(key, nonce, &[], &ciphertext);

        let input_stores = store_felts(SRC_PTR, &ciphertext);
        let [tag0, tag1] = tag;
        let source = format!(
            "
    use miden::core::crypto::aead_eidos

    begin
        {input_stores}

        push.{tag1}.{tag0}
        push.{SCRATCH_PTR}
        push.{num_felts}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}

        exec.aead_eidos::decrypt
    end
    "
        );

        let mut test = miden_utils_testing::build_test_by_mode!(false, source.as_str(), &[])
            .with_library(core_lib.package());

        // Each bit flip changes exactly one ciphertext limb under XOR encryption. Check both
        // limbs of every plaintext Felt, including each position in full batches and tails.
        for index in 0..plaintext.len() {
            for (limb, mask) in [1, 1_u64 << 32].into_iter().enumerate() {
                let mut forged_plaintext = plaintext.clone();
                forged_plaintext[index] =
                    Felt::new(plaintext[index].as_canonical_u64() ^ mask).unwrap();
                test.handlers.clear();
                test.add_event_handler(
                    AEAD_EIDOS_DECRYPT_EVENT_NAME,
                    PlaintextHandler(forged_plaintext),
                );
                assert_aead_error(
                    &format!("plaintext length {num_felts}, ciphertext limb {}", 2 * index + limb),
                    &test,
                    "AEAD ciphertext mismatch",
                );
            }
        }
    }
}

#[test]
fn decrypt_empty_ad_rejects_forged_tag() {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let key_elements = key.into_elements();
    let nonce_elements = nonce.into_elements();
    let plaintext = stream_plaintext_felts(5);
    let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
    let mut tag = auth_tag_expanded(key, nonce, &[], &ciphertext);
    tag[0] += Felt::ONE;

    let input_stores = store_felts(SRC_PTR, &ciphertext);
    let [tag0, tag1] = tag;
    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        {input_stores}

        push.{tag1}.{tag0}
        push.{SCRATCH_PTR}
        push.5
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}

        exec.aead_eidos::decrypt
    end
    "
    );

    let core_lib = CoreLibrary::default();
    let test = miden_utils_testing::build_test_by_mode!(false, source.as_str(), &[])
        .with_library(core_lib.package())
        .with_event_handler(AEAD_EIDOS_DECRYPT_EVENT_NAME, PlaintextHandler(plaintext));
    assert_aead_error("forged tag", &test, "AEAD tag mismatch");
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
    let stores = store_felts(SRC_PTR, &plaintext);

    let plaintext_len = plaintext.len();
    let ciphertext_len = ciphertext.len();
    let source = format!(
        "
    use test::aead_primitives

    begin
        {stores}

        push.{plaintext_len}
        push.{COUNTER}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}
        exec.aead_primitives::derive_ctr_key
        exec.aead_primitives::encrypt_felts_expanded
        dropw drop drop drop

        push.{ciphertext_len}
        push.{DST_PTR}
        push.{nonce_elements:?}
        push.{key_elements:?}
        exec.aead_primitives::derive_mac_key
        push.{nonce_elements:?}
        swapw
        exec.aead_primitives::auth_empty_ad_expanded_exact

        push.{expected_tag_0}
        assert_eq.err=\"tag0 must match Rust reference\"
        push.{expected_tag_1}
        assert_eq.err=\"tag1 must match Rust reference\"
    end
    "
    );

    let test = build_primitives_test(&source);
    test.check_constraints();
    test.expect_stack_and_memory(&[], DST_PTR as u32, &expected_memory);
}

#[track_caller]
fn assert_stream_encryption(num_felts: u64, before_encrypt: &str) {
    let tail_frame = FMP_INIT_VALUE.as_canonical_u64();
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let ctr_key = derive_ctr_key(key, nonce);
    let ctr_key_elements = ctr_key.into_elements();
    let plaintext = stream_plaintext_felts(num_felts as usize);
    let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
    let expected_counter = COUNTER + num_felts.div_ceil(8);
    let expected_src = SRC_PTR + num_felts;
    let expected_dst = DST_PTR + 2 * num_felts;

    // Sentinels after the plaintext must not affect the ciphertext. Sentinels after the output
    // must remain unchanged after the tail copy.
    let mut stores = store_felts(SRC_PTR, &plaintext);
    stores.push_str(&store_sentinels(SRC_PTR + num_felts, 1001));
    stores.push_str(&store_sentinels(DST_PTR + 2 * num_felts, 2001));
    let mut expected_memory = felts_to_u64(&ciphertext);
    expected_memory.extend(2001..2001 + SENTINEL_CELLS);
    let scratch_check = if num_felts.is_multiple_of(8) {
        String::new()
    } else {
        format!(
            "push.{tail_frame}
                repeat.6
                    padw dup.4 mem_loadw_le padw
                    assert_eqw.err=\"tail scratch must be cleared\"
                    add.4
                end
                drop"
        )
    };

    let source = format!(
        "
    use test::aead_primitives

    begin
        {stores}

        push.{num_felts}
        push.{COUNTER}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{ctr_key_elements:?}

        {before_encrypt}
        exec.aead_primitives::encrypt_felts_expanded

        push.{ctr_key_elements:?}
        assert_eqw.err=\"K_CTR must be preserved by exact-length stream path\"
        push.{expected_src}
        assert_eq.err=\"exact stream src_ptr must advance by num plaintext felts\"
        push.{expected_dst}
        assert_eq.err=\"exact stream dst_ptr must advance by logical ciphertext limbs\"
        push.{expected_counter}
        assert_eq.err=\"exact stream counter must advance by used stream blocks\"
        {scratch_check}
    end
    "
    );

    let test = build_primitives_test(&source);
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

const SENTINEL_CELLS: u64 = 8;

/// Generates MASM to store consecutive values starting at `first_value` in `SENTINEL_CELLS`
/// cells at `ptr`. Individual stores allow `ptr` to be unaligned.
fn store_sentinels(ptr: u64, first_value: u64) -> String {
    (0..SENTINEL_CELLS)
        .map(|i| {
            format!(
                "
        push.{}
        push.{}
        mem_store
",
                first_value + i,
                ptr + i
            )
        })
        .collect()
}

fn assert_decrypt_accepts_layout(src_ptr: u64, dst_ptr: u64, num_felts: usize, scratch_ptr: u64) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let key_elements = key.into_elements();
    let nonce_elements = nonce.into_elements();
    let plaintext = stream_plaintext_felts(num_felts);
    let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
    let tag = auth_tag_expanded(key, nonce, &[], &ciphertext);
    let mut input_stores = store_felts(src_ptr, &ciphertext);

    // Sentinels detect advice writes past the plaintext output and exercise re-encryption with
    // nonzero values past the tail. Add them only where they cannot overlap source, scratch,
    // or local memory.
    let sentinel_start = dst_ptr + num_felts as u64;
    let src_end = src_ptr + ciphertext.len() as u64;
    let scratch_end = scratch_ptr + 2 * num_felts as u64;
    let disjoint =
        |start: u64, end: u64| sentinel_start + SENTINEL_CELLS <= start || end <= sentinel_start;
    let sentinels = disjoint(src_ptr, src_end)
        && disjoint(scratch_ptr, scratch_end)
        && sentinel_start + SENTINEL_CELLS <= FMP_INIT_VALUE.as_canonical_u64();
    if sentinels {
        input_stores.push_str(&store_sentinels(sentinel_start, 3001));
    }

    let [tag0, tag1] = tag;
    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        {input_stores}

        push.{tag1}.{tag0}
        push.{scratch_ptr}
        push.{num_felts}
        push.{dst_ptr}
        push.{src_ptr}
        push.{nonce_elements:?}
        push.{key_elements:?}

        exec.aead_eidos::decrypt
    end
    "
    );

    let test = build_test!(&source, &[]);
    let mut expected_memory = felts_to_u64(&plaintext);
    if sentinels {
        expected_memory.extend(3001..3001 + SENTINEL_CELLS);
    }
    if expected_memory.is_empty() {
        test.expect_stack(&[]);
    } else {
        test.expect_stack_and_memory(&[], dst_ptr as u32, &expected_memory);
    }
}

fn assert_encrypt_felts_accepts_layout(src_ptr: u64, dst_ptr: u64, num_felts: usize) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let plaintext = stream_plaintext_felts(num_felts);
    let ciphertext = encrypt_felts_expanded(key, nonce, &plaintext);
    let [t0, t1] = auth_tag_expanded(key, nonce, &[], &ciphertext);
    let source = format!(
        "use miden::core::crypto::aead_eidos
        begin
            {}
            push.{dst_ptr}.{num_felts}.{src_ptr}
            push.{nonce:?} push.{key:?}
            exec.aead_eidos::encrypt
            push.{t0} assert_eq push.{t1} assert_eq
        end",
        store_felts(src_ptr, &plaintext),
        nonce = nonce.into_elements(),
        key = key.into_elements(),
    );
    let test = build_test!(&source, &[]);
    if ciphertext.is_empty() {
        test.expect_stack(&[]);
    } else {
        test.expect_stack_and_memory(&[], dst_ptr as u32, &felts_to_u64(&ciphertext));
    }
}

#[track_caller]
fn assert_aead_error(case: &str, test: &Test, expected_error: &str) {
    let error = test.execute().expect_err(case);
    let expected_code = miden_core::mast::error_code_from_msg(expected_error);
    assert!(
        matches!(
            &error,
            ExecutionError::OperationError {
                err: OperationError::FailedAssertion { err_code, err_msg }
                    | OperationError::U32AssertionFailed { err_code, err_msg, .. },
                ..
            } if *err_code == expected_code && err_msg.is_none()
        ),
        "{case}: expected {expected_error:?} ({expected_code}), got {error:?}"
    );
}

#[track_caller]
fn assert_encrypt_rejected(src_ptr: u64, dst_ptr: u64, count: u64, expected_error: &str) {
    let source = format!(
        "use miden::core::crypto::aead_eidos
        begin
            push.{dst_ptr}.{count}.{src_ptr}
            push.[16, 32, 48, 64] push.[1, 2, 3, 4]
            exec.aead_eidos::encrypt
        end"
    );
    assert_aead_error("invalid range or length", &build_test!(&source, &[]), expected_error);
}

fn assert_encrypt_exhausts_counter(counter: u64, count: u64, src_advance: u64, dst_advance: u64) {
    let key = word([1, 2, 3, 4]);
    let nonce = word([0x10, 0x20, 0x30, 0x40]);
    let ctr_key_elements = derive_ctr_key(key, nonce).into_elements();
    let expected_src = SRC_PTR + src_advance;
    let expected_dst = DST_PTR + dst_advance;
    let exhausted_counter = u64::from(u32::MAX) + 1;
    let source = format!(
        "
    use test::aead_primitives

    begin
        push.{count}
        push.{counter}
        push.{DST_PTR}
        push.{SRC_PTR}
        push.{ctr_key_elements:?}

        exec.aead_primitives::encrypt_felts_expanded

        push.{ctr_key_elements:?}
        assert_eqw.err=\"K_CTR must be preserved\"
        push.{expected_src}
        assert_eq.err=\"source pointer must advance by the plaintext length\"
        push.{expected_dst}
        assert_eq.err=\"destination pointer must advance by the ciphertext length\"
        push.{exhausted_counter}
        assert_eq.err=\"the returned counter must be one past u32::MAX\"
    end
    "
    );

    build_primitives_test(&source).expect_stack(&[]);
}

#[track_caller]
fn assert_decrypt_rejected_before_event(
    case: &str,
    src_ptr: u64,
    dst_ptr: u64,
    num_felts: u64,
    scratch_ptr: u64,
    expected_error: &str,
) {
    let source = format!(
        "
    use miden::core::crypto::aead_eidos

    begin
        push.0.0
        push.{scratch_ptr}
        push.{num_felts}
        push.{dst_ptr}
        push.{src_ptr}
        push.[16, 32, 48, 64]
        push.[1, 2, 3, 4]

        exec.aead_eidos::decrypt
    end
    "
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let core_lib = CoreLibrary::default();
    let test = miden_utils_testing::build_test_by_mode!(false, source.as_str(), &[])
        .with_library(core_lib.package())
        .with_event_handler(AEAD_EIDOS_DECRYPT_EVENT_NAME, CountingHandler(Arc::clone(&calls)));

    assert_aead_error(case, &test, expected_error);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "{case} must be rejected before the plaintext event"
    );
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
        // Abort an unexpected event before an invalid length can drive further work.
        Err("unexpected plaintext event".into())
    }
}

fn build_primitives_test(source: &str) -> Test {
    build_test!(source, &[]).with_module(
        "test::aead_primitives",
        include_str!("../../asm/crypto/aead_eidos/primitives.masm"),
    )
}
