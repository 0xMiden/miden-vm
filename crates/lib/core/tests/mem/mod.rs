use miden_assembly::Linkage;
use miden_processor::{
    ContextId, DefaultHost, ExecutionError, FastProcessor, Felt, ONE, Program, StackInputs, Word,
    ZERO, operation::OperationError, trace::RowIndex,
};
use miden_utils_testing::{
    AdviceStack, build_expected_compress, build_expected_hash, expect_exec_error_matches,
    felt_slice_to_ints,
};
use rstest::rstest;

#[test]
fn test_memcopy_words_fails_on_overlap() {
    // Source [1000, 1000 + 4*3) = [1000, 1012)
    // Dest   [1008, 1008 + 4*3) = [1008, 1020)
    // These overlap at [1008, 1012).
    let source = "
    use miden::core::mem

    begin
        push.0.0.0.1.1000 mem_storew_be dropw
        push.0.0.1.0.1004 mem_storew_be dropw
        push.0.0.1.1.1008 mem_storew_be dropw

        push.1008.1000.3 exec.mem::memcopy_words
    end
    ";

    let test = build_test!(source, &[]);
    expect_assert_error_code_from_msg!(test, "source and destination ranges must not overlap");
}

#[test]
fn test_memcopy_elements_fails_on_overlap() {
    // Source [1000, 1000 + 10) = [1000, 1010)
    // Dest   [1005, 1005 + 10) = [1005, 1015)
    // These overlap at [1005, 1010).
    let source = "
    use miden::core::mem

    begin
        push.1.2.3.4.1000 mem_storew_be dropw
        push.5.6.7.8.1004 mem_storew_be dropw
        push.9.10.11.12.1008 mem_storew_be dropw

        push.1005.1000.10 exec.mem::memcopy_elements
    end
    ";

    let test = build_test!(source, &[]);
    expect_assert_error_code_from_msg!(test, "source and destination ranges must not overlap");
}

#[test]
fn test_memcopy_words() {
    use miden_core_lib::CoreLibrary;

    let source = "
    use miden::core::mem

    begin
        push.0.0.0.1.1000 mem_storew_be dropw
        push.0.0.1.0.1004 mem_storew_be dropw
        push.0.0.1.1.1008 mem_storew_be dropw
        push.0.1.0.0.1012 mem_storew_be dropw
        push.0.1.0.1.1016 mem_storew_be dropw

        push.2000.1000.5 exec.mem::memcopy_words
    end
    ";

    let core_lib = CoreLibrary::default();
    let assembler = miden_assembly::Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("failed to load core library");

    let program: Program = assembler
        .assemble_program("program", source)
        .expect("Failed to compile test source.")
        .unwrap_program();

    let mut host = DefaultHost::default().with_library(&core_lib).unwrap();

    let processor = FastProcessor::new(StackInputs::default());
    let exec_output = processor.execute_sync(&program, &mut host).unwrap();

    let dummy_clk = RowIndex::from(0_usize);

    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from_u32(1000), dummy_clk)
            .unwrap(),
        Word::new([ZERO, ZERO, ZERO, ONE]),
        "Address 1000"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from_u32(1004), dummy_clk)
            .unwrap(),
        Word::new([ZERO, ZERO, ONE, ZERO]),
        "Address 1004"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from_u32(1008), dummy_clk)
            .unwrap(),
        Word::new([ZERO, ZERO, ONE, ONE]),
        "Address 1008"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from_u32(1012), dummy_clk)
            .unwrap(),
        Word::new([ZERO, ONE, ZERO, ZERO]),
        "Address 1012"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from_u32(1016), dummy_clk)
            .unwrap(),
        Word::new([ZERO, ONE, ZERO, ONE]),
        "Address 1016"
    );

    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from_u32(2000), dummy_clk)
            .unwrap(),
        Word::new([ZERO, ZERO, ZERO, ONE]),
        "Address 2000"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from_u32(2004), dummy_clk)
            .unwrap(),
        Word::new([ZERO, ZERO, ONE, ZERO]),
        "Address 2004"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from_u32(2008), dummy_clk)
            .unwrap(),
        Word::new([ZERO, ZERO, ONE, ONE]),
        "Address 2008"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from_u32(2012), dummy_clk)
            .unwrap(),
        Word::new([ZERO, ONE, ZERO, ZERO]),
        "Address 2012"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from_u32(2016), dummy_clk)
            .unwrap(),
        Word::new([ZERO, ONE, ZERO, ONE]),
        "Address 2016"
    );
}

#[test]
fn test_memcopy_elements() {
    use miden_core_lib::CoreLibrary;

    let source = "
    use miden::core::mem

    begin
        push.1.2.3.4.1000 mem_storew_be dropw
        push.5.6.7.8.1004 mem_storew_be dropw
        push.9.10.11.12.1008 mem_storew_be dropw
        push.13.14.15.16.1012 mem_storew_be dropw
        push.17.18.19.20.1016 mem_storew_be dropw

        push.2002.1001.18 exec.mem::memcopy_elements
    end
    ";

    let core_lib = CoreLibrary::default();
    let assembler = miden_assembly::Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("failed to load core library");

    let program: Program = assembler
        .assemble_program("program", source)
        .expect("Failed to compile test source.")
        .unwrap_program();

    let mut host = DefaultHost::default().with_library(&core_lib).unwrap();

    let processor = FastProcessor::new(StackInputs::default());
    let exec_output = processor.execute_sync(&program, &mut host).unwrap();

    for addr in 2002_u32..2020_u32 {
        assert_eq!(
            exec_output
                .memory
                .read_element(ContextId::root(), Felt::from_u32(addr))
                .unwrap(),
            Felt::from_u32(addr - 2000),
            "Address {addr}"
        );
    }
}

#[rstest]
#[case(1000)]
#[case(u32::MAX - 7)]
fn test_pipe_double_words_to_memory(#[case] start_addr: u32) {
    let end_addr = u64::from(start_addr) + 8;
    let source = format!(
        "
        use miden::core::mem
        use miden::core::sys

        begin
            push.{end_addr}
            push.{start_addr}
            padw padw padw  # hasher state

            exec.mem::pipe_double_words_to_memory

            exec.sys::truncate_stack
        end"
    );

    let operand_stack = &[];
    // Preserve the frame pointer when the destination includes the final memory word.
    let data = &[1, 2, 3, 4, 5, 6, miden_core::FMP_INIT_VALUE.as_canonical_u64(), 8];
    let mut state = [0; 12];
    state[..8].copy_from_slice(data);
    let mut expected_stack = felt_slice_to_ints(&build_expected_compress(&state));
    expected_stack.push(end_addr);
    build_test!(source, operand_stack, &data).expect_stack_and_memory(
        &expected_stack,
        start_addr,
        data,
    );
}

#[test]
fn test_pipe_words_to_memory() {
    let mem_addr = 1000;
    let one_word = format!(
        "
        use miden::core::mem
        use miden::core::crypto::hashes::eidos

        begin
            push.{mem_addr} # target address
            push.1  # number of words

            exec.mem::pipe_words_to_memory
            exec.eidos::digest

            # truncate stack
            swapdw dropw dropw
        end"
    );

    let operand_stack = &[];
    let data = &[1, 2, 3, 4];
    let mut expected_stack = felt_slice_to_ints(&build_expected_hash(data));
    expected_stack.push(1004);
    build_test!(one_word, operand_stack, &data).expect_stack_and_memory(
        &expected_stack,
        mem_addr,
        data,
    );

    let three_words = format!(
        "
        use miden::core::mem
        use miden::core::crypto::hashes::eidos

        begin
            push.{mem_addr} # target address
            push.3  # number of words

            exec.mem::pipe_words_to_memory
            exec.eidos::digest

            # truncate stack
            swapdw dropw dropw
        end"
    );

    let operand_stack = &[];
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut expected_stack = felt_slice_to_ints(&build_expected_hash(data));
    expected_stack.push(1012);
    build_test!(three_words, operand_stack, &data).expect_stack_and_memory(
        &expected_stack,
        mem_addr,
        data,
    );
}

#[rstest]
#[case::partial_block(1000, 1004, "copy range length must be a multiple of 8")]
#[case::reversed(1008, 1000, "write pointer must not exceed end pointer")]
#[case::unaligned(1001, 1009, "write pointer must be word-aligned")]
#[case::wide_start(1 << 32, 1 << 32, "write pointer must fit in a u32")]
#[case::wide_end(1000, (1 << 32) + 8, "copy range exceeds the u32 address space")]
fn pipe_double_words_rejects_invalid_range_before_reading_advice(
    #[case] start: u64,
    #[case] end: u64,
    #[case] message: &str,
) {
    let source = format!(
        "use miden::core::mem
        begin
            push.{end}.{start}
            padw padw padw
            exec.mem::pipe_double_words_to_memory
        end"
    );
    // Empty advice distinguishes range rejection from entering the copying loop.
    let test = build_test!(source.as_str(), &[]);
    let expected_code = miden_core::mast::error_code_from_msg(message);
    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, .. }
                | OperationError::U32AssertionFailed { err_code, .. },
            ..
        } if err_code == expected_code
    );
}

#[rstest]
#[case::generic("push.8.1073741823 exec.mem::pipe_words_to_memory")]
#[case::domain("push.8.1073741823.42 exec.mem::pipe_words_to_memory_in_domain")]
fn pipe_words_rejects_tail_overflow_before_reading_advice(#[case] invocation: &str) {
    // The complete-block prefix ends at 2^32, leaving no room for the final word.
    let source = format!("use miden::core::mem begin {invocation} end");
    let test = build_test!(source.as_str(), &[]);
    let expected_code =
        miden_core::mast::error_code_from_msg("copy tail address must fit in a u32");
    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::U32AssertionFailed { err_code, .. },
            ..
        } if err_code == expected_code
    );
}

#[test]
fn pipe_double_words_empty_preserves_state_and_advice() {
    let source = "use miden::core::mem
        use miden::core::sys
        begin
            push.1000.1000
            push.12.11.10.9.8.7.6.5.4.3.2.1
            exec.mem::pipe_double_words_to_memory
            adv_push eq.99 assert
            exec.sys::truncate_stack
        end";
    let mut expected: Vec<u64> = (1..=12).collect();
    expected.push(1000);
    build_test!(source, &[], &[99]).expect_stack(&expected);
}

#[test]
fn pipe_words_to_memory_hashes_empty_input_canonically() {
    use miden_core::chiplets::hasher;

    const MEM_ADDR: u64 = 1000;
    const CANARY: [u64; 4] = [41, 42, 43, 44];
    let source = format!(
        "
        use miden::core::mem
        use miden::core::crypto::hashes::eidos
        use miden::core::sys

        begin
            push.[41,42,43,44] push.{MEM_ADDR} mem_storew_le dropw

            push.{MEM_ADDR} push.0
            exec.mem::pipe_words_to_memory
            exec.eidos::digest
            movup.4 eq.{MEM_ADDR} assert
            exec.sys::truncate_stack
        end
        "
    );

    let digest = hasher::hash_elements(&[]);
    let mut expected_stack = felt_slice_to_ints(digest.as_elements());
    expected_stack.resize(16, 0);
    build_test!(source.as_str(), &[]).expect_stack_and_memory(
        &expected_stack,
        MEM_ADDR as u32,
        &CANARY,
    );
}

/// The advice pipe, the memory-based hasher, and the native hasher must agree for empty, odd,
/// even, and maximum-size inputs. A second domain checks that the pipe does not bake in the
/// kernel tag.
#[test]
fn pipe_words_to_memory_in_domain_matches_native_and_memory_hashes() {
    use miden_core::{chiplets::eidos_compression, program::KERNEL_DOMAIN_TAG};
    use miden_crypto::hash::eidos::Eidos;

    const MEM_ADDR: u64 = 1000;
    const OTHER_DOMAIN: u64 = 42;
    const CANARY: [u64; 4] = [91, 92, 93, 94];

    let kernel_domain = KERNEL_DOMAIN_TAG.as_canonical_u64();
    let cases = [
        (0, 0),
        (0, kernel_domain),
        (1, kernel_domain),
        (2, kernel_domain),
        (3, kernel_domain),
        (4, kernel_domain),
        (255, kernel_domain),
        (3, OTHER_DOMAIN),
    ];

    for (num_words, domain) in cases {
        let num_felts = num_words * 4;
        let data: Vec<u64> = (1..=num_felts as u64).collect();
        let felts: Vec<Felt> = data.iter().copied().map(Felt::new_unchecked).collect();
        let guard_addr = MEM_ADDR + num_felts as u64;

        let source = format!(
            "
            use miden::core::mem
            use miden::core::crypto::hashes::eidos

            begin
                push.[91,92,93,94] push.{guard_addr} mem_storew_le dropw

                push.{MEM_ADDR} push.{num_words} push.{domain}
                exec.mem::pipe_words_to_memory_in_domain
                movup.4 eq.{guard_addr} assert

                dupw
                push.{domain} push.{num_felts} push.{MEM_ADDR}
                exec.eidos::hash_elements_in_domain
                assert_eqw

                swapw dropw
            end
            "
        );

        let mut digest = eidos_compression::init_chaining_word(domain as u32, num_felts as u32);
        if felts.is_empty() {
            digest = Eidos::compress(digest, [Felt::ZERO; 8]);
        } else {
            for chunk in felts.chunks(8) {
                let mut block = [Felt::ZERO; 8];
                block[..chunk.len()].copy_from_slice(chunk);
                digest = Eidos::compress(digest, block);
            }
        }
        let mut expected_stack = felt_slice_to_ints(digest.as_elements());
        expected_stack.resize(16, 0);
        let expected_memory: Vec<u64> = data.iter().copied().chain(CANARY).collect();
        build_test!(source.as_str(), &[], data.as_slice()).expect_stack_and_memory(
            &expected_stack,
            MEM_ADDR as u32,
            &expected_memory,
        );
    }
}

#[test]
fn test_pipe_preimage_to_memory() {
    let mem_addr = 1000;
    let three_words = format!(
        "use miden::core::mem

        begin
            padw adv_loadw # push commitment to stack
            push.{mem_addr}    # target address
            push.3     # number of words

            exec.mem::pipe_preimage_to_memory
            swap drop
        end"
    );

    let operand_stack = &[];
    let data: &[u64] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let advice_stack = advice_stack_from_hash_and_data(build_expected_hash(data).into(), data);
    build_test!(three_words, operand_stack, advice_stack).expect_stack_and_memory(
        &[1012],
        mem_addr,
        data,
    );
}

#[test]
fn test_pipe_preimage_to_memory_invalid_preimage() {
    let three_words = "
    use miden::core::mem

    begin
        padw adv_loadw  # push commitment to stack
        push.1000   # target address
        push.3      # number of words

        exec.mem::pipe_preimage_to_memory
    end
    ";

    let operand_stack = &[];
    let data: &[u64] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut corrupted_hash = build_expected_hash(data);
    corrupted_hash[0] += Felt::ONE; // corrupt the expected hash
    let advice_stack = advice_stack_from_hash_and_data(corrupted_hash.into(), data);
    let res = build_test!(three_words, operand_stack, advice_stack).execute();
    assert!(res.is_err());
}

#[test]
fn test_pipe_double_words_preimage_to_memory() {
    // Word-aligned address, as required by `pipe_double_words_preimage_to_memory`.
    let mem_addr = 1000;
    let four_words = format!(
        "use miden::core::mem

        begin
            padw adv_loadw # push commitment to stack
            push.{mem_addr}    # target address
            push.4     # number of words

            exec.mem::pipe_double_words_preimage_to_memory
            swap drop
        end"
    );

    let operand_stack = &[];
    let data: &[u64] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let advice_stack = advice_stack_from_hash_and_data(build_expected_hash(data).into(), data);
    build_test!(four_words, operand_stack, advice_stack).expect_stack_and_memory(
        &[mem_addr + (4u64 * 4u64)],
        mem_addr as u32,
        data,
    );
}

#[test]
fn pipe_double_words_preimage_to_memory_accepts_canonical_empty_hash() {
    use miden_core::chiplets::hasher;

    const MEM_ADDR: u64 = 1000;
    const CANARY: [u64; 4] = [41, 42, 43, 44];
    let source = format!(
        "
        use miden::core::mem

        begin
            push.[41,42,43,44] push.{MEM_ADDR} mem_storew_le dropw

            padw adv_loadw
            push.{MEM_ADDR}
            push.0
            exec.mem::pipe_double_words_preimage_to_memory
            swap drop
        end
        "
    );

    let mut advice_stack = AdviceStack::new();
    advice_stack.append_word(hasher::hash_elements(&[]));
    build_test!(source.as_str(), &[], advice_stack).expect_stack_and_memory(
        &[MEM_ADDR],
        MEM_ADDR as u32,
        &CANARY,
    );
}

#[test]
fn test_pipe_empty_preimage_to_memory_with_domain() {
    use miden_core::{chiplets::hasher, program};

    const MEM_ADDR: u64 = 1000;
    let source = format!(
        "
        use miden::core::mem

        begin
            push.[41,42,43,44] push.{MEM_ADDR} mem_storew_le dropw

            padw adv_loadw
            push.{MEM_ADDR}
            push.0
            push.{domain}
            exec.mem::pipe_double_words_preimage_to_memory_with_domain
            swap drop
        end
        ",
        domain = program::KERNEL_DOMAIN_TAG.as_canonical_u64(),
    );

    let commitment = hasher::hash_elements_in_domain(&[], program::domain::KERNEL_COMMITMENT);
    let mut advice_stack = AdviceStack::new();
    advice_stack.append_word(commitment);

    build_test!(source.as_str(), &[], advice_stack).expect_stack_and_memory(
        &[MEM_ADDR],
        MEM_ADDR as u32,
        &[41, 42, 43, 44],
    );
}

#[test]
fn test_pipe_double_words_preimage_to_memory_invalid_preimage() {
    let four_words = "
    use miden::core::mem

    begin
        padw adv_loadw  # push commitment to stack
        push.1000   # target address
        push.4      # number of words

        exec.mem::pipe_double_words_preimage_to_memory
    end
    ";

    let operand_stack = &[];
    let data: &[u64] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut corrupted_hash = build_expected_hash(data);
    corrupted_hash[0] += Felt::ONE; // corrupt the expected hash
    let advice_stack = advice_stack_from_hash_and_data(corrupted_hash.into(), data);
    let test = build_test!(four_words, operand_stack, advice_stack);
    expect_assert_error_message!(test);
}

#[test]
fn test_pipe_double_words_preimage_to_memory_invalid_count() {
    let three_words = "
    use miden::core::mem

    begin
        padw adv_loadw  # push commitment to stack
        push.1000   # target address
        push.3      # number of words

        exec.mem::pipe_double_words_preimage_to_memory
    end
    ";

    let operand_stack = &[];
    let data: &[u64] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let advice_stack = advice_stack_from_hash_and_data(build_expected_hash(data).into(), data);
    let test = build_test!(three_words, operand_stack, advice_stack);
    expect_assert_error_message!(test);
}

fn advice_stack_from_hash_and_data(hash: Word, data: &[u64]) -> AdviceStack {
    let mut advice_stack = AdviceStack::new();
    advice_stack.append_word(hash);
    advice_stack.append_elements(data.iter().map(|&value| Felt::new_unchecked(value)));
    advice_stack
}
