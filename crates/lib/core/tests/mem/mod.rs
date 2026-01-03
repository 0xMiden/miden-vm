use miden_air::trace::RowIndex;
use miden_core::{Word, assert_matches};
use miden_processor::{ContextId, DefaultHost, ExecutionError, Program, fast::FastProcessor};
use miden_utils_testing::{
    Felt, ONE, ZERO, build_expected_hash, build_expected_perm, felt_slice_to_ints,
};

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
        .with_dynamic_library(&core_lib)
        .expect("failed to load core library");

    let program: Program =
        assembler.assemble_program(source).expect("Failed to compile test source.");

    let mut host = DefaultHost::default().with_library(&core_lib).unwrap();

    let processor = FastProcessor::new(&[]);
    let exec_output = processor.execute_sync(&program, &mut host).unwrap();

    let dummy_clk = RowIndex::from(0_usize);

    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from(1000_u32), dummy_clk, &())
            .unwrap(),
        Word::new([ZERO, ZERO, ZERO, ONE]),
        "Address 1000"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from(1004_u32), dummy_clk, &())
            .unwrap(),
        Word::new([ZERO, ZERO, ONE, ZERO]),
        "Address 1004"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from(1008_u32), dummy_clk, &())
            .unwrap(),
        Word::new([ZERO, ZERO, ONE, ONE]),
        "Address 1008"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from(1012_u32), dummy_clk, &())
            .unwrap(),
        Word::new([ZERO, ONE, ZERO, ZERO]),
        "Address 1012"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from(1016_u32), dummy_clk, &())
            .unwrap(),
        Word::new([ZERO, ONE, ZERO, ONE]),
        "Address 1016"
    );

    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from(2000_u32), dummy_clk, &())
            .unwrap(),
        Word::new([ZERO, ZERO, ZERO, ONE]),
        "Address 2000"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from(2004_u32), dummy_clk, &())
            .unwrap(),
        Word::new([ZERO, ZERO, ONE, ZERO]),
        "Address 2004"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from(2008_u32), dummy_clk, &())
            .unwrap(),
        Word::new([ZERO, ZERO, ONE, ONE]),
        "Address 2008"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from(2012_u32), dummy_clk, &())
            .unwrap(),
        Word::new([ZERO, ONE, ZERO, ZERO]),
        "Address 2012"
    );
    assert_eq!(
        exec_output
            .memory
            .read_word(ContextId::root(), Felt::from(2016_u32), dummy_clk, &())
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
        .with_dynamic_library(&core_lib)
        .expect("failed to load core library");

    let program: Program =
        assembler.assemble_program(source).expect("Failed to compile test source.");

    let mut host = DefaultHost::default().with_library(&core_lib).unwrap();

    let processor = FastProcessor::new(&[]);
    let exec_output = processor.execute_sync(&program, &mut host).unwrap();

    for addr in 2002_u32..2020_u32 {
        assert_eq!(
            exec_output
                .memory
                .read_element(ContextId::root(), Felt::from(addr), &())
                .unwrap(),
            Felt::from(addr - 2000),
            "Address {}",
            addr
        );
    }
}

#[test]
fn test_pipe_double_words_to_memory() {
    let start_addr = 1000;
    let end_addr = 1008;
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
    let data = &[1, 2, 3, 4, 5, 6, 7, 8];
    let mut expected_stack =
        felt_slice_to_ints(&build_expected_perm(&[0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]));
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
        use miden::core::crypto::hashes::rpo256

        begin
            push.{mem_addr} # target address
            push.1  # number of words

            exec.mem::pipe_words_to_memory
            exec.rpo256::squeeze_digest

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
        use miden::core::crypto::hashes::rpo256

        begin
            push.{mem_addr} # target address
            push.3  # number of words

            exec.mem::pipe_words_to_memory
            exec.rpo256::squeeze_digest

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

#[test]
fn test_pipe_preimage_to_memory() {
    let mem_addr = 1000;
    let three_words = format!(
        "use miden::core::mem

        begin
            adv_push.4 # push commitment to stack
            push.{mem_addr}    # target address
            push.3     # number of words

            exec.mem::pipe_preimage_to_memory
            swap drop
        end"
    );

    let operand_stack = &[];
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut advice_stack = felt_slice_to_ints(&build_expected_hash(data));
    advice_stack.reverse();
    advice_stack.extend(data);
    build_test!(three_words, operand_stack, &advice_stack).expect_stack_and_memory(
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
        adv_push.4  # push commitment to stack
        push.1000   # target address
        push.3      # number of words

        exec.mem::pipe_preimage_to_memory
    end
    ";

    let operand_stack = &[];
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut advice_stack = felt_slice_to_ints(&build_expected_hash(data));
    advice_stack.reverse();
    advice_stack[0] += 1; // corrupt the expected hash
    advice_stack.extend(data);
    let res = build_test!(three_words, operand_stack, &advice_stack).execute();
    assert!(res.is_err());
}

#[test]
fn test_pipe_double_words_preimage_to_memory() {
    // Word-aligned address, as required by `pipe_double_words_preimage_to_memory`.
    let mem_addr = 1000;
    let four_words = format!(
        "use miden::core::mem

        begin
            adv_push.4 # push commitment to stack
            push.{mem_addr}    # target address
            push.4     # number of words

            exec.mem::pipe_double_words_preimage_to_memory
            swap drop
        end"
    );

    let operand_stack = &[];
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut advice_stack = felt_slice_to_ints(&build_expected_hash(data));
    advice_stack.reverse();
    advice_stack.extend(data);
    build_test!(four_words, operand_stack, &advice_stack).expect_stack_and_memory(
        &[mem_addr + (4u64 * 4u64)],
        mem_addr as u32,
        data,
    );
}

#[test]
fn test_pipe_double_words_preimage_to_memory_invalid_preimage() {
    let four_words = "
    use miden::core::mem

    begin
        adv_push.4  # push commitment to stack
        push.1000   # target address
        push.4      # number of words

        exec.mem::pipe_double_words_preimage_to_memory
    end
    ";

    let operand_stack = &[];
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut advice_stack = felt_slice_to_ints(&build_expected_hash(data));
    advice_stack.reverse();
    advice_stack[0] += 1; // corrupt the expected hash
    advice_stack.extend(data);
    let execution_result = build_test!(four_words, operand_stack, &advice_stack).execute();
    assert_matches!(execution_result, Err(ExecutionError::FailedAssertion { .. }));
}

#[test]
fn test_pipe_double_words_preimage_to_memory_invalid_count() {
    let three_words = "
    use miden::core::mem

    begin
        adv_push.4  # push commitment to stack
        push.1000   # target address
        push.3      # number of words

        exec.mem::pipe_double_words_preimage_to_memory
    end
    ";

    let operand_stack = &[];
    let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut advice_stack = felt_slice_to_ints(&build_expected_hash(data));
    advice_stack.reverse();
    advice_stack.extend(data);
    let execution_result = build_test!(three_words, operand_stack, &advice_stack).execute();
    assert_matches!(execution_result, Err(ExecutionError::FailedAssertion { .. }));
}
