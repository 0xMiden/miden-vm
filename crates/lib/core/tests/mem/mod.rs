use miden_air::trace::RowIndex;
use miden_core::{Word, assert_matches, field::PrimeCharacteristicRing, stack::StackInputs};
use miden_processor::{
    ContextId, DefaultHost, ExecutionError, OperationError, Program, fast::FastProcessor,
};
use miden_utils_testing::{
    AdviceStackBuilder, Felt, ONE, ZERO, build_expected_hash, build_expected_perm,
    felt_slice_to_ints,
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
        .with_dynamic_library(&core_lib)
        .expect("failed to load core library");

    let program: Program =
        assembler.assemble_program(source).expect("Failed to compile test source.");

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
        felt_slice_to_ints(&build_expected_perm(&[1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0]));
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
        use miden::core::crypto::hashes::poseidon2

        begin
            push.{mem_addr} # target address
            push.1  # number of words

            exec.mem::pipe_words_to_memory
            exec.poseidon2::squeeze_digest

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
        use miden::core::crypto::hashes::poseidon2

        begin
            push.{mem_addr} # target address
            push.3  # number of words

            exec.mem::pipe_words_to_memory
            exec.poseidon2::squeeze_digest

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
            padw adv_loadw # push commitment to stack
            push.{mem_addr}    # target address
            push.3     # number of words

            exec.mem::pipe_preimage_to_memory
            swap drop
        end"
    );

    let operand_stack = &[];
    let data: &[u64] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut builder = AdviceStackBuilder::new();
    builder.push_for_adv_loadw(build_expected_hash(data).into());
    builder.push_u64_slice(data);
    let advice_stack = builder.build_vec_u64();
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
    let mut builder = AdviceStackBuilder::new();
    builder.push_for_adv_loadw(corrupted_hash.into());
    builder.push_u64_slice(data);
    let advice_stack = builder.build_vec_u64();
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
            padw adv_loadw # push commitment to stack
            push.{mem_addr}    # target address
            push.4     # number of words

            exec.mem::pipe_double_words_preimage_to_memory
            swap drop
        end"
    );

    let operand_stack = &[];
    let data: &[u64] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut builder = AdviceStackBuilder::new();
    builder.push_for_adv_loadw(build_expected_hash(data).into());
    builder.push_u64_slice(data);
    let advice_stack = builder.build_vec_u64();
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
    let mut builder = AdviceStackBuilder::new();
    builder.push_for_adv_loadw(corrupted_hash.into());
    builder.push_u64_slice(data);
    let advice_stack = builder.build_vec_u64();
    let execution_result = build_test!(four_words, operand_stack, &advice_stack).execute();
    assert_matches!(
        execution_result,
        Err(ExecutionError::OperationError {
            err: OperationError::FailedAssertion { .. },
            ..
        })
    );
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
    let mut builder = AdviceStackBuilder::new();
    builder.push_for_adv_loadw(build_expected_hash(data).into());
    builder.push_u64_slice(data);
    let advice_stack = builder.build_vec_u64();
    let execution_result = build_test!(three_words, operand_stack, &advice_stack).execute();
    assert_matches!(
        execution_result,
        Err(ExecutionError::OperationError {
            err: OperationError::FailedAssertion { .. },
            ..
        })
    );
}
