use miden_core::Word;
use miden_processor::{AdviceInputs, ContextId, DefaultHost, Program};
use miden_utils_testing::{
    ExecutionOptions, ONE, Process, StackInputs, ZERO, build_expected_hash, build_expected_perm,
    felt_slice_to_ints,
};

#[test]
fn test_memcopy_words() {
    use miden_stdlib::StdLibrary;

    let source = "
    use.std::mem

    begin
        push.0.0.0.1.1000 mem_storew dropw
        push.0.0.1.0.1004 mem_storew dropw
        push.0.0.1.1.1008 mem_storew dropw
        push.0.1.0.0.1012 mem_storew dropw
        push.0.1.0.1.1016 mem_storew dropw

        push.2000.1000.5 exec.mem::memcopy_words
    end
    ";

    let stdlib = StdLibrary::default();
    let assembler = miden_assembly::Assembler::default()
        .with_dynamic_library(&stdlib)
        .expect("failed to load stdlib");

    let program: Program =
        assembler.assemble_program(source).expect("Failed to compile test source.");

    let mut host = DefaultHost::default().with_library(&stdlib).unwrap();

    let mut process = Process::new(
        program.kernel().clone(),
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    );
    process.execute(&program, &mut host).unwrap();

    assert_eq!(
        process.chiplets.memory.get_word(ContextId::root(), 1000).unwrap(),
        Some(Word::new([ZERO, ZERO, ZERO, ONE])),
        "Address 1000"
    );
    assert_eq!(
        process.chiplets.memory.get_word(ContextId::root(), 1004).unwrap(),
        Some(Word::new([ZERO, ZERO, ONE, ZERO])),
        "Address 1004"
    );
    assert_eq!(
        process.chiplets.memory.get_word(ContextId::root(), 1008).unwrap(),
        Some(Word::new([ZERO, ZERO, ONE, ONE])),
        "Address 1008"
    );
    assert_eq!(
        process.chiplets.memory.get_word(ContextId::root(), 1012).unwrap(),
        Some(Word::new([ZERO, ONE, ZERO, ZERO])),
        "Address 1012"
    );
    assert_eq!(
        process.chiplets.memory.get_word(ContextId::root(), 1016).unwrap(),
        Some(Word::new([ZERO, ONE, ZERO, ONE])),
        "Address 1016"
    );

    assert_eq!(
        process.chiplets.memory.get_word(ContextId::root(), 2000).unwrap(),
        Some(Word::new([ZERO, ZERO, ZERO, ONE])),
        "Address 2000"
    );
    assert_eq!(
        process.chiplets.memory.get_word(ContextId::root(), 2004).unwrap(),
        Some(Word::new([ZERO, ZERO, ONE, ZERO])),
        "Address 2004"
    );
    assert_eq!(
        process.chiplets.memory.get_word(ContextId::root(), 2008).unwrap(),
        Some(Word::new([ZERO, ZERO, ONE, ONE])),
        "Address 2008"
    );
    assert_eq!(
        process.chiplets.memory.get_word(ContextId::root(), 2012).unwrap(),
        Some(Word::new([ZERO, ONE, ZERO, ZERO])),
        "Address 2012"
    );
    assert_eq!(
        process.chiplets.memory.get_word(ContextId::root(), 2016).unwrap(),
        Some(Word::new([ZERO, ONE, ZERO, ONE])),
        "Address 2016"
    );
}

#[test]
fn test_pipe_double_words_to_memory() {
    let start_addr = 1000;
    let end_addr = 1008;
    let source = format!(
        "
        use.std::mem
        use.std::sys

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
        use.std::mem
        use.std::crypto::hashes::rpo

        begin
            push.{mem_addr} # target address
            push.1  # number of words

            exec.mem::pipe_words_to_memory
            exec.rpo::squeeze_digest

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
        use.std::mem
        use.std::crypto::hashes::rpo

        begin
            push.{mem_addr} # target address
            push.3  # number of words

            exec.mem::pipe_words_to_memory
            exec.rpo::squeeze_digest

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
        "use.std::mem

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
    use.std::mem

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
