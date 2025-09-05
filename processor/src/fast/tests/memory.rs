use super::*;

#[test]
fn test_memory_word_access_alignment() {
    let mut host = DefaultHost::default();

    // mloadw
    {
        let program = simple_program_with_ops(vec![Operation::MLoadW]);

        // loadw at address 40 is allowed
        FastProcessor::new(&[40_u32.into()]).execute_sync(&program, &mut host).unwrap();

        // but loadw at address 43 is not allowed
        let err = FastProcessor::new(&[43_u32.into()])
            .execute_sync(&program, &mut host)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "word memory access at address 43 in context 0 is unaligned at clock cycle 1"
        );
    }

    // mstorew
    {
        let program = simple_program_with_ops(vec![Operation::MStoreW]);

        // storew at address 40 is allowed
        FastProcessor::new(&[40_u32.into()]).execute_sync(&program, &mut host).unwrap();

        // but storew at address 43 is not allowed
        let err = FastProcessor::new(&[43_u32.into()])
            .execute_sync(&program, &mut host)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "word memory access at address 43 in context 0 is unaligned at clock cycle 1"
        );
    }
}

#[test]
fn test_mloadw_success() {
    let mut host = DefaultHost::default();
    let addr = Felt::from(40_u32);
    let word_at_addr = [1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into()];
    let ctx = 0_u32.into();
    let dummy_clk: RowIndex = 0_u32.into();

    // load the contents of address 40
    {
        let mut processor = FastProcessor::new(&[addr]);
        processor
            .memory
            .write_word(ctx, addr, dummy_clk, word_at_addr.into(), &())
            .unwrap();

        let program = simple_program_with_ops(vec![Operation::MLoadW]);
        let stack_outputs = processor.execute_sync_mut(&program, &mut host).unwrap();

        assert_eq!(
            stack_outputs.stack_truncated(4),
            // memory order is the reverse from the stack order
            &[word_at_addr[3], word_at_addr[2], word_at_addr[1], word_at_addr[0]]
        );
    }

    // load the contents of address 100 (should yield the ZERO word)
    {
        let mut processor = FastProcessor::new(&[100_u32.into()]);
        processor
            .memory
            .write_word(ctx, addr, dummy_clk, word_at_addr.into(), &())
            .unwrap();

        let program = simple_program_with_ops(vec![Operation::MLoadW]);
        let stack_outputs = processor.execute_sync_mut(&program, &mut host).unwrap();

        assert_eq!(stack_outputs.stack_truncated(16), &vec![ZERO; 16]);
    }
}

#[test]
fn test_mstorew_success() {
    let mut host = DefaultHost::default();
    let addr = Felt::from(40_u32);
    let word_to_store = [1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into()];
    let ctx = 0_u32.into();
    let clk = 0_u32.into();

    // Store the word at address 40
    let mut processor = FastProcessor::new(&[
        word_to_store[0],
        word_to_store[1],
        word_to_store[2],
        word_to_store[3],
        addr,
    ]);
    let program = simple_program_with_ops(vec![Operation::MStoreW]);
    processor.execute_sync_mut(&program, &mut host).unwrap();

    // Ensure that the memory was correctly modified
    assert_eq!(
        processor.memory.read_word(ctx, addr, clk, &(), &mut NoopTracer).unwrap(),
        word_to_store.into()
    );
}

#[rstest]
#[case(40_u32, 42_u32)]
#[case(41_u32, 42_u32)]
#[case(42_u32, 42_u32)]
#[case(43_u32, 42_u32)]
fn test_mstore_success(#[case] addr: u32, #[case] value_to_store: u32) {
    let mut host = DefaultHost::default();
    let ctx = 0_u32.into();
    let clk = 1_u32.into();
    let value_to_store = Felt::from(value_to_store);

    // Store the value at address 40
    let mut processor = FastProcessor::new(&[value_to_store, addr.into()]);
    let program = simple_program_with_ops(vec![Operation::MStore]);
    processor.execute_sync_mut(&program, &mut host).unwrap();

    // Ensure that the memory was correctly modified
    let word_addr = addr - (addr % WORD_SIZE as u32);
    let word = processor
        .memory
        .read_word(ctx, word_addr.into(), clk, &(), &mut NoopTracer)
        .unwrap();
    assert_eq!(word[addr as usize % WORD_SIZE], value_to_store);
}

#[rstest]
#[case(40_u32)]
#[case(41_u32)]
#[case(42_u32)]
#[case(43_u32)]
fn test_mload_success(#[case] addr_to_access: u32) {
    let mut host = DefaultHost::default();
    let addr_with_word = 40_u32;
    let word_at_addr = [1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into()];
    let ctx = 0_u32.into();
    let dummy_clk = 0_u32.into();

    // Initialize processor with a word at address 40
    let mut processor = FastProcessor::new(&[addr_to_access.into()]);
    processor
        .memory
        .write_word(ctx, addr_with_word.into(), dummy_clk, word_at_addr.into(), &())
        .unwrap();

    let program = simple_program_with_ops(vec![Operation::MLoad]);
    let stack_outputs = processor.execute_sync_mut(&program, &mut host).unwrap();

    // Ensure that Operation::MLoad correctly reads the value on the stack
    assert_eq!(
        stack_outputs.stack_truncated(1)[0],
        word_at_addr[addr_to_access as usize % WORD_SIZE]
    );
}

#[test]
fn test_mstream() {
    let mut host = DefaultHost::default();
    let addr = 40_u32;
    let word_at_addr_40 = Word::from([ONE, 2_u32.into(), 3_u32.into(), 4_u32.into()]);
    let word_at_addr_44 = Word::from([Felt::from(5_u32), 6_u32.into(), 7_u32.into(), 8_u32.into()]);
    let ctx = 0_u32.into();
    let clk = 1_u32.into();

    let mut processor = {
        let stack_init = {
            let mut stack = vec![ZERO; 16];
            stack[MIN_STACK_DEPTH - 1 - 12] = addr.into();
            stack
        };
        FastProcessor::new(&stack_init)
    };
    // Store values at addresses 40 and 44
    processor
        .memory
        .write_word(ctx, addr.into(), clk, word_at_addr_40, &())
        .unwrap();
    processor
        .memory
        .write_word(ctx, (addr + 4).into(), clk, word_at_addr_44, &())
        .unwrap();

    let program = simple_program_with_ops(vec![Operation::MStream]);
    let stack_outputs = processor.execute_sync_mut(&program, &mut host).unwrap();

    // Ensure that Operation::MStream correctly reads the values on the stack
    assert_eq!(
        stack_outputs.stack_truncated(8),
        // memory order is the reverse from the stack order
        &[
            word_at_addr_44[3],
            word_at_addr_44[2],
            word_at_addr_44[1],
            word_at_addr_44[0],
            word_at_addr_40[3],
            word_at_addr_40[2],
            word_at_addr_40[1],
            word_at_addr_40[0]
        ]
    );
}
