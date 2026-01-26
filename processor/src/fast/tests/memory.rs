use miden_core::field::PrimeCharacteristicRing;

use super::*;

#[test]
fn test_memory_word_access_alignment() {
    let mut host = DefaultHost::default();

    // mloadw
    {
        let program = simple_program_with_ops(vec![Operation::MLoadW]);

        // loadw at address 40 is allowed
        FastProcessor::new(StackInputs::new(&[Felt::from_u32(40)]).unwrap())
            .execute_sync(&program, &mut host)
            .unwrap();

        // but loadw at address 43 is not allowed
        let err = FastProcessor::new(StackInputs::new(&[Felt::from_u32(43)]).unwrap())
            .execute_sync(&program, &mut host)
            .unwrap_err();
        assert_eq!(err.to_string(), "word access at memory address 43 in context 0 is unaligned");
    }

    // mstorew
    {
        let program = simple_program_with_ops(vec![Operation::MStoreW]);

        // storew at address 40 is allowed
        FastProcessor::new(StackInputs::new(&[Felt::from_u32(40)]).unwrap())
            .execute_sync(&program, &mut host)
            .unwrap();

        // but storew at address 43 is not allowed
        let err = FastProcessor::new(StackInputs::new(&[Felt::from_u32(43)]).unwrap())
            .execute_sync(&program, &mut host)
            .unwrap_err();
        assert_eq!(err.to_string(), "word access at memory address 43 in context 0 is unaligned");
    }
}

#[test]
fn test_mloadw_success() {
    let mut host = DefaultHost::default();
    let addr = Felt::from_u32(40);
    let word_at_addr = [Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4)];
    let ctx = 0_u32.into();
    let dummy_clk: RowIndex = 0_u32.into();

    // load the contents of address 40
    {
        let mut processor = FastProcessor::new(StackInputs::new(&[addr]).unwrap());
        processor.memory.write_word(ctx, addr, dummy_clk, word_at_addr.into()).unwrap();

        let program = simple_program_with_ops(vec![Operation::MLoadW]);
        let stack_outputs = processor.execute_sync_mut(&program, &mut host).unwrap();

        // Memory word[i] maps to stack position i (word[0] at top)
        assert_eq!(
            stack_outputs.get_num_elements(4),
            &[word_at_addr[0], word_at_addr[1], word_at_addr[2], word_at_addr[3]]
        );
    }

    // load the contents of address 100 (should yield the ZERO word)
    {
        let mut processor = FastProcessor::new(StackInputs::new(&[Felt::from_u32(100)]).unwrap());
        processor.memory.write_word(ctx, addr, dummy_clk, word_at_addr.into()).unwrap();

        let program = simple_program_with_ops(vec![Operation::MLoadW]);
        let stack_outputs = processor.execute_sync_mut(&program, &mut host).unwrap();

        assert_eq!(stack_outputs.get_num_elements(16), &vec![ZERO; 16]);
    }
}

#[test]
fn test_mstorew_success() {
    let mut host = DefaultHost::default();
    let addr = Felt::from_u32(40);
    let word_to_store =
        Word::from([Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4)]);
    let ctx = 0_u32.into();
    let clk = 0_u32.into();

    // Store the word at address 40
    // Stack layout: [addr, word[0], word[1], word[2], word[3]] with addr at position 0 (top)
    let mut processor = FastProcessor::new(
        StackInputs::new(&[
            addr,
            word_to_store[0],
            word_to_store[1],
            word_to_store[2],
            word_to_store[3],
        ])
        .unwrap(),
    );
    let program = simple_program_with_ops(vec![Operation::MStoreW]);
    processor.execute_sync_mut(&program, &mut host).unwrap();

    // Ensure that the memory was correctly modified
    assert_eq!(processor.memory.read_word(ctx, addr, clk).unwrap(), word_to_store);
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
    let value_to_store = Felt::from_u32(value_to_store);

    // Store the value at address - addr at top, value at position 1
    let mut processor =
        FastProcessor::new(StackInputs::new(&[Felt::from_u32(addr), value_to_store]).unwrap());
    let program = simple_program_with_ops(vec![Operation::MStore]);
    processor.execute_sync_mut(&program, &mut host).unwrap();

    // Ensure that the memory was correctly modified
    let word_addr = addr - (addr % WORD_SIZE as u32);
    let word = processor.memory.read_word(ctx, Felt::from_u32(word_addr), clk).unwrap();
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
    let word_at_addr = [Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4)];
    let ctx = 0_u32.into();
    let dummy_clk = 0_u32.into();

    // Initialize processor with a word at address 40
    let mut processor =
        FastProcessor::new(StackInputs::new(&[Felt::from_u32(addr_to_access)]).unwrap());
    processor
        .memory
        .write_word(ctx, Felt::from_u32(addr_with_word), dummy_clk, word_at_addr.into())
        .unwrap();

    let program = simple_program_with_ops(vec![Operation::MLoad]);
    let stack_outputs = processor.execute_sync_mut(&program, &mut host).unwrap();

    // Ensure that Operation::MLoad correctly reads the value on the stack
    assert_eq!(
        stack_outputs.get_num_elements(1)[0],
        word_at_addr[addr_to_access as usize % WORD_SIZE]
    );
}

#[test]
fn test_mstream() {
    let mut host = DefaultHost::default();
    let addr = 40_u32;
    let word_at_addr_40 =
        Word::from([ONE, Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4)]);
    let word_at_addr_44 =
        Word::from([Felt::from_u32(5), Felt::from_u32(6), Felt::from_u32(7), Felt::from_u32(8)]);
    let ctx = 0_u32.into();
    let clk: RowIndex = 1_u32.into();

    let mut processor = {
        let mut stack_init = vec![ZERO; 16];
        stack_init[12] = Felt::from_u32(addr);
        FastProcessor::new(StackInputs::new(&stack_init).unwrap())
    };
    // Store values at addresses 40 and 44
    processor
        .memory
        .write_word(ctx, Felt::from_u32(addr), clk, word_at_addr_40)
        .unwrap();
    processor
        .memory
        .write_word(ctx, Felt::from_u32(addr + 4), clk, word_at_addr_44)
        .unwrap();

    let program = simple_program_with_ops(vec![Operation::MStream]);
    let stack_outputs = processor.execute_sync_mut(&program, &mut host).unwrap();

    // Word at addr 40 goes to positions 0-3, word at addr 44 goes to positions 4-7
    // word[0] at lowest position (top of stack)
    assert_eq!(
        stack_outputs.get_num_elements(8),
        &[
            word_at_addr_40[0],
            word_at_addr_40[1],
            word_at_addr_40[2],
            word_at_addr_40[3],
            word_at_addr_44[0],
            word_at_addr_44[1],
            word_at_addr_44[2],
            word_at_addr_44[3]
        ]
    );
}
