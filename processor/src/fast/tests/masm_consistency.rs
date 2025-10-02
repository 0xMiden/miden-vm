use super::*;

#[rstest]
// ---- syscalls --------------------------------

// check stack is preserved after syscall
#[case(Some("export.foo add end"), "begin push.1 syscall.foo swap.8 drop end", vec![16_u32.into(); 16])]
// check that `fn_hash` register is updated correctly
#[case(Some("export.foo caller end"), "begin syscall.foo end", vec![16_u32.into(); 16])]
#[case(Some("export.foo caller end"), "proc.bar syscall.foo end begin call.bar end", vec![16_u32.into(); 16])]
// check that clk works correctly through syscalls
#[case(Some("export.foo clk add end"), "begin syscall.foo end", vec![16_u32.into(); 16])]
// check that fmp register is updated correctly after syscall
#[case(Some("export.foo.2 locaddr.0 locaddr.1 swap.8 drop swap.8 drop end"), "proc.bar syscall.foo end begin call.bar end", vec![16_u32.into(); 16])]
// check that memory context is updated correctly across a syscall (i.e. anything stored before the
// syscall is retrievable after, but not during)
#[case(Some("export.foo add end"), "proc.bar push.100 mem_store.44 syscall.foo mem_load.44 swap.8 drop end begin call.bar end", vec![16_u32.into(); 16])]
// check that syscalls share the same memory context
#[case(Some("export.foo push.100 mem_store.44 end export.baz mem_load.44 swap.8 drop end"), 
    "proc.bar 
        syscall.foo syscall.baz 
    end 
    begin call.bar end", 
    vec![16_u32.into(); 16]
)]
// ---- calls ------------------------

// check stack is preserved after call
#[case(None, "proc.foo add end begin push.1 call.foo swap.8 drop end", vec![16_u32.into(); 16])]
// check that `clk` works correctly though calls
#[case(None, "
    proc.foo clk add end 
    begin push.1 
    if.true call.foo else swap end 
    clk swap.8 drop
    end", 
    vec![16_u32.into(); 16]
)]
// check that fmp register is updated correctly after call
#[case(None,"
    proc.foo.2 locaddr.0 locaddr.1 swap.8 drop swap.8 drop end
    begin call.foo end", 
    vec![16_u32.into(); 16]
)]
// check that 2 functions creating different memory contexts don't interfere with each other
#[case(None,"
    proc.foo push.100 mem_store.44 end
    proc.bar mem_load.44 assertz end
    begin call.foo mem_load.44 assertz call.bar end", 
    vec![16_u32.into(); 16]
)]
// check that memory context is updated correctly across a call (i.e. anything stored before the
// call is retrievable after, but not during)
#[case(None,"
    proc.foo mem_load.44 assertz end
    proc.bar push.100 mem_store.44 call.foo mem_load.44 swap.8 drop end
    begin call.bar end", 
    vec![16_u32.into(); 16]
)]
// ---- dyncalls ------------------------

// check stack is preserved after dyncall
#[case(None, "
    proc.foo add end 
    begin 
        procref.foo mem_storew.100 dropw push.100
        dyncall swap.8 drop 
    end", 
    vec![16_u32.into(); 16]
)]
// check that `clk` works correctly though dyncalls
#[case(None, "
    proc.foo clk add end 
    begin 
        push.1 
        if.true 
            procref.foo mem_storew.100 dropw
            push.100 dyncall
            push.100 dyncall
        else 
            swap 
        end 
        clk swap.8 drop
    end", 
    vec![16_u32.into(); 16]
)]
// check that fmp register is updated correctly after dyncall
#[case(None,"
    proc.foo.2 locaddr.0 locaddr.1 swap.8 drop swap.8 drop end
    begin 
        procref.foo mem_storew.100 dropw push.100
        dyncall
    end", 
    vec![16_u32.into(); 16]
)]
// check that 2 functions creating different memory contexts don't interfere with each other
#[case(None,"
    proc.foo push.100 mem_store.44 end
    proc.bar mem_load.44 assertz end
    begin 
        procref.foo mem_storew.100 dropw push.100 dyncall
        mem_load.44 assertz 
        procref.bar mem_storew.104 dropw push.104 dyncall
    end", 
    vec![16_u32.into(); 16]
)]
// check that memory context is updated correctly across a dyncall (i.e. anything stored before the
// call is retrievable after, but not during)
#[case(None,"
    proc.foo mem_load.44 assertz end
    proc.bar 
        push.100 mem_store.44 
        procref.foo mem_storew.104 dropw push.104 dyncall
        mem_load.44 swap.8 drop 
    end
    begin 
        procref.bar mem_storew.104 dropw push.104 dyncall
    end", 
    vec![16_u32.into(); 16]
)]
// ---- dyn ------------------------

// check stack is preserved after dynexec
#[case(None, "
    proc.foo add end 
    begin 
        procref.foo mem_storew.100 dropw push.100
        dynexec swap.8 drop 
    end", 
    vec![16_u32.into(); 16]
)]
// check that `clk` works correctly though dynexecs
#[case(None, "
    proc.foo clk add end 
    begin 
        push.1 
        if.true 
            procref.foo mem_storew.100 dropw
            push.100 dynexec
            push.100 dynexec
        else 
            swap 
        end 
        clk swap.8 drop
    end", 
    vec![16_u32.into(); 16]
)]
// check that fmp register is updated correctly after dynexec
#[case(None,"
    proc.foo.2 locaddr.0 locaddr.1 swap.8 drop swap.8 drop end
    begin 
        procref.foo mem_storew.100 dropw push.100
        dynexec
    end", 
    vec![16_u32.into(); 16]
)]
// check that dynexec doesn't create a new memory context
#[case(None,"
    proc.foo push.100 mem_store.44 end
    proc.bar mem_load.44 sub.100 assertz end
    begin 
        procref.foo mem_storew.104 dropw push.104 dynexec
        mem_load.44 sub.100 assertz 
        procref.bar mem_storew.108 dropw push.108 dynexec
    end", 
    vec![16_u32.into(); 16]
)]
// ---- loop --------------------------------

// check that the loop is never entered if the condition is false (and that clk is properly updated)
#[case(None, "begin while.true push.1 assertz end clk swap.8 drop end", vec![3_u32.into(), 2_u32.into(), 1_u32.into(), ZERO])]
// check that the loop is entered if the condition is true, and that the stack and clock are managed
// properly
#[case(None,
    "begin 
        while.true 
            clk swap.15 drop
        end 
        clk swap.8 drop 
        end",
    vec![42_u32.into(), ZERO, ONE, ONE, ONE, ONE]
)]
// ---- horner ops --------------------------------
#[case(None,
    "begin
        push.1.2.3.4 mem_storew.40 dropw
        horner_eval_base
        end",
    // first 3 addresses in the vec are the alpha_ptr, acc_high and acc_low, respectively.
    vec![100_u32.into(), 4_u32.into(), 40_u32.into(), 4_u32.into(), 5_u32.into(), 6_u32.into(), 7_u32.into(),
        8_u32.into(), 9_u32.into(), 10_u32.into(), 11_u32.into(), 12_u32.into(), 13_u32.into(),
        14_u32.into(), 15_u32.into(), 16_u32.into()]
)]
// ---- log precompile ops --------------------------------
#[case(None,
    "begin
        log_precompile
        end",
    vec![1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into(),
         5_u32.into(), 6_u32.into(), 7_u32.into(), 8_u32.into()],
)]
#[case(None,
    "begin 
        push.1.2.3.4 mem_storew.40 dropw
        horner_eval_ext
        end",
    // first 3 addresses in the vec are the alpha_ptr, acc_high and acc_low, respectively.
    vec![100_u32.into(), 4_u32.into(), 40_u32.into(), 4_u32.into(), 5_u32.into(), 6_u32.into(), 7_u32.into(),
        8_u32.into(), 9_u32.into(), 10_u32.into(), 11_u32.into(), 12_u32.into(), 13_u32.into(),
        14_u32.into(), 15_u32.into(), 16_u32.into()]
)]
// ---- u32 ops --------------------------------
// check that u32 6/3 works as expected
#[case(None,"
    begin 
        u32divmod
    end", 
    vec![6_u32.into(), 3_u32.into()]
)]
// check that overflowing add properly sets the overflow bit
#[case(None,"
    begin 
        u32overflowing_add sub.1 assertz
    end", 
    vec![Felt::from(u32::MAX), ONE]
)]
fn test_masm_consistency(
    #[case] kernel_source: Option<&'static str>,
    #[case] program_source: &'static str,
    #[case] stack_inputs: Vec<Felt>,
) {
    let (program, kernel_lib) = {
        let source_manager = Arc::new(DefaultSourceManager::default());

        match kernel_source {
            Some(kernel_source) => {
                let kernel_lib =
                    Assembler::new(source_manager.clone()).assemble_kernel(kernel_source).unwrap();
                let program = Assembler::with_kernel(source_manager, kernel_lib.clone())
                    .assemble_program(program_source)
                    .unwrap();

                (program, Some(kernel_lib))
            },
            None => {
                let program =
                    Assembler::new(source_manager).assemble_program(program_source).unwrap();
                (program, None)
            },
        }
    };

    let mut host = DefaultHost::default();
    if let Some(kernel_lib) = &kernel_lib {
        host.load_library(kernel_lib.mast_forest()).unwrap();
    }

    // fast processor
    let processor = FastProcessor::new(&stack_inputs);
    let fast_stack_outputs = processor.execute_sync(&program, &mut host).unwrap();

    // slow processor
    let mut slow_processor = Process::new(
        kernel_lib.map(|k| k.kernel().clone()).unwrap_or_default(),
        StackInputs::new(stack_inputs).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    );
    let slow_stack_outputs = slow_processor.execute(&program, &mut host).unwrap();

    assert_eq!(fast_stack_outputs, slow_stack_outputs);
}

/// Tests that emitted errors are consistent between the fast and slow processors.
#[rstest]
// check that error is returned if condition is not a boolean
#[case(None, "begin while.true swap end end", vec![2_u32.into(); 16])]
#[case(None, "begin while.true push.100 end end", vec![ONE; 16])]
// check that dynamically calling a hash that doesn't exist fails
#[case(None,"
    begin 
        dyncall
    end", 
    vec![16_u32.into(); 16]
)]
// check that dynamically calling a hash that doesn't exist fails
#[case(None,"
    begin 
        dynexec
    end", 
    vec![16_u32.into(); 16]
)]
// check that u32 division by 0 results in an error
#[case(None,"
    begin 
        u32divmod
    end", 
    vec![ZERO; 16]
)]
// check that adding any value to a u32::MAX results in an error
#[case(None,"
    begin 
        u32overflowing_add
    end", 
    vec![Felt::from(u32::MAX) + ONE, ZERO]
)]
fn test_masm_errors_consistency(
    #[case] kernel_source: Option<&'static str>,
    #[case] program_source: &'static str,
    #[case] stack_inputs: Vec<Felt>,
) {
    let (program, kernel_lib) = {
        let source_manager = Arc::new(DefaultSourceManager::default());

        match kernel_source {
            Some(kernel_source) => {
                let kernel_lib =
                    Assembler::new(source_manager.clone()).assemble_kernel(kernel_source).unwrap();
                let program = Assembler::with_kernel(source_manager, kernel_lib.clone())
                    .assemble_program(program_source)
                    .unwrap();

                (program, Some(kernel_lib))
            },
            None => {
                let program =
                    Assembler::new(source_manager).assemble_program(program_source).unwrap();
                (program, None)
            },
        }
    };

    let mut host = DefaultHost::default();
    if let Some(kernel_lib) = &kernel_lib {
        host.load_library(kernel_lib.mast_forest()).unwrap();
    }

    // fast processor
    let processor = FastProcessor::new(&stack_inputs);
    let fast_stack_outputs = processor.execute_sync(&program, &mut host).unwrap_err();

    // slow processor
    let mut slow_processor = Process::new(
        kernel_lib.map(|k| k.kernel().clone()).unwrap_or_default(),
        StackInputs::new(stack_inputs).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    );
    let slow_stack_outputs = slow_processor.execute(&program, &mut host).unwrap_err();

    assert_eq!(fast_stack_outputs.to_string(), slow_stack_outputs.to_string());
}

/// Tests that `log_precompile` correctly computes the RPO permutation and updates the stack.
///
/// This test verifies:
/// 1. The RPO permutation is applied correctly to [CAP_PREV, TAG, HASH_CALL_DATA]
/// 2. The stack is updated with [R0, R1, CAP_NEXT] as expected
/// 3. The capacity is properly initialized to [0,0,0,0] for the first call
#[test]
fn test_log_precompile_correctness() {
    use miden_core::crypto::hash::Rpo256;

    // Stack inputs: [1,2,3,4,5,6,7,8] (provided to both processors)
    // After initialization: Both processors reverse, giving stack = [8,7,6,5,4,3,2,1] (8 on top)
    // Maps to: HASH_CALL_DATA=[5,6,7,8], TAG=[1,2,3,4]
    let stack_inputs = vec![
        1_u32.into(),
        2_u32.into(),
        3_u32.into(),
        4_u32.into(),
        5_u32.into(),
        6_u32.into(),
        7_u32.into(),
        8_u32.into(),
    ];

    // Compute expected output using RPO permutation
    // Input state: [CAP_PREV, TAG, HASH_CALL_DATA]
    // CAP_PREV is initialized to [0,0,0,0] by default
    let mut hasher_state = [ZERO; 12];
    // CAP_PREV (positions 0-3): [0,0,0,0]
    hasher_state[0..4].copy_from_slice(&[ZERO, ZERO, ZERO, ZERO]);
    // TAG (positions 4-7): stack.get(4..7) = [1,2,3,4]
    hasher_state[4..8].copy_from_slice(&[1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into()]);
    // HASH_CALL_DATA (positions 8-11): stack.get(0..3) = [5,6,7,8]
    hasher_state[8..12].copy_from_slice(&[5_u32.into(), 6_u32.into(), 7_u32.into(), 8_u32.into()]);

    // Apply RPO permutation
    Rpo256::apply_permutation(&mut hasher_state);

    // Extract expected outputs
    // Output state layout: [CAP_NEXT (0-3), R0 (4-7), R1 (8-11)]
    // But on stack, each word is written reversed: [R0[3], R0[2], R0[1], R0[0], ...]
    let expected_cap_next = [hasher_state[0], hasher_state[1], hasher_state[2], hasher_state[3]];
    let expected_r0 = [hasher_state[4], hasher_state[5], hasher_state[6], hasher_state[7]];
    let expected_r1 = [hasher_state[8], hasher_state[9], hasher_state[10], hasher_state[11]];

    // Stack output order: each word is reversed
    let expected_r1_on_stack = [expected_r1[3], expected_r1[2], expected_r1[1], expected_r1[0]];
    let expected_r0_on_stack = [expected_r0[3], expected_r0[2], expected_r0[1], expected_r0[0]];
    let expected_cap_next_on_stack = [
        expected_cap_next[3],
        expected_cap_next[2],
        expected_cap_next[1],
        expected_cap_next[0],
    ];

    // Execute the program
    let program_source = "begin log_precompile end";
    let program = {
        let source_manager = Arc::new(DefaultSourceManager::default());
        Assembler::new(source_manager).assemble_program(program_source).unwrap()
    };

    let mut host = DefaultHost::default();
    let processor = FastProcessor::new(&stack_inputs);
    let stack_outputs = processor.execute_sync(&program, &mut host).unwrap();

    // Verify stack outputs: [R1, R0, CAP_NEXT, ...]
    let output_stack = stack_outputs.stack_truncated(16);

    // Check R1 (positions 0-3) - reversed on stack
    assert_eq!(output_stack[0], expected_r1_on_stack[0], "R1[3] on stack mismatch");
    assert_eq!(output_stack[1], expected_r1_on_stack[1], "R1[2] on stack mismatch");
    assert_eq!(output_stack[2], expected_r1_on_stack[2], "R1[1] on stack mismatch");
    assert_eq!(output_stack[3], expected_r1_on_stack[3], "R1[0] on stack mismatch");

    // Check R0 (positions 4-7) - reversed on stack
    assert_eq!(output_stack[4], expected_r0_on_stack[0], "R0[3] on stack mismatch");
    assert_eq!(output_stack[5], expected_r0_on_stack[1], "R0[2] on stack mismatch");
    assert_eq!(output_stack[6], expected_r0_on_stack[2], "R0[1] on stack mismatch");
    assert_eq!(output_stack[7], expected_r0_on_stack[3], "R0[0] on stack mismatch");

    // Check CAP_NEXT (positions 8-11) - reversed on stack
    assert_eq!(output_stack[8], expected_cap_next_on_stack[0], "CAP_NEXT[3] on stack mismatch");
    assert_eq!(output_stack[9], expected_cap_next_on_stack[1], "CAP_NEXT[2] on stack mismatch");
    assert_eq!(output_stack[10], expected_cap_next_on_stack[2], "CAP_NEXT[1] on stack mismatch");
    assert_eq!(output_stack[11], expected_cap_next_on_stack[3], "CAP_NEXT[0] on stack mismatch");

    // Positions 12-15 should be zeros (default padding)
    assert_eq!(output_stack[12], ZERO, "Stack position 12 should be 0");
    assert_eq!(output_stack[13], ZERO, "Stack position 13 should be 0");
    assert_eq!(output_stack[14], ZERO, "Stack position 14 should be 0");
    assert_eq!(output_stack[15], ZERO, "Stack position 15 should be 0");
}
