use alloc::string::String;

use miden_core::field::PrimeCharacteristicRing;
use rstest::fixture;

use super::*;

#[rstest]
// ---- syscalls --------------------------------

// check stack is preserved after syscall
#[case(Some("pub proc foo add end"), "begin push.1 syscall.foo swap.8 drop end", vec![Felt::from_u32(16); 16])]
// check that `fn_hash` register is updated correctly
#[case(Some("pub proc foo caller end"), "begin syscall.foo end", vec![Felt::from_u32(16); 16])]
#[case(Some("pub proc foo caller end"), "proc bar syscall.foo end begin call.bar end", vec![Felt::from_u32(16); 16])]
// check that clk works correctly through syscalls
#[case(Some("pub proc foo clk add end"), "begin syscall.foo end", vec![Felt::from_u32(16); 16])]
// check that fmp register is updated correctly after syscall
#[case(Some("@locals(2) pub proc foo locaddr.0 locaddr.1 swap.8 drop swap.8 drop end"), "proc bar syscall.foo end begin call.bar end", vec![Felt::from_u32(16); 16])]
// check that memory context is updated correctly across a syscall (i.e. anything stored before the
// syscall is retrievable after, but not during)
#[case(Some("pub proc foo add end"), "proc bar push.100 mem_store.44 syscall.foo mem_load.44 swap.8 drop end begin call.bar end", vec![Felt::from_u32(16); 16])]
// check that syscalls share the same memory context
#[case(Some("pub proc foo push.100 mem_store.44 end pub proc baz mem_load.44 swap.8 drop end"),
    "proc bar
        syscall.foo syscall.baz
    end
    begin call.bar end",
    vec![Felt::from_u32(16); 16]
)]
// ---- calls ------------------------

// check stack is preserved after call
#[case(None, "proc foo add end begin push.1 call.foo swap.8 drop end", vec![Felt::from_u32(16); 16])]
// check that `clk` works correctly though calls
#[case(None, "
    proc foo clk add end
    begin push.1
    if.true call.foo else swap end
    clk swap.8 drop
    end",
    vec![Felt::from_u32(16); 16]
)]
// check that fmp register is updated correctly after call
#[case(None,"
    @locals(2) proc foo locaddr.0 locaddr.1 swap.8 drop swap.8 drop end
    begin call.foo end",
    vec![Felt::from_u32(16); 16]
)]
// check that 2 functions creating different memory contexts don't interfere with each other
#[case(None,"
    proc foo push.100 mem_store.44 end
    proc bar mem_load.44 assertz end
    begin call.foo mem_load.44 assertz call.bar end",
    vec![Felt::from_u32(16); 16]
)]
// check that memory context is updated correctly across a call (i.e. anything stored before the
// call is retrievable after, but not during)
#[case(None,"
    proc foo mem_load.44 assertz end
    proc bar push.100 mem_store.44 call.foo mem_load.44 swap.8 drop end
    begin call.bar end",
    vec![Felt::from_u32(16); 16]
)]
// ---- dyncalls ------------------------

// check stack is preserved after dyncall
#[case(None, "
    proc foo add end
    begin
        procref.foo mem_storew_le.100 dropw push.100
        dyncall swap.8 drop
    end",
    vec![Felt::from_u32(16); 16]
)]
// check that `clk` works correctly though dyncalls
#[case(None, "
    proc foo clk add end
    begin
        push.1
        if.true
            procref.foo mem_storew_le.100 dropw
            push.100 dyncall
            push.100 dyncall
        else
            swap
        end
        clk swap.8 drop
    end",
    vec![Felt::from_u32(16); 16]
)]
// check that fmp register is updated correctly after dyncall
#[case(None,"
    @locals(2) proc foo locaddr.0 locaddr.1 swap.8 drop swap.8 drop end
    begin
        procref.foo mem_storew_le.100 dropw push.100
        dyncall
    end",
    vec![Felt::from_u32(16); 16]
)]
// check that 2 functions creating different memory contexts don't interfere with each other
#[case(None,"
    proc foo push.100 mem_store.44 end
    proc bar mem_load.44 assertz end
    begin
        procref.foo mem_storew_le.100 dropw push.100 dyncall
        mem_load.44 assertz
        procref.bar mem_storew_le.104 dropw push.104 dyncall
    end",
    vec![Felt::from_u32(16); 16]
)]
// check that memory context is updated correctly across a dyncall (i.e. anything stored before the
// call is retrievable after, but not during)
#[case(None,"
    proc foo mem_load.44 assertz end
    proc bar
        push.100 mem_store.44
        procref.foo mem_storew_le.104 dropw push.104 dyncall
        mem_load.44 swap.8 drop
    end
    begin
        procref.bar mem_storew_le.104 dropw push.104 dyncall
    end",
    vec![Felt::from_u32(16); 16]
)]
// ---- dyn ------------------------

// check stack is preserved after dynexec
#[case(None, "
    proc foo add end
    begin
        procref.foo mem_storew_le.100 dropw push.100
        dynexec swap.8 drop
    end",
    vec![Felt::from_u32(16); 16]
)]
// check that `clk` works correctly though dynexecs
#[case(None, "
    proc foo clk add end
    begin
        push.1
        if.true
            procref.foo mem_storew_le.100 dropw
            push.100 dynexec
            push.100 dynexec
        else
            swap
        end
        clk swap.8 drop
    end",
    vec![Felt::from_u32(16); 16]
)]
// check that fmp register is updated correctly after dynexec
#[case(None,"
    @locals(2) proc foo locaddr.0 locaddr.1 swap.8 drop swap.8 drop end
    begin
        procref.foo mem_storew_le.100 dropw push.100
        dynexec
    end",
    vec![Felt::from_u32(16); 16]
)]
// check that dynexec doesn't create a new memory context
#[case(None,"
    proc foo push.100 mem_store.44 end
    proc bar mem_load.44 sub.100 assertz end
    begin
        procref.foo mem_storew_le.104 dropw push.104 dynexec
        mem_load.44 sub.100 assertz
        procref.bar mem_storew_le.108 dropw push.108 dynexec
    end",
    vec![Felt::from_u32(16); 16]
)]
// ---- loop --------------------------------

// check that the loop is never entered if the condition is false (and that clk is properly updated)
// Stack: [ZERO, 1, 2, 3] with ZERO at top (for while.true condition)
#[case(None, "begin while.true push.1 assertz end clk swap.8 drop end", vec![ZERO, Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3)])]
// check that the loop is entered if the condition is true, and that the stack and clock are managed
// properly
// Stack: [ONE, ONE, ONE, ONE, ZERO, 42] with first ONE at top (for while.true condition)
#[case(None,
    "begin
        while.true
            clk swap.15 drop
        end
        clk swap.8 drop
    end",
    vec![ONE, ONE, ONE, ONE, ZERO, Felt::from_u32(42)]
)]
// ---- horner ops --------------------------------
#[case(None,
    "begin
        push.1.2.3.4 mem_storew_le.40 dropw
        horner_eval_base
    end",
    vec![Felt::from_u32(16), Felt::from_u32(15), Felt::from_u32(14), Felt::from_u32(13), Felt::from_u32(12), Felt::from_u32(11), Felt::from_u32(10),
        Felt::from_u32(9), Felt::from_u32(8), Felt::from_u32(7), Felt::from_u32(6), Felt::from_u32(5), Felt::from_u32(4),
        Felt::from_u32(40), Felt::from_u32(4), Felt::from_u32(100)]
)]
#[case(None,
    "begin
        push.1.2.3.4 mem_storew_le.40 dropw
        horner_eval_ext
        end",
    vec![Felt::from_u32(16), Felt::from_u32(15), Felt::from_u32(14), Felt::from_u32(13), Felt::from_u32(12), Felt::from_u32(11), Felt::from_u32(10),
        Felt::from_u32(9), Felt::from_u32(8), Felt::from_u32(7), Felt::from_u32(6), Felt::from_u32(5), Felt::from_u32(4),
        Felt::from_u32(40), Felt::from_u32(4), Felt::from_u32(100)]
)]
// ---- log precompile ops --------------------------------
// Stack: [1, 2, 3, 4, 5, 6, 7, 8] with 1 at top
#[case(None, "begin log_precompile end",
    vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4),
         Felt::from_u32(5), Felt::from_u32(6), Felt::from_u32(7), Felt::from_u32(8)],
)]
// ---- u32 ops --------------------------------
// check that u32 6/3 works as expected
#[case(None,"
    begin
        u32divmod
    end",
    vec![Felt::from_u32(6), Felt::from_u32(3)]
)]
// check that overflowing add properly sets the overflow bit
#[case(None,"
    begin
        u32overflowing_add swap sub.1 assertz
    end",
    vec![Felt::from_u32(u32::MAX), ONE]
)]
fn test_masm_consistency(
    testname: String,
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
    let processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap());
    let fast_stack_outputs = processor.execute_sync(&program, &mut host).unwrap().stack;

    // fast processor by step
    let stepped_stack_outputs = {
        let processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap());
        processor.execute_by_step_sync(&program, &mut host).unwrap()
    };

    assert_eq!(fast_stack_outputs, stepped_stack_outputs);
    insta::assert_debug_snapshot!(testname, fast_stack_outputs);
}

/// Tests that emitted errors are consistent between the fast and slow processors.
#[rstest]
// check that error is returned if condition is not a boolean
#[case(None, "begin while.true swap end end", vec![Felt::from_u32(2); 16])]
#[case(None, "begin while.true push.100 end end", vec![ONE; 16])]
// check that dynamically calling a hash that doesn't exist fails
#[case(None,"
    begin
        dyncall
    end",
    vec![Felt::from_u32(16); 16]
)]
// check that dynamically calling a hash that doesn't exist fails
#[case(None,"
    begin
        dynexec
    end",
    vec![Felt::from_u32(16); 16]
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
    vec![Felt::from_u32(u32::MAX) + ONE, ZERO]
)]
fn test_masm_errors_consistency(
    testname: String,
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
    let processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap());
    let fast_err = processor.execute_sync(&program, &mut host).unwrap_err();

    // fast processor by step
    let fast_stepped_err = {
        let processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap());
        processor.execute_by_step_sync(&program, &mut host).unwrap_err()
    };

    assert_eq!(fast_err.to_string(), fast_stepped_err.to_string());
    insta::assert_debug_snapshot!(testname, fast_err);
}

/// Tests that `log_precompile` correctly computes the RPO permutation and updates the stack.
///
/// This test verifies:
/// 1. The RPO permutation is applied correctly with LE sponge layout [RATE0, RATE1, CAP]
/// 2. The stack is updated with [R0, R1, CAP_NEXT] as expected
/// 3. The capacity is properly initialized to [0,0,0,0] for the first call
#[test]
fn test_log_precompile_correctness() {
    use miden_core::crypto::hash::Rpo256;

    // Stack inputs: [1,2,3,4,5,6,7,8] with 1 at top
    // The stack represents [COMM, TAG] where COMM=[1,2,3,4] and TAG=[5,6,7,8]
    let stack_inputs = [1, 2, 3, 4, 5, 6, 7, 8].map(Felt::new);
    let comm_calldata: Word = [1, 2, 3, 4].map(Felt::new).into();
    let tag: Word = [5, 6, 7, 8].map(Felt::new).into();
    let cap_prev = Word::empty();

    // Compute expected output using RPO permutation
    // Input state: [COMM, TAG, CAP_PREV], with CAP_PREV = [0,0,0,0]
    let mut hasher_state = [ZERO; 12];
    hasher_state[0..4].copy_from_slice(comm_calldata.as_slice());
    hasher_state[4..8].copy_from_slice(tag.as_slice());
    hasher_state[8..12].copy_from_slice(cap_prev.as_slice());

    // Apply RPO permutation
    Rpo256::apply_permutation(&mut hasher_state);

    // The implementation writes output to stack as:
    // stack[0..4] = R0 elements, stack[4..8] = R1 elements, stack[8..12] = CAP_NEXT elements
    // Each written as: stack[i] = word[i]
    let expected_r0: Word = hasher_state[0..4].try_into().unwrap();
    let expected_r1: Word = hasher_state[4..8].try_into().unwrap();
    let expected_cap: Word = hasher_state[8..12].try_into().unwrap();

    // Execute the program
    let program_source = "begin log_precompile end";
    let program = {
        let source_manager = Arc::new(DefaultSourceManager::default());
        Assembler::new(source_manager).assemble_program(program_source).unwrap()
    };

    let mut host = DefaultHost::default();
    let processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap());
    let execution_output = processor.execute_sync(&program, &mut host).unwrap();

    let actual_r0 = execution_output.stack.get_word(0).unwrap();
    let actual_r1 = execution_output.stack.get_word(4).unwrap();
    let actual_cap = execution_output.stack.get_word(8).unwrap();

    assert_eq!(expected_r0, actual_r0, "R0 mismatch");
    assert_eq!(expected_r1, actual_r1, "R1 mismatch");
    assert_eq!(expected_cap, actual_cap, "CAP_NEXT mismatch");
}

// Workaround to make insta and rstest work together.
// See: https://github.com/la10736/rstest/issues/183#issuecomment-1564088329
#[fixture]
fn testname() -> String {
    // Replace `::` with `__` to make snapshot file names Windows-compatible.
    // Windows does not allow `:` in file names.
    std::thread::current().name().unwrap().replace("::", "__")
}
