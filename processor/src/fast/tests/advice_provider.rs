use miden_assembly::package::Package;

use super::*;
use crate::test_utils::TestHost;

#[test]
fn test_advice_provider() {
    let kernel_source = "
        pub proc foo
            push.2323 mem_store.100 push.11 emit drop
        end
    ";

    let program_source = "
    @locals(4)
    proc truncate_stack
        loc_storew_be.0 dropw movupw.3
        sdepth neq.16
        while.true
            dropw movupw.3
            sdepth neq.16
        end
        loc_loadw_be.0
    end

    # mainly used to break basic blocks
    proc noop
        swap swap
    end

    # tests different cases of batch sizes
    proc basic_block
        # batch with 1 group
        swap drop swap push.1 emit drop

        call.noop

        # batch with 2 groups
        push.1 drop push.2 emit drop

        call.noop

        # batch with 3 groups (rounded up to 4)
        push.1 push.2 drop drop push.3 emit drop

        call.noop

        # batch with 5 groups (rounded up to 8)
        push.1 push.2 push.3 push.4 drop drop drop drop push.4 emit drop

        call.noop

        # batch with 8 pushes (which forces a noop to be inserted in the last position of the batch)
        push.0 push.1 push.2 push.3 push.4 push.5 push.6 push.7 push.5 emit drop

        call.noop

        # basic block with >1 batches (where clk needs to be incremented in-between batches due to the inserted RESPAN)
        push.0 push.1 push.2 push.3 push.4 push.5 push.6 push.6 emit drop
        drop drop drop drop drop drop drop drop drop push.7 emit drop
    end

    proc exec_me
        push.22 mem_store.0
        push.9 emit drop

    end

    proc dyncall_me
        push.23 mem_store.0
        push.100 emit drop

    end

    proc dynexec_me
        push.24 mem_store.0
        push.101 emit drop

    end

    proc will_syscall
        syscall.foo
    end

    proc control_flow
        # if true
        push.1 push.16 emit drop if.true
            swap swap push.17 emit drop
        else
            swap swap
        end

        # if false
        push.0 push.18 emit drop if.true
            swap swap
        else
            swap swap push.19 emit drop
        end

        # loop
        push.3 push.1
        while.true
            push.20 emit drop
            sub.1 dup neq.0
        end

        push.21 emit drop

    end

    begin
        # check that initial state is consistent
        push.0 emit drop push.10 add drop push.1 emit drop

        # check that basic blocks are handled correctly
        exec.basic_block

        # check that memory state is restored properly after call
        push.42 mem_store.0 push.8 emit drop
        exec.exec_me
        push.10 emit drop


        # check that syscalls are handled correctly
        call.will_syscall
        push.12 emit drop


        # check that dyncalls are handled correctly
        procref.dyncall_me mem_storew_le.4 dropw push.4 dyncall push.13 emit drop
        procref.will_syscall mem_storew_le.8 dropw push.8 dyncall push.14 emit drop

        # check that dynexecs are handled correctly
        procref.dynexec_me mem_storew_le.4 dropw push.4 dynexec push.15 emit drop

        # check that control flow operations are handled correctly
        exec.control_flow

        exec.truncate_stack
        push.22 emit drop

    end
    ";

    let (program, kernel_lib) = {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let kernel = parse_kernel_source(source_manager.clone(), kernel_source);

        let kernel_lib = Assembler::new(source_manager.clone())
            .assemble_kernel("kernel", kernel)
            .map(Arc::<Package>::from)
            .unwrap();
        let program = Assembler::with_kernel(source_manager, kernel_lib.clone())
            .unwrap()
            .assemble_program("program", exec_source(program_source))
            .unwrap()
            .unwrap_program();

        (program, kernel_lib)
    };

    let mut fast_host = TestHost::with_kernel_forest(kernel_lib.mast_forest().clone());
    let processor = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default())
        .expect("advice inputs should fit advice map limits");
    let fast_stack_outputs = processor.execute_sync(&program, &mut fast_host).unwrap().stack;

    // check outputs
    insta::assert_debug_snapshot!("stack_outputs", fast_stack_outputs);

    // check event checkpoints
    insta::assert_debug_snapshot!("event_checkpoints", fast_host.snapshots());
}
