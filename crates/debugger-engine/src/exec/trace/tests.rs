use std::sync::Arc;

use miden_assembly::DefaultSourceManager;
use miden_assembly_syntax::ast::types::Type;
use miden_processor::{ContextId, trace::RowIndex};

use super::ExecutionTrace;
use crate::{Executor, debug::NativePtr, exec::DebugQuery, felt::ToMidenRepr};

fn empty_trace() -> ExecutionTrace {
    ExecutionTrace {
        processor: miden_processor::FastProcessor::new(miden_processor::StackInputs::default()),
        outputs: miden_processor::StackOutputs::default(),
    }
}

fn execute_trace(source: &str) -> ExecutionTrace {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let program = miden_assembly::Assembler::new(source_manager.clone())
        .assemble_program("program", source)
        .map(Arc::from)
        .unwrap();

    Executor::new(vec![]).capture_trace(program, source_manager)
}

#[test]
fn parse_result_reads_multi_felt_outputs_in_stack_order() {
    let outputs = 0x0807_0605_0403_0201_u64.to_felts();
    let trace = ExecutionTrace {
        outputs: miden_processor::StackOutputs::new(&outputs).unwrap(),
        ..empty_trace()
    };

    let result = trace.parse_result::<u64>().unwrap();

    assert_eq!(result, 0x0807_0605_0403_0201_u64);
}

#[test]
fn read_bytes_for_type_preserves_little_endian_bytes() {
    let trace = execute_trace(
        r#"
begin
    push.4660
    push.8
    mem_store

    push.67305985
    push.12
    mem_store

    push.134678021
    push.13
    mem_store
end
"#,
    );
    let ctx = ContextId::root();

    let u16_bytes = trace
        .read_bytes_for_type_in_context(
            NativePtr::new(8, 0),
            &Type::U16,
            ctx,
            RowIndex::from(0_u32),
        )
        .unwrap();
    let u64_bytes = trace
        .read_bytes_for_type_in_context(
            NativePtr::new(12, 0),
            &Type::U64,
            ctx,
            RowIndex::from(0_u32),
        )
        .unwrap();
    let unaligned_u32_bytes = trace
        .read_bytes_for_type_in_context(
            NativePtr::new(12, 1),
            &Type::U32,
            ctx,
            RowIndex::from(0_u32),
        )
        .unwrap();

    assert_eq!(u16_bytes, vec![0x34, 0x12]);
    assert_eq!(u64_bytes, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(unaligned_u32_bytes, vec![2, 3, 4, 5]);
}

#[test]
fn debug_query_reads_rust_memory_from_byte_address() {
    let trace = execute_trace(
        r#"
begin
    push.67305985
    push.3
    mem_store

    push.134678021
    push.4
    mem_store
end
"#,
    );

    assert_eq!(trace.read_from_rust_memory::<u64>(12), Some(0x0807_0605_0403_0201));
}

#[test]
fn debug_query_reads_uninitialized_rust_memory_as_zero() {
    let trace = execute_trace(
        r#"
begin
    push.67305985
    push.3
    mem_store
end
"#,
    );

    assert_eq!(trace.read_from_rust_memory::<u64>(12), Some(0x0000_0000_0403_0201));
}
