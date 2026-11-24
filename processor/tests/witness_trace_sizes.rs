//! Cross-check live row estimates against witness materialization, including on threadless WASM.

use miden_assembly::Assembler;
use miden_processor::{
    DefaultHost, ExecutionOptions, Felt, Processor, Program, StackInputs, advice::AdviceInputs,
};
use miden_utils_testing::crypto::{MerkleTree, init_merkle_leaf, init_merkle_store};

/// Repeated and multi-batch blocks exercise controller addresses across fragment boundaries.
const PROGRAM: &str = "
begin
    push.1 push.2
    repeat.8
        u32wrapping_add dup.1 swap
        push.3 u32and drop
    end
    if.true
        push.5 mul
    else
        push.7 add
    end
    padw padw padw compress dropw dropw dropw
    repeat.4
        push.11 u32wrapping_add
    end
    drop
end
";

fn request<'p>(program: &'p Program, stack: &[u64], advice: AdviceInputs) -> Processor<'p> {
    let stack: Vec<Felt> = stack.iter().map(|&v| Felt::new(v).unwrap()).collect();
    let options = ExecutionOptions::default()
        .with_core_trace_fragment_size(64)
        .expect("valid fragment size");
    Processor::new(program)
        .with_stack_inputs(StackInputs::new(&stack).unwrap())
        .with_advice(advice)
        .with_options(options)
}

fn check_trace_sizes(program_src: &str, stack: &[u64], advice: &AdviceInputs) {
    let program = Assembler::default()
        .assemble_program("test", program_src)
        .unwrap()
        .unwrap_program();
    let halted = request(&program, stack, advice.clone())
        .record_witness()
        .start()
        .unwrap()
        .run_to_completion_sync(&mut DefaultHost::default())
        .unwrap();
    let estimate = halted.trace_len_upper_bound().unwrap();
    let output = halted.finish().unwrap();
    let (vm, precompile) = output.witness.into_parts();
    assert!(precompile.is_none());
    let trace = vm.build_trace(&miden_vm_stark::memory::default_budget()).unwrap();
    assert_eq!(output.claim.stack_outputs(), trace.stack_outputs());
    let actual = trace.trace_len_summary();
    assert_eq!(estimate.core_rows(), actual.core_rows());
    assert_eq!(estimate.core_height(), actual.core_height());
    assert_eq!(estimate.chiplets(), actual.chiplets());
    assert_eq!(estimate.chiplets_height(), actual.chiplets_height());
    assert_eq!(estimate.byte_pair_lookup_rows(), actual.byte_pair_lookup_rows());
    assert!(estimate.eidos_compression_rows() >= actual.eidos_compression_rows());
    assert!(estimate.eidos_compression_height() >= actual.eidos_compression_height());
}

#[test]
fn witness_trace_sizes() {
    check_trace_sizes(PROGRAM, &[1], &AdviceInputs::default());
    check_trace_sizes(
        "begin crypto_stream end",
        &[1, 2, 3, 4, 0, 0, 8, 1],
        &AdviceInputs::default(),
    );
}

#[test]
fn merkle_witness_trace_sizes() {
    let index = 3usize;
    let (leaves, store) = init_merkle_store(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(leaves).unwrap();
    let root = tree.root();
    let advice = AdviceInputs::default().with_merkle_store(store);

    // mtree_get consumes [d, i, R, ...] with depth on top.
    let get_stack = [
        tree.depth() as u64,
        index as u64,
        root[0].as_canonical_u64(),
        root[1].as_canonical_u64(),
        root[2].as_canonical_u64(),
        root[3].as_canonical_u64(),
    ];
    check_trace_sizes("begin mtree_get dropw end", &get_stack, &advice);

    // mtree_set consumes [d, i, R, V_new] with depth on top.
    let new_node = init_merkle_leaf(9);
    let set_stack = [
        tree.depth() as u64,
        index as u64,
        root[0].as_canonical_u64(),
        root[1].as_canonical_u64(),
        root[2].as_canonical_u64(),
        root[3].as_canonical_u64(),
        new_node[0].as_canonical_u64(),
        new_node[1].as_canonical_u64(),
        new_node[2].as_canonical_u64(),
        new_node[3].as_canonical_u64(),
    ];
    check_trace_sizes("begin mtree_set end", &set_stack, &advice);
}
