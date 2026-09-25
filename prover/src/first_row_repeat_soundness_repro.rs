//! Regression test for a REPEAT row placed before the committed program starts.

use alloc::{vec, vec::Vec};
use core::borrow::Borrow;

use miden_air::CoreCols;
use miden_core::{
    Felt,
    mast::{BasicBlockNodeBuilder, LoopNodeBuilder, MastForest},
    operations::{Operation, opcodes},
    program::{Program, StackOutputs},
    utils::{Matrix, RowMajorMatrix},
};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use crate::{
    Prover,
    repro_harness::{ReproTrace, core_row_mut},
};

struct ForgedTrace {
    repro: ReproTrace,
    core: RowMajorMatrix<Felt>,
    chiplets: RowMajorMatrix<Felt>,
    eidos_compression: RowMajorMatrix<Felt>,
    and8: RowMajorMatrix<Felt>,
    forged_outputs: StackOutputs,
}

fn build_program(root_ops: Vec<Operation>) -> Program {
    let mut mast_forest = MastForest::new();
    let root = BasicBlockNodeBuilder::new(root_ops).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(root);
    Program::new(mast_forest.into(), root)
}

fn build_loop_program(body_ops: Vec<Operation>) -> Program {
    let mut mast_forest = MastForest::new();
    let body = BasicBlockNodeBuilder::new(body_ops).add_to_forest(&mut mast_forest).unwrap();
    let root = LoopNodeBuilder::new(body).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(root);
    Program::new(mast_forest.into(), root)
}

fn execute(program: &Program, stack: &[u64]) -> miden_processor::trace::VmTrace {
    let stack = stack.iter().map(|&v| Felt::new_unchecked(v)).collect::<Vec<_>>();
    let mut host = DefaultHost::default();
    let (trace, precompile_witness) = FastProcessor::new(StackInputs::new(&stack).unwrap())
        .execute_and_build_trace_sync(program, &mut host, Prover::DEFAULT_MAX_PROVER_MEMORY_BYTES)
        .unwrap();
    assert!(precompile_witness.is_none());
    trace
}

fn core_row(matrix: &RowMajorMatrix<Felt>, row: usize) -> &CoreCols<Felt> {
    let width = matrix.width();
    matrix.values[row * width..(row + 1) * width].borrow()
}

fn opcode(row: &CoreCols<Felt>) -> u8 {
    row.decoder
        .op_bits
        .iter()
        .enumerate()
        .map(|(i, bit)| (bit.as_canonical_u64() as u8) << i)
        .sum()
}

/// Builds `REPEAT | <honest execution of the program on the popped inputs> | HALT...`.
///
/// Row 0 carries the public stack inputs `[1, 5, 7]` and a REPEAT opcode. REPEAT pops the loop
/// condition, so every later row is copied (one row down) from an honest execution of the same
/// program on `[5, 7]`. Its hasher and byte-lookup matrices are copied without shifting rows.
fn build_first_row_repeat_trace() -> ForgedTrace {
    let program = build_program(vec![Operation::Add]);
    let honest_trace = execute(&program, &[1, 5, 7]);
    let popped_trace = execute(&program, &[5, 7]);

    let (honest_core, ..) = honest_trace.main_trace().clone_air_matrices();
    let (popped_core, chiplets, eidos_compression, and8) =
        popped_trace.main_trace().clone_air_matrices();
    assert_eq!(honest_core.height(), popped_core.height());
    assert_eq!(core_row(&honest_core, 0).stack.top[0], Felt::ONE);

    let loop_trace = execute(&build_loop_program(vec![Operation::Not]), &[0, 1]);
    let (loop_core, ..) = loop_trace.main_trace().clone_air_matrices();
    let repeat_row = (0..loop_core.height())
        .find(|&row| opcode(core_row(&loop_core, row)) == opcodes::REPEAT)
        .expect("the two-iteration loop executes REPEAT");
    let repeat_decoder = core_row(&loop_core, repeat_row).decoder.clone();

    let mut core = popped_core.clone();
    for row in (1..core.height()).rev() {
        let src = core_row(&popped_core, row - 1).clone();
        let dst = core_row_mut(&mut core, row);
        dst.system = src.system;
        dst.decoder = src.decoder;
        dst.stack = src.stack;
        dst.system.clk = Felt::from_u32(row as u32);
    }

    let root_addr = core_row(&popped_core, 0).decoder.addr;
    let row0 = core_row_mut(&mut core, 0);
    row0.decoder = repeat_decoder;
    row0.decoder.addr = root_addr;
    row0.stack = core_row(&honest_core, 0).stack.clone();

    let forged_outputs = *popped_trace.stack_outputs();
    assert_ne!(forged_outputs, *honest_trace.stack_outputs());

    ForgedTrace {
        repro: ReproTrace::new(&honest_trace),
        core,
        chiplets,
        eidos_compression,
        and8,
        forged_outputs,
    }
}

#[test]
fn first_row_repeat_is_rejected() {
    let forged = build_first_row_repeat_trace();
    let honest_outcome =
        forged.repro.prove_and_verify_current().expect("the honest trace must verify");
    assert!(honest_outcome.is_complete(), "the honest proof must verify completely");

    let result = forged.repro.prove_and_verify_parts_allowing_lookup_rejection(
        forged.core,
        forged.chiplets,
        forged.eidos_compression,
        forged.and8,
        forged.forged_outputs,
    );
    let error = result.expect_err("a REPEAT row before the committed program must be rejected");
    assert!(
        error.starts_with("verifier rejected:"),
        "the forged trace must produce a proof and fail verification, not fail lookup \
         construction or another prover precheck: {error}"
    );
}
