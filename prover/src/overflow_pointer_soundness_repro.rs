use alloc::{vec, vec::Vec};
use core::borrow::{Borrow, BorrowMut};

use miden_air::{CoreCols, PublicInputs, trace::RowIndex};
use miden_core::{
    Felt,
    deferred::TRUE_DIGEST,
    mast::{BasicBlockNodeBuilder, MastForest},
    operations::{Operation, opcodes},
    program::{ExecutionClaim, Program, StackOutputs},
    proof::{ExecutionProof, HashFunction, StarkProof, VmProof},
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::stark::verifier::VerifierError;
use miden_processor::{DefaultHost, FastProcessor, StackInputs};
use miden_verifier::{StarkVerificationError, VerificationError, Verifier};

use crate::{Prover, config, prove_stark};

fn core_row_mut(matrix: &mut RowMajorMatrix<Felt>, row: usize) -> &mut CoreCols<Felt> {
    let width = matrix.width();
    matrix.values[row * width..(row + 1) * width].borrow_mut()
}

fn core_row(matrix: &RowMajorMatrix<Felt>, row: usize) -> &CoreCols<Felt> {
    let width = matrix.width();
    matrix.values[row * width..(row + 1) * width].borrow()
}

#[test]
fn verifier_rejects_forged_overflow_pop_order() {
    let operations = vec![
        Operation::Push(Felt::new_unchecked(101)),
        Operation::Push(Felt::new_unchecked(102)),
        Operation::Noop,
        Operation::Drop,
        Operation::Noop,
        Operation::Drop,
        Operation::Noop,
    ];
    let mut mast_forest = MastForest::new();
    let basic_block_id =
        BasicBlockNodeBuilder::new(operations).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(basic_block_id);
    let program = Program::new(mast_forest.into(), basic_block_id);

    // Top first: [16, 15, ..., 2, 1]. The two PUSH operations create overflow records for 1 and 2.
    let stack_values = (1..17).rev().map(Felt::new_unchecked).collect::<Vec<_>>();
    let stack_inputs = StackInputs::new(&stack_values).unwrap();
    let mut host = DefaultHost::default();
    let (trace, precompile_witness) = FastProcessor::new(stack_inputs)
        .execute_and_build_trace_sync(&program, &mut host, Prover::DEFAULT_MAX_PROVER_MEMORY_BYTES)
        .unwrap();
    assert!(precompile_witness.is_none());
    assert_eq!(trace.precompile_root(), TRUE_DIGEST);

    let main = trace.main_trace();
    let push_rows = (0..main.core_height())
        .filter(|&row| main.get_op_code(RowIndex::from(row)) == Felt::from_u8(opcodes::PUSH))
        .collect::<Vec<_>>();
    let drop_rows = (0..main.core_height())
        .filter(|&row| main.get_op_code(RowIndex::from(row)) == Felt::from_u8(opcodes::DROP))
        .collect::<Vec<_>>();
    assert_eq!(push_rows, vec![1, 2]);
    assert_eq!(drop_rows, vec![4, 6]);

    let first_record_clk = main.clk(RowIndex::from(push_rows[0]));
    let first_record_value = main.stack_element(15, RowIndex::from(push_rows[0]));
    let first_record_prev = main.parent_overflow_address(RowIndex::from(push_rows[0]));
    let second_record_clk = main.clk(RowIndex::from(push_rows[1]));
    let second_record_value = main.stack_element(15, RowIndex::from(push_rows[1]));
    let second_record_prev = main.parent_overflow_address(RowIndex::from(push_rows[1]));
    assert_eq!(
        (first_record_clk, first_record_value, first_record_prev),
        (Felt::new_unchecked(1), Felt::new_unchecked(1), Felt::new_unchecked(0)),
    );
    assert_eq!(
        (second_record_clk, second_record_value, second_record_prev),
        (Felt::new_unchecked(2), Felt::new_unchecked(2), Felt::new_unchecked(1)),
    );

    let (mut core_matrix, chiplets_matrix, poseidon2_matrix) = main.to_air_matrices();

    // Redirect the first DROP to consume the older overflow record R1.
    core_row_mut(&mut core_matrix, drop_rows[0]).stack.b1 = first_record_clk;
    {
        let row = core_row_mut(&mut core_matrix, drop_rows[0] + 1);
        row.stack.top[15] = first_record_value;
        row.stack.b1 = first_record_prev;
    }

    // Preserve the forged value across NOOP and redirect the second DROP to consume R2.
    {
        let row = core_row_mut(&mut core_matrix, drop_rows[1]);
        row.stack.top[15] = first_record_value;
        row.stack.b1 = second_record_clk;
    }

    // Consume R2 and keep the swapped bottom elements through the final/padding rows.
    for row_idx in (drop_rows[1] + 1)..core_matrix.height() {
        let row = core_row_mut(&mut core_matrix, row_idx);
        row.stack.top[14] = first_record_value;
        row.stack.top[15] = second_record_value;
        row.stack.b1 = if row_idx == drop_rows[1] + 1 {
            second_record_prev
        } else {
            Felt::new_unchecked(0)
        };
    }

    // The stack-overflow bus adds `(clk, s15, b1)` on PUSH and removes
    // `(b1, s15', b1')` on DROP. The forged trace removes both records in non-LIFO order.
    let first_drop = core_row(&core_matrix, drop_rows[0]);
    let first_drop_next = core_row(&core_matrix, drop_rows[0] + 1);
    assert_eq!(
        (first_drop.stack.b1, first_drop_next.stack.top[15], first_drop_next.stack.b1),
        (first_record_clk, first_record_value, first_record_prev),
    );
    let second_drop = core_row(&core_matrix, drop_rows[1]);
    let second_drop_next = core_row(&core_matrix, drop_rows[1] + 1);
    assert_eq!(
        (second_drop.stack.b1, second_drop_next.stack.top[15], second_drop_next.stack.b1),
        (second_record_clk, second_record_value, second_record_prev),
    );

    // The honest output ends in [..., 2, 1]; claim [..., 1, 2] instead.
    let mut output_elements =
        core::array::from_fn(|i| trace.stack_outputs().get_element(i).unwrap());
    output_elements.swap(14, 15);
    let forged_outputs = StackOutputs::from(output_elements);
    assert_ne!(forged_outputs, *trace.stack_outputs());

    let public_inputs = PublicInputs::new(
        trace.program_info().clone(),
        trace.init_stack_state(),
        forged_outputs,
        trace.precompile_root(),
    );
    let (public_values, aux_inputs) = public_inputs.to_air_inputs();
    let stark_config = config::poseidon2_config(config::pcs_params(), config::RELATION_DIGEST);
    let proof_bytes = prove_stark(
        &stark_config,
        core_matrix,
        chiplets_matrix,
        poseidon2_matrix,
        &public_values,
        &aux_inputs,
    )
    .expect("the low-level prover should encode the forged trace for the verifier regression");
    let proof = ExecutionProof::new(
        VmProof {
            proof: StarkProof::new(proof_bytes, HashFunction::Poseidon2),
            precompile_root: TRUE_DIGEST,
        },
        miden_core::proof::PrecompileStatus::Empty,
    );
    let claim = ExecutionClaim::from_program_info(
        trace.program_info().clone(),
        trace.init_stack_state(),
        forged_outputs,
    );

    let verification_result = Verifier::new().verify(&claim, &proof);
    assert!(
        matches!(
            verification_result,
            Err(VerificationError::StarkVerificationError(_, source))
                if matches!(
                    *source,
                    StarkVerificationError::Verifier(VerifierError::ConstraintMismatch)
                )
        ),
        "the forged public output must fail an AIR constraint",
    );
}
