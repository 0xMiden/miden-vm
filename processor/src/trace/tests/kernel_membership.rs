use alloc::vec::Vec;
use core::borrow::Borrow;

use miden_air::{
    ChipletCols, MidenMultiAir, ProverStatement, StarkConfig, Statement, config, debug,
};
use miden_core::{
    Felt, ONE, ZERO,
    field::QuadFelt,
    mast::{BasicBlockNodeBuilder, CallNodeBuilder, JoinNodeBuilder, MastForest, MastNodeExt},
    operations::Operation,
    program::{KernelDescriptor, Program, hash_kernel_leaf},
    utils::{Matrix, RowMajorMatrix},
};

use super::build_trace_from_program;

fn program_with_kernel_calls() -> Program {
    let mut forest = MastForest::new();
    let a = BasicBlockNodeBuilder::new(vec![Operation::Noop])
        .add_to_forest(&mut forest)
        .unwrap();
    let b = BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap])
        .add_to_forest(&mut forest)
        .unwrap();
    let unused = BasicBlockNodeBuilder::new(vec![Operation::Push(ONE), Operation::Drop])
        .add_to_forest(&mut forest)
        .unwrap();
    let kernel =
        KernelDescriptor::new(&[forest[a].digest(), forest[b].digest(), forest[unused].digest()])
            .unwrap();
    let call_a = CallNodeBuilder::new_syscall(a).add_to_forest(&mut forest).unwrap();
    let call_b = CallNodeBuilder::new_syscall(b).add_to_forest(&mut forest).unwrap();
    let aa = JoinNodeBuilder::new([call_a, call_a]).add_to_forest(&mut forest).unwrap();
    let ab = JoinNodeBuilder::new([call_a, call_b]).add_to_forest(&mut forest).unwrap();
    let entry = JoinNodeBuilder::new([aa, ab]).add_to_forest(&mut forest).unwrap();
    forest.make_root(entry);
    Program::with_kernel(forest.into(), entry, kernel)
}

fn kernel_rows(matrix: &RowMajorMatrix<Felt>) -> Vec<usize> {
    (0..matrix.height())
        .filter(|&i| {
            let row = &matrix.values[i * matrix.width()..(i + 1) * matrix.width()];
            row[0] == ZERO && row[1..4] == [ONE; 3] && row[4] == ZERO
        })
        .collect()
}

#[test]
fn kernel_membership_authenticates_distinct_accessed_procedures() {
    let program = program_with_kernel_calls();
    let trace = build_trace_from_program(&program, &[]);
    #[cfg(feature = "std")]
    {
        use crate::{AdviceInputs, DefaultHost, ExecutionOptions, FastProcessor, StackInputs};
        let streamed =
            rayon::ThreadPoolBuilder::new().num_threads(2).build().unwrap().install(|| {
                FastProcessor::new_with_options(
                    StackInputs::default(),
                    AdviceInputs::default(),
                    ExecutionOptions::default()
                        .with_core_trace_fragment_size(super::TEST_TRACE_FRAGMENT_SIZE)
                        .unwrap(),
                )
                .unwrap()
                .execute_and_build_trace_sync(&program, &mut DefaultHost::default(), u64::MAX)
                .unwrap()
                .0
            });
        let buffered = trace.main_trace().clone_air_matrices();
        let streamed = streamed.main_trace().clone_air_matrices();
        for (expected, actual) in [buffered.0, buffered.1, buffered.2, buffered.3]
            .into_iter()
            .zip([streamed.0, streamed.1, streamed.2, streamed.3])
        {
            assert_eq!(
                expected.values, actual.values,
                "streamed and buffered kernel authentication differ"
            );
        }
    }
    trace.check_constraints();
    let (_, chiplets, ..) = trace.main_trace().clone_air_matrices();
    let rows = kernel_rows(&chiplets);
    assert_eq!(rows.len(), 2, "unused exports must not add kernel rows");
    let mut multiplicities: Vec<_> =
        rows.iter().map(|&i| chiplets.values[i * chiplets.width() + 5]).collect();
    multiplicities.sort();
    assert_eq!(multiplicities, [ONE, Felt::from_u8(3)]);
    assert_eq!(trace.program_info().kernel_root(), program.kernel().commitment());
    for row in rows {
        let cols: &ChipletCols<Felt> =
            chiplets.values[row * chiplets.width()..(row + 1) * chiplets.width()].borrow();
        assert_ne!(cols.kernel_rom().hasher_start, ZERO);
        assert_eq!(cols.kernel_rom().depth, Felt::from_u8(2));
        assert_eq!(
            cols.kernel_rom().leaf,
            hash_kernel_leaf(cols.kernel_rom().root.into()).into_elements(),
        );
    }
}

#[test]
fn kernel_membership_rejects_broken_authorization_links() {
    let trace = build_trace_from_program(&program_with_kernel_calls(), &[]);
    let (core, chiplets, compression, and8) = trace.main_trace().clone_air_matrices();
    let rows = kernel_rows(&chiplets);
    let width = chiplets.width();
    for tamper in [
        "callee",
        "multiplicity",
        "start",
        "index",
        "bit",
        "root",
        "depth",
        "zero_depth",
        "negative_depth",
        "large_depth",
        "swapped_returns",
        "swapped_authentication",
    ] {
        let mut altered = chiplets.clone();
        let (mut inputs, auxiliary) = trace.public_inputs().to_air_inputs();
        let row = rows[0] * width;
        match tamper {
            "callee" => {
                // Authenticate the other exported procedure while retaining the original calls.
                let other = rows[1] * width;
                for column in 6..18 {
                    altered.values[row + column] = chiplets.values[other + column];
                }
            },
            "multiplicity" => altered.values[row + 5] += ONE,
            "start" => altered.values[row + 10] += ONE,
            "index" => altered.values[row + 11] += ONE,
            "bit" => altered.values[row + 12] = ONE - altered.values[row + 12],
            "root" => inputs[1].1[0] += ONE,
            "depth" => altered.values[row + 13] += ONE,
            "zero_depth" => altered.values[row + 13] = ZERO,
            "negative_depth" => altered.values[row + 13] = -ONE,
            "large_depth" => altered.values[row + 13] = Felt::new_unchecked(1 << 32),
            "swapped_authentication" => {
                // Preserve the membership and syscall multisets, but bind each raw digest to
                // the other procedure's leaf. Only the leaf-compression link rejects this.
                let other = rows[1] * width;
                for column in 10..18 {
                    altered.values.swap(row + column, other + column);
                }
            },
            "swapped_returns" => {
                // Swapping both terminal rows preserves the return multiset if messages omit
                // depth. Init and syscall messages stay honest; the final-level tag must reject it.
                let other = rows[1] * width;
                let start = altered.values[row + 10];
                let other_start = altered.values[other + 10];
                let depth = altered.values[row + 13];
                let other_depth = altered.values[other + 13];
                altered.values[row + 13] = other_start + other_depth - start;
                altered.values[other + 13] = start + depth - other_start;
            },
            _ => unreachable!(),
        }
        let statement =
            Statement::<Felt, QuadFelt, _>::new(MidenMultiAir::new(), inputs, auxiliary).unwrap();
        let statement = ProverStatement::new(
            statement,
            vec![core.clone(), altered, compression.clone(), and8.clone()],
        )
        .unwrap();
        let config = config::eidos_config(config::pcs_params(), config::RELATION_DIGEST);
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            debug::check_constraints(&statement, config.challenger());
        }));
        assert!(rejected.is_err(), "accepted altered kernel {tamper}");
    }
}

#[test]
fn unused_nonempty_kernel_preserves_root_without_kernel_rows() {
    let original = program_with_kernel_calls();
    let mut forest = MastForest::new();
    let entry = BasicBlockNodeBuilder::new(vec![Operation::Noop])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(entry);
    let program = Program::with_kernel(forest.into(), entry, original.kernel().clone());
    let trace = build_trace_from_program(&program, &[]);
    trace.check_constraints();
    let (_, chiplets, ..) = trace.main_trace().clone_air_matrices();
    assert!(kernel_rows(&chiplets).is_empty());
    assert_eq!(trace.program_info().kernel_root(), original.kernel().commitment());
}
