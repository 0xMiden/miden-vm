//! Fragment boundary testing for parallel trace generation.
//!
//! This module contains focused tests for verifying that trace generation works correctly
//! when fragment boundaries occur at various points in program execution.
//!
//! Each test module focuses on a specific control flow operation type:
//! - [join_tests] - Tests JOIN node fragment boundaries
//! - [split_tests] - Tests SPLIT node fragment boundaries
//! - [loop_tests] - Tests LOOP node fragment boundaries
//! - [call_tests] - Tests CALL node fragment boundaries
//! - [syscall_tests] - Tests SYSCALL node fragment boundaries
//! - [basic_block_tests] - Tests basic block fragment boundaries
//! - [dyn_tests] - Tests DYN node fragment boundaries
//! - [dyncall_tests] - Tests DYNCALL node fragment boundaries
//! - [external_tests] - Tests EXTERNAL node fragment boundaries

use miden_core::{Felt, Operation, Word};

pub(super) mod basic_block_tests;
pub(super) mod call_tests;
pub(super) mod dyn_tests;
pub(super) mod dyncall_tests;
pub(super) mod external_tests;
pub(super) mod join_tests;
pub(super) mod loop_tests;
pub(super) mod split_tests;
pub(super) mod syscall_tests;

// Re-export common utilities for all test modules
pub(super) use alloc::{string::String, sync::Arc, vec::Vec};
pub(super) use std::string::ToString;

pub(super) use miden_core::{
    Kernel, ONE, Program, ZERO,
    mast::{MastForest, MastNodeExt},
};
pub(super) use miden_utils_testing::get_column_name;
pub(super) use pretty_assertions::assert_eq;
pub(super) use rstest::{fixture, rstest};
pub(super) use winter_prover::Trace;

pub(super) use crate::{DefaultHost, HostLibrary, fast::FastProcessor, parallel::build_trace};

// Common constants used across all test modules
pub(super) const DEFAULT_STACK: &[Felt] = &[Felt::new(1), Felt::new(2), Felt::new(3)];

/// The procedure that DYN and DYNCALL will call in the tests below. Its digest needs to be put on
/// the stack before the call.
pub(super) const DYN_TARGET_PROC_HASH: &[Felt] = &[
    Felt::new(10995436151082118190),
    Felt::new(776663942277617877),
    Felt::new(3177713792132750309),
    Felt::new(10407898805173442467),
];

/// The digest of a procedure available to be called via an EXTERNAL node.
pub(super) const EXTERNAL_LIB_PROC_DIGEST: Word = Word::new([
    Felt::new(9552974201798903089),
    Felt::new(993192251238261044),
    Felt::new(1885027269046469428),
    Felt::new(8558115384207742312),
]);

/// Common test logic for fragment boundary testing.
///
/// This function executes a program twice:
/// 1. With the specified fragment_size (creates multiple fragments)
/// 2. With MAX_FRAGMENT_SIZE (creates single fragment)
///
/// It then verifies that both traces are identical, ensuring fragment boundary logic is correct.
pub(super) fn test_fragment_boundary_trace_consistency(
    program: &Program,
    fragment_size: usize,
    stack_inputs: &[Felt],
) {
    /// This is the largest fragment size that can be proved
    const MAX_FRAGMENT_SIZE: usize = 1 << 29;

    let trace_from_fragments = {
        let processor = FastProcessor::new(stack_inputs);
        let mut host = DefaultHost::default();
        host.load_library(create_simple_library()).unwrap();
        let (execution_output, trace_fragment_contexts) =
            processor.execute_for_trace_sync(program, &mut host, fragment_size).unwrap();

        build_trace(
            execution_output,
            trace_fragment_contexts,
            program.hash(),
            program.kernel().clone(),
        )
    };

    let trace_from_single_fragment = {
        let processor = FastProcessor::new(stack_inputs);
        let mut host = DefaultHost::default();
        host.load_library(create_simple_library()).unwrap();
        let (execution_output, trace_fragment_contexts) =
            processor.execute_for_trace_sync(program, &mut host, MAX_FRAGMENT_SIZE).unwrap();
        assert!(trace_fragment_contexts.core_trace_contexts.len() == 1);

        build_trace(
            execution_output,
            trace_fragment_contexts,
            program.hash(),
            program.kernel().clone(),
        )
    };

    // Ensure that the trace generated from multiple fragments is identical to the one generated
    // from a single fragment.
    for col_idx in 0..miden_air::trace::PADDED_TRACE_WIDTH {
        let col_from_fragments = trace_from_fragments.main_segment().get_column(col_idx);
        let col_from_single_fragment =
            trace_from_single_fragment.main_segment().get_column(col_idx);

        // Since the parallel trace generator only generates core traces, its column length will
        // be lower than the slow processor's trace in the case where the range checker or
        // chiplets column length exceeds the core trace length. We also ignore the last element
        // in the column, since it is a random value inserted at the end of trace generation,
        // and will not match when the 2 traces don't have the same length.
        let len = col_from_fragments.len().min(col_from_single_fragment.len()) - 1;

        if col_from_fragments[..len] != col_from_single_fragment[..len] {
            // Find the first row where the columns disagree
            for (row_idx, (val_from_fragments, val_from_single_fragment)) in col_from_fragments
                [..len]
                .iter()
                .zip(col_from_single_fragment[..len].iter())
                .enumerate()
            {
                if val_from_fragments != val_from_single_fragment {
                    panic!(
                        "Trace columns do not match between trace generated as multiple fragments vs a single fragment at column {} ({}) row {}: multiple={}, single={}",
                        col_idx,
                        get_column_name(col_idx),
                        row_idx,
                        val_from_fragments,
                        val_from_single_fragment
                    );
                }
            }
        }
    }

    // Sanity check to ensure that the traces are identical.
    assert_eq!(format!("{trace_from_fragments:?}"), format!("{trace_from_single_fragment:?}"));
}

/// Creates a library with a single procedure containing just a SWAP operation.
pub(super) fn create_simple_library() -> HostLibrary {
    let mut mast_forest = MastForest::new();
    let swap_block = mast_forest
        .add_block(vec![Operation::Swap, Operation::Swap], Vec::new())
        .unwrap();
    mast_forest.make_root(swap_block);
    HostLibrary::from(Arc::new(mast_forest))
}

/// Workaround to make insta and rstest work together.
/// See: https://github.com/la10736/rstest/issues/183#issuecomment-1564088329
#[fixture]
pub(super) fn testname() -> String {
    std::thread::current().name().unwrap().to_string()
}
