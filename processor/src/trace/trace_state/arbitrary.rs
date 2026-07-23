use alloc::collections::VecDeque;

use miden_air::trace::chiplets::hasher::STATE_WIDTH;
use proptest::{collection, prelude::*};

use super::*;

const MAX_REPLAY_ITEMS: usize = 8;

fn arb_row_index() -> impl Strategy<Value = RowIndex> {
    any::<u32>().prop_map(RowIndex::from)
}

// TODO: use any::<MerklePath>() once miden-crypto exposes its impl outside test code:
// https://github.com/0xMiden/crypto/issues/1072
fn arb_merkle_path() -> impl Strategy<Value = MerklePath> {
    collection::vec(any::<Word>(), 0..=MAX_REPLAY_ITEMS).prop_map(MerklePath::new)
}

fn arb_vec_deque<T, S>(strategy: S) -> impl Strategy<Value = VecDeque<T>>
where
    T: core::fmt::Debug + 'static,
    S: Strategy<Value = T> + 'static,
{
    collection::vec(strategy, 0..=MAX_REPLAY_ITEMS).prop_map(VecDeque::from)
}

impl Arbitrary for SystemState {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (arb_row_index(), any::<ContextId>(), any::<Word>(), any::<Word>())
            .prop_map(|(clk, ctx, fn_hash, deferred_root)| Self {
                clk,
                ctx,
                fn_hash,
                deferred_root,
            })
            .boxed()
    }
}

impl Arbitrary for DecoderState {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<Felt>(), any::<Felt>())
            .prop_map(|(current_addr, parent_addr)| Self { current_addr, parent_addr })
            .boxed()
    }
}

impl Arbitrary for StackState {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<[Felt; MIN_STACK_DEPTH]>(),
            MIN_STACK_DEPTH..=MIN_STACK_DEPTH + 64,
            any::<Felt>(),
        )
            .prop_map(|(stack_top, stack_depth, last_overflow_addr)| Self {
                stack_top,
                stack_depth,
                last_overflow_addr,
            })
            .boxed()
    }
}

impl Arbitrary for CoreTraceState {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<SystemState>(), any::<DecoderState>(), any::<StackState>())
            .prop_map(|(system, decoder, stack)| Self { system, decoder, stack })
            .boxed()
    }
}

impl Arbitrary for CoreTraceFragmentContext {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<CoreTraceState>(),
            any::<ExecutionReplay>(),
            any::<ContinuationStack<MastForestId>>(),
            any::<MastForestId>(),
        )
            .prop_map(|(state, replay, continuation, initial_mast_forest_id)| Self {
                state,
                replay,
                continuation,
                initial_mast_forest_id,
            })
            .boxed()
    }
}

impl Arbitrary for NodeEndData {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<Felt>(), any::<Felt>(), any::<Felt>())
            .prop_map(|(ended_node_addr, prev_addr, prev_parent_addr)| Self {
                ended_node_addr,
                prev_addr,
                prev_parent_addr,
            })
            .boxed()
    }
}

impl Arbitrary for ExecutionContextSystemInfo {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<ContextId>(), any::<Word>())
            .prop_map(|(parent_ctx, parent_fn_hash)| Self { parent_ctx, parent_fn_hash })
            .boxed()
    }
}

impl Arbitrary for ExecutionContextReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        arb_vec_deque(any::<ExecutionContextSystemInfo>())
            .prop_map(|execution_contexts| Self { execution_contexts })
            .boxed()
    }
}

impl Arbitrary for BlockStackReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (arb_vec_deque(any::<Felt>()), arb_vec_deque(any::<NodeEndData>()))
            .prop_map(|(node_start_parent_addr, node_end)| Self {
                node_start_parent_addr,
                node_end,
            })
            .boxed()
    }
}

impl Arbitrary for MastForestResolutionReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        arb_vec_deque((any::<MastNodeId>(), any::<MastForestId>()))
            .prop_map(|mast_forest_resolutions| Self { mast_forest_resolutions })
            .boxed()
    }
}

impl Arbitrary for MemoryReadsReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            arb_vec_deque((any::<Felt>(), any::<Felt>(), any::<ContextId>(), arb_row_index())),
            arb_vec_deque((any::<Word>(), any::<Felt>(), any::<ContextId>(), arb_row_index())),
        )
            .prop_map(|(elements_read, words_read)| Self { elements_read, words_read })
            .boxed()
    }
}

impl Arbitrary for MemoryWritesReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            arb_vec_deque((any::<Felt>(), any::<Felt>(), any::<ContextId>(), arb_row_index())),
            arb_vec_deque((any::<Word>(), any::<Felt>(), any::<ContextId>(), arb_row_index())),
        )
            .prop_map(|(elements_written, words_written)| Self { elements_written, words_written })
            .boxed()
    }
}

impl Arbitrary for AdviceReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            arb_vec_deque(any::<Felt>()),
            arb_vec_deque(any::<Word>()),
            arb_vec_deque(any::<[Word; 2]>()),
        )
            .prop_map(|(stack_pops, stack_word_pops, stack_dword_pops)| Self {
                stack_pops,
                stack_word_pops,
                stack_dword_pops,
            })
            .boxed()
    }
}

impl Arbitrary for BitwiseOp {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![Just(Self::U32And), Just(Self::U32Xor)].boxed()
    }
}

impl Arbitrary for BitwiseReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        arb_vec_deque((any::<BitwiseOp>(), any::<Felt>(), any::<Felt>()))
            .prop_map(|u32op_with_operands| Self { u32op_with_operands })
            .boxed()
    }
}

impl Arbitrary for KernelReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        arb_vec_deque(any::<Word>())
            .prop_map(|kernel_proc_accesses| Self { kernel_proc_accesses })
            .boxed()
    }
}

impl Arbitrary for RangeCheckerReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        arb_vec_deque(any::<[u16; 4]>())
            .prop_map(|range_checks_u32_ops| Self { range_checks_u32_ops })
            .boxed()
    }
}

impl Arbitrary for BlockAddressReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        arb_vec_deque(any::<Felt>())
            .prop_map(|block_addresses| Self { block_addresses })
            .boxed()
    }
}

impl Arbitrary for HasherResponseReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            arb_vec_deque((any::<Felt>(), any::<[Felt; STATE_WIDTH]>())),
            arb_vec_deque((any::<Felt>(), any::<Word>())),
            arb_vec_deque((any::<Felt>(), any::<Word>(), any::<Word>())),
        )
            .prop_map(
                |(permutation_operations, build_merkle_root_operations, mrupdate_operations)| {
                    Self {
                        permutation_operations,
                        build_merkle_root_operations,
                        mrupdate_operations,
                    }
                },
            )
            .boxed()
    }
}

impl Arbitrary for HasherOp {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<[Felt; STATE_WIDTH]>().prop_map(Self::Permute),
            (any::<Word>(), any::<Word>(), any::<Felt>(), any::<Word>())
                .prop_map(Self::HashControlBlock),
            (any::<MastForestId>(), any::<MastNodeId>(), any::<Word>())
                .prop_map(Self::HashBasicBlock),
            (any::<Word>(), arb_merkle_path(), any::<Felt>()).prop_map(Self::BuildMerkleRoot),
            (any::<Word>(), any::<Word>(), arb_merkle_path(), any::<Felt>())
                .prop_map(Self::UpdateMerkleRoot),
        ]
        .boxed()
    }
}

impl Arbitrary for HasherRequestReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        arb_vec_deque(any::<HasherOp>())
            .prop_map(|hasher_ops| Self { hasher_ops })
            .boxed()
    }
}

impl Arbitrary for StackOverflowReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            arb_vec_deque((any::<Felt>(), any::<Felt>())),
            arb_vec_deque((MIN_STACK_DEPTH..=MIN_STACK_DEPTH + 64, any::<Felt>())),
        )
            .prop_map(|(overflow_values, restore_context_info)| Self {
                overflow_values,
                restore_context_info,
            })
            .boxed()
    }
}

impl Arbitrary for ExecutionReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<BlockStackReplay>(),
            any::<ExecutionContextReplay>(),
            any::<StackOverflowReplay>(),
            any::<MemoryReadsReplay>(),
            any::<AdviceReplay>(),
            any::<HasherResponseReplay>(),
            any::<BlockAddressReplay>(),
            any::<MastForestResolutionReplay>(),
        )
            .prop_map(
                |(
                    block_stack,
                    execution_context,
                    stack_overflow,
                    memory_reads,
                    advice,
                    hasher,
                    block_address,
                    mast_forest_resolution,
                )| Self {
                    block_stack,
                    execution_context,
                    stack_overflow,
                    memory_reads,
                    advice,
                    hasher,
                    block_address,
                    mast_forest_resolution,
                },
            )
            .boxed()
    }
}

impl Arbitrary for AceReplay {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        arb_vec_deque((arb_row_index(), any::<CircuitEvaluation>()))
            .prop_map(|circuit_evaluations| Self { circuit_evaluations })
            .boxed()
    }
}
