//! Binary serialization for trace fragment state.
//!
//! This module implements the trusted wire format for the replay state captured in
//! [`TraceReplay`](super::TraceReplay): core trace fragment contexts, range checker, memory,
//! bitwise, hasher, and ACE replays. Sparse MAST node and digest maps are accepted as trusted
//! replay data and are not checked against a source `MastForest` commitment on read; see
//! <https://github.com/0xMiden/miden-vm/issues/3303>.

use super::*;

// SERIALIZATION
// ================================================================================================

impl Serializable for SystemState {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.clk.write_into(target);
        self.ctx.write_into(target);
        self.fn_hash.write_into(target);
        self.deferred_root.write_into(target);
    }
}

impl Deserializable for SystemState {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            clk: RowIndex::read_from(source)?,
            ctx: ContextId::read_from(source)?,
            fn_hash: Word::read_from(source)?,
            deferred_root: Word::read_from(source)?,
        })
    }
}

impl Serializable for DecoderState {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.current_addr.write_into(target);
        self.parent_addr.write_into(target);
    }
}

impl Deserializable for DecoderState {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            current_addr: Felt::read_from(source)?,
            parent_addr: Felt::read_from(source)?,
        })
    }
}

impl Serializable for StackState {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.stack_top.write_into(target);
        self.stack_depth.write_into(target);
        self.last_overflow_addr.write_into(target);
    }
}

impl Deserializable for StackState {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let stack_top = <[Felt; MIN_STACK_DEPTH]>::read_from(source)?;
        let stack_depth = usize::read_from(source)?;
        if stack_depth < MIN_STACK_DEPTH {
            return Err(DeserializationError::InvalidValue(format!(
                "stack depth {stack_depth} is below minimum {MIN_STACK_DEPTH}"
            )));
        }
        Ok(Self {
            stack_top,
            stack_depth,
            last_overflow_addr: Felt::read_from(source)?,
        })
    }
}

impl Serializable for CoreTraceState {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.system.write_into(target);
        self.decoder.write_into(target);
        self.stack.write_into(target);
    }
}

impl Deserializable for CoreTraceState {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            system: SystemState::read_from(source)?,
            decoder: DecoderState::read_from(source)?,
            stack: StackState::read_from(source)?,
        })
    }
}

impl Serializable for CoreTraceFragmentContext {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.state.write_into(target);
        self.replay.write_into(target);
        self.continuation.write_into(target);
        self.initial_mast_forest_id.write_into(target);
    }
}

impl Deserializable for CoreTraceFragmentContext {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            state: CoreTraceState::read_from(source)?,
            replay: ExecutionReplay::read_from(source)?,
            continuation: ContinuationStack::<MastForestId>::read_from(source)?,
            initial_mast_forest_id: MastForestId::read_from(source)?,
        })
    }
}

impl Serializable for NodeEndData {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.ended_node_addr.write_into(target);
        self.prev_addr.write_into(target);
        self.prev_parent_addr.write_into(target);
    }
}

impl Deserializable for NodeEndData {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            ended_node_addr: Felt::read_from(source)?,
            prev_addr: Felt::read_from(source)?,
            prev_parent_addr: Felt::read_from(source)?,
        })
    }
}

impl Serializable for ExecutionContextSystemInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.parent_ctx.write_into(target);
        self.parent_fn_hash.write_into(target);
    }
}

impl Deserializable for ExecutionContextSystemInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            parent_ctx: ContextId::read_from(source)?,
            parent_fn_hash: Word::read_from(source)?,
        })
    }

    fn min_serialized_size() -> usize {
        ContextId::min_serialized_size() + Word::min_serialized_size()
    }
}

impl Serializable for ExecutionContextReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.execution_contexts.write_into(target);
    }
}

impl Deserializable for ExecutionContextReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            execution_contexts: VecDeque::read_from(source)?,
        })
    }
}

impl Serializable for BlockStackReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.node_start_parent_addr.write_into(target);
        self.node_end.write_into(target);
    }
}

impl Deserializable for BlockStackReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            node_start_parent_addr: VecDeque::read_from(source)?,
            node_end: VecDeque::read_from(source)?,
        })
    }
}

impl Serializable for MastForestResolutionReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.mast_forest_resolutions.write_into(target);
    }
}

impl Deserializable for MastForestResolutionReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            mast_forest_resolutions: read_mast_forest_resolution_queue(source)?,
        })
    }
}

fn read_mast_forest_resolution_queue<R: ByteReader>(
    source: &mut R,
) -> Result<VecDeque<(MastNodeId, MastForestId)>, DeserializationError> {
    let len = read_bounded_len(
        source,
        "MastForestResolutionReplay",
        u32::min_serialized_size() + MastForestId::min_serialized_size(),
    )?;
    source.read_many_iter(len)?.collect()
}

impl Serializable for MemoryReadsReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.elements_read.write_into(target);
        self.words_read.write_into(target);
    }
}

impl Deserializable for MemoryReadsReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            elements_read: VecDeque::read_from(source)?,
            words_read: VecDeque::read_from(source)?,
        })
    }
}

impl Serializable for MemoryWritesReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.elements_written.write_into(target);
        self.words_written.write_into(target);
    }
}

impl Deserializable for MemoryWritesReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            elements_written: VecDeque::read_from(source)?,
            words_written: VecDeque::read_from(source)?,
        })
    }
}

impl Serializable for AdviceReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.stack_pops.write_into(target);
        self.stack_word_pops.write_into(target);
        self.stack_dword_pops.write_into(target);
    }
}

impl Deserializable for AdviceReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            stack_pops: VecDeque::read_from(source)?,
            stack_word_pops: VecDeque::read_from(source)?,
            stack_dword_pops: VecDeque::read_from(source)?,
        })
    }
}

impl Serializable for BitwiseOp {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::U32And => 0u8,
            Self::U32Xor => 1u8,
        }
        .write_into(target);
    }
}

impl Deserializable for BitwiseOp {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match u8::read_from(source)? {
            0 => Ok(Self::U32And),
            1 => Ok(Self::U32Xor),
            tag => Err(DeserializationError::InvalidValue(format!(
                "invalid bitwise replay op tag {tag}"
            ))),
        }
    }
}

impl Serializable for BitwiseReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.u32op_with_operands.write_into(target);
    }
}

impl Deserializable for BitwiseReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            u32op_with_operands: VecDeque::read_from(source)?,
        })
    }
}

impl Serializable for KernelReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.kernel_proc_accesses.write_into(target);
    }
}

impl Deserializable for KernelReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            kernel_proc_accesses: VecDeque::read_from(source)?,
        })
    }
}

impl Serializable for AceReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.circuit_evaluations.write_into(target);
    }
}

impl Deserializable for AceReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            circuit_evaluations: VecDeque::read_from(source)?,
        })
    }
}

impl Serializable for RangeCheckReplayValues {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Two(values) => {
                target.write_u8(0);
                values.write_into(target);
            },
            Self::Four(values) => {
                target.write_u8(1);
                values.write_into(target);
            },
        }
    }
}

impl Deserializable for RangeCheckReplayValues {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(match source.read_u8()? {
            0 => Self::Two(<[u16; 2]>::read_from(source)?),
            1 => Self::Four(<[u16; 4]>::read_from(source)?),
            tag => {
                return Err(DeserializationError::InvalidValue(format!(
                    "invalid range check replay variant tag {tag}"
                )));
            },
        })
    }

    // The default `size_of::<Self>()` (16) overestimates the on-wire size: the smallest variant
    // is the one-byte tag plus two u16 limbs.
    fn min_serialized_size() -> usize {
        5
    }
}

impl Serializable for RangeCheckerReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.range_checks.write_into(target);
    }
}

impl Deserializable for RangeCheckerReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            range_checks: VecDeque::read_from(source)?,
        })
    }
}

impl Serializable for BlockAddressReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.block_addresses.write_into(target);
    }
}

impl Deserializable for BlockAddressReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            block_addresses: VecDeque::read_from(source)?,
        })
    }
}

impl Serializable for HasherResponseReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.permutation_operations.write_into(target);
        self.build_merkle_root_operations.write_into(target);
        self.mrupdate_operations.write_into(target);
    }
}

impl Deserializable for HasherResponseReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            permutation_operations: VecDeque::read_from(source)?,
            build_merkle_root_operations: VecDeque::read_from(source)?,
            mrupdate_operations: VecDeque::read_from(source)?,
        })
    }
}

impl Serializable for HasherOp {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Permute(state) => {
                0u8.write_into(target);
                state.write_into(target);
            },
            Self::HashControlBlock((h1, h2, domain, expected_hash)) => {
                1u8.write_into(target);
                h1.write_into(target);
                h2.write_into(target);
                domain.write_into(target);
                expected_hash.write_into(target);
            },
            Self::HashBasicBlock((forest_id, node_id, expected_hash)) => {
                2u8.write_into(target);
                forest_id.write_into(target);
                node_id.write_into(target);
                expected_hash.write_into(target);
            },
            Self::BuildMerkleRoot((leaf, path, index)) => {
                3u8.write_into(target);
                leaf.write_into(target);
                path.write_into(target);
                index.write_into(target);
            },
            Self::UpdateMerkleRoot((old_value, new_value, path, index)) => {
                4u8.write_into(target);
                old_value.write_into(target);
                new_value.write_into(target);
                path.write_into(target);
                index.write_into(target);
            },
        }
    }
}

impl Deserializable for HasherOp {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match u8::read_from(source)? {
            0 => Ok(Self::Permute(<[Felt; STATE_WIDTH]>::read_from(source)?)),
            1 => Ok(Self::HashControlBlock((
                Word::read_from(source)?,
                Word::read_from(source)?,
                Felt::read_from(source)?,
                Word::read_from(source)?,
            ))),
            2 => Ok(Self::HashBasicBlock((
                MastForestId::read_from(source)?,
                MastNodeId::read_from(source)?,
                Word::read_from(source)?,
            ))),
            3 => Ok(Self::BuildMerkleRoot((
                Word::read_from(source)?,
                MerklePath::read_from(source)?,
                Felt::read_from(source)?,
            ))),
            4 => Ok(Self::UpdateMerkleRoot((
                Word::read_from(source)?,
                Word::read_from(source)?,
                MerklePath::read_from(source)?,
                Felt::read_from(source)?,
            ))),
            tag => Err(DeserializationError::InvalidValue(format!(
                "invalid hasher replay op tag {tag}"
            ))),
        }
    }

    fn min_serialized_size() -> usize {
        u8::min_serialized_size()
            + (MastForestId::min_serialized_size()
                + u32::min_serialized_size()
                + Word::min_serialized_size())
    }
}

impl Serializable for HasherRequestReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match &self.sink {
            HasherOpSink::Buffered(ops) => ops.write_into(target),
            #[cfg(feature = "std")]
            HasherOpSink::Streamed(_) => {
                panic!("cannot serialize streamed hasher request replay")
            },
        }
    }
}

impl Deserializable for HasherRequestReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            sink: HasherOpSink::Buffered(VecDeque::read_from(source)?),
        })
    }
}

impl Serializable for StackOverflowReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.overflow_values.write_into(target);
        self.restore_context_info.write_into(target);
    }
}

impl Deserializable for StackOverflowReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            overflow_values: VecDeque::read_from(source)?,
            restore_context_info: VecDeque::read_from(source)?,
        })
    }
}

impl Serializable for ExecutionReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.block_stack.write_into(target);
        self.execution_context.write_into(target);
        self.stack_overflow.write_into(target);
        self.memory_reads.write_into(target);
        self.advice.write_into(target);
        self.hasher.write_into(target);
        self.block_address.write_into(target);
        self.mast_forest_resolution.write_into(target);
    }
}

impl Deserializable for ExecutionReplay {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            block_stack: BlockStackReplay::read_from(source)?,
            execution_context: ExecutionContextReplay::read_from(source)?,
            stack_overflow: StackOverflowReplay::read_from(source)?,
            memory_reads: MemoryReadsReplay::read_from(source)?,
            advice: AdviceReplay::read_from(source)?,
            hasher: HasherResponseReplay::read_from(source)?,
            block_address: BlockAddressReplay::read_from(source)?,
            mast_forest_resolution: MastForestResolutionReplay::read_from(source)?,
        })
    }
}
