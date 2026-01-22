use alloc::{
    borrow::Borrow,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::{
    ast::Instruction,
    debuginfo::{Location, Span},
    diagnostics::Report,
};
use miden_core::{
    AssemblyOp, Decorator, DecoratorList, Felt, Operation,
    mast::{DecoratorId, MastNodeId},
    sys_events::SystemEvent,
};

use crate::{ProcedureContext, assembler::BodyWrapper, mast_forest_builder::MastForestBuilder};

// PENDING ASM OP
// ================================================================================================

/// Information about an instruction being tracked, pending cycle count computation.
///
/// When an instruction is encountered during assembly, we don't yet know how many VM cycles
/// it will consume. This struct holds the instruction's metadata until the cycle count can
/// be computed (when the next instruction begins or the block ends).
#[derive(Debug)]
struct PendingAsmOp {
    /// Operation index where this instruction started (before any ops were added for it).
    op_start: usize,
    /// Source location in the original source file, if available.
    location: Option<Location>,
    /// The fully-qualified procedure path (e.g., "std::math::u64::add").
    context_name: String,
    /// The string representation of the instruction (e.g., "add", "push.1").
    op: String,
    /// Whether this instruction is a breakpoint.
    should_break: bool,
}

// BASIC BLOCK BUILDER
// ================================================================================================

/// A helper struct for constructing basic blocks while compiling procedure bodies.
///
/// Operations and decorators can be added to a basic block builder via various `add_*()` and
/// `push_*()` methods, and then basic blocks can be extracted from the builder via `extract_*()`
/// methods.
///
/// The same basic block builder can be used to construct many blocks. It is expected that when the
/// last basic block in a procedure's body is constructed [`Self::try_into_basic_block`] will be
/// used.
#[derive(Debug)]
pub struct BasicBlockBuilder<'a> {
    ops: Vec<Operation>,
    decorators: DecoratorList,
    epilogue: Vec<Operation>,
    /// Pending assembly operation info, waiting for cycle count to be computed.
    pending_asm_op: Option<PendingAsmOp>,
    /// Finalized AssemblyOps with their operation indices (op_idx, AssemblyOp).
    asm_ops: Vec<(usize, AssemblyOp)>,
    mast_forest_builder: &'a mut MastForestBuilder,
}

/// Constructors
impl<'a> BasicBlockBuilder<'a> {
    /// Returns a new [`BasicBlockBuilder`] instantiated with the specified optional wrapper.
    ///
    /// If the wrapper is provided, the prologue of the wrapper is immediately appended to the
    /// vector of span operations. The epilogue of the wrapper is appended to the list of operations
    /// upon consumption of the builder via the [`Self::try_into_basic_block`] method.
    pub(super) fn new(
        wrapper: Option<BodyWrapper>,
        mast_forest_builder: &'a mut MastForestBuilder,
    ) -> Self {
        match wrapper {
            Some(wrapper) => Self {
                ops: wrapper.prologue,
                decorators: Vec::new(),
                epilogue: wrapper.epilogue,
                pending_asm_op: None,
                asm_ops: Vec::new(),
                mast_forest_builder,
            },
            None => Self {
                ops: Default::default(),
                decorators: Default::default(),
                epilogue: Default::default(),
                pending_asm_op: None,
                asm_ops: Vec::new(),
                mast_forest_builder,
            },
        }
    }
}

/// Accessors
impl BasicBlockBuilder<'_> {
    /// Returns a reference to the internal [`MastForestBuilder`].
    pub fn mast_forest_builder(&self) -> &MastForestBuilder {
        self.mast_forest_builder
    }

    /// Returns a mutable reference to the internal [`MastForestBuilder`].
    pub fn mast_forest_builder_mut(&mut self) -> &mut MastForestBuilder {
        self.mast_forest_builder
    }
}

/// Operations
impl BasicBlockBuilder<'_> {
    /// Adds the specified operation to the list of basic block operations.
    pub fn push_op(&mut self, op: Operation) {
        self.ops.push(op);
    }

    /// Adds the specified sequence of operations to the list of basic block operations.
    pub fn push_ops<I, O>(&mut self, ops: I)
    where
        I: IntoIterator<Item = O>,
        O: Borrow<Operation>,
    {
        self.ops.extend(ops.into_iter().map(|o| *o.borrow()));
    }

    /// Adds the specified operation n times to the list of basic block operations.
    pub fn push_op_many(&mut self, op: Operation, n: usize) {
        let new_len = self.ops.len() + n;
        self.ops.resize(new_len, op);
    }

    /// Converts the system event into its corresponding event ID, and adds an `Emit` operation
    /// to the list of basic block operations.
    pub fn push_system_event(&mut self, sys_event: SystemEvent) {
        let event_id = sys_event.event_id();
        self.push_ops([Operation::Push(event_id.as_felt()), Operation::Emit, Operation::Drop]);
    }
}

/// Decorators
impl BasicBlockBuilder<'_> {
    /// Add the specified decorator to the list of basic block decorators.
    pub fn push_decorator(&mut self, decorator: Decorator) -> Result<(), Report> {
        let decorator_id = self.mast_forest_builder.ensure_decorator(decorator)?;
        self.decorators.push((self.ops.len(), decorator_id));

        Ok(())
    }

    /// Tracks an instruction for AssemblyOp metadata collection.
    ///
    /// This stores the instruction's metadata in a pending state. The cycle count will be
    /// computed when [`Self::set_instruction_cycle_count`] is called (typically after all
    /// operations for the instruction have been added).
    pub fn track_instruction(
        &mut self,
        instruction: &Span<Instruction>,
        proc_ctx: &ProcedureContext,
    ) -> Result<(), Report> {
        let span = instruction.span();
        self.pending_asm_op = Some(PendingAsmOp {
            op_start: self.ops.len(),
            location: proc_ctx.source_manager().location(span).ok(),
            context_name: proc_ctx.path().to_string(),
            op: instruction.to_string(),
            should_break: instruction.should_break(),
        });

        Ok(())
    }

    /// Finalizes the pending AssemblyOp with the computed cycle count.
    ///
    /// Computes the number of cycles elapsed since the last invocation of
    /// [`Self::track_instruction`] and creates an [`AssemblyOp`] with that cycle count.
    ///
    /// If the cycle count is 0 (instruction did not contribute any operations to the basic block,
    /// e.g., exec, call, syscall), returns the [`AssemblyOp`] so it can be attached to a node-level
    /// decorator. Otherwise, stores the [`AssemblyOp`] in the internal `asm_ops` list for later
    /// registration with the node's debug info.
    pub fn set_instruction_cycle_count(&mut self) -> Option<AssemblyOp> {
        let pending = self.pending_asm_op.take().expect("no pending asm op to finalize");

        // Compute the cycle count for the instruction
        let cycle_count = self.ops.len() - pending.op_start;

        let asm_op = AssemblyOp::new(
            pending.location,
            pending.context_name,
            cycle_count as u8,
            pending.op,
            pending.should_break,
        );

        if cycle_count == 0 {
            // Return for node-level attachment (exec/call/syscall)
            Some(asm_op)
        } else {
            // Store for basic block registration
            self.asm_ops.push((pending.op_start, asm_op));
            None
        }
    }
}

/// Basic Block Constructors
impl BasicBlockBuilder<'_> {
    /// Creates and returns a new basic block node from the operations and decorators currently in
    /// this builder.
    ///
    /// If there are no operations however, then no node is created, the decorators are left
    /// untouched and `None` is returned. Use [`Self::drain_decorators`] to retrieve the decorators
    /// in this case.
    ///
    /// This consumes all operations in the builder, but does not touch the operations in the
    /// epilogue of the builder.
    pub fn make_basic_block(&mut self) -> Result<Option<MastNodeId>, Report> {
        if !self.ops.is_empty() {
            let ops = self.ops.drain(..).collect();
            let decorators = self.decorators.drain(..).collect();
            let asm_ops = core::mem::take(&mut self.asm_ops);

            let basic_block_node_id =
                self.mast_forest_builder
                    .ensure_block(ops, decorators, asm_ops, vec![], vec![])?;

            Ok(Some(basic_block_node_id))
        } else {
            Ok(None)
        }
    }

    /// Creates and returns a new basic block node from the operations and decorators currently in
    /// this builder. If there are no operations however, we return the decorators that were
    /// accumulated up until this point. If the builder is empty, then no node is created and
    /// `Nothing` is returned.
    ///
    /// The main differences with [`Self::make_basic_block`] are:
    /// - Operations contained in the epilogue of the builder are appended to the list of ops which
    ///   go into the new BASIC BLOCK node.
    /// - The builder is consumed in the process.
    /// - Hence, any remaining decorators if no basic block was created are drained and returned.
    pub fn try_into_basic_block(mut self) -> Result<BasicBlockOrDecorators, Report> {
        self.ops.append(&mut self.epilogue);

        if let Some(basic_block_node_id) = self.make_basic_block()? {
            Ok(BasicBlockOrDecorators::BasicBlock(basic_block_node_id))
        } else if let Some(decorator_ids) = self.drain_decorators() {
            Ok(BasicBlockOrDecorators::Decorators(decorator_ids))
        } else {
            Ok(BasicBlockOrDecorators::Nothing)
        }
    }

    /// Drains and returns the decorators in the builder, if any.
    ///
    /// This should only be called after [`Self::make_basic_block`], when no blocks were created.
    /// In other words, there MUST NOT be any operations left in the builder when this is called.
    ///
    /// # Panics
    ///
    /// Panics if there are still operations left in the builder.
    pub fn drain_decorators(&mut self) -> Option<Vec<DecoratorId>> {
        assert!(self.ops.is_empty());
        if !self.decorators.is_empty() {
            Some(self.decorators.drain(..).map(|(_, decorator_id)| decorator_id).collect())
        } else {
            None
        }
    }
}

/// Holds either the node id of a basic block, or a list of decorators that are currently not
/// attached to any node.
pub enum BasicBlockOrDecorators {
    BasicBlock(MastNodeId),
    Decorators(Vec<DecoratorId>),
    Nothing,
}

impl BasicBlockBuilder<'_> {
    /// Registers an error message in the MAST Forest and returns the
    /// corresponding error code as a Felt.
    pub fn register_error(&mut self, msg: Arc<str>) -> Felt {
        self.mast_forest_builder.register_error(msg)
    }
}
