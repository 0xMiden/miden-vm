use alloc::{borrow::Borrow, string::ToString, sync::Arc, vec::Vec};

use miden_assembly_syntax::{ast::Instruction, debuginfo::Span, diagnostics::Report};
use miden_core::{
    AssemblyOp, Decorator, DecoratorList, Felt, Operation,
    mast::{DecoratorId, MastNodeId},
    sys_events::SystemEvent,
};

use crate::{ProcedureContext, assembler::BodyWrapper, mast_forest_builder::MastForestBuilder};

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
    last_asmop_pos: usize,
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
                last_asmop_pos: 0,
                mast_forest_builder,
            },
            None => Self {
                ops: Default::default(),
                decorators: Default::default(),
                epilogue: Default::default(),
                last_asmop_pos: 0,
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

    /// Adds an AsmOp decorator to the list of basic block decorators.
    ///
    /// This indicates that the provided instruction should be tracked and the cycle count for
    /// this instruction will be computed when the call to set_instruction_cycle_count() is made.
    pub fn track_instruction(
        &mut self,
        instruction: &Span<Instruction>,
        proc_ctx: &ProcedureContext,
    ) -> Result<(), Report> {
        let span = instruction.span();
        let location = proc_ctx.source_manager().location(span).ok();
        let context_name = proc_ctx.name().to_string();
        let num_cycles = 0;
        let op = instruction.to_string();
        let should_break = instruction.should_break();
        let op = AssemblyOp::new(location, context_name, num_cycles, op, should_break);
        self.push_decorator(Decorator::AsmOp(op))?;
        self.last_asmop_pos = self.decorators.len() - 1;

        Ok(())
    }

    /// Computes the number of cycles elapsed since the last invocation of track_instruction() and
    /// updates the related AsmOp decorator to include this cycle count.
    ///
    /// If the cycle count is 0, the original decorator is removed from the list and returned. This
    /// can happen for instructions which do not contribute any operations to the span block - e.g.,
    /// exec, call, and syscall.
    pub fn set_instruction_cycle_count(&mut self) -> Option<DecoratorId> {
        // get the last asmop decorator and the cycle at which it was added
        let (op_start, assembly_op_id) =
            self.decorators.get_mut(self.last_asmop_pos).expect("no asmop decorator");

        let assembly_op = match &mut self.mast_forest_builder[*assembly_op_id] {
            Decorator::AsmOp(assembly_op) => assembly_op,
            _ => panic!("internal error: last asmop decorator is not an AsmOp"),
        };

        // compute the cycle count for the instruction
        let cycle_count = self.ops.len() - *op_start;

        // if the cycle count is 0, remove the decorator; otherwise update its cycle count
        if cycle_count == 0 {
            let (_, decorator_id) = self.decorators.remove(self.last_asmop_pos);
            Some(decorator_id)
        } else {
            assembly_op.set_num_cycles(cycle_count as u8);

            None
        }
    }
}

/// Span Constructors
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

            let basic_block_node_id = self.mast_forest_builder.ensure_block(ops, decorators)?;

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
