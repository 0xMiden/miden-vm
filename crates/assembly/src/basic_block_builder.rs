use alloc::{
    borrow::Borrow,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::{
    ast::{DebugInlineCallInfo, DebugVarInfo, Instruction},
    debuginfo::{Location, Span},
    diagnostics::Report,
};
use miden_core::{
    Felt,
    events::SystemEvent,
    operations::{AssemblyOp, Operation},
};
use miden_mast_package::debug_info::{
    DebugFunctionIdx, DebugLocIdx, DebugSourceAsmOp, DebugSourceInlineCall, DebugSourceVar,
};

use crate::{
    ProcedureContext,
    assembler::BodyWrapper,
    mast_forest_builder::{MastForestBuilder, MastNodeUse},
};

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
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ActiveInlineCall {
    callee_idx: DebugFunctionIdx,
    loc_idx: DebugLocIdx,
}

// BASIC BLOCK BUILDER
// ================================================================================================

/// A helper struct for constructing basic blocks while compiling procedure bodies.
///
/// Operations and debug metadata can be added to a basic block builder, and then basic blocks can
/// be extracted from the builder via `extract_*()` methods.
///
/// The same basic block builder can be used to construct many blocks. It is expected that when the
/// last basic block in a procedure's body is constructed [`Self::try_into_basic_block`] will be
/// used.
#[derive(Debug)]
pub struct BasicBlockBuilder<'a> {
    ops: Vec<Operation>,
    epilogue: Vec<Operation>,
    /// Pending assembly operation info, waiting for cycle count to be computed.
    pending_asm_op: Option<PendingAsmOp>,
    /// Assembly op metadata attached to operations in this block.
    asm_ops: Vec<DebugSourceAsmOp>,
    /// Debug variables attached to operations in this block.
    debug_vars: Vec<DebugSourceVar>,
    /// Inline call chains attached to operations in this block.
    inline_calls: Vec<DebugSourceInlineCall>,
    /// The source-level inline call chain active for subsequently generated operations.
    active_inline_calls: Vec<ActiveInlineCall>,
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
                epilogue: wrapper.epilogue,
                pending_asm_op: None,
                asm_ops: Vec::new(),
                debug_vars: Vec::new(),
                inline_calls: Vec::new(),
                active_inline_calls: Vec::new(),
                mast_forest_builder,
            },
            None => Self {
                ops: Default::default(),
                epilogue: Default::default(),
                pending_asm_op: None,
                asm_ops: Vec::new(),
                debug_vars: Default::default(),
                inline_calls: Default::default(),
                active_inline_calls: Vec::new(),
                mast_forest_builder,
            },
        }
    }

    pub(super) fn with_active_inline_calls(
        wrapper: Option<BodyWrapper>,
        mast_forest_builder: &'a mut MastForestBuilder,
        active_inline_calls: Vec<ActiveInlineCall>,
    ) -> Self {
        let mut builder = Self::new(wrapper, mast_forest_builder);
        builder.active_inline_calls = active_inline_calls;
        builder
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

    pub(super) fn active_inline_calls(&self) -> &[ActiveInlineCall] {
        &self.active_inline_calls
    }

    pub(super) fn active_inline_call_rows(&self, op_idx: u32) -> Vec<DebugSourceInlineCall> {
        self.active_inline_calls
            .iter()
            .map(|inline_call| DebugSourceInlineCall {
                op_idx,
                callee_idx: inline_call.callee_idx,
                loc_idx: inline_call.loc_idx,
            })
            .collect()
    }
}

/// Operations
impl BasicBlockBuilder<'_> {
    /// Adds the specified operation to the list of basic block operations.
    pub fn push_op(&mut self, op: Operation) {
        if !self.active_inline_calls.is_empty() {
            self.record_active_inline_calls(self.ops.len() as u32);
        }
        self.ops.push(op);
    }

    /// Adds the specified sequence of operations to the list of basic block operations.
    pub fn push_ops<I, O>(&mut self, ops: I)
    where
        I: IntoIterator<Item = O>,
        O: Borrow<Operation>,
    {
        if self.active_inline_calls.is_empty() {
            self.ops.extend(ops.into_iter().map(|op| *op.borrow()));
        } else {
            for op in ops {
                self.push_op(*op.borrow());
            }
        }
    }

    /// Adds the specified operation n times to the list of basic block operations.
    pub fn push_op_many(&mut self, op: Operation, n: usize) {
        if self.active_inline_calls.is_empty() {
            self.ops.resize(self.ops.len() + n, op);
        } else {
            for _ in 0..n {
                self.push_op(op);
            }
        }
    }

    /// Converts the system event into its corresponding event ID, and adds an `Emit` operation
    /// to the list of basic block operations.
    pub fn push_system_event(&mut self, sys_event: SystemEvent) {
        let event_id = sys_event.event_id();
        self.push_ops([Operation::Push(event_id.as_felt()), Operation::Emit, Operation::Drop]);
    }
}

/// Assembly metadata
impl BasicBlockBuilder<'_> {
    /// Tracks an instruction for AssemblyOp metadata collection.
    ///
    /// This stores the instruction's metadata in a pending state. The cycle count will be
    /// computed when [`Self::set_instruction_cycle_count`] is called (typically after all
    /// operations for the instruction have been added).
    pub fn track_instruction(
        &mut self,
        instruction: &Span<Instruction>,
        proc_ctx: &ProcedureContext,
    ) {
        let span = instruction.span();
        self.pending_asm_op = Some(PendingAsmOp {
            op_start: self.ops.len(),
            location: proc_ctx.source_manager().location(span).ok(),
            context_name: proc_ctx.path().to_string(),
            op: instruction.to_string(),
        });
    }

    /// Finalizes the pending AssemblyOp with the computed cycle count.
    ///
    /// Computes the number of cycles elapsed since the last invocation of
    /// [`Self::track_instruction`] and creates an [`AssemblyOp`] with that cycle count.
    ///
    /// If the cycle count is 0 (instruction did not contribute any operations to the basic block,
    /// e.g., exec, call, syscall), returns the [`AssemblyOp`] so it can be attached to a control
    /// node. Otherwise, stores the [`AssemblyOp`] in the internal `asm_ops` list for later
    /// registration with the node's debug info.
    pub fn set_instruction_cycle_count(&mut self) -> Option<AssemblyOp> {
        let pending = self.pending_asm_op.take().expect("no pending asm op to finalize");

        // Compute the cycle count for the instruction
        let cycle_count = self.ops.len() - pending.op_start;
        match cycle_count {
            0 => {
                let asm_op = AssemblyOp::new(
                    pending.location,
                    pending.context_name,
                    cycle_count as u8,
                    pending.op,
                );

                Some(asm_op)
            },
            _ => {
                let debug_info = self.mast_forest_builder.debug_info_mut();
                let location_idx = pending.location.map(|loc| debug_info.add_location(loc));
                let context_name_idx = debug_info.add_string(pending.context_name);
                let op_name_idx = debug_info.add_string(pending.op);
                let asm_op = DebugSourceAsmOp::new(
                    pending.op_start as u32,
                    location_idx,
                    context_name_idx,
                    op_name_idx,
                    cycle_count as u8,
                );
                self.asm_ops.push(asm_op);
                None
            },
        }
    }

    /// Adds a debug variable to the list of debug variables for this basic block.
    ///
    /// Debug variables are stored in dedicated CSR storage (not as decorators) and are
    /// only accessed by the debugger. They track source-level variable locations at
    /// specific points in program execution.
    pub fn push_debug_var(&mut self, debug_var: DebugVarInfo) -> Result<(), Report> {
        let debug_info = self.mast_forest_builder.debug_info_mut();
        let name_idx = debug_info.add_string(debug_var.name().clone());
        let location_idx = debug_var.location().cloned().map(|loc| debug_info.add_location(loc));
        let type_id = if let Some(ty) = debug_var.ty() {
            let declared_ty = debug_var.declared_type();
            Some(debug_info.register_debug_type(None, declared_ty.as_deref(), ty)?)
        } else {
            None
        };
        let debug_var = DebugSourceVar {
            op_idx: self.ops.len() as u32,
            name_idx,
            type_id,
            arg_idx: debug_var.arg_index(),
            location_idx,
            value_location: debug_var.value_location().clone(),
        };
        self.debug_vars.push(debug_var);
        Ok(())
    }

    /// Appends one frame to the inline call chain active for subsequently generated operations.
    pub fn push_debug_inline_call(
        &mut self,
        inline_call: &DebugInlineCallInfo,
        source_manager: &dyn miden_assembly_syntax::debuginfo::SourceManager,
    ) {
        let Some(call_site_span) =
            source_manager.file_line_col_to_span(inline_call.call_site().clone())
        else {
            return;
        };
        let Ok(call_site) = source_manager.location(call_site_span) else {
            return;
        };

        let callee_idx = self.mast_forest_builder.register_inline_function(inline_call);
        let loc_idx = self.mast_forest_builder.debug_info_mut().add_location(call_site);
        self.active_inline_calls.push(ActiveInlineCall { callee_idx, loc_idx });
    }

    /// Clears the inline call chain active for subsequently generated operations.
    pub fn clear_debug_inline_calls(&mut self) {
        self.active_inline_calls.clear();
    }

    fn record_active_inline_calls(&mut self, op_idx: u32) {
        self.inline_calls.extend(self.active_inline_calls.iter().map(|inline_call| {
            DebugSourceInlineCall {
                op_idx,
                callee_idx: inline_call.callee_idx,
                loc_idx: inline_call.loc_idx,
            }
        }));
    }
}

/// Basic Block Constructors
impl BasicBlockBuilder<'_> {
    /// Creates and returns a new basic block node from the operations currently in this builder.
    ///
    /// If there are no operations however, then no node is created and `None` is returned.
    ///
    /// This consumes all operations in the builder, but does not touch the operations in the
    /// epilogue of the builder.
    pub(crate) fn make_basic_block(&mut self) -> Result<Option<MastNodeUse>, Report> {
        if !self.ops.is_empty() {
            let ops = core::mem::take(&mut self.ops);
            let asm_ops = core::mem::take(&mut self.asm_ops);
            let debug_vars = core::mem::take(&mut self.debug_vars);
            let inline_calls = core::mem::take(&mut self.inline_calls);

            let basic_block_node_use = self.mast_forest_builder.ensure_block_use(
                ops,
                asm_ops,
                debug_vars,
                inline_calls,
                vec![],
            )?;

            Ok(Some(basic_block_node_use))
        } else {
            Ok(None)
        }
    }

    /// Creates and returns a new basic block node from the operations currently in this builder.
    /// If the builder is empty, then no node is created.
    ///
    /// The main differences with [`Self::make_basic_block`] are:
    /// - Operations contained in the epilogue of the builder are appended to the list of ops which
    ///   go into the new BASIC BLOCK node.
    /// - The builder is consumed in the process.
    pub fn try_into_basic_block(mut self) -> Result<Option<MastNodeUse>, Report> {
        self.ops.append(&mut self.epilogue);
        self.make_basic_block()
    }
}

impl BasicBlockBuilder<'_> {
    /// Registers an error message in the MAST Forest and returns the
    /// corresponding error code as a Felt.
    pub fn register_error(&mut self, msg: Arc<str>) -> Felt {
        self.mast_forest_builder.register_error(msg)
    }
}
