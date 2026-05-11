use miden_assembly_syntax::{
    Word,
    ast::{InvocationTarget, InvokeKind},
    diagnostics::Report,
};
use miden_core::operations::{AssemblyOp, Operation};
use smallvec::SmallVec;

use crate::{
    Assembler, GlobalItemIndex,
    basic_block_builder::BasicBlockBuilder,
    mast_forest_builder::{MastForestBuilder, MastNodeRef},
};

/// Procedure Invocation
impl Assembler {
    /// Returns the [`MastNodeRef`] of the invoked procedure specified by `callee`.
    ///
    /// For example, given `exec.f`, this method would return the procedure body id of `f`. If the
    /// only representation of `f` that we have is its MAST root, then this method will also insert
    /// a [`core::mast::ExternalNode`] that wraps `f`'s MAST root and return the corresponding id.
    pub(super) fn invoke(
        &self,
        kind: InvokeKind,
        callee: &InvocationTarget,
        caller: GlobalItemIndex,
        mast_forest_builder: &mut MastForestBuilder,
        asm_op: Option<AssemblyOp>,
    ) -> Result<MastNodeRef, Report> {
        let resolved = self
            .resolve_target(kind, callee, caller, mast_forest_builder)?
            .ok_or_else(|| self.invalid_invoke_target_report(kind, callee, caller))?;

        match kind {
            InvokeKind::ProcRef | InvokeKind::Exec => Ok(resolved.node),
            InvokeKind::Call | InvokeKind::SysCall => mast_forest_builder.ensure_call_node_ref(
                resolved.node,
                matches!(kind, InvokeKind::SysCall),
                asm_op.expect("call and syscall invocations must provide an AssemblyOp"),
            ),
        }
    }

    /// Creates a new DYN block for the dynamic code execution and return.
    pub(super) fn dynexec(
        &self,
        mast_forest_builder: &mut MastForestBuilder,
        asm_op: AssemblyOp,
    ) -> Result<Option<MastNodeRef>, Report> {
        let dyn_node_ref = mast_forest_builder.ensure_dyn_node_ref(false, asm_op)?;

        Ok(Some(dyn_node_ref))
    }

    /// Creates a new DYNCALL block for the dynamic function call and return.
    pub(super) fn dyncall(
        &self,
        mast_forest_builder: &mut MastForestBuilder,
        asm_op: AssemblyOp,
    ) -> Result<Option<MastNodeRef>, Report> {
        let dyn_call_node_ref = mast_forest_builder.ensure_dyn_node_ref(true, asm_op)?;

        Ok(Some(dyn_call_node_ref))
    }

    pub(super) fn procref(
        &self,
        callee: &InvocationTarget,
        caller: GlobalItemIndex,
        block_builder: &mut BasicBlockBuilder,
    ) -> Result<(), Report> {
        let mast_root = {
            let resolved = self
                .resolve_target(
                    InvokeKind::ProcRef,
                    callee,
                    caller,
                    block_builder.mast_forest_builder_mut(),
                )?
                .ok_or_else(|| {
                    self.invalid_invoke_target_report(InvokeKind::ProcRef, callee, caller)
                })?;
            // Note: it's ok to `unwrap()` here since `proc_body_id` was returned from
            // `mast_forest_builder`
            block_builder.mast_forest_builder().mast_root_for_ref(resolved.node).unwrap()
        };

        self.procref_mast_root(mast_root, block_builder)
    }

    fn procref_mast_root(
        &self,
        mast_root: Word,
        block_builder: &mut BasicBlockBuilder,
    ) -> Result<(), Report> {
        // Create an array with `Push` operations containing root elements.
        // Push in reverse order so that mast_root[0] ends up on top.
        let ops = mast_root
            .iter()
            .rev()
            .map(|elem| Operation::Push(*elem))
            .collect::<SmallVec<[_; 4]>>();
        block_builder.push_ops(ops);
        Ok(())
    }
}
