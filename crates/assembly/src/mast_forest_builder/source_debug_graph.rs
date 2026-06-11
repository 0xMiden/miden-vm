use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

#[cfg(feature = "std")]
use miden_assembly_syntax::debuginfo::{FileLineCol, Location};
use miden_core::{
    mast::MastNodeId,
    operations::{AssemblyOp, DebugVarInfo},
    utils::{IndexVec, newtype_id},
};

// Final dense ID for a source/debug occurrence of a MAST node.
newtype_id!(SourceNodeId);

/// Finalized source/debug occurrence for a reduced execution node.
#[derive(Clone, Debug)]
pub(crate) struct SourceNode {
    /// Final execution MAST node represented by this source occurrence.
    exec_node: MastNodeId,
    /// Source/debug children in the same order as the execution node children they describe.
    children: Vec<SourceNodeId>,
    /// Inclusive operation start within the final execution node.
    op_start: usize,
    /// Exclusive operation end within the final execution node.
    op_end: usize,
    /// Assembly operation metadata attached to operation offsets in this occurrence.
    asm_ops: Vec<(usize, AssemblyOp)>,
    /// Debug variable metadata attached to operation offsets in this occurrence.
    debug_vars: Vec<(usize, DebugVarInfo)>,
}

impl SourceNode {
    pub(super) fn new(
        exec_node: MastNodeId,
        children: Vec<SourceNodeId>,
        op_start: usize,
        op_end: usize,
        asm_ops: Vec<(usize, AssemblyOp)>,
        debug_vars: Vec<(usize, DebugVarInfo)>,
    ) -> Self {
        Self {
            exec_node,
            children,
            op_start,
            op_end,
            asm_ops,
            debug_vars,
        }
    }

    pub(crate) fn exec_node(&self) -> MastNodeId {
        self.exec_node
    }

    pub(crate) fn children(&self) -> &[SourceNodeId] {
        &self.children
    }

    pub(crate) fn op_start(&self) -> usize {
        self.op_start
    }

    pub(crate) fn op_end(&self) -> usize {
        self.op_end
    }

    pub(crate) fn asm_ops(&self) -> &[(usize, AssemblyOp)] {
        &self.asm_ops
    }

    pub(crate) fn debug_vars(&self) -> &[(usize, DebugVarInfo)] {
        &self.debug_vars
    }

    #[cfg(feature = "std")]
    fn rewrite_source_locations(
        &mut self,
        rewrite_location: &mut impl FnMut(Location) -> Location,
        rewrite_file_line_col: &mut impl FnMut(FileLineCol) -> FileLineCol,
    ) {
        for (_, asm_op) in self.asm_ops.iter_mut() {
            if let Some(location) = asm_op.location().cloned() {
                asm_op.set_location(rewrite_location(location));
            }
        }
        for (_, debug_var) in self.debug_vars.iter_mut() {
            if let Some(location) = debug_var.location().cloned() {
                debug_var.set_location(rewrite_file_line_col(location));
            }
        }
    }
}

/// Source/debug occurrence graph produced alongside a reduced execution MAST forest.
#[derive(Clone, Debug, Default)]
pub(crate) struct SourceDebugGraph {
    /// Dense source/debug occurrence nodes keyed by [`SourceNodeId`].
    nodes: IndexVec<SourceNodeId, SourceNode>,
    /// Source/debug roots corresponding to procedure roots in the finalized MAST forest.
    roots: Vec<SourceNodeId>,
    /// Error-code messages collected while assembling this source graph.
    error_messages: BTreeMap<u64, Arc<str>>,
}

impl SourceDebugGraph {
    pub(super) fn new(nodes: IndexVec<SourceNodeId, SourceNode>, roots: Vec<SourceNodeId>) -> Self {
        Self {
            nodes,
            roots,
            error_messages: BTreeMap::new(),
        }
    }

    pub(crate) fn nodes(&self) -> &IndexVec<SourceNodeId, SourceNode> {
        &self.nodes
    }

    pub(crate) fn roots(&self) -> &[SourceNodeId] {
        &self.roots
    }

    pub(crate) fn error_messages(&self) -> &BTreeMap<u64, Arc<str>> {
        &self.error_messages
    }

    pub(crate) fn with_error_messages(mut self, error_messages: BTreeMap<u64, Arc<str>>) -> Self {
        self.error_messages = error_messages;
        self
    }

    pub(crate) fn unique_root_for_exec_node(&self, exec_node: MastNodeId) -> Option<SourceNodeId> {
        let mut roots = self
            .roots
            .iter()
            .copied()
            .filter(|root| self.nodes[*root].exec_node() == exec_node);
        let root = roots.next()?;
        roots.next().is_none().then_some(root)
    }

    #[cfg(feature = "std")]
    pub(crate) fn with_rewritten_source_locations(
        mut self,
        mut rewrite_location: impl FnMut(Location) -> Location,
        mut rewrite_file_line_col: impl FnMut(FileLineCol) -> FileLineCol,
    ) -> Self {
        for source_node in self.nodes.iter_mut() {
            source_node.rewrite_source_locations(&mut rewrite_location, &mut rewrite_file_line_col);
        }
        self
    }
}
