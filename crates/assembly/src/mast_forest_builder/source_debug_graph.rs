#![allow(dead_code)]

use alloc::vec::Vec;

use miden_assembly_syntax::debuginfo::{FileLineCol, Location};
use miden_core::{
    mast::MastNodeId,
    operations::{AssemblyOp, DebugVarInfo},
    utils::{Idx, IndexVec},
};

/// Final dense ID for a source/debug occurrence of a MAST node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub(crate) struct SourceMastNodeId(u32);

impl From<u32> for SourceMastNodeId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<SourceMastNodeId> for u32 {
    fn from(value: SourceMastNodeId) -> Self {
        value.0
    }
}

impl Idx for SourceMastNodeId {}

/// Finalized source/debug occurrence for a reduced execution node.
#[derive(Clone, Debug)]
pub(crate) struct SourceMastNode {
    exec_node: MastNodeId,
    children: Vec<SourceMastNodeId>,
    op_start: usize,
    op_end: usize,
    asm_ops: Vec<(usize, AssemblyOp)>,
    debug_vars: Vec<(usize, DebugVarInfo)>,
}

impl SourceMastNode {
    pub(super) fn new(
        exec_node: MastNodeId,
        children: Vec<SourceMastNodeId>,
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

    pub(crate) fn children(&self) -> &[SourceMastNodeId] {
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
    nodes: IndexVec<SourceMastNodeId, SourceMastNode>,
    roots: Vec<SourceMastNodeId>,
}

impl SourceDebugGraph {
    pub(super) fn new(
        nodes: IndexVec<SourceMastNodeId, SourceMastNode>,
        roots: Vec<SourceMastNodeId>,
    ) -> Self {
        Self { nodes, roots }
    }

    pub(crate) fn nodes(&self) -> &IndexVec<SourceMastNodeId, SourceMastNode> {
        &self.nodes
    }

    pub(crate) fn roots(&self) -> &[SourceMastNodeId] {
        &self.roots
    }

    pub(crate) fn source_nodes_for_exec_node(
        &self,
        exec_node: MastNodeId,
    ) -> impl Iterator<Item = (SourceMastNodeId, &SourceMastNode)> {
        self.nodes
            .as_slice()
            .iter()
            .enumerate()
            .filter_map(move |(index, source_node)| {
                (source_node.exec_node() == exec_node)
                    .then_some((SourceMastNodeId::from(index as u32), source_node))
            })
    }

    pub(crate) fn unique_root_for_exec_node(
        &self,
        exec_node: MastNodeId,
    ) -> Option<SourceMastNodeId> {
        let mut roots = self
            .roots
            .iter()
            .copied()
            .filter(|root| self.nodes[*root].exec_node() == exec_node);
        let root = roots.next()?;
        roots.next().is_none().then_some(root)
    }

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
