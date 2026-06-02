//! Type definitions for the debug_info section.
//!
//! This module provides types for storing debug information in MASP packages,
//! enabling debuggers to provide meaningful source-level debugging experiences.
//!
//! # Overview
//!
//! The debug info section contains:
//! - **Type definitions**: Describe the types of variables (primitives, structs, arrays, etc.)
//! - **Source file paths**: Deduplicated file paths for source locations
//! - **Function metadata**: Function signatures, local variables, and inline call sites
//!
//! # Usage
//!
//! Debuggers can use this information along with MAST debug metadata to provide source-level
//! variable inspection, stepping, and call stack visualization.

use alloc::{boxed::Box, collections::BTreeMap, string::String, sync::Arc, vec::Vec};

use miden_core::{
    Word,
    mast::{MastForestRootMap, MastNodeId},
    operations::DebugVarInfo,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use miden_debug_types::{ColumnNumber, LineNumber, Location};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// DEBUG SOURCE GRAPH LOOKUP ERROR
// ================================================================================================

/// Error returned when a caller needs a unique source/debug occurrence but the graph cannot supply
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DebugSourceGraphLookupError {
    /// The requested parent source/debug occurrence is not present.
    #[error("source/debug occurrence {source_node:?} is not present")]
    MissingSourceNode { source_node: DebugSourceMastNodeId },
    /// Multiple source/debug roots point at the same executable MAST node.
    #[error("multiple source/debug roots point at executable MAST node {exec_node:?}")]
    AmbiguousRoot { exec_node: MastNodeId },
    /// Multiple children of one source/debug occurrence point at the same executable MAST node.
    #[error(
        "multiple children of source/debug occurrence {parent:?} point at executable MAST node {exec_node:?}"
    )]
    AmbiguousChild {
        parent: DebugSourceMastNodeId,
        exec_node: MastNodeId,
    },
}

// PACKAGE DEBUG INFO MERGE ERROR
// ================================================================================================

/// Error returned when package-owned source/debug metadata cannot be remapped after a
/// [`miden_core::mast::MastForest`] merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PackageDebugInfoMergeError {
    /// The package has source-keyed metadata rows without a source graph to define source IDs.
    #[error("debug info for forest {forest_index} has source-map rows but no source graph")]
    SourceMapWithoutGraph { forest_index: usize },
    /// A source/debug occurrence points at an execution node that was not present in the merge map.
    #[error(
        "debug info for forest {forest_index} references execution node {exec_node:?}, which is not present in the merge map"
    )]
    MissingExecNodeMapping {
        forest_index: usize,
        exec_node: MastNodeId,
    },
    /// A source-keyed metadata row refers to a source/debug occurrence that was not present in the
    /// corresponding source graph.
    #[error(
        "debug info for forest {forest_index} references source/debug occurrence {source_node:?}, which is not present in the source graph"
    )]
    MissingSourceNodeMapping {
        forest_index: usize,
        source_node: DebugSourceMastNodeId,
    },
}

// DEBUG TYPE INDEX
// ================================================================================================

/// A strongly-typed index into the type table of a [`DebugTypesSection`].
///
/// This prevents accidental misuse of raw `u32` indices (e.g., using a string index
/// where a type index is expected).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
pub struct DebugTypeIdx(u32);

impl DebugTypeIdx {
    /// Returns the inner value as a `u32`.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<u32> for DebugTypeIdx {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<DebugTypeIdx> for u32 {
    fn from(value: DebugTypeIdx) -> Self {
        value.0
    }
}

impl Serializable for DebugTypeIdx {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.0);
    }

    fn get_size_hint(&self) -> usize {
        4
    }
}

impl Deserializable for DebugTypeIdx {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(source.read_u32()?))
    }

    fn min_serialized_size() -> usize {
        4
    }
}

// DEBUG TYPES SECTION
// ================================================================================================

/// The version of the debug_types section format.
pub const DEBUG_TYPES_VERSION: u8 = 1;

/// Debug types section containing type definitions for a MASP package.
///
/// This section stores type information (primitives, structs, enums, arrays, pointers,
/// function types) that enables debuggers to properly display values.
///
/// String indices in sub-types (e.g., `name_idx` in `DebugFieldInfo`) are relative
/// to this section's own string table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugTypesSection {
    /// Version of the debug types format
    pub version: u8,
    /// String table containing type names, field names
    pub strings: Vec<Arc<str>>,
    /// Type table containing all type definitions
    pub types: Vec<DebugTypeInfo>,
}

impl DebugTypesSection {
    /// Creates a new empty debug types section.
    pub fn new() -> Self {
        Self {
            version: DEBUG_TYPES_VERSION,
            strings: Vec::new(),
            types: Vec::new(),
        }
    }

    /// Adds a string to the string table and returns its index.
    pub fn add_string(&mut self, s: Arc<str>) -> u32 {
        if let Some(idx) = self.strings.iter().position(|existing| **existing == *s) {
            return idx as u32;
        }
        let idx = self.strings.len() as u32;
        self.strings.push(s);
        idx
    }

    /// Gets a string by index.
    pub fn get_string(&self, idx: u32) -> Option<Arc<str>> {
        self.strings.get(idx as usize).cloned()
    }

    /// Adds a type to the type table and returns its index.
    pub fn add_type(&mut self, ty: DebugTypeInfo) -> DebugTypeIdx {
        let idx = DebugTypeIdx(self.types.len() as u32);
        self.types.push(ty);
        idx
    }

    /// Gets a type by index.
    pub fn get_type(&self, idx: DebugTypeIdx) -> Option<&DebugTypeInfo> {
        self.types.get(idx.0 as usize)
    }

    /// Returns true if the section is empty (no types).
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }
}

// DEBUG SOURCES SECTION
// ================================================================================================

/// The version of the debug_sources section format.
pub const DEBUG_SOURCES_VERSION: u8 = 1;

/// Debug sources section containing source file paths and checksums.
///
/// This section stores deduplicated source file information that is referenced
/// by the debug functions section.
///
/// String indices in sub-types (e.g., `path_idx` in `DebugFileInfo`) are relative
/// to this section's own string table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugSourcesSection {
    /// Version of the debug sources format
    pub version: u8,
    /// String table containing file paths
    pub strings: Vec<Arc<str>>,
    /// Source file table
    pub files: Vec<DebugFileInfo>,
}

impl DebugSourcesSection {
    /// Creates a new empty debug sources section.
    pub fn new() -> Self {
        Self {
            version: DEBUG_SOURCES_VERSION,
            strings: Vec::new(),
            files: Vec::new(),
        }
    }

    /// Adds a string to the string table and returns its index.
    pub fn add_string(&mut self, s: Arc<str>) -> u32 {
        if let Some(idx) = self.strings.iter().position(|existing| **existing == *s) {
            return idx as u32;
        }
        let idx = self.strings.len() as u32;
        self.strings.push(s);
        idx
    }

    /// Gets a string by index.
    pub fn get_string(&self, idx: u32) -> Option<Arc<str>> {
        self.strings.get(idx as usize).cloned()
    }

    /// Adds a file to the file table and returns its index.
    pub fn add_file(&mut self, file: DebugFileInfo) -> u32 {
        if let Some(idx) = self.files.iter().position(|existing| existing.path_idx == file.path_idx)
        {
            return idx as u32;
        }
        let idx = self.files.len() as u32;
        self.files.push(file);
        idx
    }

    /// Gets a file by index.
    pub fn get_file(&self, idx: u32) -> Option<&DebugFileInfo> {
        self.files.get(idx as usize)
    }

    /// Returns true if the section is empty (no files).
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

// DEBUG FUNCTIONS SECTION
// ================================================================================================

/// The version of the debug_functions section format.
pub const DEBUG_FUNCTIONS_VERSION: u8 = 1;
/// The version of the debug_source_graph section format.
pub const DEBUG_SOURCE_GRAPH_VERSION: u8 = 1;
/// The version of the debug_source_map section format.
pub const DEBUG_SOURCE_MAP_VERSION: u8 = 1;

/// Debug functions section containing function metadata, variables, and inlined calls.
///
/// This section stores function debug information including local variables and
/// inlined call sites.
///
/// String indices in sub-types (e.g., `name_idx` in `DebugFunctionInfo`) are relative
/// to this section's own string table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugFunctionsSection {
    /// Version of the debug functions format
    pub version: u8,
    /// String table containing function names, variable names, linkage names
    pub strings: Vec<Arc<str>>,
    /// Function debug information
    pub functions: Vec<DebugFunctionInfo>,
}

impl DebugFunctionsSection {
    /// Creates a new empty debug functions section.
    pub fn new() -> Self {
        Self {
            version: DEBUG_FUNCTIONS_VERSION,
            strings: Vec::new(),
            functions: Vec::new(),
        }
    }

    /// Adds a string to the string table and returns its index.
    pub fn add_string(&mut self, s: Arc<str>) -> u32 {
        if let Some(idx) = self.strings.iter().position(|existing| **existing == *s) {
            return idx as u32;
        }
        let idx = self.strings.len() as u32;
        self.strings.push(s);
        idx
    }

    /// Gets a string by index.
    pub fn get_string(&self, idx: u32) -> Option<Arc<str>> {
        self.strings.get(idx as usize).cloned()
    }

    /// Adds a function to the function table.
    pub fn add_function(&mut self, func: DebugFunctionInfo) {
        self.functions.push(func);
    }

    /// Returns true if the section is empty (no functions).
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}

// PACKAGE DEBUG INFO
// ================================================================================================

/// Trusted package-owned debug information decoded from well-known debug sections.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PackageDebugInfo {
    /// Type definitions for source-level debug consumers.
    pub types: Option<DebugTypesSection>,
    /// Source file table.
    pub sources: Option<DebugSourcesSection>,
    /// Function metadata.
    pub functions: Option<DebugFunctionsSection>,
    /// Source/debug MAST occurrence graph.
    pub source_graph: Option<DebugSourceGraphSection>,
    /// Source-keyed assembly operation and debug variable rows.
    pub source_map: Option<DebugSourceMapSection>,
}

impl PackageDebugInfo {
    /// Returns true if no package debug sections were decoded.
    pub fn is_empty(&self) -> bool {
        self.types.is_none()
            && self.sources.is_none()
            && self.functions.is_none()
            && self.source_graph.is_none()
            && self.source_map.is_none()
    }

    /// Merges package-owned source/debug metadata after a [`miden_core::mast::MastForest`] merge.
    ///
    /// [`miden_core::mast::MastForest::merge`] remains execution-only. This helper applies the
    /// returned node mappings to package source/debug sections so callers can merge
    /// `(MastForest, PackageDebugInfo)` pairs without reattaching debug metadata to the forest.
    ///
    /// This merges only `debug_source_graph` and `debug_source_map`; type, source-file, and
    /// function sections have their own string/index tables and are left for higher-level package
    /// composition.
    pub fn merge_source_debug<'a>(
        inputs: impl IntoIterator<Item = (usize, &'a PackageDebugInfo)>,
        root_map: &MastForestRootMap,
    ) -> Result<Self, PackageDebugInfoMergeError> {
        let mut nodes = Vec::new();
        let mut roots = Vec::new();
        let mut asm_ops = Vec::new();
        let mut debug_vars = Vec::new();
        let mut saw_source_graph = false;
        let mut saw_source_map = false;

        for (forest_index, debug_info) in inputs {
            let source_graph = debug_info.source_graph.as_ref();
            let source_map = debug_info.source_map.as_ref();
            if source_graph.is_none() && source_map.is_some_and(|source_map| !source_map.is_empty())
            {
                return Err(PackageDebugInfoMergeError::SourceMapWithoutGraph { forest_index });
            }

            let Some(source_graph) = source_graph else {
                continue;
            };
            saw_source_graph = true;

            let mut source_id_map = BTreeMap::new();
            for old_source_idx in 0..source_graph.nodes.len() {
                source_id_map.insert(
                    DebugSourceMastNodeId::from(old_source_idx as u32),
                    DebugSourceMastNodeId::from(nodes.len() as u32 + old_source_idx as u32),
                );
            }

            for (old_source_idx, source_node) in source_graph.nodes.iter().enumerate() {
                let exec_node = root_map.map_node(forest_index, &source_node.exec_node).ok_or(
                    PackageDebugInfoMergeError::MissingExecNodeMapping {
                        forest_index,
                        exec_node: source_node.exec_node,
                    },
                )?;
                let children = source_node
                    .children
                    .iter()
                    .map(|child| {
                        source_id_map.get(child).copied().ok_or(
                            PackageDebugInfoMergeError::MissingSourceNodeMapping {
                                forest_index,
                                source_node: *child,
                            },
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                nodes.push(DebugSourceMastNode::new(
                    exec_node,
                    children,
                    source_node.op_start,
                    source_node.op_end,
                ));
                debug_assert_eq!(
                    source_id_map[&DebugSourceMastNodeId::from(old_source_idx as u32)].as_u32()
                        as usize,
                    nodes.len() - 1,
                );
            }

            for root in source_graph.roots.iter().copied() {
                roots.push(source_id_map.get(&root).copied().ok_or(
                    PackageDebugInfoMergeError::MissingSourceNodeMapping {
                        forest_index,
                        source_node: root,
                    },
                )?);
            }

            let Some(source_map) = source_map else {
                continue;
            };
            saw_source_map = true;
            for row in &source_map.asm_ops {
                let source_node = source_id_map.get(&row.source_node).copied().ok_or(
                    PackageDebugInfoMergeError::MissingSourceNodeMapping {
                        forest_index,
                        source_node: row.source_node,
                    },
                )?;
                asm_ops.push(DebugSourceAsmOp {
                    source_node,
                    op_idx: row.op_idx,
                    location: row.location.clone(),
                    context_name: row.context_name.clone(),
                    op: row.op.clone(),
                    num_cycles: row.num_cycles,
                });
            }
            for row in &source_map.debug_vars {
                let source_node = source_id_map.get(&row.source_node).copied().ok_or(
                    PackageDebugInfoMergeError::MissingSourceNodeMapping {
                        forest_index,
                        source_node: row.source_node,
                    },
                )?;
                debug_vars.push(DebugSourceVar::new(source_node, row.op_idx, row.var.clone()));
            }
        }

        Ok(Self {
            source_graph: saw_source_graph.then_some(DebugSourceGraphSection {
                version: DEBUG_SOURCE_GRAPH_VERSION,
                nodes,
                roots,
            }),
            source_map: saw_source_map.then_some(DebugSourceMapSection {
                version: DEBUG_SOURCE_MAP_VERSION,
                asm_ops,
                debug_vars,
            }),
            ..Self::default()
        })
    }

    /// Returns a source/debug occurrence by ID.
    pub fn source_node(&self, source_node: DebugSourceMastNodeId) -> Option<&DebugSourceMastNode> {
        self.source_graph.as_ref()?.source_node(source_node)
    }

    /// Returns all source/debug occurrences that point at `exec_node`.
    pub fn source_nodes_for_exec_node(
        &self,
        exec_node: MastNodeId,
    ) -> impl Iterator<Item = (DebugSourceMastNodeId, &DebugSourceMastNode)> {
        self.source_graph
            .iter()
            .flat_map(move |source_graph| source_graph.source_nodes_for_exec_node(exec_node))
    }

    /// Returns all source/debug roots that point at `exec_node`.
    pub fn source_roots_for_exec_node(
        &self,
        exec_node: MastNodeId,
    ) -> impl Iterator<Item = (DebugSourceMastNodeId, &DebugSourceMastNode)> {
        self.source_graph
            .iter()
            .flat_map(move |source_graph| source_graph.source_roots_for_exec_node(exec_node))
    }

    /// Returns the unique source/debug root that points at `exec_node`.
    ///
    /// Returns `Ok(None)` if no source graph is present, or if no root points at `exec_node`.
    pub fn unique_source_root_for_exec_node(
        &self,
        exec_node: MastNodeId,
    ) -> Result<Option<DebugSourceMastNodeId>, DebugSourceGraphLookupError> {
        self.source_graph
            .as_ref()
            .map(|source_graph| source_graph.unique_source_root_for_exec_node(exec_node))
            .unwrap_or(Ok(None))
    }

    /// Returns the unique child of `parent` that points at `exec_node`.
    ///
    /// Returns `Ok(None)` if no source graph is present, or if no child points at `exec_node`.
    pub fn unique_child_source_node_for_exec_node(
        &self,
        parent: DebugSourceMastNodeId,
        exec_node: MastNodeId,
    ) -> Result<Option<DebugSourceMastNodeId>, DebugSourceGraphLookupError> {
        self.source_graph
            .as_ref()
            .map(|source_graph| {
                source_graph.unique_child_source_node_for_exec_node(parent, exec_node)
            })
            .unwrap_or(Ok(None))
    }

    /// Returns `parent`'s source/debug child at `child_index`, if present.
    ///
    /// Returns `Ok(None)` if no source graph is present, or if `child_index` is out of range.
    pub fn child_source_node(
        &self,
        parent: DebugSourceMastNodeId,
        child_index: usize,
    ) -> Result<Option<(DebugSourceMastNodeId, &DebugSourceMastNode)>, DebugSourceGraphLookupError>
    {
        self.source_graph
            .as_ref()
            .map(|source_graph| source_graph.child_source_node(parent, child_index))
            .unwrap_or(Ok(None))
    }

    /// Returns assembly operation rows for a source/debug occurrence.
    pub fn asm_ops_for_source_node(
        &self,
        source_node: DebugSourceMastNodeId,
    ) -> impl Iterator<Item = &DebugSourceAsmOp> {
        self.source_map
            .iter()
            .flat_map(move |source_map| source_map.asm_ops_for_source_node(source_node))
    }

    /// Returns the first assembly operation row for `source_node`, if present.
    pub fn first_asm_op_for_source_node(
        &self,
        source_node: DebugSourceMastNodeId,
    ) -> Option<&DebugSourceAsmOp> {
        self.source_map.as_ref()?.first_asm_op_for_source_node(source_node)
    }

    /// Returns the assembly operation row for `source_node` at `op_idx`, if present.
    pub fn asm_op_for_operation(
        &self,
        source_node: DebugSourceMastNodeId,
        op_idx: u32,
    ) -> Option<&DebugSourceAsmOp> {
        self.source_map.as_ref()?.asm_op_for_operation(source_node, op_idx)
    }

    /// Returns debug variable rows for a source/debug occurrence.
    pub fn debug_vars_for_source_node(
        &self,
        source_node: DebugSourceMastNodeId,
    ) -> impl Iterator<Item = &DebugSourceVar> {
        self.source_map
            .iter()
            .flat_map(move |source_map| source_map.debug_vars_for_source_node(source_node))
    }

    /// Returns debug variable rows for `source_node` at `op_idx`.
    pub fn debug_vars_for_operation(
        &self,
        source_node: DebugSourceMastNodeId,
        op_idx: u32,
    ) -> impl Iterator<Item = &DebugSourceVar> {
        self.source_map
            .iter()
            .flat_map(move |source_map| source_map.debug_vars_for_operation(source_node, op_idx))
    }
}

// DEBUG SOURCE CURSOR
// ================================================================================================

/// A cursor into package-owned source/debug MAST occurrence metadata.
///
/// Execution still runs by [`MastNodeId`], but source-aware diagnostics and debuggers need a stable
/// source occurrence beside the reduced execution node. This cursor captures that active
/// [`DebugSourceMastNodeId`] and exposes graph navigation with explicit ambiguity errors.
#[derive(Clone, Copy, Debug)]
pub struct DebugSourceCursor<'a> {
    debug_info: &'a PackageDebugInfo,
    source_node: DebugSourceMastNodeId,
}

impl<'a> DebugSourceCursor<'a> {
    /// Creates a cursor for `source_node`, validating that the package source graph contains it.
    pub fn new(
        debug_info: &'a PackageDebugInfo,
        source_node: DebugSourceMastNodeId,
    ) -> Result<Self, DebugSourceGraphLookupError> {
        debug_info
            .source_node(source_node)
            .ok_or(DebugSourceGraphLookupError::MissingSourceNode { source_node })?;
        Ok(Self { debug_info, source_node })
    }

    /// Creates a cursor for the unique source/debug root that points at `exec_node`.
    ///
    /// Returns `Ok(None)` if the package has no source graph, or if no source root points at
    /// `exec_node`.
    pub fn from_unique_root_for_exec_node(
        debug_info: &'a PackageDebugInfo,
        exec_node: MastNodeId,
    ) -> Result<Option<Self>, DebugSourceGraphLookupError> {
        debug_info
            .unique_source_root_for_exec_node(exec_node)?
            .map(|source_node| Self::new(debug_info, source_node))
            .transpose()
    }

    /// Returns the active source/debug occurrence ID.
    pub fn source_node(&self) -> DebugSourceMastNodeId {
        self.source_node
    }

    /// Returns the active source/debug occurrence record.
    pub fn source_record(&self) -> &'a DebugSourceMastNode {
        self.debug_info
            .source_node(self.source_node)
            .expect("DebugSourceCursor validates source node on construction")
    }

    /// Returns a cursor for the active occurrence's child at `child_index`.
    ///
    /// This is the preferred navigation for static control-flow children because source children
    /// may share the same executable node.
    pub fn child_by_index(
        &self,
        child_index: usize,
    ) -> Result<Option<Self>, DebugSourceGraphLookupError> {
        self.debug_info
            .child_source_node(self.source_node, child_index)?
            .map(|(source_node, _)| Self::new(self.debug_info, source_node))
            .transpose()
    }

    /// Returns a cursor for the unique active occurrence child that points at `exec_node`.
    ///
    /// This is useful only when child position is unavailable. If several source children collapse
    /// to the same execution node, this reports ambiguity instead of silently choosing one.
    pub fn unique_child_for_exec_node(
        &self,
        exec_node: MastNodeId,
    ) -> Result<Option<Self>, DebugSourceGraphLookupError> {
        self.debug_info
            .unique_child_source_node_for_exec_node(self.source_node, exec_node)?
            .map(|source_node| Self::new(self.debug_info, source_node))
            .transpose()
    }

    /// Returns source-keyed assembly operation metadata for `op_idx`.
    pub fn asm_op_for_operation(&self, op_idx: u32) -> Option<&'a DebugSourceAsmOp> {
        self.debug_info.asm_op_for_operation(self.source_node, op_idx)
    }

    /// Returns the first assembly operation row for the active source occurrence.
    pub fn first_asm_op(&self) -> Option<&'a DebugSourceAsmOp> {
        self.debug_info.first_asm_op_for_source_node(self.source_node)
    }

    /// Returns source-keyed debug variable rows for `op_idx`.
    pub fn debug_vars_for_operation(
        &self,
        op_idx: u32,
    ) -> impl Iterator<Item = &'a DebugSourceVar> {
        self.debug_info.debug_vars_for_operation(self.source_node, op_idx)
    }
}

// DEBUG SOURCE GRAPH SECTION
// ================================================================================================

/// A strongly-typed index into the source/debug MAST occurrence graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct DebugSourceMastNodeId(u32);

impl DebugSourceMastNodeId {
    /// Returns the inner value as a `u32`.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<u32> for DebugSourceMastNodeId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<DebugSourceMastNodeId> for u32 {
    fn from(value: DebugSourceMastNodeId) -> Self {
        value.0
    }
}

impl Serializable for DebugSourceMastNodeId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.0);
    }
}

impl Deserializable for DebugSourceMastNodeId {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(source.read_u32()?))
    }

    fn min_serialized_size() -> usize {
        4
    }
}

/// A source/debug MAST occurrence that points at a reduced execution node.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugSourceMastNode {
    /// The reduced execution MAST node represented by this source occurrence.
    pub exec_node: MastNodeId,
    /// Child source occurrences.
    pub children: Vec<DebugSourceMastNodeId>,
    /// Inclusive start operation index in the reduced execution node.
    pub op_start: u32,
    /// Exclusive end operation index in the reduced execution node.
    pub op_end: u32,
}

impl DebugSourceMastNode {
    /// Creates a source/debug occurrence record.
    pub fn new(
        exec_node: MastNodeId,
        children: Vec<DebugSourceMastNodeId>,
        op_start: u32,
        op_end: u32,
    ) -> Self {
        Self { exec_node, children, op_start, op_end }
    }
}

/// Package-owned source/debug MAST occurrence graph.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugSourceGraphSection {
    /// Version of the debug source graph format.
    pub version: u8,
    /// Source/debug occurrence nodes.
    pub nodes: Vec<DebugSourceMastNode>,
    /// Source/debug occurrence roots.
    pub roots: Vec<DebugSourceMastNodeId>,
}

impl DebugSourceGraphSection {
    /// Creates an empty source/debug occurrence graph section.
    pub fn new() -> Self {
        Self {
            version: DEBUG_SOURCE_GRAPH_VERSION,
            nodes: Vec::new(),
            roots: Vec::new(),
        }
    }

    /// Returns true if the section contains no source occurrences.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.roots.is_empty()
    }

    /// Returns a source/debug occurrence by ID.
    pub fn source_node(&self, source_node: DebugSourceMastNodeId) -> Option<&DebugSourceMastNode> {
        self.nodes.get(source_node.as_u32() as usize)
    }

    /// Returns all source/debug occurrences that point at `exec_node`.
    pub fn source_nodes_for_exec_node(
        &self,
        exec_node: MastNodeId,
    ) -> impl Iterator<Item = (DebugSourceMastNodeId, &DebugSourceMastNode)> {
        self.nodes.iter().enumerate().filter_map(move |(index, source_node)| {
            (source_node.exec_node == exec_node)
                .then_some((DebugSourceMastNodeId::from(index as u32), source_node))
        })
    }

    /// Returns all source/debug roots that point at `exec_node`.
    pub fn source_roots_for_exec_node(
        &self,
        exec_node: MastNodeId,
    ) -> impl Iterator<Item = (DebugSourceMastNodeId, &DebugSourceMastNode)> {
        self.roots.iter().copied().filter_map(move |source_node_id| {
            self.source_node(source_node_id)
                .filter(|source_node| source_node.exec_node == exec_node)
                .map(|source_node| (source_node_id, source_node))
        })
    }

    /// Returns the unique source/debug root that points at `exec_node`.
    pub fn unique_source_root_for_exec_node(
        &self,
        exec_node: MastNodeId,
    ) -> Result<Option<DebugSourceMastNodeId>, DebugSourceGraphLookupError> {
        let mut roots = self
            .source_roots_for_exec_node(exec_node)
            .map(|(source_node_id, _)| source_node_id);
        let first = roots.next();
        if roots.next().is_some() {
            return Err(DebugSourceGraphLookupError::AmbiguousRoot { exec_node });
        }
        Ok(first)
    }

    /// Returns children of `parent` that point at `exec_node`.
    pub fn child_source_nodes_for_exec_node(
        &self,
        parent: DebugSourceMastNodeId,
        exec_node: MastNodeId,
    ) -> Result<
        impl Iterator<Item = (DebugSourceMastNodeId, &DebugSourceMastNode)> + '_,
        DebugSourceGraphLookupError,
    > {
        let parent_node = self
            .source_node(parent)
            .ok_or(DebugSourceGraphLookupError::MissingSourceNode { source_node: parent })?;

        Ok(parent_node.children.iter().copied().filter_map(move |source_node_id| {
            self.source_node(source_node_id)
                .filter(|source_node| source_node.exec_node == exec_node)
                .map(|source_node| (source_node_id, source_node))
        }))
    }

    /// Returns the unique child of `parent` that points at `exec_node`.
    pub fn unique_child_source_node_for_exec_node(
        &self,
        parent: DebugSourceMastNodeId,
        exec_node: MastNodeId,
    ) -> Result<Option<DebugSourceMastNodeId>, DebugSourceGraphLookupError> {
        let mut children = self
            .child_source_nodes_for_exec_node(parent, exec_node)?
            .map(|(source_node_id, _)| source_node_id);
        let first = children.next();
        if children.next().is_some() {
            return Err(DebugSourceGraphLookupError::AmbiguousChild { parent, exec_node });
        }
        Ok(first)
    }

    /// Returns `parent`'s source/debug child at `child_index`, if present.
    pub fn child_source_node(
        &self,
        parent: DebugSourceMastNodeId,
        child_index: usize,
    ) -> Result<Option<(DebugSourceMastNodeId, &DebugSourceMastNode)>, DebugSourceGraphLookupError>
    {
        let parent_node = self
            .source_node(parent)
            .ok_or(DebugSourceGraphLookupError::MissingSourceNode { source_node: parent })?;
        let Some(child) = parent_node.children.get(child_index).copied() else {
            return Ok(None);
        };
        let child_node = self
            .source_node(child)
            .ok_or(DebugSourceGraphLookupError::MissingSourceNode { source_node: child })?;

        Ok(Some((child, child_node)))
    }
}

/// Assembly operation metadata keyed by a source/debug MAST occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugSourceAsmOp {
    /// Source/debug occurrence that owns this operation row.
    pub source_node: DebugSourceMastNodeId,
    /// Operation index local to the reduced execution node.
    pub op_idx: u32,
    /// Optional source location for the assembly operation.
    #[cfg_attr(feature = "serde", serde(default))]
    pub location: Option<Location>,
    /// Assembly context name.
    pub context_name: String,
    /// Assembly operation text.
    pub op: String,
    /// Number of VM cycles taken by the operation.
    pub num_cycles: u8,
}

impl DebugSourceAsmOp {
    /// Creates a source-keyed assembly operation metadata row.
    pub fn new(
        source_node: DebugSourceMastNodeId,
        op_idx: u32,
        location: Option<Location>,
        context_name: String,
        op: String,
        num_cycles: u8,
    ) -> Self {
        Self {
            source_node,
            op_idx,
            location,
            context_name,
            op,
            num_cycles,
        }
    }
}

/// Debug variable metadata keyed by a source/debug MAST occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugSourceVar {
    /// Source/debug occurrence that owns this variable row.
    pub source_node: DebugSourceMastNodeId,
    /// Operation index local to the reduced execution node.
    pub op_idx: u32,
    /// Debug variable metadata.
    pub var: DebugVarInfo,
}

impl DebugSourceVar {
    /// Creates a source-keyed debug variable metadata row.
    pub fn new(source_node: DebugSourceMastNodeId, op_idx: u32, var: DebugVarInfo) -> Self {
        Self { source_node, op_idx, var }
    }
}

/// Package-owned source-keyed debug metadata rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugSourceMapSection {
    /// Version of the debug source map format.
    pub version: u8,
    /// Source-keyed assembly operation rows.
    pub asm_ops: Vec<DebugSourceAsmOp>,
    /// Source-keyed debug variable rows.
    pub debug_vars: Vec<DebugSourceVar>,
}

impl DebugSourceMapSection {
    /// Creates an empty source-keyed debug metadata section.
    pub fn new() -> Self {
        Self {
            version: DEBUG_SOURCE_MAP_VERSION,
            asm_ops: Vec::new(),
            debug_vars: Vec::new(),
        }
    }

    /// Returns true if the section contains no metadata rows.
    pub fn is_empty(&self) -> bool {
        self.asm_ops.is_empty() && self.debug_vars.is_empty()
    }

    /// Returns assembly operation rows for a source/debug occurrence.
    pub fn asm_ops_for_source_node(
        &self,
        source_node: DebugSourceMastNodeId,
    ) -> impl Iterator<Item = &DebugSourceAsmOp> {
        self.asm_ops.iter().filter(move |row| row.source_node == source_node)
    }

    /// Returns the first assembly operation row for `source_node`, if present.
    pub fn first_asm_op_for_source_node(
        &self,
        source_node: DebugSourceMastNodeId,
    ) -> Option<&DebugSourceAsmOp> {
        self.asm_ops_for_source_node(source_node).min_by_key(|row| row.op_idx)
    }

    /// Returns the assembly operation row for `source_node` at `op_idx`, if present.
    pub fn asm_op_for_operation(
        &self,
        source_node: DebugSourceMastNodeId,
        op_idx: u32,
    ) -> Option<&DebugSourceAsmOp> {
        self.asm_ops_for_source_node(source_node).find(|row| row.op_idx == op_idx)
    }

    /// Returns debug variable rows for a source/debug occurrence.
    pub fn debug_vars_for_source_node(
        &self,
        source_node: DebugSourceMastNodeId,
    ) -> impl Iterator<Item = &DebugSourceVar> {
        self.debug_vars.iter().filter(move |row| row.source_node == source_node)
    }

    /// Returns debug variable rows for `source_node` at `op_idx`.
    pub fn debug_vars_for_operation(
        &self,
        source_node: DebugSourceMastNodeId,
        op_idx: u32,
    ) -> impl Iterator<Item = &DebugSourceVar> {
        self.debug_vars_for_source_node(source_node)
            .filter(move |row| row.op_idx == op_idx)
    }
}

// DEBUG TYPE INFO
// ================================================================================================

/// Type information for debug purposes.
///
/// This encodes the type of a variable or expression, enabling debuggers to properly
/// display values on the stack or in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DebugTypeInfo {
    /// A primitive type (e.g., i32, i64, felt, etc.)
    Primitive(DebugPrimitiveType),
    /// A pointer type pointing to another type
    Pointer {
        /// The type being pointed to (index into type table)
        pointee_type_idx: DebugTypeIdx,
    },
    /// An array type
    Array {
        /// The element type (index into type table)
        element_type_idx: DebugTypeIdx,
        /// Number of elements (None for dynamically-sized arrays)
        count: Option<u32>,
    },
    /// A struct type
    Struct {
        /// Name of the struct (index into string table)
        name_idx: u32,
        /// Size in bytes
        size: u32,
        /// Fields of the struct
        fields: Vec<DebugFieldInfo>,
    },
    /// A function type
    Function {
        /// Return type (index into type table, None for void)
        return_type_idx: Option<DebugTypeIdx>,
        /// Parameter types (indices into type table)
        param_type_indices: Vec<DebugTypeIdx>,
    },
    /// An enum type.
    Enum {
        /// Name of the enum (index into string table).
        name_idx: u32,
        /// Size in bytes.
        size: u32,
        /// Type of the enum discriminant.
        discriminant_type_idx: DebugTypeIdx,
        /// Variants of the enum.
        variants: Vec<DebugVariantInfo>,
    },
    /// An unknown or opaque type
    Unknown,
}

/// Primitive type variants supported by the debug info format.
///
/// New variants must be added at the end to maintain backwards compatibility
/// with previously serialized debug info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum DebugPrimitiveType {
    /// Void type (0 bytes)
    Void = 0,
    /// Boolean (1 byte)
    Bool,
    /// Signed 8-bit integer
    I8,
    /// Unsigned 8-bit integer
    U8,
    /// Signed 16-bit integer
    I16,
    /// Unsigned 16-bit integer
    U16,
    /// Signed 32-bit integer
    I32,
    /// Unsigned 32-bit integer
    U32,
    /// Signed 64-bit integer
    I64,
    /// Unsigned 64-bit integer
    U64,
    /// Signed 128-bit integer
    I128,
    /// Unsigned 128-bit integer
    U128,
    /// 32-bit floating point
    F32,
    /// 64-bit floating point
    F64,
    /// Miden field element (64-bit, but with field semantics)
    Felt,
    /// Miden word (4 field elements)
    Word,
    /// Unsigned 256-bit integer
    U256,
}

impl DebugPrimitiveType {
    /// Returns the size of this primitive type in bytes.
    pub const fn size_in_bytes(self) -> u32 {
        match self {
            Self::Void => 0,
            Self::Bool | Self::I8 | Self::U8 => 1,
            Self::I16 | Self::U16 => 2,
            Self::I32 | Self::U32 | Self::F32 => 4,
            Self::I64 | Self::U64 | Self::F64 | Self::Felt => 8,
            Self::I128 | Self::U128 => 16,
            Self::Word | Self::U256 => 32,
        }
    }

    /// Returns the size of this primitive type in Miden stack elements (felts).
    pub const fn size_in_felts(self) -> u32 {
        match self {
            Self::Void => 0,
            Self::Bool
            | Self::I8
            | Self::U8
            | Self::I16
            | Self::U16
            | Self::I32
            | Self::U32
            | Self::Felt => 1,
            Self::I64 | Self::U64 | Self::F32 | Self::F64 => 2,
            Self::I128 | Self::U128 | Self::Word | Self::U256 => 4,
        }
    }

    /// Converts a discriminant byte to a primitive type.
    pub fn from_discriminant(discriminant: u8) -> Option<Self> {
        match discriminant {
            0 => Some(Self::Void),
            1 => Some(Self::Bool),
            2 => Some(Self::I8),
            3 => Some(Self::U8),
            4 => Some(Self::I16),
            5 => Some(Self::U16),
            6 => Some(Self::I32),
            7 => Some(Self::U32),
            8 => Some(Self::I64),
            9 => Some(Self::U64),
            10 => Some(Self::I128),
            11 => Some(Self::U128),
            12 => Some(Self::F32),
            13 => Some(Self::F64),
            14 => Some(Self::Felt),
            15 => Some(Self::Word),
            16 => Some(Self::U256),
            _ => None,
        }
    }
}

/// Field information within a struct type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugFieldInfo {
    /// Name of the field (index into string table)
    pub name_idx: u32,
    /// Type of the field (index into type table)
    pub type_idx: DebugTypeIdx,
    /// Byte offset within the struct
    pub offset: u32,
}

/// Variant information within an enum type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugVariantInfo {
    /// Name of the variant (index into string table).
    pub name_idx: u32,
    /// Payload type of this variant (index into type table), if present.
    pub type_idx: Option<DebugTypeIdx>,
    /// Byte offset of the payload from the base of the enum value, if present.
    pub payload_offset: Option<u32>,
    /// Discriminant value for this variant.
    pub discriminant: u128,
}

// DEBUG FILE INFO
// ================================================================================================

/// Source file information.
///
/// Contains the path and optional metadata for a source file referenced by debug info.
///
/// TODO: Consider adding `directory_idx: Option<u32>` to reduce serialized debug info size.
/// When `directory_idx` is set, `path_idx` would be a relative path; otherwise `path_idx`
/// is expected to be absolute. This would allow sharing common directory prefixes across
/// multiple files.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugFileInfo {
    /// Full path to the source file (index into string table).
    pub path_idx: u32,
    /// Optional checksum of the file content for verification.
    ///
    /// When present, debuggers can use this to verify that the source file on disk
    /// matches the version used during compilation.
    ///
    /// Boxed to reduce the size of `DebugFileInfo` when checksums are not used.
    pub checksum: Option<Box<[u8; 32]>>,
}

impl DebugFileInfo {
    /// Creates a new file info with a path.
    pub fn new(path_idx: u32) -> Self {
        Self { path_idx, checksum: None }
    }

    /// Sets the checksum.
    pub fn with_checksum(mut self, checksum: [u8; 32]) -> Self {
        self.checksum = Some(Box::new(checksum));
        self
    }
}

// DEBUG FUNCTION INFO
// ================================================================================================

/// Debug information for a function.
///
/// Links source-level function information to the compiled MAST representation,
/// including local variables and inlined call sites.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugFunctionInfo {
    /// Name of the function (index into string table)
    pub name_idx: u32,
    /// Linkage name / mangled name (index into string table, optional)
    pub linkage_name_idx: Option<u32>,
    /// File containing this function (index into file table)
    pub file_idx: u32,
    /// Line number where the function starts (1-indexed)
    pub line: LineNumber,
    /// Column number where the function starts (1-indexed)
    pub column: ColumnNumber,
    /// Type of this function (index into type table, optional)
    pub type_idx: Option<DebugTypeIdx>,
    /// MAST root digest of this function (if known).
    /// This links the debug info to the compiled code.
    pub mast_root: Option<Word>,
    /// Local variables declared in this function
    pub variables: Vec<DebugVariableInfo>,
    /// Inline call sites within this function
    pub inlined_calls: Vec<DebugInlinedCallInfo>,
}

impl DebugFunctionInfo {
    /// Creates a new function info.
    pub fn new(name_idx: u32, file_idx: u32, line: LineNumber, column: ColumnNumber) -> Self {
        Self {
            name_idx,
            linkage_name_idx: None,
            file_idx,
            line,
            column,
            type_idx: None,
            mast_root: None,
            variables: Vec::new(),
            inlined_calls: Vec::new(),
        }
    }

    /// Sets the linkage name.
    pub fn with_linkage_name(mut self, linkage_name_idx: u32) -> Self {
        self.linkage_name_idx = Some(linkage_name_idx);
        self
    }

    /// Sets the type index.
    pub fn with_type(mut self, type_idx: DebugTypeIdx) -> Self {
        self.type_idx = Some(type_idx);
        self
    }

    /// Sets the MAST root digest.
    pub fn with_mast_root(mut self, mast_root: Word) -> Self {
        self.mast_root = Some(mast_root);
        self
    }

    /// Adds a variable to this function.
    pub fn add_variable(&mut self, variable: DebugVariableInfo) {
        self.variables.push(variable);
    }

    /// Adds an inlined call site.
    pub fn add_inlined_call(&mut self, call: DebugInlinedCallInfo) {
        self.inlined_calls.push(call);
    }
}

// DEBUG VARIABLE INFO
// ================================================================================================

/// Debug information for a local variable or parameter.
///
/// This struct captures the source-level information about a variable, enabling
/// debuggers to display variable names, types, and locations to users.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugVariableInfo {
    /// Name of the variable (index into string table)
    pub name_idx: u32,
    /// Type of the variable (index into type table)
    pub type_idx: DebugTypeIdx,
    /// If this is a parameter, its 1-based index (0 = not a parameter)
    pub arg_index: u32,
    /// Line where the variable is declared (1-indexed)
    pub line: LineNumber,
    /// Column where the variable is declared (1-indexed)
    pub column: ColumnNumber,
    /// Scope depth indicating the lexical nesting level of this variable.
    ///
    /// - `0` = function-level scope (parameters and variables at function body level)
    /// - `1` = first nested block (e.g., inside an `if` or `loop`)
    /// - `2` = second nested block, and so on
    ///
    /// This is used by debuggers to:
    /// 1. Determine variable visibility at a given execution point
    /// 2. Handle variable shadowing (a variable with the same name but higher depth shadows one
    ///    with lower depth when both are in scope)
    /// 3. Display variables grouped by their scope level
    ///
    /// For example, in:
    /// ```text
    /// fn foo(x: i32) {           // x has scope_depth 0
    ///     let y = 1;             // y has scope_depth 0
    ///     if condition {
    ///         let z = 2;         // z has scope_depth 1
    ///         let x = 3;         // this x has scope_depth 1, shadows parameter x
    ///     }
    /// }
    /// ```
    pub scope_depth: u32,
}

impl DebugVariableInfo {
    /// Creates a new variable info.
    pub fn new(
        name_idx: u32,
        type_idx: DebugTypeIdx,
        line: LineNumber,
        column: ColumnNumber,
    ) -> Self {
        Self {
            name_idx,
            type_idx,
            arg_index: 0,
            line,
            column,
            scope_depth: 0,
        }
    }

    /// Sets this variable as a parameter with the given 1-based index.
    pub fn with_arg_index(mut self, arg_index: u32) -> Self {
        self.arg_index = arg_index;
        self
    }

    /// Sets the scope depth.
    pub fn with_scope_depth(mut self, scope_depth: u32) -> Self {
        self.scope_depth = scope_depth;
        self
    }

    /// Returns true if this variable is a function parameter.
    pub fn is_parameter(&self) -> bool {
        self.arg_index > 0
    }
}

// DEBUG INLINED CALL INFO
// ================================================================================================

/// Debug information for an inlined function call.
///
/// Captures the call site location when a function has been inlined,
/// enabling debuggers to show the original call stack.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugInlinedCallInfo {
    /// The function that was inlined (index into function table)
    pub callee_idx: u32,
    /// Call site file (index into file table)
    pub file_idx: u32,
    /// Call site line number (1-indexed)
    pub line: LineNumber,
    /// Call site column number (1-indexed)
    pub column: ColumnNumber,
}

impl DebugInlinedCallInfo {
    /// Creates a new inlined call info.
    pub fn new(callee_idx: u32, file_idx: u32, line: LineNumber, column: ColumnNumber) -> Self {
        Self { callee_idx, file_idx, line, column }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_types_section_string_dedup() {
        let mut section = DebugTypesSection::new();

        let idx1 = section.add_string(Arc::from("test.rs"));
        let idx2 = section.add_string(Arc::from("main.rs"));
        let idx3 = section.add_string(Arc::from("test.rs")); // Duplicate

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0); // Should return same index
        assert_eq!(section.strings.len(), 2);
    }

    #[test]
    fn test_debug_sources_section_string_dedup() {
        let mut section = DebugSourcesSection::new();

        let idx1 = section.add_string(Arc::from("test.rs"));
        let idx2 = section.add_string(Arc::from("main.rs"));
        let idx3 = section.add_string(Arc::from("test.rs")); // Duplicate

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0); // Should return same index
        assert_eq!(section.strings.len(), 2);
    }

    #[test]
    fn test_debug_functions_section_string_dedup() {
        let mut section = DebugFunctionsSection::new();

        let idx1 = section.add_string(Arc::from("foo"));
        let idx2 = section.add_string(Arc::from("bar"));
        let idx3 = section.add_string(Arc::from("foo")); // Duplicate

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0); // Should return same index
        assert_eq!(section.strings.len(), 2);
    }

    #[test]
    fn test_package_source_debug_merge_remaps_execution_nodes_without_collapsing_sources() {
        use miden_core::{
            mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor},
            operations::{DebugVarInfo, DebugVarLocation, Operation},
        };

        fn forest_with_add_block() -> (MastForest, MastNodeId) {
            let mut forest = MastForest::new();
            let block = BasicBlockNodeBuilder::new(alloc::vec![Operation::Add])
                .add_to_forest(&mut forest)
                .unwrap();
            forest.make_root(block);
            (forest, block)
        }

        fn debug_info_for_block(
            block: MastNodeId,
            context: &str,
            var_name: &str,
        ) -> PackageDebugInfo {
            let source_node = DebugSourceMastNodeId::from(0);
            PackageDebugInfo {
                source_graph: Some(DebugSourceGraphSection {
                    version: DEBUG_SOURCE_GRAPH_VERSION,
                    nodes: alloc::vec![DebugSourceMastNode::new(block, alloc::vec![], 0, 1,)],
                    roots: alloc::vec![source_node],
                }),
                source_map: Some(DebugSourceMapSection {
                    version: DEBUG_SOURCE_MAP_VERSION,
                    asm_ops: alloc::vec![DebugSourceAsmOp::new(
                        source_node,
                        0,
                        None,
                        context.into(),
                        "add".into(),
                        1,
                    )],
                    debug_vars: alloc::vec![DebugSourceVar::new(
                        source_node,
                        0,
                        DebugVarInfo::new(var_name, DebugVarLocation::Stack(0)),
                    )],
                }),
                ..PackageDebugInfo::default()
            }
        }

        let (forest_a, block_a) = forest_with_add_block();
        let (forest_b, block_b) = forest_with_add_block();
        let debug_a = debug_info_for_block(block_a, "alias_a", "x");
        let debug_b = debug_info_for_block(block_b, "alias_b", "y");

        let (_merged_forest, root_map) = MastForest::merge([&forest_a, &forest_b]).unwrap();
        let merged_a = root_map.map_root(0, &block_a).unwrap();
        let merged_b = root_map.map_root(1, &block_b).unwrap();
        assert_eq!(merged_a, merged_b);

        let merged_debug =
            PackageDebugInfo::merge_source_debug([(0, &debug_a), (1, &debug_b)], &root_map)
                .unwrap();
        let source_graph = merged_debug.source_graph.as_ref().unwrap();
        assert_eq!(source_graph.nodes.len(), 2);
        assert_eq!(source_graph.roots.len(), 2);
        assert!(source_graph.nodes.iter().all(|node| node.exec_node == merged_a));

        let source_a = source_graph.roots[0];
        let source_b = source_graph.roots[1];
        assert_ne!(source_a, source_b);
        assert_eq!(
            merged_debug.first_asm_op_for_source_node(source_a).unwrap().context_name,
            "alias_a",
        );
        assert_eq!(
            merged_debug.first_asm_op_for_source_node(source_b).unwrap().context_name,
            "alias_b",
        );
        assert_eq!(
            merged_debug
                .debug_vars_for_operation(source_a, 0)
                .map(|row| row.var.name())
                .collect::<Vec<_>>(),
            alloc::vec!["x"],
        );
        assert_eq!(
            merged_debug
                .debug_vars_for_operation(source_b, 0)
                .map(|row| row.var.name())
                .collect::<Vec<_>>(),
            alloc::vec!["y"],
        );
    }

    #[test]
    fn test_package_source_debug_merge_remaps_non_root_execution_nodes() {
        use miden_core::{
            mast::{BasicBlockNodeBuilder, CallNodeBuilder, MastForest, MastForestContributor},
            operations::Operation,
        };

        let mut forest = MastForest::new();
        let callee = BasicBlockNodeBuilder::new(alloc::vec![Operation::Add])
            .add_to_forest(&mut forest)
            .unwrap();
        let call = CallNodeBuilder::new(callee).add_to_forest(&mut forest).unwrap();
        forest.make_root(call);

        let root_source = DebugSourceMastNodeId::from(0);
        let child_source = DebugSourceMastNodeId::from(1);
        let debug_info = PackageDebugInfo {
            source_graph: Some(DebugSourceGraphSection {
                version: DEBUG_SOURCE_GRAPH_VERSION,
                nodes: alloc::vec![
                    DebugSourceMastNode::new(call, alloc::vec![child_source], 0, 1),
                    DebugSourceMastNode::new(callee, alloc::vec![], 0, 1),
                ],
                roots: alloc::vec![root_source],
            }),
            source_map: Some(DebugSourceMapSection {
                version: DEBUG_SOURCE_MAP_VERSION,
                asm_ops: alloc::vec![DebugSourceAsmOp::new(
                    child_source,
                    0,
                    None,
                    "callee".into(),
                    "add".into(),
                    1,
                )],
                debug_vars: alloc::vec![],
            }),
            ..PackageDebugInfo::default()
        };

        let (_merged_forest, root_map) = MastForest::merge([&forest]).unwrap();
        let merged_callee = root_map.map_node(0, &callee).unwrap();

        let merged_debug =
            PackageDebugInfo::merge_source_debug([(0, &debug_info)], &root_map).unwrap();
        let source_graph = merged_debug.source_graph.as_ref().unwrap();
        let merged_child = source_graph.nodes[source_graph.roots[0].as_u32() as usize].children[0];
        assert_eq!(source_graph.nodes[merged_child.as_u32() as usize].exec_node, merged_callee,);
        assert_eq!(
            merged_debug.first_asm_op_for_source_node(merged_child).unwrap().context_name,
            "callee",
        );
    }

    #[test]
    fn test_source_debug_lookup_uses_source_node_identity() {
        use miden_core::operations::{DebugVarInfo, DebugVarLocation};

        let exec_node = MastNodeId::new_unchecked(7);
        let source_a = DebugSourceMastNodeId::from(0);
        let source_b = DebugSourceMastNodeId::from(1);
        let graph = DebugSourceGraphSection {
            version: DEBUG_SOURCE_GRAPH_VERSION,
            nodes: alloc::vec![
                DebugSourceMastNode::new(exec_node, alloc::vec![], 0, 1),
                DebugSourceMastNode::new(exec_node, alloc::vec![], 0, 1),
            ],
            roots: alloc::vec![source_a, source_b],
        };
        assert_eq!(graph.source_nodes_for_exec_node(exec_node).count(), 2);
        assert_eq!(graph.source_node(source_a).unwrap().exec_node, exec_node);

        let source_map = DebugSourceMapSection {
            version: DEBUG_SOURCE_MAP_VERSION,
            asm_ops: alloc::vec![
                DebugSourceAsmOp::new(source_a, 0, None, "alias_a".into(), "add".into(), 1),
                DebugSourceAsmOp::new(source_b, 0, None, "alias_b".into(), "add".into(), 1),
                DebugSourceAsmOp::new(source_b, 2, None, "alias_b_later".into(), "mul".into(), 1),
            ],
            debug_vars: alloc::vec![
                DebugSourceVar::new(
                    source_a,
                    0,
                    DebugVarInfo::new("x", DebugVarLocation::Stack(0)),
                ),
                DebugSourceVar::new(
                    source_b,
                    0,
                    DebugVarInfo::new("y", DebugVarLocation::Stack(1)),
                ),
            ],
        };

        assert_eq!(source_map.asm_op_for_operation(source_a, 0).unwrap().context_name, "alias_a",);
        assert_eq!(source_map.asm_op_for_operation(source_b, 0).unwrap().context_name, "alias_b",);
        assert_eq!(
            source_map.first_asm_op_for_source_node(source_b).unwrap().context_name,
            "alias_b",
        );
        let vars_b = source_map.debug_vars_for_operation(source_b, 0).collect::<Vec<_>>();
        assert_eq!(vars_b.len(), 1);
        assert_eq!(vars_b[0].var.name(), "y");
    }

    #[test]
    fn test_source_graph_unique_navigation_reports_ambiguity() {
        let root_exec = MastNodeId::new_unchecked(7);
        let child_exec = MastNodeId::new_unchecked(8);
        let other_exec = MastNodeId::new_unchecked(9);
        let root = DebugSourceMastNodeId::from(0);
        let child_a = DebugSourceMastNodeId::from(1);
        let child_b = DebugSourceMastNodeId::from(2);
        let other_root = DebugSourceMastNodeId::from(3);
        let graph = DebugSourceGraphSection {
            version: DEBUG_SOURCE_GRAPH_VERSION,
            nodes: alloc::vec![
                DebugSourceMastNode::new(root_exec, alloc::vec![child_a, child_b], 0, 1),
                DebugSourceMastNode::new(child_exec, alloc::vec![], 0, 1),
                DebugSourceMastNode::new(child_exec, alloc::vec![], 0, 1),
                DebugSourceMastNode::new(root_exec, alloc::vec![], 0, 1),
            ],
            roots: alloc::vec![root],
        };

        assert_eq!(graph.unique_source_root_for_exec_node(root_exec).unwrap(), Some(root));
        assert_eq!(graph.unique_source_root_for_exec_node(other_exec).unwrap(), None);
        assert_eq!(graph.child_source_nodes_for_exec_node(root, child_exec).unwrap().count(), 2,);
        assert_eq!(graph.child_source_node(root, 0).unwrap().unwrap().0, child_a);
        assert_eq!(graph.child_source_node(root, 1).unwrap().unwrap().0, child_b);
        assert!(graph.child_source_node(root, 2).unwrap().is_none());
        assert_eq!(
            graph.unique_child_source_node_for_exec_node(root, child_exec),
            Err(DebugSourceGraphLookupError::AmbiguousChild {
                parent: root,
                exec_node: child_exec
            }),
        );
        assert_eq!(
            graph.unique_child_source_node_for_exec_node(
                DebugSourceMastNodeId::from(99),
                child_exec,
            ),
            Err(DebugSourceGraphLookupError::MissingSourceNode {
                source_node: DebugSourceMastNodeId::from(99),
            }),
        );

        let ambiguous_roots = DebugSourceGraphSection {
            roots: alloc::vec![root, other_root],
            ..graph
        };
        assert_eq!(
            ambiguous_roots.unique_source_root_for_exec_node(root_exec),
            Err(DebugSourceGraphLookupError::AmbiguousRoot { exec_node: root_exec }),
        );

        let package_debug = PackageDebugInfo {
            source_graph: Some(ambiguous_roots),
            ..PackageDebugInfo::default()
        };
        assert_eq!(
            package_debug.unique_source_root_for_exec_node(root_exec),
            Err(DebugSourceGraphLookupError::AmbiguousRoot { exec_node: root_exec }),
        );
        assert_eq!(package_debug.child_source_node(root, 1).unwrap().unwrap().0, child_b);
    }

    #[test]
    fn test_source_cursor_navigates_static_children_and_reports_ambiguity() {
        use miden_core::operations::{DebugVarInfo, DebugVarLocation};

        let root_exec = MastNodeId::new_unchecked(7);
        let child_exec = MastNodeId::new_unchecked(8);
        let root = DebugSourceMastNodeId::from(0);
        let child_a = DebugSourceMastNodeId::from(1);
        let child_b = DebugSourceMastNodeId::from(2);
        let debug_info = PackageDebugInfo {
            source_graph: Some(DebugSourceGraphSection {
                version: DEBUG_SOURCE_GRAPH_VERSION,
                nodes: alloc::vec![
                    DebugSourceMastNode::new(root_exec, alloc::vec![child_a, child_b], 0, 1),
                    DebugSourceMastNode::new(child_exec, alloc::vec![], 0, 1),
                    DebugSourceMastNode::new(child_exec, alloc::vec![], 0, 1),
                ],
                roots: alloc::vec![root],
            }),
            source_map: Some(DebugSourceMapSection {
                version: DEBUG_SOURCE_MAP_VERSION,
                asm_ops: alloc::vec![
                    DebugSourceAsmOp::new(child_a, 0, None, "child_a".into(), "add".into(), 1),
                    DebugSourceAsmOp::new(child_b, 0, None, "child_b".into(), "add".into(), 1),
                ],
                debug_vars: alloc::vec![
                    DebugSourceVar::new(
                        child_a,
                        0,
                        DebugVarInfo::new("a", DebugVarLocation::Stack(0)),
                    ),
                    DebugSourceVar::new(
                        child_b,
                        0,
                        DebugVarInfo::new("b", DebugVarLocation::Stack(1)),
                    ),
                ],
            }),
            ..PackageDebugInfo::default()
        };

        let root_cursor = DebugSourceCursor::from_unique_root_for_exec_node(&debug_info, root_exec)
            .unwrap()
            .unwrap();
        let child_a_cursor = root_cursor.child_by_index(0).unwrap().unwrap();
        let child_b_cursor = root_cursor.child_by_index(1).unwrap().unwrap();

        assert_eq!(child_a_cursor.source_node(), child_a);
        assert_eq!(child_b_cursor.source_node(), child_b);
        assert_eq!(child_a_cursor.asm_op_for_operation(0).unwrap().context_name, "child_a");
        assert_eq!(child_b_cursor.asm_op_for_operation(0).unwrap().context_name, "child_b");
        assert_eq!(
            child_a_cursor
                .debug_vars_for_operation(0)
                .map(|row| row.var.name())
                .collect::<Vec<_>>(),
            alloc::vec!["a"],
        );
        assert_eq!(
            child_b_cursor
                .debug_vars_for_operation(0)
                .map(|row| row.var.name())
                .collect::<Vec<_>>(),
            alloc::vec!["b"],
        );
        assert!(matches!(
            root_cursor.unique_child_for_exec_node(child_exec),
            Err(DebugSourceGraphLookupError::AmbiguousChild {
                parent,
                exec_node
            }) if parent == root && exec_node == child_exec
        ),);
    }

    #[test]
    fn test_primitive_type_sizes() {
        assert_eq!(DebugPrimitiveType::Void.size_in_bytes(), 0);
        assert_eq!(DebugPrimitiveType::I32.size_in_bytes(), 4);
        assert_eq!(DebugPrimitiveType::I64.size_in_bytes(), 8);
        assert_eq!(DebugPrimitiveType::Felt.size_in_bytes(), 8);
        assert_eq!(DebugPrimitiveType::Word.size_in_bytes(), 32);
        assert_eq!(DebugPrimitiveType::U256.size_in_bytes(), 32);

        assert_eq!(DebugPrimitiveType::Void.size_in_felts(), 0);
        assert_eq!(DebugPrimitiveType::I32.size_in_felts(), 1);
        assert_eq!(DebugPrimitiveType::I64.size_in_felts(), 2);
        assert_eq!(DebugPrimitiveType::Word.size_in_felts(), 4);
        assert_eq!(DebugPrimitiveType::U256.size_in_felts(), 4);
    }

    #[test]
    fn test_primitive_type_roundtrip() {
        for discriminant in 0..=16 {
            let ty = DebugPrimitiveType::from_discriminant(discriminant).unwrap();
            assert_eq!(ty as u8, discriminant);
        }
        assert!(DebugPrimitiveType::from_discriminant(17).is_none());
    }
}
