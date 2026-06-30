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
//! - **Function metadata**: Function signatures and source locations
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

// DEBUG SOURCE GRAPH LOOKUP ERROR
// ================================================================================================

/// Error returned when a caller needs a unique source/debug occurrence but the graph cannot supply
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DebugSourceGraphLookupError {
    /// The requested parent source/debug occurrence is not present.
    #[error("source/debug occurrence {source_node:?} is not present")]
    MissingSourceNode { source_node: DebugSourceNodeId },
    /// Multiple source/debug roots point at the same executable MAST node.
    #[error("multiple source/debug roots point at executable MAST node {exec_node:?}")]
    AmbiguousRoot { exec_node: MastNodeId },
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
        source_node: DebugSourceNodeId,
    },
    /// A debug type row refers to a string index that is not present in its type string table.
    #[error(
        "debug info for forest {forest_index} references type string index {string_idx}, which is not present in the type string table"
    )]
    MissingTypeStringMapping { forest_index: usize, string_idx: u32 },
    /// A debug type or function row refers to a type index that is not present in its type table.
    #[error(
        "debug info for forest {forest_index} references type index {type_idx:?}, which is not present in the type table"
    )]
    MissingTypeMapping {
        forest_index: usize,
        type_idx: DebugTypeIdx,
    },
    /// A debug source-file row refers to a string index that is not present in its source string
    /// table.
    #[error(
        "debug info for forest {forest_index} references source string index {string_idx}, which is not present in the source string table"
    )]
    MissingSourceStringMapping { forest_index: usize, string_idx: u32 },
    /// A debug function or inline-call row refers to a source-file index that is not present in its
    /// source-file table.
    #[error(
        "debug info for forest {forest_index} references source file index {file_idx}, which is not present in the source file table"
    )]
    MissingSourceFileMapping { forest_index: usize, file_idx: u32 },
    /// A debug function row refers to a string index that is not present in its function string
    /// table.
    #[error(
        "debug info for forest {forest_index} references function string index {string_idx}, which is not present in the function string table"
    )]
    MissingFunctionStringMapping { forest_index: usize, string_idx: u32 },
    /// A debug inline-call row refers to a function index that is not present in its function
    /// table.
    #[error(
        "debug info for forest {forest_index} references function index {function_idx}, which is not present in the function table"
    )]
    MissingFunctionMapping { forest_index: usize, function_idx: u32 },
}

// DEBUG TYPE INDEX
// ================================================================================================

/// A strongly-typed index into the type table of a [`DebugTypesSection`].
///
/// This prevents accidental misuse of raw `u32` indices (e.g., using a string index
/// where a type index is expected).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
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
///
/// Version 2 removes the version 1 local-variable and inline-call payloads.
pub const DEBUG_FUNCTIONS_VERSION: u8 = 2;
/// The version of the debug_source_graph section format.
pub const DEBUG_SOURCE_GRAPH_VERSION: u8 = 1;
/// The version of the debug_source_map section format.
pub const DEBUG_SOURCE_MAP_VERSION: u8 = 1;
/// The version of the debug_error_messages section format.
pub const DEBUG_ERROR_MESSAGES_VERSION: u8 = 1;

/// Debug functions section containing function metadata.
///
/// This section stores function debug information.
///
/// String indices in sub-types (e.g., `name_idx` in `DebugFunctionInfo`) are relative
/// to this section's own string table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DebugFunctionsSection {
    /// Version of the debug functions format
    pub version: u8,
    /// String table containing function names and linkage names
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
pub struct PackageDebugInfo {
    /// Type definitions for source-level debug consumers.
    pub(crate) types: Option<DebugTypesSection>,
    /// Source file table.
    pub(crate) sources: Option<DebugSourcesSection>,
    /// Function metadata.
    pub(crate) functions: Option<DebugFunctionsSection>,
    /// Source/debug MAST occurrence graph.
    pub(crate) source_graph: Option<DebugSourceGraphSection>,
    /// Source-keyed assembly operation and debug variable rows.
    pub(crate) source_map: Option<DebugSourceMapSection>,
    /// Assertion error messages keyed by runtime error code.
    pub(crate) error_messages: Option<DebugErrorMessagesSection>,
}

impl PackageDebugInfo {
    /// Creates debug info with source/debug graph and map sections.
    pub fn with_source_debug(
        source_graph: DebugSourceGraphSection,
        source_map: DebugSourceMapSection,
    ) -> Self {
        Self {
            source_graph: Some(source_graph),
            source_map: Some(source_map),
            ..Self::default()
        }
    }

    /// Sets the source/debug graph section.
    pub fn with_source_graph(mut self, source_graph: DebugSourceGraphSection) -> Self {
        self.source_graph = Some(source_graph);
        self
    }

    /// Sets the source/debug map section.
    pub fn with_source_map(mut self, source_map: DebugSourceMapSection) -> Self {
        self.source_map = Some(source_map);
        self
    }

    /// Sets the assertion error messages section.
    pub fn with_error_messages(mut self, error_messages: DebugErrorMessagesSection) -> Self {
        self.error_messages = Some(error_messages);
        self
    }

    /// Returns the type definitions section, if present.
    pub fn types(&self) -> Option<&DebugTypesSection> {
        self.types.as_ref()
    }

    /// Returns the source file table section, if present.
    pub fn sources(&self) -> Option<&DebugSourcesSection> {
        self.sources.as_ref()
    }

    /// Returns the function metadata section, if present.
    pub fn functions(&self) -> Option<&DebugFunctionsSection> {
        self.functions.as_ref()
    }

    /// Returns the source/debug graph section, if present.
    pub fn source_graph(&self) -> Option<&DebugSourceGraphSection> {
        self.source_graph.as_ref()
    }

    /// Returns the source/debug map section, if present.
    pub fn source_map(&self) -> Option<&DebugSourceMapSection> {
        self.source_map.as_ref()
    }

    /// Returns the assertion error messages section, if present.
    pub fn error_messages(&self) -> Option<&DebugErrorMessagesSection> {
        self.error_messages.as_ref()
    }

    /// Returns true if no package debug sections were decoded.
    pub fn is_empty(&self) -> bool {
        self.types.is_none()
            && self.sources.is_none()
            && self.functions.is_none()
            && self.source_graph.is_none()
            && self.source_map.is_none()
            && self.error_messages.is_none()
    }

    /// Merges package-owned source/debug metadata after a [`miden_core::mast::MastForest`] merge.
    ///
    /// [`miden_core::mast::MastForest::merge`] remains execution-only. This helper applies the
    /// returned node mappings to package source/debug sections so callers can merge
    /// `(MastForest, PackageDebugInfo)` pairs without reattaching debug metadata to the forest.
    ///
    /// This also merges the type, source-file, and function tables referenced by source-map
    /// inline-call rows.
    pub fn merge_source_debug<'a>(
        inputs: impl IntoIterator<Item = (usize, &'a PackageDebugInfo)>,
        root_map: &MastForestRootMap,
    ) -> Result<Self, PackageDebugInfoMergeError> {
        let mut types = DebugTypesSection::new();
        let mut sources = DebugSourcesSection::new();
        let mut functions = DebugFunctionsSection::new();
        let mut nodes = Vec::new();
        let mut roots = Vec::new();
        let mut asm_ops = Vec::new();
        let mut debug_vars = Vec::new();
        let mut inline_calls = Vec::new();
        let mut error_messages = BTreeMap::new();
        let mut saw_types = false;
        let mut saw_sources = false;
        let mut saw_functions = false;
        let mut saw_source_graph = false;
        let mut saw_source_map = false;
        let mut saw_error_messages = false;

        for (forest_index, debug_info) in inputs {
            let type_map = merge_debug_types(forest_index, debug_info.types.as_ref(), &mut types)?;
            saw_types |= debug_info.types.is_some();
            let source_file_map =
                merge_debug_sources(forest_index, debug_info.sources.as_ref(), &mut sources)?;
            saw_sources |= debug_info.sources.is_some();
            let function_map = merge_debug_functions(
                forest_index,
                debug_info.functions.as_ref(),
                &mut functions,
                &source_file_map,
                &type_map,
            )?;
            saw_functions |= debug_info.functions.is_some();

            let source_graph = debug_info.source_graph.as_ref();
            let source_map = debug_info.source_map.as_ref();
            if source_graph.is_none() && source_map.is_some_and(|source_map| !source_map.is_empty())
            {
                return Err(PackageDebugInfoMergeError::SourceMapWithoutGraph { forest_index });
            }

            if let Some(section) = debug_info.error_messages.as_ref() {
                saw_error_messages = true;
                for row in section.messages() {
                    error_messages.entry(row.err_code).or_insert_with(|| row.message.clone());
                }
            }

            let Some(source_graph) = source_graph else {
                continue;
            };
            saw_source_graph = true;

            let mut source_id_map = BTreeMap::new();
            for old_source_idx in 0..source_graph.nodes().len() {
                source_id_map.insert(
                    DebugSourceNodeId::from(old_source_idx as u32),
                    DebugSourceNodeId::from(nodes.len() as u32 + old_source_idx as u32),
                );
            }

            for (old_source_idx, source_node) in source_graph.nodes().iter().enumerate() {
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
                nodes.push(DebugSourceNode::new(
                    exec_node,
                    children,
                    source_node.op_start,
                    source_node.op_end,
                ));
                debug_assert_eq!(
                    source_id_map[&DebugSourceNodeId::from(old_source_idx as u32)].as_u32()
                        as usize,
                    nodes.len() - 1,
                );
            }

            for root in source_graph.roots().iter().copied() {
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
            for row in source_map.asm_ops() {
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
            for row in source_map.debug_vars() {
                let source_node = source_id_map.get(&row.source_node).copied().ok_or(
                    PackageDebugInfoMergeError::MissingSourceNodeMapping {
                        forest_index,
                        source_node: row.source_node,
                    },
                )?;
                debug_vars.push(DebugSourceVar::new(source_node, row.op_idx, row.var.clone()));
            }
            for row in source_map.inline_calls() {
                let source_node = source_id_map.get(&row.source_node).copied().ok_or(
                    PackageDebugInfoMergeError::MissingSourceNodeMapping {
                        forest_index,
                        source_node: row.source_node,
                    },
                )?;
                let callee_idx = function_map.get(&row.callee_idx).copied().ok_or(
                    PackageDebugInfoMergeError::MissingFunctionMapping {
                        forest_index,
                        function_idx: row.callee_idx,
                    },
                )?;
                let file_idx = source_file_map.get(&row.file_idx).copied().ok_or(
                    PackageDebugInfoMergeError::MissingSourceFileMapping {
                        forest_index,
                        file_idx: row.file_idx,
                    },
                )?;
                inline_calls.push(DebugSourceInlineCall::new(
                    source_node,
                    row.op_idx,
                    callee_idx,
                    file_idx,
                    row.line,
                    row.column,
                ));
            }
        }

        Ok(Self {
            types: saw_types.then_some(types),
            sources: saw_sources.then_some(sources),
            functions: saw_functions.then_some(functions),
            source_graph: saw_source_graph
                .then_some(DebugSourceGraphSection::from_parts(nodes, roots)),
            source_map: saw_source_map.then_some(
                DebugSourceMapSection::from_parts_with_inline_calls(
                    asm_ops,
                    debug_vars,
                    inline_calls,
                ),
            ),
            error_messages: saw_error_messages.then_some(DebugErrorMessagesSection::from_parts(
                error_messages
                    .into_iter()
                    .map(|(err_code, message)| DebugErrorMessage::new(err_code, message))
                    .collect(),
            )),
        })
    }

    /// Returns a source/debug occurrence by ID.
    pub fn source_node(&self, source_node: DebugSourceNodeId) -> Option<&DebugSourceNode> {
        self.source_graph.as_ref()?.source_node(source_node)
    }

    /// Returns the unique source/debug root that points at `exec_node`.
    ///
    /// Returns `Ok(None)` if no source graph is present, or if no root points at `exec_node`.
    pub fn unique_source_root_for_exec_node(
        &self,
        exec_node: MastNodeId,
    ) -> Result<Option<DebugSourceNodeId>, DebugSourceGraphLookupError> {
        self.source_graph
            .as_ref()
            .map(|source_graph| source_graph.unique_source_root_for_exec_node(exec_node))
            .unwrap_or(Ok(None))
    }

    /// Returns `parent`'s source/debug child at `child_index`, if present.
    ///
    /// Returns `Ok(None)` if no source graph is present, or if `child_index` is out of range.
    pub fn child_source_node(
        &self,
        parent: DebugSourceNodeId,
        child_index: usize,
    ) -> Result<Option<(DebugSourceNodeId, &DebugSourceNode)>, DebugSourceGraphLookupError> {
        self.source_graph
            .as_ref()
            .map(|source_graph| source_graph.child_source_node(parent, child_index))
            .unwrap_or(Ok(None))
    }

    /// Returns assembly operation rows for a source/debug occurrence.
    pub fn asm_ops_for_source_node(
        &self,
        source_node: DebugSourceNodeId,
    ) -> impl Iterator<Item = &DebugSourceAsmOp> {
        self.source_map
            .iter()
            .flat_map(move |source_map| source_map.asm_ops_for_source_node(source_node))
    }

    /// Returns the first assembly operation row for `source_node`, if present.
    pub fn first_asm_op_for_source_node(
        &self,
        source_node: DebugSourceNodeId,
    ) -> Option<&DebugSourceAsmOp> {
        self.source_map.as_ref()?.first_asm_op_for_source_node(source_node)
    }

    /// Returns the assembly operation row for `source_node` at or before `op_idx`, if present.
    pub fn asm_op_for_operation(
        &self,
        source_node: DebugSourceNodeId,
        op_idx: u32,
    ) -> Option<&DebugSourceAsmOp> {
        self.source_map.as_ref()?.asm_op_for_operation(source_node, op_idx)
    }

    /// Returns debug variable rows for a source/debug occurrence.
    pub fn debug_vars_for_source_node(
        &self,
        source_node: DebugSourceNodeId,
    ) -> impl Iterator<Item = &DebugSourceVar> {
        self.source_map
            .iter()
            .flat_map(move |source_map| source_map.debug_vars_for_source_node(source_node))
    }

    /// Returns debug variable rows for `source_node` at `op_idx`.
    pub fn debug_vars_for_operation(
        &self,
        source_node: DebugSourceNodeId,
        op_idx: u32,
    ) -> impl Iterator<Item = &DebugSourceVar> {
        self.source_map
            .iter()
            .flat_map(move |source_map| source_map.debug_vars_for_operation(source_node, op_idx))
    }

    /// Returns inline-call rows for a source/debug occurrence.
    pub fn inline_calls_for_source_node(
        &self,
        source_node: DebugSourceNodeId,
    ) -> impl Iterator<Item = &DebugSourceInlineCall> {
        self.source_map
            .iter()
            .flat_map(move |source_map| source_map.inline_calls_for_source_node(source_node))
    }

    /// Returns inline-call rows for `source_node` at `op_idx`.
    pub fn inline_calls_for_operation(
        &self,
        source_node: DebugSourceNodeId,
        op_idx: u32,
    ) -> impl Iterator<Item = &DebugSourceInlineCall> {
        self.source_map
            .iter()
            .flat_map(move |source_map| source_map.inline_calls_for_operation(source_node, op_idx))
    }

    /// Returns the assertion error message for `err_code`, if present.
    pub fn error_message(&self, err_code: u64) -> Option<Arc<str>> {
        self.error_messages.as_ref()?.message(err_code)
    }
}

fn merge_debug_types(
    forest_index: usize,
    section: Option<&DebugTypesSection>,
    output: &mut DebugTypesSection,
) -> Result<BTreeMap<u32, DebugTypeIdx>, PackageDebugInfoMergeError> {
    let Some(section) = section else {
        return Ok(BTreeMap::new());
    };

    let mut string_map = BTreeMap::new();
    for (old_idx, string) in section.strings.iter().enumerate() {
        string_map.insert(old_idx as u32, output.add_string(string.clone()));
    }

    let base_idx = output.types.len() as u32;
    let type_map = (0..section.types.len())
        .map(|old_idx| (old_idx as u32, DebugTypeIdx::from(base_idx + old_idx as u32)))
        .collect::<BTreeMap<_, _>>();

    for ty in &section.types {
        output.add_type(remap_debug_type_info(forest_index, ty, &string_map, &type_map)?);
    }

    Ok(type_map)
}

fn merge_debug_sources(
    forest_index: usize,
    section: Option<&DebugSourcesSection>,
    output: &mut DebugSourcesSection,
) -> Result<BTreeMap<u32, u32>, PackageDebugInfoMergeError> {
    let Some(section) = section else {
        return Ok(BTreeMap::new());
    };

    let mut string_map = BTreeMap::new();
    for (old_idx, string) in section.strings.iter().enumerate() {
        string_map.insert(old_idx as u32, output.add_string(string.clone()));
    }

    let mut file_map = BTreeMap::new();
    for (old_idx, file) in section.files.iter().enumerate() {
        let path_idx = string_map.get(&file.path_idx).copied().ok_or(
            PackageDebugInfoMergeError::MissingSourceStringMapping {
                forest_index,
                string_idx: file.path_idx,
            },
        )?;
        let file = DebugFileInfo {
            path_idx,
            checksum: file.checksum.clone(),
        };
        let new_idx =
            output.files.iter().position(|existing| *existing == file).unwrap_or_else(|| {
                let new_idx = output.files.len();
                output.files.push(file);
                new_idx
            }) as u32;
        file_map.insert(old_idx as u32, new_idx);
    }

    Ok(file_map)
}

fn merge_debug_functions(
    forest_index: usize,
    section: Option<&DebugFunctionsSection>,
    output: &mut DebugFunctionsSection,
    source_file_map: &BTreeMap<u32, u32>,
    type_map: &BTreeMap<u32, DebugTypeIdx>,
) -> Result<BTreeMap<u32, u32>, PackageDebugInfoMergeError> {
    let Some(section) = section else {
        return Ok(BTreeMap::new());
    };

    let mut string_map = BTreeMap::new();
    for (old_idx, string) in section.strings.iter().enumerate() {
        string_map.insert(old_idx as u32, output.add_string(string.clone()));
    }

    let mut function_map = BTreeMap::new();
    for (old_idx, function) in section.functions.iter().enumerate() {
        let name_idx = remap_string_index(
            forest_index,
            function.name_idx,
            &string_map,
            |forest_index, string_idx| PackageDebugInfoMergeError::MissingFunctionStringMapping {
                forest_index,
                string_idx,
            },
        )?;
        let linkage_name_idx = function
            .linkage_name_idx
            .map(|idx| {
                remap_string_index(forest_index, idx, &string_map, |forest_index, string_idx| {
                    PackageDebugInfoMergeError::MissingFunctionStringMapping {
                        forest_index,
                        string_idx,
                    }
                })
            })
            .transpose()?;
        let file_idx = source_file_map.get(&function.file_idx).copied().ok_or(
            PackageDebugInfoMergeError::MissingSourceFileMapping {
                forest_index,
                file_idx: function.file_idx,
            },
        )?;
        let type_idx = function
            .type_idx
            .map(|idx| remap_type_idx(forest_index, idx, type_map))
            .transpose()?;
        let new_idx = output.functions.len() as u32;
        output.add_function(DebugFunctionInfo {
            name_idx,
            linkage_name_idx,
            file_idx,
            line: function.line,
            column: function.column,
            type_idx,
            mast_root: function.mast_root,
        });
        function_map.insert(old_idx as u32, new_idx);
    }

    Ok(function_map)
}

fn remap_debug_type_info(
    forest_index: usize,
    ty: &DebugTypeInfo,
    string_map: &BTreeMap<u32, u32>,
    type_map: &BTreeMap<u32, DebugTypeIdx>,
) -> Result<DebugTypeInfo, PackageDebugInfoMergeError> {
    Ok(match ty {
        DebugTypeInfo::Primitive(primitive) => DebugTypeInfo::Primitive(*primitive),
        DebugTypeInfo::Pointer { pointee_type_idx } => DebugTypeInfo::Pointer {
            pointee_type_idx: remap_type_idx(forest_index, *pointee_type_idx, type_map)?,
        },
        DebugTypeInfo::Array { element_type_idx, count } => DebugTypeInfo::Array {
            element_type_idx: remap_type_idx(forest_index, *element_type_idx, type_map)?,
            count: *count,
        },
        DebugTypeInfo::Struct { name_idx, size, fields } => DebugTypeInfo::Struct {
            name_idx: remap_string_index(
                forest_index,
                *name_idx,
                string_map,
                |forest_index, string_idx| PackageDebugInfoMergeError::MissingTypeStringMapping {
                    forest_index,
                    string_idx,
                },
            )?,
            size: *size,
            fields: fields
                .iter()
                .map(|field| {
                    Ok(DebugFieldInfo {
                        name_idx: remap_string_index(
                            forest_index,
                            field.name_idx,
                            string_map,
                            |forest_index, string_idx| {
                                PackageDebugInfoMergeError::MissingTypeStringMapping {
                                    forest_index,
                                    string_idx,
                                }
                            },
                        )?,
                        type_idx: remap_type_idx(forest_index, field.type_idx, type_map)?,
                        offset: field.offset,
                    })
                })
                .collect::<Result<_, PackageDebugInfoMergeError>>()?,
        },
        DebugTypeInfo::Function { return_type_idx, param_type_indices } => {
            DebugTypeInfo::Function {
                return_type_idx: return_type_idx
                    .map(|idx| remap_type_idx(forest_index, idx, type_map))
                    .transpose()?,
                param_type_indices: param_type_indices
                    .iter()
                    .map(|idx| remap_type_idx(forest_index, *idx, type_map))
                    .collect::<Result<_, _>>()?,
            }
        },
        DebugTypeInfo::Enum {
            name_idx,
            size,
            discriminant_type_idx,
            variants,
        } => DebugTypeInfo::Enum {
            name_idx: remap_string_index(
                forest_index,
                *name_idx,
                string_map,
                |forest_index, string_idx| PackageDebugInfoMergeError::MissingTypeStringMapping {
                    forest_index,
                    string_idx,
                },
            )?,
            size: *size,
            discriminant_type_idx: remap_type_idx(forest_index, *discriminant_type_idx, type_map)?,
            variants: variants
                .iter()
                .map(|variant| {
                    Ok(DebugVariantInfo {
                        name_idx: remap_string_index(
                            forest_index,
                            variant.name_idx,
                            string_map,
                            |forest_index, string_idx| {
                                PackageDebugInfoMergeError::MissingTypeStringMapping {
                                    forest_index,
                                    string_idx,
                                }
                            },
                        )?,
                        type_idx: variant
                            .type_idx
                            .map(|idx| remap_type_idx(forest_index, idx, type_map))
                            .transpose()?,
                        payload_offset: variant.payload_offset,
                        discriminant: variant.discriminant,
                    })
                })
                .collect::<Result<_, PackageDebugInfoMergeError>>()?,
        },
        DebugTypeInfo::Unknown => DebugTypeInfo::Unknown,
    })
}

fn remap_string_index(
    forest_index: usize,
    string_idx: u32,
    string_map: &BTreeMap<u32, u32>,
    error: impl FnOnce(usize, u32) -> PackageDebugInfoMergeError,
) -> Result<u32, PackageDebugInfoMergeError> {
    string_map
        .get(&string_idx)
        .copied()
        .ok_or_else(|| error(forest_index, string_idx))
}

fn remap_type_idx(
    forest_index: usize,
    type_idx: DebugTypeIdx,
    type_map: &BTreeMap<u32, DebugTypeIdx>,
) -> Result<DebugTypeIdx, PackageDebugInfoMergeError> {
    type_map
        .get(&type_idx.as_u32())
        .copied()
        .ok_or(PackageDebugInfoMergeError::MissingTypeMapping { forest_index, type_idx })
}

// DEBUG SOURCE GRAPH SECTION
// ================================================================================================

/// A strongly-typed index into the source/debug MAST occurrence graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct DebugSourceNodeId(u32);

impl DebugSourceNodeId {
    /// Returns the inner value as a `u32`.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<u32> for DebugSourceNodeId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<DebugSourceNodeId> for u32 {
    fn from(value: DebugSourceNodeId) -> Self {
        value.0
    }
}

impl Serializable for DebugSourceNodeId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.0);
    }
}

impl Deserializable for DebugSourceNodeId {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(source.read_u32()?))
    }

    fn min_serialized_size() -> usize {
        4
    }
}

/// A source/debug occurrence for code that produced an executable MAST node.
///
/// The `exec_node` field points into the package [`MastForest`](crate::MastForest) after executable
/// MAST reduction and deduplication. More than one [`DebugSourceNode`] may point at the same
/// `exec_node`: for example, two source procedures can compile to the same MAST root while still
/// carrying different source spans, assembly-op rows, or debug-variable rows. Consumers should
/// treat the [`DebugSourceNodeId`] as the identity of the source occurrence and use `exec_node`
/// only to find the executable node it describes.
///
/// Source-map rows in [`DebugSourceMapSection`] attach assembly operations and debug variables to
/// these source occurrences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugSourceNode {
    /// The executable MAST node represented by this source occurrence.
    pub exec_node: MastNodeId,
    /// Child source occurrences, in the same order as the executable node's children.
    pub children: Vec<DebugSourceNodeId>,
    /// Inclusive start operation index in the executable node.
    pub op_start: u32,
    /// Exclusive end operation index in the executable node.
    pub op_end: u32,
}

impl DebugSourceNode {
    /// Creates a source/debug occurrence record.
    pub fn new(
        exec_node: MastNodeId,
        children: Vec<DebugSourceNodeId>,
        op_start: u32,
        op_end: u32,
    ) -> Self {
        Self { exec_node, children, op_start, op_end }
    }
}

/// Package-owned source/debug MAST occurrence graph.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DebugSourceGraphSection {
    /// Version of the debug source graph format.
    version: u8,
    /// Source/debug occurrence nodes.
    nodes: Vec<DebugSourceNode>,
    /// Source/debug occurrence roots.
    roots: Vec<DebugSourceNodeId>,
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

    /// Creates a source/debug occurrence graph section from validated parts.
    pub fn from_parts(nodes: Vec<DebugSourceNode>, roots: Vec<DebugSourceNodeId>) -> Self {
        Self {
            version: DEBUG_SOURCE_GRAPH_VERSION,
            nodes,
            roots,
        }
    }

    /// Returns the source graph section format version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns source/debug occurrence nodes.
    pub fn nodes(&self) -> &[DebugSourceNode] {
        &self.nodes
    }

    /// Returns source/debug occurrence roots.
    pub fn roots(&self) -> &[DebugSourceNodeId] {
        &self.roots
    }

    /// Returns true if the section contains no source occurrences.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.roots.is_empty()
    }

    /// Returns a source/debug occurrence by ID.
    fn source_node(&self, source_node: DebugSourceNodeId) -> Option<&DebugSourceNode> {
        self.nodes.get(source_node.as_u32() as usize)
    }

    /// Returns all source/debug roots that point at `exec_node`.
    fn source_roots_for_exec_node(
        &self,
        exec_node: MastNodeId,
    ) -> impl Iterator<Item = (DebugSourceNodeId, &DebugSourceNode)> {
        self.roots.iter().copied().filter_map(move |source_node_id| {
            self.source_node(source_node_id)
                .filter(|source_node| source_node.exec_node == exec_node)
                .map(|source_node| (source_node_id, source_node))
        })
    }

    /// Returns the unique source/debug root that points at `exec_node`.
    fn unique_source_root_for_exec_node(
        &self,
        exec_node: MastNodeId,
    ) -> Result<Option<DebugSourceNodeId>, DebugSourceGraphLookupError> {
        let mut roots = self
            .source_roots_for_exec_node(exec_node)
            .map(|(source_node_id, _)| source_node_id);
        let first = roots.next();
        if roots.next().is_some() {
            return Err(DebugSourceGraphLookupError::AmbiguousRoot { exec_node });
        }
        Ok(first)
    }

    /// Returns `parent`'s source/debug child at `child_index`, if present.
    fn child_source_node(
        &self,
        parent: DebugSourceNodeId,
        child_index: usize,
    ) -> Result<Option<(DebugSourceNodeId, &DebugSourceNode)>, DebugSourceGraphLookupError> {
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
pub struct DebugSourceAsmOp {
    /// Source/debug occurrence that owns this operation row.
    pub source_node: DebugSourceNodeId,
    /// Operation index local to the reduced execution node.
    pub op_idx: u32,
    /// Optional source location for the assembly operation.
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
        source_node: DebugSourceNodeId,
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
pub struct DebugSourceVar {
    /// Source/debug occurrence that owns this variable row.
    pub source_node: DebugSourceNodeId,
    /// Operation index local to the reduced execution node.
    pub op_idx: u32,
    /// Debug variable metadata.
    pub var: DebugVarInfo,
}

impl DebugSourceVar {
    /// Creates a source-keyed debug variable metadata row.
    pub fn new(source_node: DebugSourceNodeId, op_idx: u32, var: DebugVarInfo) -> Self {
        Self { source_node, op_idx, var }
    }
}

/// Inline-call metadata keyed by a source/debug MAST occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugSourceInlineCall {
    /// Source/debug occurrence that owns this inline-call row.
    pub source_node: DebugSourceNodeId,
    /// Operation index local to the reduced execution node.
    pub op_idx: u32,
    /// Inlined callee function index in the debug functions table.
    pub callee_idx: u32,
    /// Call-site source file index in the debug sources table.
    pub file_idx: u32,
    /// Call-site line number.
    pub line: LineNumber,
    /// Call-site column number.
    pub column: ColumnNumber,
}

impl DebugSourceInlineCall {
    /// Creates a source-keyed inline-call metadata row.
    pub fn new(
        source_node: DebugSourceNodeId,
        op_idx: u32,
        callee_idx: u32,
        file_idx: u32,
        line: LineNumber,
        column: ColumnNumber,
    ) -> Self {
        Self {
            source_node,
            op_idx,
            callee_idx,
            file_idx,
            line,
            column,
        }
    }
}

/// Package-owned source-keyed debug metadata rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DebugSourceMapSection {
    /// Version of the debug source map format.
    version: u8,
    /// Deduplicated source locations referenced by assembly operation rows.
    locations: Vec<Location>,
    /// Deduplicated strings referenced by assembly operation rows.
    strings: Vec<String>,
    /// Source-keyed assembly operation rows.
    asm_ops: Vec<DebugSourceAsmOp>,
    /// Source-keyed debug variable rows.
    debug_vars: Vec<DebugSourceVar>,
    /// Source-keyed inline-call rows.
    inline_calls: Vec<DebugSourceInlineCall>,
}

impl DebugSourceMapSection {
    /// Creates an empty source-keyed debug metadata section.
    pub fn new() -> Self {
        Self {
            version: DEBUG_SOURCE_MAP_VERSION,
            locations: Vec::new(),
            strings: Vec::new(),
            asm_ops: Vec::new(),
            debug_vars: Vec::new(),
            inline_calls: Vec::new(),
        }
    }

    /// Creates a source-keyed debug metadata section from rows.
    pub fn from_parts(asm_ops: Vec<DebugSourceAsmOp>, debug_vars: Vec<DebugSourceVar>) -> Self {
        Self::from_parts_with_inline_calls(asm_ops, debug_vars, Vec::new())
    }

    /// Creates a source-keyed debug metadata section from rows, including inline calls.
    pub fn from_parts_with_inline_calls(
        asm_ops: Vec<DebugSourceAsmOp>,
        debug_vars: Vec<DebugSourceVar>,
        inline_calls: Vec<DebugSourceInlineCall>,
    ) -> Self {
        let locations = intern_locations(&asm_ops);
        let strings = intern_source_map_strings(&asm_ops);
        Self {
            version: DEBUG_SOURCE_MAP_VERSION,
            locations,
            strings,
            asm_ops,
            debug_vars,
            inline_calls,
        }
    }

    /// Returns the source map section format version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns source-keyed assembly operation rows.
    pub fn asm_ops(&self) -> &[DebugSourceAsmOp] {
        &self.asm_ops
    }

    /// Returns the deduplicated source locations referenced by assembly operation rows.
    pub fn locations(&self) -> &[Location] {
        &self.locations
    }

    /// Returns the deduplicated strings referenced by assembly operation rows.
    pub fn strings(&self) -> &[String] {
        &self.strings
    }

    /// Returns source-keyed debug variable rows.
    pub fn debug_vars(&self) -> &[DebugSourceVar] {
        &self.debug_vars
    }

    /// Returns source-keyed inline-call rows.
    pub fn inline_calls(&self) -> &[DebugSourceInlineCall] {
        &self.inline_calls
    }

    /// Returns true if the section contains no metadata rows.
    pub fn is_empty(&self) -> bool {
        self.asm_ops.is_empty() && self.debug_vars.is_empty() && self.inline_calls.is_empty()
    }

    /// Returns assembly operation rows for a source/debug occurrence.
    fn asm_ops_for_source_node(
        &self,
        source_node: DebugSourceNodeId,
    ) -> impl Iterator<Item = &DebugSourceAsmOp> {
        self.asm_ops.iter().filter(move |row| row.source_node == source_node)
    }

    /// Returns the first assembly operation row for `source_node`, if present.
    fn first_asm_op_for_source_node(
        &self,
        source_node: DebugSourceNodeId,
    ) -> Option<&DebugSourceAsmOp> {
        self.asm_ops_for_source_node(source_node).min_by_key(|row| row.op_idx)
    }

    /// Returns the assembly operation row for `source_node` at or before `op_idx`, if present.
    fn asm_op_for_operation(
        &self,
        source_node: DebugSourceNodeId,
        op_idx: u32,
    ) -> Option<&DebugSourceAsmOp> {
        self.asm_ops_for_source_node(source_node)
            .filter(|row| row.op_idx <= op_idx)
            .max_by_key(|row| row.op_idx)
    }

    /// Returns debug variable rows for a source/debug occurrence.
    fn debug_vars_for_source_node(
        &self,
        source_node: DebugSourceNodeId,
    ) -> impl Iterator<Item = &DebugSourceVar> {
        self.debug_vars.iter().filter(move |row| row.source_node == source_node)
    }

    /// Returns debug variable rows for `source_node` at `op_idx`.
    fn debug_vars_for_operation(
        &self,
        source_node: DebugSourceNodeId,
        op_idx: u32,
    ) -> impl Iterator<Item = &DebugSourceVar> {
        self.debug_vars_for_source_node(source_node)
            .filter(move |row| row.op_idx == op_idx)
    }

    /// Returns inline-call rows for a source/debug occurrence.
    fn inline_calls_for_source_node(
        &self,
        source_node: DebugSourceNodeId,
    ) -> impl Iterator<Item = &DebugSourceInlineCall> {
        self.inline_calls.iter().filter(move |row| row.source_node == source_node)
    }

    /// Returns inline-call rows for `source_node` at `op_idx`.
    fn inline_calls_for_operation(
        &self,
        source_node: DebugSourceNodeId,
        op_idx: u32,
    ) -> impl Iterator<Item = &DebugSourceInlineCall> {
        self.inline_calls_for_source_node(source_node)
            .filter(move |row| row.op_idx == op_idx)
    }
}

fn intern_locations(asm_ops: &[DebugSourceAsmOp]) -> Vec<Location> {
    let mut locations = Vec::new();
    let mut by_location = BTreeMap::new();
    for location in asm_ops.iter().filter_map(|row| row.location.as_ref()) {
        by_location.entry(location.clone()).or_insert_with(|| {
            let idx = locations.len();
            locations.push(location.clone());
            idx
        });
    }
    locations
}

fn intern_source_map_strings(asm_ops: &[DebugSourceAsmOp]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut by_string = BTreeMap::new();
    for value in asm_ops.iter().flat_map(|row| [&row.context_name, &row.op]) {
        by_string.entry(value.clone()).or_insert_with(|| {
            let idx = strings.len();
            strings.push(value.clone());
            idx
        });
    }
    strings
}

// DEBUG ERROR MESSAGES SECTION
// ================================================================================================

/// Assertion error message keyed by its runtime error code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugErrorMessage {
    /// Runtime error code emitted by the assembled assertion operation.
    pub err_code: u64,
    /// Human-readable assertion error message from source.
    pub message: Arc<str>,
}

impl DebugErrorMessage {
    /// Creates an assertion error message metadata row.
    pub fn new(err_code: u64, message: Arc<str>) -> Self {
        Self { err_code, message }
    }
}

/// Package-owned assertion error messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DebugErrorMessagesSection {
    /// Version of the debug error messages format.
    version: u8,
    /// Error messages keyed by runtime error code.
    messages: Vec<DebugErrorMessage>,
}

impl DebugErrorMessagesSection {
    /// Creates an empty assertion error message section.
    pub fn new() -> Self {
        Self {
            version: DEBUG_ERROR_MESSAGES_VERSION,
            messages: Vec::new(),
        }
    }

    /// Creates an assertion error message section from rows.
    pub fn from_parts(messages: Vec<DebugErrorMessage>) -> Self {
        Self {
            version: DEBUG_ERROR_MESSAGES_VERSION,
            messages,
        }
    }

    /// Returns the error message section format version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns error message rows.
    pub fn messages(&self) -> &[DebugErrorMessage] {
        &self.messages
    }

    /// Returns true if the section contains no metadata rows.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Returns the assertion error message for `err_code`, if present.
    pub fn message(&self, err_code: u64) -> Option<Arc<str>> {
        self.messages
            .iter()
            .find(|row| row.err_code == err_code)
            .map(|row| row.message.clone())
    }
}

// DEBUG TYPE INFO
// ================================================================================================

/// Type information for debug purposes.
///
/// This encodes the type of a variable or expression, enabling debuggers to properly
/// display values on the stack or in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
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
            | Self::F32
            | Self::Felt => 1,
            Self::I64 | Self::U64 | Self::F64 => 2,
            Self::I128 | Self::U128 | Self::Word => 4,
            Self::U256 => 8,
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
/// Links source-level function information to the compiled MAST representation.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    fn test_debug_source_map_inline_calls_are_keyed_by_source_operation() {
        let source_a = DebugSourceNodeId::from(0);
        let source_b = DebugSourceNodeId::from(1);
        let inline_a = DebugSourceInlineCall::new(
            source_a,
            3,
            0,
            0,
            LineNumber::new(10).unwrap(),
            ColumnNumber::new(4).unwrap(),
        );
        let inline_b = DebugSourceInlineCall::new(
            source_b,
            3,
            1,
            0,
            LineNumber::new(20).unwrap(),
            ColumnNumber::new(8).unwrap(),
        );
        let source_map = DebugSourceMapSection::from_parts_with_inline_calls(
            alloc::vec![],
            alloc::vec![],
            alloc::vec![inline_a.clone(), inline_b.clone()],
        );

        assert_eq!(source_map.inline_calls(), &[inline_a.clone(), inline_b]);
        assert_eq!(
            source_map.inline_calls_for_operation(source_a, 3).collect::<Vec<_>>(),
            alloc::vec![&inline_a],
        );
        assert!(source_map.inline_calls_for_operation(source_a, 4).next().is_none());
    }

    #[test]
    fn test_package_source_debug_merge_remaps_execution_nodes_without_collapsing_sources() {
        use miden_core::{
            mast::{BasicBlockNodeBuilder, DenseMastForestBuilder, MastForest},
            operations::{DebugVarInfo, DebugVarLocation, Operation},
        };

        fn forest_with_add_block() -> (MastForest, MastNodeId) {
            let mut builder = DenseMastForestBuilder::new();
            let block = builder
                .push_node(BasicBlockNodeBuilder::new(alloc::vec![Operation::Add]))
                .unwrap();
            builder.mark_root(block);
            let (forest, remapping) = builder.finish_with_id_map().unwrap();
            let block = remapping.get(block).unwrap();
            (forest, block)
        }

        fn debug_info_for_block(
            block: MastNodeId,
            context: &str,
            var_name: &str,
        ) -> PackageDebugInfo {
            let source_node = DebugSourceNodeId::from(0);
            let mut sources = DebugSourcesSection::new();
            let path_idx = sources.add_string(Arc::from(alloc::format!("{context}.masm")));
            let file_idx = sources.add_file(DebugFileInfo::new(path_idx));
            let mut functions = DebugFunctionsSection::new();
            let name_idx = functions.add_string(Arc::from(alloc::format!("{context}_callee")));
            functions.add_function(DebugFunctionInfo::new(
                name_idx,
                file_idx,
                LineNumber::new(7).unwrap(),
                ColumnNumber::new(3).unwrap(),
            ));
            PackageDebugInfo {
                sources: Some(sources),
                functions: Some(functions),
                source_graph: Some(DebugSourceGraphSection {
                    version: DEBUG_SOURCE_GRAPH_VERSION,
                    nodes: alloc::vec![DebugSourceNode::new(block, alloc::vec![], 0, 1,)],
                    roots: alloc::vec![source_node],
                }),
                source_map: Some(DebugSourceMapSection::from_parts_with_inline_calls(
                    alloc::vec![DebugSourceAsmOp::new(
                        source_node,
                        0,
                        None,
                        context.into(),
                        "add".into(),
                        1,
                    )],
                    alloc::vec![DebugSourceVar::new(
                        source_node,
                        0,
                        DebugVarInfo::new(var_name, DebugVarLocation::Stack(0)),
                    )],
                    alloc::vec![DebugSourceInlineCall::new(
                        source_node,
                        0,
                        0,
                        file_idx,
                        LineNumber::new(9).unwrap(),
                        ColumnNumber::new(5).unwrap(),
                    )],
                )),
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
        let sources = merged_debug.sources.as_ref().unwrap();
        let functions = merged_debug.functions.as_ref().unwrap();
        let inline_a = merged_debug.inline_calls_for_operation(source_a, 0).collect::<Vec<_>>();
        let inline_b = merged_debug.inline_calls_for_operation(source_b, 0).collect::<Vec<_>>();
        assert_eq!(inline_a.len(), 1);
        assert_eq!(inline_b.len(), 1);

        let file_a = sources.get_file(inline_a[0].file_idx).unwrap();
        let path_a = sources.get_string(file_a.path_idx).unwrap();
        let function_a = &functions.functions[inline_a[0].callee_idx as usize];
        let function_name_a = functions.get_string(function_a.name_idx).unwrap();
        assert_eq!(path_a.as_ref(), "alias_a.masm");
        assert_eq!(function_name_a.as_ref(), "alias_a_callee");
        assert_eq!(function_a.file_idx, inline_a[0].file_idx);

        let file_b = sources.get_file(inline_b[0].file_idx).unwrap();
        let path_b = sources.get_string(file_b.path_idx).unwrap();
        let function_b = &functions.functions[inline_b[0].callee_idx as usize];
        let function_name_b = functions.get_string(function_b.name_idx).unwrap();
        assert_eq!(path_b.as_ref(), "alias_b.masm");
        assert_eq!(function_name_b.as_ref(), "alias_b_callee");
        assert_eq!(function_b.file_idx, inline_b[0].file_idx);
    }

    #[test]
    fn test_package_source_debug_merge_remaps_non_root_execution_nodes() {
        use miden_core::{
            mast::{BasicBlockNodeBuilder, CallNodeBuilder, DenseMastForestBuilder, MastForest},
            operations::Operation,
        };

        let mut builder = DenseMastForestBuilder::new();
        let callee = builder
            .push_node(BasicBlockNodeBuilder::new(alloc::vec![Operation::Add]))
            .unwrap();
        let call = builder.push_node(CallNodeBuilder::new(callee)).unwrap();
        builder.mark_root(call);
        let (forest, remapping) = builder.finish_with_id_map().unwrap();
        let callee = remapping.get(callee).unwrap();
        let call = remapping.get(call).unwrap();

        let root_source = DebugSourceNodeId::from(0);
        let child_source = DebugSourceNodeId::from(1);
        let debug_info = PackageDebugInfo {
            source_graph: Some(DebugSourceGraphSection {
                version: DEBUG_SOURCE_GRAPH_VERSION,
                nodes: alloc::vec![
                    DebugSourceNode::new(call, alloc::vec![child_source], 0, 1),
                    DebugSourceNode::new(callee, alloc::vec![], 0, 1),
                ],
                roots: alloc::vec![root_source],
            }),
            source_map: Some(DebugSourceMapSection::from_parts(
                alloc::vec![DebugSourceAsmOp::new(
                    child_source,
                    0,
                    None,
                    "callee".into(),
                    "add".into(),
                    1,
                )],
                alloc::vec![],
            )),
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
        let source_a = DebugSourceNodeId::from(0);
        let source_b = DebugSourceNodeId::from(1);
        let graph = DebugSourceGraphSection {
            version: DEBUG_SOURCE_GRAPH_VERSION,
            nodes: alloc::vec![
                DebugSourceNode::new(exec_node, alloc::vec![], 0, 1),
                DebugSourceNode::new(exec_node, alloc::vec![], 0, 1),
            ],
            roots: alloc::vec![source_a, source_b],
        };
        assert_eq!(graph.nodes().iter().filter(|node| node.exec_node == exec_node).count(), 2);
        assert_eq!(graph.source_node(source_a).unwrap().exec_node, exec_node);

        let source_map = DebugSourceMapSection::from_parts(
            alloc::vec![
                DebugSourceAsmOp::new(source_a, 0, None, "alias_a".into(), "add".into(), 1),
                DebugSourceAsmOp::new(source_b, 0, None, "alias_b".into(), "add".into(), 1),
                DebugSourceAsmOp::new(source_b, 2, None, "alias_b_later".into(), "mul".into(), 1),
            ],
            alloc::vec![
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
        );

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
    fn test_source_graph_navigation_uses_child_indices() {
        let root_exec = MastNodeId::new_unchecked(7);
        let child_exec = MastNodeId::new_unchecked(8);
        let other_exec = MastNodeId::new_unchecked(9);
        let root = DebugSourceNodeId::from(0);
        let child_a = DebugSourceNodeId::from(1);
        let child_b = DebugSourceNodeId::from(2);
        let other_root = DebugSourceNodeId::from(3);
        let graph = DebugSourceGraphSection {
            version: DEBUG_SOURCE_GRAPH_VERSION,
            nodes: alloc::vec![
                DebugSourceNode::new(root_exec, alloc::vec![child_a, child_b], 0, 1),
                DebugSourceNode::new(child_exec, alloc::vec![], 0, 1),
                DebugSourceNode::new(child_exec, alloc::vec![], 0, 1),
                DebugSourceNode::new(root_exec, alloc::vec![], 0, 1),
            ],
            roots: alloc::vec![root],
        };

        assert_eq!(graph.unique_source_root_for_exec_node(root_exec).unwrap(), Some(root));
        assert_eq!(graph.unique_source_root_for_exec_node(other_exec).unwrap(), None);
        assert_eq!(graph.child_source_node(root, 0).unwrap().unwrap().0, child_a);
        assert_eq!(graph.child_source_node(root, 1).unwrap().unwrap().0, child_b);
        assert!(graph.child_source_node(root, 2).unwrap().is_none());
        assert_eq!(
            graph.child_source_node(DebugSourceNodeId::from(99), 0),
            Err(DebugSourceGraphLookupError::MissingSourceNode {
                source_node: DebugSourceNodeId::from(99),
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
    fn test_primitive_type_sizes() {
        assert_eq!(DebugPrimitiveType::Void.size_in_bytes(), 0);
        assert_eq!(DebugPrimitiveType::I32.size_in_bytes(), 4);
        assert_eq!(DebugPrimitiveType::F32.size_in_bytes(), 4);
        assert_eq!(DebugPrimitiveType::I64.size_in_bytes(), 8);
        assert_eq!(DebugPrimitiveType::F64.size_in_bytes(), 8);
        assert_eq!(DebugPrimitiveType::Felt.size_in_bytes(), 8);
        assert_eq!(DebugPrimitiveType::Word.size_in_bytes(), 32);
        assert_eq!(DebugPrimitiveType::U256.size_in_bytes(), 32);

        assert_eq!(DebugPrimitiveType::Void.size_in_felts(), 0);
        assert_eq!(DebugPrimitiveType::I32.size_in_felts(), 1);
        assert_eq!(DebugPrimitiveType::F32.size_in_felts(), 1);
        assert_eq!(DebugPrimitiveType::I64.size_in_felts(), 2);
        assert_eq!(DebugPrimitiveType::F64.size_in_felts(), 2);
        assert_eq!(DebugPrimitiveType::Word.size_in_felts(), 4);
        // A `u256` occupies eight 32-bit limbs on the stack.
        assert_eq!(DebugPrimitiveType::U256.size_in_felts(), 8);
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
