//! Debug information sections for MASP packages.
//!
//! This module provides types for encoding source-level debug information in the
//! `debug_types`, `debug_sources`, and `debug_functions` custom sections of a MASP package.
//! This information is used by debuggers to map between the Miden VM execution state
//! and the original source code.

#[cfg(feature = "arbitrary")]
mod arbitrary;
mod builder;
mod serialization;
mod types;

use alloc::{boxed::Box, sync::Arc, vec::Vec};

pub use builder::*;
use miden_core::mast::{MastForestRootMap, MastNodeId};
#[cfg(all(feature = "arbitrary", test))]
use miden_core::serde::{Deserializable, Serializable};
use miden_debug_types::{Location, Uri};
use miden_utils_indexing::{Idx, IndexVec};
pub use types::*;

type FxHashMap<K, V> = hashbrown::HashMap<K, V, rustc_hash::FxBuildHasher>;
type FxHashSet<K> = hashbrown::HashSet<K, rustc_hash::FxBuildHasher>;

pub const DEBUG_INFO_VERSION: u8 = 2;

// PACKAGE DEBUG INFO
// ================================================================================================

/// Trusted package-owned debug information decoded from well-known debug sections.
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
pub type PackageDebugInfo = DebugInfo<MastNodeId, DebugSourceNodeId>;

/// Represents debug information bound to a pending/finalized [`miden_core::mast::MastForest`].
///
/// This includes all debug information needed for source-level debugging, and recovery of program
/// state during execution (such as the types of local variables in the source program, and their
/// location in memory or on the operand stack).
#[derive(Eq, PartialEq)]
pub struct DebugInfo<Exec: Idx, Src: Idx> {
    /// The version tag associated with this debug info instance
    version: u8,
    /// Strings referenced by records in this debug info instance
    strings: IndexVec<DebugStringIdx, Arc<str>>,
    /// Source file table
    ///
    /// Currently this maintains the set of source paths referenced by this debug info instance,
    /// as well as an optional checksum of the content at the point its source was captured so it
    /// can be compared later.
    files: IndexVec<DebugFileIdx, DebugFileInfo>,
    /// Source locations table
    ///
    /// Unique source locations referenced by this debug info instance.
    locations: IndexVec<DebugLocIdx, DebugLoc>,
    /// Type table containing uniqued type definitions referenced by this debug info instance.
    types: IndexVec<DebugTypeIdx, DebugTypeInfo>,
    /// Function debug information
    ///
    /// This information is used to map source-level function information on to source nodes, or
    /// directly to a MAST root in cases where no source node is known, but the procedure root is.
    ///
    /// Function information includes, source-level name, linkage name, source file, line/column,
    /// type signature and MAST root. A few of these are optional as they are not always available.
    /// Information available is best-effort.
    functions: IndexVec<DebugFunctionIdx, FunctionInfo<Src>>,
    /// Source/debug occurrence nodes.
    ///
    /// This represents all instruction-level debug information for a given execution node in the
    /// MAST forest. Multiple source nodes can exist for a given execution node, depending on how
    /// many source occurances produced the same node (i.e. same MAST root).
    nodes: IndexVec<Src, SourceNode<Exec, Src>>,
    /// Source/debug occurrence roots.
    ///
    /// Roots are source nodes which correspond to procedure roots in the MAST forest.
    roots: Vec<Src>,
    /// Assertion error messages uniqued by runtime error code.
    error_messages: Vec<DebugErrorMessage>,
}

// FUNDAMENTAL TRAIT IMPLS
// ================================================================================================

impl<Exec: Idx, Src: Idx> Default for DebugInfo<Exec, Src> {
    fn default() -> Self {
        Self {
            version: DEBUG_INFO_VERSION,
            strings: Default::default(),
            files: Default::default(),
            locations: Default::default(),
            types: Default::default(),
            functions: Default::default(),
            nodes: Default::default(),
            roots: Default::default(),
            error_messages: Default::default(),
        }
    }
}

impl<Exec, Src> Clone for DebugInfo<Exec, Src>
where
    Exec: Idx + Clone,
    Src: Idx + Clone,
{
    fn clone(&self) -> Self {
        Self {
            version: self.version,
            strings: self.strings.clone(),
            files: self.files.clone(),
            locations: self.locations.clone(),
            types: self.types.clone(),
            functions: self.functions.clone(),
            nodes: self.nodes.clone(),
            roots: self.roots.clone(),
            error_messages: self.error_messages.clone(),
        }
    }
}

impl<Exec, Src> core::fmt::Debug for DebugInfo<Exec, Src>
where
    Exec: Idx + core::fmt::Debug,
    Src: Idx + core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DebugInfo")
            .field("version", &self.version)
            .field("strings", &self.strings)
            .field("files", &self.files)
            .field("locations", &self.locations)
            .field("types", &self.types)
            .field("functions", &self.functions)
            .field("nodes", &self.nodes)
            .field("roots", &self.roots)
            .field("error_messages", &self.error_messages)
            .finish()
    }
}

// INDEXING
// ================================================================================================

impl<Exec: Idx, Src: Idx> core::ops::Index<DebugStringIdx> for DebugInfo<Exec, Src> {
    type Output = Arc<str>;

    fn index(&self, index: DebugStringIdx) -> &Self::Output {
        &self.strings[index]
    }
}

impl<Exec: Idx, Src: Idx> core::ops::Index<DebugFileIdx> for DebugInfo<Exec, Src> {
    type Output = DebugFileInfo;

    fn index(&self, index: DebugFileIdx) -> &Self::Output {
        &self.files[index]
    }
}

impl<Exec: Idx, Src: Idx> core::ops::Index<DebugFunctionIdx> for DebugInfo<Exec, Src> {
    type Output = FunctionInfo<Src>;

    fn index(&self, index: DebugFunctionIdx) -> &Self::Output {
        &self.functions[index]
    }
}

impl<Exec: Idx, Src: Idx> core::ops::Index<DebugTypeIdx> for DebugInfo<Exec, Src> {
    type Output = DebugTypeInfo;

    fn index(&self, index: DebugTypeIdx) -> &Self::Output {
        &self.types[index]
    }
}

impl<Exec: Idx, Src: Idx> core::ops::Index<DebugLocIdx> for DebugInfo<Exec, Src> {
    type Output = DebugLoc;

    fn index(&self, index: DebugLocIdx) -> &Self::Output {
        &self.locations[index]
    }
}

/// A marker trait for [Idx] impls that may be used as a source node index with [DebugInfo]
///
/// This is needed to avoid coherence issues with [core::ops::Index] impls for [DebugInfo]
pub trait SourceNodeIdMarker: Idx + core::hash::Hash {}

impl<Exec: Idx, Src: SourceNodeIdMarker> core::ops::Index<Src> for DebugInfo<Exec, Src> {
    type Output = SourceNode<Exec, Src>;

    fn index(&self, index: Src) -> &Self::Output {
        &self.nodes[index]
    }
}

// ACCESSORS
// ================================================================================================

impl<Exec: Idx, Src: Idx> DebugInfo<Exec, Src> {
    /// Get the version of this debug info instance
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Get access to the strings table in this debug info
    pub fn strings(&self) -> &IndexVec<DebugStringIdx, Arc<str>> {
        &self.strings
    }

    /// Gets a string by index.
    pub fn get_string(&self, idx: DebugStringIdx) -> Option<Arc<str>> {
        self.strings.get(idx).cloned()
    }

    /// Get access to the files table in this debug info
    pub fn files(&self) -> &IndexVec<DebugFileIdx, DebugFileInfo> {
        &self.files
    }

    /// Gets a file by index.
    pub fn get_file(&self, idx: DebugFileIdx) -> Option<&DebugFileInfo> {
        self.files.get(idx)
    }

    /// Gets the [DebugFileIdx] for a source file whose URI is `uri`, if it is recorded in the
    /// debug info built so far.
    pub fn get_file_index_by_uri(&self, uri: &Uri) -> Option<DebugFileIdx> {
        self.files
            .iter()
            .position(|file| {
                self.strings
                    .get(file.path_idx)
                    .map(|path| path.as_ref() == uri.as_str())
                    .unwrap_or(false)
            })
            .map(|pos| DebugFileIdx::from(pos as u32))
    }

    /// Apply `trimmer` to every distinct file path referenced by the file table.
    ///
    /// If `trimmer` returns `None`, the file path is left unmodified. Otherwise, the returned path
    /// is interned and the corresponding file records are retargeted to it. Other debug records
    /// which reference the original string are left unchanged.
    pub fn trim_file_paths(&mut self, mut trimmer: impl FnMut(&str) -> Option<Arc<str>>) {
        use hashbrown::hash_map::Entry;

        let mut string_indices = FxHashMap::<Arc<str>, DebugStringIdx>::default();
        for (index, string) in self.strings.iter().enumerate() {
            string_indices
                .entry(string.clone())
                .or_insert_with(|| DebugStringIdx::from(index as u32));
        }

        // Multiple file rows may share a path string (for example, when they have different
        // checksums). Apply the trimmer once per path and retarget each file row to the result.
        // Appending/reusing a string rather than mutating the original preserves unrelated records
        // which happen to reference the same globally-interned string.
        let mut remapped_paths = FxHashMap::<DebugStringIdx, DebugStringIdx>::default();
        for file in self.files.iter_mut() {
            let old_path_idx = file.path_idx;
            let new_path_idx = if let Some(new_path_idx) = remapped_paths.get(&old_path_idx) {
                *new_path_idx
            } else {
                let path = self.strings[old_path_idx].clone();
                let new_path_idx = match trimmer(path.as_ref()) {
                    None => old_path_idx,
                    Some(new_path) => match string_indices.entry(new_path.clone()) {
                        Entry::Occupied(entry) => *entry.get(),
                        Entry::Vacant(entry) => {
                            let index =
                                self.strings.push(new_path).expect("too many debug info strings");
                            entry.insert(index);
                            index
                        },
                    },
                };
                remapped_paths.insert(old_path_idx, new_path_idx);
                new_path_idx
            };
            file.path_idx = new_path_idx;
        }
    }

    /// Get access to the types table in this debug info
    pub fn types(&self) -> &IndexVec<DebugTypeIdx, DebugTypeInfo> {
        &self.types
    }

    /// Gets a type by index.
    pub fn get_type(&self, idx: DebugTypeIdx) -> Option<&DebugTypeInfo> {
        self.types.get(idx)
    }

    /// Get access to the locatinos table in this debug info
    pub fn locations(&self) -> &IndexVec<DebugLocIdx, DebugLoc> {
        &self.locations
    }

    /// Returns the deduplicated source locations referenced by assembly operation rows.
    pub fn get_location(&self, idx: DebugLocIdx) -> Option<Location> {
        let DebugLoc { file_idx, start, end } = self.locations.get(idx)?;
        let file = &self.files[*file_idx];
        let uri = self.strings[file.path_idx].clone();
        Some(Location {
            uri: Uri::from(uri),
            start: *start,
            end: *end,
        })
    }

    /// Get access to the error messages table in this debug info
    pub fn error_messages(&self) -> &[DebugErrorMessage] {
        &self.error_messages
    }

    /// Returns the assertion error message for `err_code`, if present.
    pub fn error_message(&self, err_code: u64) -> Option<Arc<str>> {
        self.error_messages
            .iter()
            .find(|row| row.err_code == err_code)
            .map(|row| self.strings[row.message].clone())
    }

    /// Returns source/debug occurrence nodes.
    pub fn nodes(&self) -> &IndexVec<Src, SourceNode<Exec, Src>> {
        &self.nodes
    }

    /// Returns source/debug occurrence roots.
    pub fn roots(&self) -> &[Src] {
        &self.roots
    }

    /// Returns a source/debug occurrence by ID.
    pub fn source_node(&self, source_node: Src) -> Option<&SourceNode<Exec, Src>> {
        self.nodes.get(source_node)
    }

    /// Get access to the functions table in this debug info
    pub fn functions(&self) -> &[FunctionInfo<Src>] {
        self.functions.as_slice()
    }

    /// Gets the function info for `idx`
    pub fn get_function(&self, idx: DebugFunctionIdx) -> Option<&FunctionInfo<Src>> {
        self.functions.get(idx)
    }

    /// Returns all source/debug roots that point at `exec_node`.
    pub fn source_roots_for_exec_node(
        &self,
        exec_node: Exec,
    ) -> impl Iterator<Item = (Src, &SourceNode<Exec, Src>)> {
        self.roots.iter().copied().filter_map(move |source_node_id| {
            let source_node = &self.nodes[source_node_id];
            if source_node.exec_node == exec_node {
                Some((source_node_id, source_node))
            } else {
                None
            }
        })
    }

    /// Returns the unique source/debug root that points at `exec_node`.
    pub fn unique_source_root_for_exec_node(
        &self,
        exec_node: Exec,
    ) -> Result<Option<Src>, SourceGraphLookupError<Exec, Src>> {
        let mut roots = self
            .source_roots_for_exec_node(exec_node)
            .map(|(source_node_id, _)| source_node_id);
        let first = roots.next();
        if roots.next().is_some() {
            return Err(SourceGraphLookupError::AmbiguousRoot { exec_node });
        }
        Ok(first)
    }

    /// Returns `parent`'s source/debug child at `child_index`, if present.
    pub fn child_source_node(
        &self,
        parent: Src,
        child_index: usize,
    ) -> Result<Option<(Src, &SourceNode<Exec, Src>)>, SourceGraphLookupError<Exec, Src>> {
        let parent_node = self
            .source_node(parent)
            .ok_or(SourceGraphLookupError::MissingSourceNode { source_node: parent })?;
        let Some(child) = parent_node.children.get(child_index).copied() else {
            return Ok(None);
        };
        let child_node = self
            .source_node(child)
            .ok_or(SourceGraphLookupError::MissingSourceNode { source_node: child })?;

        Ok(Some((child, child_node)))
    }

    /// Returns assembly operation rows for a source/debug occurrence.
    pub fn asm_ops_for_source_node(
        &self,
        source_node: Src,
    ) -> impl Iterator<Item = &DebugSourceAsmOp> {
        self.source_node(source_node).into_iter().flat_map(|node| node.asm_ops.iter())
    }

    /// Returns the first assembly operation row for `source_node`, if present.
    pub fn first_asm_op_for_source_node(&self, source_node: Src) -> Option<&DebugSourceAsmOp> {
        self.asm_ops_for_source_node(source_node).min_by_key(|row| row.op_idx)
    }

    /// Returns the assembly operation row for `source_node` at or before `op_idx`, if present.
    pub fn asm_op_for_operation(&self, source_node: Src, op_idx: u32) -> Option<&DebugSourceAsmOp> {
        self.asm_ops_for_source_node(source_node)
            .filter(|row| row.op_idx <= op_idx)
            .max_by_key(|row| row.op_idx)
    }

    /// Returns debug variable rows for a source/debug occurrence.
    pub fn debug_vars_for_source_node(
        &self,
        source_node: Src,
    ) -> impl Iterator<Item = &DebugSourceVar> {
        self.source_node(source_node)
            .into_iter()
            .flat_map(|node| node.debug_vars.iter())
    }

    /// Returns debug variable rows for `source_node` at `op_idx`.
    pub fn debug_vars_for_operation(
        &self,
        source_node: Src,
        op_idx: u32,
    ) -> impl Iterator<Item = &DebugSourceVar> {
        self.debug_vars_for_source_node(source_node)
            .filter(move |row| row.op_idx == op_idx)
    }

    /// Returns inline-call rows for a source/debug occurrence.
    pub fn inline_calls_for_source_node(
        &self,
        source_node: Src,
    ) -> impl Iterator<Item = &DebugSourceInlineCall> {
        self.source_node(source_node)
            .into_iter()
            .flat_map(|node| node.inline_calls.iter())
    }

    /// Returns inline-call rows for `source_node` at `op_idx`.
    pub fn inline_calls_for_operation(
        &self,
        source_node: Src,
        op_idx: u32,
    ) -> impl Iterator<Item = &DebugSourceInlineCall> {
        self.inline_calls_for_source_node(source_node)
            .filter(move |row| row.op_idx == op_idx)
    }
}

impl<Src: SourceNodeIdMarker> DebugInfo<MastNodeId, Src> {
    /// Merges package-owned source/debug metadata after a [`miden_core::mast::MastForest`] merge.
    ///
    /// [`miden_core::mast::MastForest::merge`] remains execution-only. This helper applies the
    /// returned node mappings to package source/debug sections so callers can merge
    /// `(MastForest, PackageDebugInfo)` pairs without reattaching debug metadata to the forest.
    ///
    /// This also merges the type, source-file, and function tables referenced by source-map
    /// inline-call rows.
    pub fn merge_source_debug<'a>(
        inputs: impl IntoIterator<Item = (usize, &'a Self)>,
        root_map: &MastForestRootMap,
    ) -> Result<Self, DebugInfoMergeError<MastNodeId, Src>>
    where
        Src: 'a,
    {
        let mut inputs = inputs.into_iter();
        let Some((base_forest_index, base)) = inputs.next() else {
            return Ok(Default::default());
        };

        // Preserve the first input's table indices exactly so that subsequent inputs continue to
        // deduplicate strings, files, and locations against the base tables. Execution node IDs are
        // positional, however, so they must be remapped just like every later input.
        let mut base = base.clone();
        for source_node in base.nodes.iter_mut() {
            source_node.exec_node = root_map
                .map_node(base_forest_index, &source_node.exec_node)
                .ok_or(DebugInfoMergeError::MissingExecNodeMapping {
                    forest_index: base_forest_index,
                    exec_node: source_node.exec_node,
                })?;
        }

        let mut builder = DebugInfoBuilder::from(Box::new(base));

        for (forest_index, debug_info) in inputs {
            let mut remapped_strings = FxHashMap::<DebugStringIdx, DebugStringIdx>::default();
            for (i, string) in debug_info.strings.iter().enumerate() {
                let prev_index =
                    DebugStringIdx::from(u32::try_from(i).expect("invalid string table index"));
                let new_index = builder.add_string(string.clone());
                remapped_strings.insert(prev_index, new_index);
            }

            // Type records may contain forward or cyclic references. Reserve every output index
            // before rewriting any record, then append records without interning so that those
            // reserved indices remain stable. This mirrors the pre-consolidation merge behavior;
            // each input table is already internally uniqued by its builder.
            let type_offset = builder.debug_info().types.len();
            let mut remapped_types = FxHashMap::<DebugTypeIdx, DebugTypeIdx>::default();
            for i in 0..debug_info.types.len() {
                let prev_index =
                    DebugTypeIdx::from(u32::try_from(i).expect("invalid types table index"));
                let new_index = DebugTypeIdx::from(
                    u32::try_from(type_offset + i).expect("too many types after merging"),
                );
                remapped_types.insert(prev_index, new_index);
            }
            for (i, debug_type) in debug_info.types.iter().enumerate() {
                let prev_index =
                    DebugTypeIdx::from(u32::try_from(i).expect("invalid types table index"));
                let debug_type = remap_debug_type_info(
                    forest_index,
                    debug_type,
                    &remapped_strings,
                    &remapped_types,
                )?;
                let new_index = builder
                    .debug_info_mut()
                    .types
                    .push(debug_type)
                    .expect("too many types after merging");
                debug_assert_eq!(new_index, remapped_types[&prev_index]);
            }

            let mut remapped_files = FxHashMap::<DebugFileIdx, DebugFileIdx>::default();
            for (i, file) in debug_info.files.iter().enumerate() {
                let prev_index =
                    DebugFileIdx::from(u32::try_from(i).expect("invalid sources table index"));
                let path_idx = remapped_strings.get(&file.path_idx).copied().ok_or(
                    DebugInfoMergeError::MissingSourceStringMapping {
                        forest_index,
                        string_idx: file.path_idx,
                    },
                )?;
                let file = DebugFileInfo::new(path_idx)
                    .with_checksum(*file.checksum().unwrap_or(&DebugFileInfo::EMPTY_CHECKSUM));
                let new_index = builder.add_file_info(file);
                remapped_files.insert(prev_index, new_index);
            }

            let mut remapped_locations = FxHashMap::<DebugLocIdx, DebugLocIdx>::default();
            for (i, loc) in debug_info.locations.iter().enumerate() {
                let prev_index =
                    DebugLocIdx::from(u32::try_from(i).expect("invalid locations table index"));
                let file_idx = remapped_files.get(&loc.file_idx).copied().ok_or(
                    DebugInfoMergeError::MissingSourceFileMapping {
                        forest_index,
                        file_idx: loc.file_idx,
                    },
                )?;
                let loc = DebugLoc { file_idx, start: loc.start, end: loc.end };
                let new_index = if let Some(existing) =
                    builder.debug_info().locations.iter().position(|l| l == &loc)
                {
                    DebugLocIdx::from(existing as u32)
                } else {
                    builder.debug_info_mut().locations.push(loc).expect("too many locations")
                };
                remapped_locations.insert(prev_index, new_index);
            }

            for error_message in debug_info.error_messages() {
                let message = remapped_strings.get(&error_message.message).copied().ok_or(
                    DebugInfoMergeError::MissingSourceStringMapping {
                        forest_index,
                        string_idx: error_message.message,
                    },
                )?;
                builder.add_error_message_with_index(error_message.err_code, message);
            }

            let mut remapped_nodes = FxHashMap::<Src, Src>::default();
            let start_node_index = builder.debug_info().nodes().len();
            for i in 0..debug_info.nodes.len() {
                let prev_index = Src::from(u32::try_from(i).expect("too many nodes"));
                let new_index = Src::from(
                    u32::try_from(start_node_index + i).expect("too many nodes after merging"),
                );
                remapped_nodes.insert(prev_index, new_index);
            }

            for (i, source_node) in debug_info.nodes.iter().enumerate() {
                let prev_index = Src::from(u32::try_from(i).expect("too many nodes"));

                let exec_node = root_map.map_node(forest_index, &source_node.exec_node).ok_or(
                    DebugInfoMergeError::MissingExecNodeMapping {
                        forest_index,
                        exec_node: source_node.exec_node,
                    },
                )?;
                let children = source_node
                    .children
                    .iter()
                    .map(|child| {
                        remapped_nodes.get(child).copied().ok_or(
                            DebugInfoMergeError::MissingSourceNodeMapping {
                                forest_index,
                                source_node: *child,
                            },
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let mut asm_ops = Vec::with_capacity(source_node.asm_ops.len());
                for row in source_node.asm_ops.iter() {
                    let location_idx = row
                        .location_idx
                        .into_option()
                        .map(|location_idx| {
                            remapped_locations.get(&location_idx).copied().ok_or(
                                DebugInfoMergeError::MissingSourceLocationMapping {
                                    forest_index,
                                    location_idx,
                                },
                            )
                        })
                        .transpose()?;
                    let context_name_idx = remapped_strings
                        .get(&row.context_name_idx)
                        .copied()
                        .ok_or(DebugInfoMergeError::MissingSourceStringMapping {
                            forest_index,
                            string_idx: row.context_name_idx,
                        })?;
                    let op_name_idx = remapped_strings.get(&row.op_name_idx).copied().ok_or(
                        DebugInfoMergeError::MissingSourceStringMapping {
                            forest_index,
                            string_idx: row.op_name_idx,
                        },
                    )?;
                    asm_ops.push(DebugSourceAsmOp::new(
                        row.op_idx,
                        location_idx,
                        context_name_idx,
                        op_name_idx,
                        row.num_cycles,
                    ));
                }

                let mut debug_vars = Vec::with_capacity(source_node.debug_vars.len());
                for row in source_node.debug_vars.iter() {
                    let name_idx = remapped_strings.get(&row.name_idx).copied().ok_or(
                        DebugInfoMergeError::MissingSourceStringMapping {
                            forest_index,
                            string_idx: row.name_idx,
                        },
                    )?;

                    let location_idx = row
                        .location_idx
                        .map(|idx| {
                            remapped_locations.get(&idx).copied().ok_or(
                                DebugInfoMergeError::MissingSourceLocationMapping {
                                    forest_index,
                                    location_idx: idx,
                                },
                            )
                        })
                        .transpose()?;
                    debug_vars.push(DebugSourceVar {
                        op_idx: row.op_idx,
                        name_idx,
                        type_id: row.type_id,
                        arg_idx: row.arg_idx,
                        location_idx,
                        value_location: row.value_location.clone(),
                    });
                }
                let new_index = builder
                    .debug_info_mut()
                    .nodes
                    .push(SourceNode {
                        exec_node,
                        children,
                        op_start: source_node.op_start,
                        op_end: source_node.op_end,
                        asm_ops,
                        debug_vars,
                        inline_calls: Vec::with_capacity(source_node.inline_calls.len()),
                    })
                    .expect("too many nodes");
                debug_assert_eq!(new_index, remapped_nodes[&prev_index],);
            }

            for root in debug_info.roots().iter().copied() {
                builder.debug_info_mut().roots.push(remapped_nodes.get(&root).copied().ok_or(
                    DebugInfoMergeError::MissingSourceNodeMapping {
                        forest_index,
                        source_node: root,
                    },
                )?);
            }

            let mut remapped_functions = FxHashMap::<DebugFunctionIdx, DebugFunctionIdx>::default();
            for (i, function) in debug_info.functions.iter().enumerate() {
                let prev_index =
                    DebugFunctionIdx::from(u32::try_from(i).expect("too many functions"));

                let source_node = function
                    .source_node
                    .into_option()
                    .map(|id| {
                        remapped_nodes.get(&id).copied().ok_or(
                            DebugInfoMergeError::MissingSourceNodeMapping {
                                forest_index,
                                source_node: id,
                            },
                        )
                    })
                    .transpose()?;
                let name_idx = remapped_strings.get(&function.name_idx).copied().ok_or(
                    DebugInfoMergeError::MissingSourceStringMapping {
                        forest_index,
                        string_idx: function.name_idx,
                    },
                )?;
                let linkage_name_idx = function
                    .linkage_name_idx
                    .into_option()
                    .map(|idx| {
                        remapped_strings.get(&idx).copied().ok_or(
                            DebugInfoMergeError::MissingSourceStringMapping {
                                forest_index,
                                string_idx: idx,
                            },
                        )
                    })
                    .transpose()?;
                let file_idx = remapped_files.get(&function.file_idx).copied().ok_or(
                    DebugInfoMergeError::MissingSourceFileMapping {
                        forest_index,
                        file_idx: function.file_idx,
                    },
                )?;
                let type_idx = function
                    .type_idx
                    .into_option()
                    .map(|idx| remap_type_idx(forest_index, idx, &remapped_types))
                    .transpose()?;
                let new_index = builder
                    .debug_info_mut()
                    .functions
                    .push(FunctionInfo {
                        source_node: source_node.into(),
                        name_idx,
                        linkage_name_idx: linkage_name_idx.into(),
                        file_idx,
                        line: function.line,
                        column: function.column,
                        type_idx: type_idx.into(),
                        mast_root: function.mast_root,
                    })
                    .expect("too many functions");
                remapped_functions.insert(prev_index, new_index);
            }

            for (prev, new) in remapped_nodes.iter() {
                let source_node = debug_info.source_node(*prev).unwrap();
                if source_node.inline_calls.is_empty() {
                    continue;
                }
                let target_node = &mut builder[*new];
                for row in source_node.inline_calls.iter() {
                    let callee_idx = remapped_functions.get(&row.callee_idx).copied().ok_or(
                        DebugInfoMergeError::MissingFunctionMapping {
                            forest_index,
                            function_idx: row.callee_idx,
                        },
                    )?;
                    let loc_idx = remapped_locations.get(&row.loc_idx).copied().ok_or(
                        DebugInfoMergeError::MissingSourceLocationMapping {
                            forest_index,
                            location_idx: row.loc_idx,
                        },
                    )?;
                    target_node.inline_calls.push(DebugSourceInlineCall {
                        op_idx: row.op_idx,
                        callee_idx,
                        loc_idx,
                    });
                }
            }
        }

        Ok(*builder.build())
    }
}

fn remap_debug_type_info<Exec: Idx, Src: Idx>(
    forest_index: usize,
    ty: &DebugTypeInfo,
    string_map: &FxHashMap<DebugStringIdx, DebugStringIdx>,
    type_map: &FxHashMap<DebugTypeIdx, DebugTypeIdx>,
) -> Result<DebugTypeInfo, DebugInfoMergeError<Exec, Src>> {
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
                |forest_index, string_idx| DebugInfoMergeError::MissingTypeStringMapping {
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
                                DebugInfoMergeError::MissingTypeStringMapping {
                                    forest_index,
                                    string_idx,
                                }
                            },
                        )?,
                        type_idx: remap_type_idx(forest_index, field.type_idx, type_map)?,
                        offset: field.offset,
                    })
                })
                .collect::<Result<_, DebugInfoMergeError<Exec, Src>>>()?,
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
                |forest_index, string_idx| DebugInfoMergeError::MissingTypeStringMapping {
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
                                DebugInfoMergeError::MissingTypeStringMapping {
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
                .collect::<Result<_, DebugInfoMergeError<Exec, Src>>>()?,
        },
        DebugTypeInfo::Unknown => DebugTypeInfo::Unknown,
    })
}

fn remap_string_index<Exec: Idx, Src: Idx>(
    forest_index: usize,
    string_idx: DebugStringIdx,
    string_map: &FxHashMap<DebugStringIdx, DebugStringIdx>,
    error: impl FnOnce(usize, DebugStringIdx) -> DebugInfoMergeError<Exec, Src>,
) -> Result<DebugStringIdx, DebugInfoMergeError<Exec, Src>> {
    string_map
        .get(&string_idx)
        .copied()
        .ok_or_else(|| error(forest_index, string_idx))
}

fn remap_type_idx<Exec: Idx, Src: Idx>(
    forest_index: usize,
    type_idx: DebugTypeIdx,
    type_map: &FxHashMap<DebugTypeIdx, DebugTypeIdx>,
) -> Result<DebugTypeIdx, DebugInfoMergeError<Exec, Src>> {
    type_map
        .get(&type_idx)
        .copied()
        .ok_or(DebugInfoMergeError::MissingTypeMapping { forest_index, type_idx })
}
