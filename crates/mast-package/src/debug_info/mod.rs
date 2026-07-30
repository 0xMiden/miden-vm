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

use alloc::{sync::Arc, vec::Vec};

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

/// Index remapping produced when importing the shared tables of one [`DebugInfo`] into another.
///
/// Source nodes are intentionally excluded because their indices depend on how the caller maps or
/// filters the source graph.
#[derive(Clone, Debug, Default)]
pub struct DebugInfoTableRemapping {
    strings: IndexVec<DebugStringIdx, DebugStringIdx>,
    files: IndexVec<DebugFileIdx, DebugFileIdx>,
    locations: IndexVec<DebugLocIdx, DebugLocIdx>,
    types: IndexVec<DebugTypeIdx, DebugTypeIdx>,
    /// While function records link a source node, for purposes of remapping, we strip the source
    /// node information, and then restore it later when finalizing the debug info
    functions: IndexVec<DebugFunctionIdx, DebugFunctionIdx>,
}

impl DebugInfoTableRemapping {
    /// Returns the destination index for a source string index.
    pub fn string(&self, index: DebugStringIdx) -> Option<DebugStringIdx> {
        self.strings.get(index).copied()
    }

    /// Returns the destination index for a source file index.
    pub fn file(&self, index: DebugFileIdx) -> Option<DebugFileIdx> {
        self.files.get(index).copied()
    }

    /// Returns the destination index for a source location index.
    pub fn location(&self, index: DebugLocIdx) -> Option<DebugLocIdx> {
        self.locations.get(index).copied()
    }

    /// Returns the destination index for a source type index.
    pub fn ty(&self, index: DebugTypeIdx) -> Option<DebugTypeIdx> {
        self.types.get(index).copied()
    }

    /// Returns the destination index for a function index.
    pub fn function(&self, index: DebugFunctionIdx) -> Option<DebugFunctionIdx> {
        self.functions.get(index).copied()
    }
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

impl<Exec: Idx, Src: Idx> DebugInfo<Exec, Src> {
    /// Imports the shared string, type, file, location, and error-message tables into `target`.
    ///
    /// The returned map translates every source table index to its destination index. Type rows
    /// are reserved as a complete batch before their payloads are rewritten, which preserves
    /// forward and cyclic references. Functions are imported with their source-node associations
    /// cleared; callers which also import source nodes must restore those associations after
    /// establishing the source-node mapping.
    pub fn merge_tables_into<TargetExec: Idx, TargetSrc: Idx>(
        &self,
        target: &mut DebugInfoBuilder<TargetExec, TargetSrc>,
    ) -> Result<DebugInfoTableRemapping, DebugInfoTableRemapError> {
        // Validate the complete source first so that an error never leaves `target` partially
        // updated.
        self.validate_shared_table_references()?;

        let mut remapping = DebugInfoTableRemapping::default();

        for (index, string) in self.strings.iter().enumerate() {
            let source = DebugStringIdx::from(
                u32::try_from(index).expect("invalid source string table index"),
            );
            let inserted = remapping
                .strings
                .push(target.add_string(string.clone()))
                .expect("too many remapped strings");
            debug_assert_eq!(inserted, source);
        }

        // Reserve the complete output range before rewriting any type row. Types may contain
        // forward or cyclic references, so their mappings cannot be discovered incrementally.
        let type_offset = target.debug_info().types.len();
        for index in 0..self.types.len() {
            let source =
                DebugTypeIdx::from(u32::try_from(index).expect("invalid source type table index"));
            let destination = DebugTypeIdx::from(
                u32::try_from(type_offset + index).expect("too many types after merging"),
            );
            let inserted = remapping.types.push(destination).expect("too many remapped types");
            debug_assert_eq!(inserted, source);
        }
        for (index, ty) in self.types.iter().enumerate() {
            let source =
                DebugTypeIdx::from(u32::try_from(index).expect("invalid source type table index"));
            let ty = remap_debug_type_info(ty, &remapping.strings, &remapping.types)?;
            let destination = target.push_type(ty);
            debug_assert_eq!(destination, remapping.types[source]);
        }

        for (index, file) in self.files.iter().enumerate() {
            let source =
                DebugFileIdx::from(u32::try_from(index).expect("invalid source file table index"));
            let path_idx = remapping.string(file.path_idx).ok_or(
                DebugInfoTableRemapError::MissingSourceString { string_idx: file.path_idx },
            )?;
            let file = DebugFileInfo::new(path_idx)
                .with_checksum(*file.checksum().unwrap_or(&DebugFileInfo::EMPTY_CHECKSUM));
            let inserted = remapping
                .files
                .push(target.add_file_info(file))
                .expect("too many remapped files");
            debug_assert_eq!(inserted, source);
        }

        for (index, location) in self.locations.iter().enumerate() {
            let source = DebugLocIdx::from(
                u32::try_from(index).expect("invalid source location table index"),
            );
            let file_idx = remapping.file(location.file_idx).ok_or(
                DebugInfoTableRemapError::MissingSourceFile { file_idx: location.file_idx },
            )?;
            let location = DebugLoc {
                file_idx,
                start: location.start,
                end: location.end,
            };
            let inserted = remapping
                .locations
                .push(target.add_location_info(location))
                .expect("too many remapped locations");
            debug_assert_eq!(inserted, source);
        }

        for error_message in self.error_messages() {
            let message = remapping.string(error_message.message).ok_or(
                DebugInfoTableRemapError::MissingSourceString { string_idx: error_message.message },
            )?;
            target.add_error_message_with_index(error_message.err_code, message);
        }

        for (index, function) in self.functions().iter().enumerate() {
            let source = DebugFunctionIdx::from(
                u32::try_from(index).expect("invalid source function table index"),
            );
            let name_idx = remapping.string(function.name_idx).ok_or(
                DebugInfoTableRemapError::MissingSourceString { string_idx: function.name_idx },
            )?;
            let linkage_name_idx = function
                .linkage_name_idx
                .try_into_option()
                .map_err(|err| DebugInfoTableRemapError::InvalidOptionField {
                    context: "debug function linkage name",
                    err,
                })?
                .map(|index| {
                    remapping
                        .string(index)
                        .ok_or(DebugInfoTableRemapError::MissingSourceString { string_idx: index })
                })
                .transpose()?;
            let type_idx = function
                .type_idx
                .try_into_option()
                .map_err(|err| DebugInfoTableRemapError::InvalidOptionField {
                    context: "debug function type",
                    err,
                })?
                .map(|tid| {
                    remapping.ty(tid).ok_or(DebugInfoTableRemapError::MissingType { type_idx: tid })
                })
                .transpose()?;
            let file_idx = remapping.file(function.file_idx).ok_or(
                DebugInfoTableRemapError::MissingSourceFile { file_idx: function.file_idx },
            )?;
            let function_idx = target.add_function(FunctionInfo {
                mast_root: function.mast_root,
                source_node: None.into(),
                type_idx: type_idx.into(),
                linkage_name_idx: linkage_name_idx.into(),
                name_idx,
                file_idx,
                line: function.line,
                column: function.column,
            });
            let inserted =
                remapping.functions.push(function_idx).expect("too many remapped functions");
            debug_assert_eq!(inserted, source);
        }

        Ok(remapping)
    }

    fn validate_shared_table_references(&self) -> Result<(), DebugInfoTableRemapError> {
        for ty in self.types.iter() {
            validate_debug_type_info(ty, &self.strings, &self.types)?;
        }
        for file in self.files.iter() {
            if self.strings.get(file.path_idx).is_none() {
                return Err(DebugInfoTableRemapError::MissingSourceString {
                    string_idx: file.path_idx,
                });
            }
        }
        for location in self.locations.iter() {
            if self.files.get(location.file_idx).is_none() {
                return Err(DebugInfoTableRemapError::MissingSourceFile {
                    file_idx: location.file_idx,
                });
            }
        }
        for error_message in self.error_messages.iter() {
            if self.strings.get(error_message.message).is_none() {
                return Err(DebugInfoTableRemapError::MissingSourceString {
                    string_idx: error_message.message,
                });
            }
        }
        for function in self.functions.iter() {
            if self.files.get(function.file_idx).is_none() {
                return Err(DebugInfoTableRemapError::MissingSourceFile {
                    file_idx: function.file_idx,
                });
            }
            if let Some(tid) = function.type_idx.try_into_option().map_err(|err| {
                DebugInfoTableRemapError::InvalidOptionField { context: "debug function type", err }
            })? && self.types.get(tid).is_none()
            {
                return Err(DebugInfoTableRemapError::MissingType { type_idx: tid });
            }
            if self.strings.get(function.name_idx).is_none() {
                return Err(DebugInfoTableRemapError::MissingSourceString {
                    string_idx: function.name_idx,
                });
            }
            if let Some(linkage_name_idx) =
                function.linkage_name_idx.try_into_option().map_err(|err| {
                    DebugInfoTableRemapError::InvalidOptionField {
                        context: "debug function linkage name",
                        err,
                    }
                })?
                && self.strings.get(linkage_name_idx).is_none()
            {
                return Err(DebugInfoTableRemapError::MissingSourceString {
                    string_idx: linkage_name_idx,
                });
            }
        }
        Ok(())
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
        let mut builder = DebugInfoBuilder::default();
        for (forest_index, debug_info) in inputs {
            let tables = debug_info
                .merge_tables_into(&mut builder)
                .map_err(|error| table_remap_error(forest_index, error))?;

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
                        .try_into_option()
                        .map_err(|err| DebugInfoMergeError::InvalidOptionField {
                            forest_index,
                            context: "debug source assembly op location",
                            err,
                        })?
                        .map(|location_idx| {
                            tables.location(location_idx).ok_or(
                                DebugInfoMergeError::MissingSourceLocationMapping {
                                    forest_index,
                                    location_idx,
                                },
                            )
                        })
                        .transpose()?;
                    let context_name_idx = tables.string(row.context_name_idx).ok_or(
                        DebugInfoMergeError::MissingSourceStringMapping {
                            forest_index,
                            string_idx: row.context_name_idx,
                        },
                    )?;
                    let op_name_idx = tables.string(row.op_name_idx).ok_or(
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
                    let name_idx = tables.string(row.name_idx).ok_or(
                        DebugInfoMergeError::MissingSourceStringMapping {
                            forest_index,
                            string_idx: row.name_idx,
                        },
                    )?;

                    let location_idx = row
                        .location_idx
                        .map(|idx| {
                            tables.location(idx).ok_or(
                                DebugInfoMergeError::MissingSourceLocationMapping {
                                    forest_index,
                                    location_idx: idx,
                                },
                            )
                        })
                        .transpose()?;
                    let type_id = row
                        .type_id
                        .map(|idx| {
                            tables.ty(idx).ok_or(DebugInfoMergeError::MissingTypeMapping {
                                forest_index,
                                type_idx: idx,
                            })
                        })
                        .transpose()?;
                    debug_vars.push(DebugSourceVar {
                        op_idx: row.op_idx,
                        name_idx,
                        type_id,
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

            for (index, function) in debug_info.functions().iter().enumerate() {
                let Some(previous_source_node) =
                    function.source_node.try_into_option().map_err(|err| {
                        DebugInfoMergeError::InvalidOptionField {
                            forest_index,
                            context: "debug function source node",
                            err,
                        }
                    })?
                else {
                    continue;
                };
                let source_node = remapped_nodes.get(&previous_source_node).copied().ok_or(
                    DebugInfoMergeError::MissingSourceNodeMapping {
                        forest_index,
                        source_node: previous_source_node,
                    },
                )?;
                let previous_function = DebugFunctionIdx::from(
                    u32::try_from(index).expect("invalid source function table index"),
                );
                let function = tables.function(previous_function).ok_or(
                    DebugInfoMergeError::MissingFunctionMapping {
                        forest_index,
                        function_idx: previous_function,
                    },
                )?;
                builder.set_function_source_node(function, source_node);
            }

            for root in debug_info.roots().iter().copied() {
                builder.debug_info_mut().roots.push(remapped_nodes.get(&root).copied().ok_or(
                    DebugInfoMergeError::MissingSourceNodeMapping {
                        forest_index,
                        source_node: root,
                    },
                )?);
            }

            for (prev, new) in remapped_nodes.iter() {
                let source_node = debug_info.source_node(*prev).unwrap();
                if source_node.inline_calls.is_empty() {
                    continue;
                }
                let target_node = &mut builder[*new];
                for row in source_node.inline_calls.iter() {
                    let callee_idx = tables.function(row.callee_idx).ok_or(
                        DebugInfoMergeError::MissingFunctionMapping {
                            forest_index,
                            function_idx: row.callee_idx,
                        },
                    )?;
                    let loc_idx = tables.location(row.loc_idx).ok_or(
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

fn validate_debug_type_info(
    ty: &DebugTypeInfo,
    strings: &IndexVec<DebugStringIdx, Arc<str>>,
    types: &IndexVec<DebugTypeIdx, DebugTypeInfo>,
) -> Result<(), DebugInfoTableRemapError> {
    match ty {
        DebugTypeInfo::Primitive(_) | DebugTypeInfo::Unknown => {},
        DebugTypeInfo::Pointer { pointee_type_idx } => {
            validate_type_idx(*pointee_type_idx, types)?;
        },
        DebugTypeInfo::Array { element_type_idx, .. } => {
            validate_type_idx(*element_type_idx, types)?;
        },
        DebugTypeInfo::Struct { name_idx, fields, .. } => {
            validate_type_string(*name_idx, strings)?;
            for field in fields {
                validate_type_string(field.name_idx, strings)?;
                validate_type_idx(field.type_idx, types)?;
            }
        },
        DebugTypeInfo::Function { return_type_idx, param_type_indices } => {
            if let Some(return_type_idx) = return_type_idx {
                validate_type_idx(*return_type_idx, types)?;
            }
            for &param_type_idx in param_type_indices {
                validate_type_idx(param_type_idx, types)?;
            }
        },
        DebugTypeInfo::Enum {
            name_idx,
            discriminant_type_idx,
            variants,
            ..
        } => {
            validate_type_string(*name_idx, strings)?;
            validate_type_idx(*discriminant_type_idx, types)?;
            for variant in variants {
                validate_type_string(variant.name_idx, strings)?;
                if let Some(type_idx) = variant.type_idx {
                    validate_type_idx(type_idx, types)?;
                }
            }
        },
    }
    Ok(())
}

fn validate_type_string(
    string_idx: DebugStringIdx,
    strings: &IndexVec<DebugStringIdx, Arc<str>>,
) -> Result<(), DebugInfoTableRemapError> {
    if strings.get(string_idx).is_none() {
        Err(DebugInfoTableRemapError::MissingTypeString { string_idx })
    } else {
        Ok(())
    }
}

fn validate_type_idx(
    type_idx: DebugTypeIdx,
    types: &IndexVec<DebugTypeIdx, DebugTypeInfo>,
) -> Result<(), DebugInfoTableRemapError> {
    if types.get(type_idx).is_none() {
        Err(DebugInfoTableRemapError::MissingType { type_idx })
    } else {
        Ok(())
    }
}

fn remap_debug_type_info(
    ty: &DebugTypeInfo,
    string_map: &IndexVec<DebugStringIdx, DebugStringIdx>,
    type_map: &IndexVec<DebugTypeIdx, DebugTypeIdx>,
) -> Result<DebugTypeInfo, DebugInfoTableRemapError> {
    Ok(match ty {
        DebugTypeInfo::Primitive(primitive) => DebugTypeInfo::Primitive(*primitive),
        DebugTypeInfo::Pointer { pointee_type_idx } => DebugTypeInfo::Pointer {
            pointee_type_idx: remap_type_idx(*pointee_type_idx, type_map)?,
        },
        DebugTypeInfo::Array { element_type_idx, count } => DebugTypeInfo::Array {
            element_type_idx: remap_type_idx(*element_type_idx, type_map)?,
            count: *count,
        },
        DebugTypeInfo::Struct { name_idx, size, fields } => DebugTypeInfo::Struct {
            name_idx: remap_type_string(*name_idx, string_map)?,
            size: *size,
            fields: fields
                .iter()
                .map(|field| {
                    Ok(DebugFieldInfo {
                        name_idx: remap_type_string(field.name_idx, string_map)?,
                        type_idx: remap_type_idx(field.type_idx, type_map)?,
                        offset: field.offset,
                    })
                })
                .collect::<Result<_, DebugInfoTableRemapError>>()?,
        },
        DebugTypeInfo::Function { return_type_idx, param_type_indices } => {
            DebugTypeInfo::Function {
                return_type_idx: return_type_idx
                    .map(|idx| remap_type_idx(idx, type_map))
                    .transpose()?,
                param_type_indices: param_type_indices
                    .iter()
                    .map(|idx| remap_type_idx(*idx, type_map))
                    .collect::<Result<_, _>>()?,
            }
        },
        DebugTypeInfo::Enum {
            name_idx,
            size,
            discriminant_type_idx,
            variants,
        } => DebugTypeInfo::Enum {
            name_idx: remap_type_string(*name_idx, string_map)?,
            size: *size,
            discriminant_type_idx: remap_type_idx(*discriminant_type_idx, type_map)?,
            variants: variants
                .iter()
                .map(|variant| {
                    Ok(DebugVariantInfo {
                        name_idx: remap_type_string(variant.name_idx, string_map)?,
                        type_idx: variant
                            .type_idx
                            .map(|idx| remap_type_idx(idx, type_map))
                            .transpose()?,
                        payload_offset: variant.payload_offset,
                        discriminant: variant.discriminant,
                    })
                })
                .collect::<Result<_, DebugInfoTableRemapError>>()?,
        },
        DebugTypeInfo::Unknown => DebugTypeInfo::Unknown,
    })
}

fn remap_type_string(
    string_idx: DebugStringIdx,
    string_map: &IndexVec<DebugStringIdx, DebugStringIdx>,
) -> Result<DebugStringIdx, DebugInfoTableRemapError> {
    string_map
        .get(string_idx)
        .copied()
        .ok_or(DebugInfoTableRemapError::MissingTypeString { string_idx })
}

fn remap_type_idx(
    type_idx: DebugTypeIdx,
    type_map: &IndexVec<DebugTypeIdx, DebugTypeIdx>,
) -> Result<DebugTypeIdx, DebugInfoTableRemapError> {
    type_map
        .get(type_idx)
        .copied()
        .ok_or(DebugInfoTableRemapError::MissingType { type_idx })
}

fn table_remap_error<Exec: Idx, Src: Idx>(
    forest_index: usize,
    error: DebugInfoTableRemapError,
) -> DebugInfoMergeError<Exec, Src> {
    match error {
        DebugInfoTableRemapError::InvalidOptionField { context, err } => {
            DebugInfoMergeError::InvalidOptionField { forest_index, context, err }
        },
        DebugInfoTableRemapError::MissingTypeString { string_idx } => {
            DebugInfoMergeError::MissingTypeStringMapping { forest_index, string_idx }
        },
        DebugInfoTableRemapError::MissingType { type_idx } => {
            DebugInfoMergeError::MissingTypeMapping { forest_index, type_idx }
        },
        DebugInfoTableRemapError::MissingSourceString { string_idx } => {
            DebugInfoMergeError::MissingSourceStringMapping { forest_index, string_idx }
        },
        DebugInfoTableRemapError::MissingSourceFile { file_idx } => {
            DebugInfoMergeError::MissingSourceFileMapping { forest_index, file_idx }
        },
    }
}
