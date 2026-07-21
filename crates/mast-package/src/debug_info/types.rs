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

use alloc::vec::Vec;
use core::num::NonZeroU32;

use miden_core::{
    Word,
    mast::MastNodeId,
    operations::{AssemblyOp, DebugVarInfo, DebugVarLocation},
};
use miden_debug_types::{ByteIndex, ColumnNumber, LineNumber};
use miden_utils_indexing::{Idx, newtype_id};

use super::{DebugInfo, PackageDebugInfo, SourceNodeIdMarker};

// DEBUG SOURCE GRAPH LOOKUP ERROR
// ================================================================================================

/// Error returned when a caller needs a unique source/debug occurrence but the graph cannot supply
/// one.
pub type DebugSourceGraphLookupError = SourceGraphLookupError<MastNodeId, DebugSourceNodeId>;

/// Error returned when a caller needs a unique source/debug occurrence but the graph cannot supply
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SourceGraphLookupError<Exec: Idx, Src: Idx> {
    /// The requested parent source/debug occurrence is not present.
    #[error("source/debug occurrence {source_node:?} is not present")]
    MissingSourceNode { source_node: Src },
    /// Multiple source/debug roots point at the same executable MAST node.
    #[error("multiple source/debug roots point at executable MAST node {exec_node:?}")]
    AmbiguousRoot { exec_node: Exec },
}

// PACKAGE DEBUG INFO MERGE ERROR
// ================================================================================================

/// Error returned when package-owned source/debug metadata cannot be remapped after a
/// [`miden_core::mast::MastForest`] merge.
pub type PackageDebugInfoMergeError = DebugInfoMergeError<MastNodeId, DebugSourceNodeId>;

/// Error returned when package-owned source/debug metadata cannot be remapped after a
/// [`miden_core::mast::MastForest`] merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DebugInfoMergeError<Exec: Idx, Src: Idx> {
    /// The package has source-keyed metadata rows without a source graph to define source IDs.
    #[error("debug info for forest {forest_index} has source-map rows but no source graph")]
    SourceMapWithoutGraph { forest_index: usize },
    /// A source/debug occurrence points at an execution node that was not present in the merge map.
    #[error(
        "debug info for forest {forest_index} references execution node {exec_node:?}, which is not present in the merge map"
    )]
    MissingExecNodeMapping { forest_index: usize, exec_node: Exec },
    /// A source-keyed metadata row refers to a source/debug occurrence that was not present in the
    /// corresponding source graph.
    #[error(
        "debug info for forest {forest_index} references source/debug occurrence {source_node:?}, which is not present in the source graph"
    )]
    MissingSourceNodeMapping { forest_index: usize, source_node: Src },
    /// A debug type row refers to a string index that is not present in its type string table.
    #[error(
        "debug info for forest {forest_index} references type string index {string_idx}, which is not present in the type string table"
    )]
    MissingTypeStringMapping {
        forest_index: usize,
        string_idx: DebugStringIdx,
    },
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
    MissingSourceStringMapping {
        forest_index: usize,
        string_idx: DebugStringIdx,
    },

    /// A debug function or inline-call row refers to a source-file index that is not present in its
    /// source-file table.
    #[error(
        "debug info for forest {forest_index} references source file index {file_idx}, which is not present in the source file table"
    )]
    MissingSourceFileMapping {
        forest_index: usize,
        file_idx: DebugFileIdx,
    },
    #[error(
        "debug info for forest {forest_index} references source location index {location_idx}, which is not present in the location table"
    )]
    MissingSourceLocationMapping {
        forest_index: usize,
        location_idx: DebugLocIdx,
    },
    /// A debug function row refers to a string index that is not present in its function string
    /// table.
    #[error(
        "debug info for forest {forest_index} references function string index {string_idx}, which is not present in the function string table"
    )]
    MissingFunctionStringMapping {
        forest_index: usize,
        string_idx: DebugStringIdx,
    },
    /// A debug inline-call row refers to a function index that is not present in its function
    /// table.
    #[error(
        "debug info for forest {forest_index} references function index {function_idx}, which is not present in the function table"
    )]
    MissingFunctionMapping {
        forest_index: usize,
        function_idx: DebugFunctionIdx,
    },
}

newtype_id!(
    /// A strongly-typed index into the strings table of [`PackageDebugInfo`].
    ///
    /// This prevents accidental misuse of raw `u32` indices (e.g., using a string index
    /// where a type index is expected).
    pub struct DebugStringIdx;
);

newtype_id!(
    /// A strongly-typed index into the type table of [`PackageDebugInfo`].
    ///
    /// This prevents accidental misuse of raw `u32` indices (e.g., using a string index
    /// where a type index is expected).
    pub struct DebugTypeIdx;
);

newtype_id!(
    /// A strongly-typed index into the sources table of [`PackageDebugInfo`].
    ///
    /// This prevents accidental misuse of raw `u32` indices (e.g., using a string index
    /// where a type index is expected).
    pub struct DebugFileIdx;
);

newtype_id!(
    /// A strongly-typed index into the functions table of [`PackageDebugInfo`].
    ///
    /// This prevents accidental misuse of raw `u32` indices (e.g., using a string index
    /// where a type index is expected).
    pub struct DebugFunctionIdx;
);

newtype_id!(
    /// A strongly-typed index into the locations table of [`PackageDebugInfo`].
    ///
    /// This prevents accidental misuse of raw `u32` indices (e.g., using a string index
    /// where a type index is expected).
    pub struct DebugLocIdx;
);

newtype_id!(
    /// A strongly-typed index into the assembly source nodes table of [`PackageDebugInfo`].
    ///
    /// This prevents accidental misuse of raw `u32` indices (e.g., using a string index
    /// where a type index is expected).
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(transparent))]
    pub struct DebugSourceNodeId;
);

impl SourceNodeIdMarker for DebugSourceNodeId {}

// PACKAGE DEBUG INFO
// ================================================================================================

/// Trusted package-owned debug information decoded from well-known debug sections.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub struct DebugLoc {
    pub file_idx: DebugFileIdx,
    pub start: ByteIndex,
    pub end: ByteIndex,
}

// DEBUG SOURCE GRAPH SECTION
// ================================================================================================

/// A source/debug occurrence for code that produced an executable MAST node.
///
/// The `exec_node` field points into the package [`MastForest`](crate::MastForest) after executable
/// MAST reduction and deduplication. More than one [`DebugSourceNode`] may point at the same
/// `exec_node`: for example, two source procedures can compile to the same MAST root while still
/// carrying different source spans, assembly-op rows, or debug-variable rows. Consumers should
/// treat the [`DebugSourceNodeId`] as the identity of the source occurrence and use `exec_node`
/// only to find the executable node it describes.
///
/// Assembly-operation, variable, and inline-call rows are stored directly on each source
/// occurrence.
pub type DebugSourceNode = SourceNode<MastNodeId, DebugSourceNodeId>;

/// A source/debug occurrence for code that produced an executable MAST node.
///
/// Indexed by a given execution node index, with children indexed by the given source node index
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceNode<Exec: Idx, Src: Idx> {
    /// The executable MAST node represented by this source occurrence.
    pub exec_node: Exec,
    /// Child source occurrences, in the same order as the executable node's children.
    pub children: Vec<Src>,
    /// Inclusive start operation index in the executable node.
    pub op_start: u32,
    /// Exclusive end operation index in the executable node.
    pub op_end: u32,
    /// Operation metadata for operations attached to this node
    pub asm_ops: Vec<DebugSourceAsmOp>,
    /// Debug variable metadata for operations attached to this node
    pub debug_vars: Vec<DebugSourceVar>,
    /// Inline-call metadata for operations attached to this node
    pub inline_calls: Vec<DebugSourceInlineCall>,
}

impl<Exec: Idx, Src: Idx> SourceNode<Exec, Src> {
    pub fn asm_op_for_operation(&self, op_idx: u32) -> Option<&DebugSourceAsmOp> {
        self.asm_ops
            .iter()
            .filter(|row| row.op_idx <= op_idx)
            .max_by_key(|row| row.op_idx)
    }

    pub fn debug_vars_for_operation(
        &self,
        op_idx: u32,
    ) -> impl Iterator<Item = &DebugSourceVar> + '_ {
        self.debug_vars.iter().filter(move |row| row.op_idx == op_idx)
    }

    pub fn debug_infos_for_operation(
        &self,
        op_idx: u32,
        debug_info: &DebugInfo<Exec, Src>,
    ) -> impl Iterator<Item = DebugVarInfo> {
        self.debug_vars_for_operation(op_idx).map(|source_var| {
            let name = debug_info[source_var.name_idx].clone();
            let mut info = DebugVarInfo::new(name, source_var.value_location.clone());
            if let Some(arg_idx) = source_var.arg_idx {
                info.set_arg_index(arg_idx.get())
            }
            if let Some(loc) = source_var.location_idx {
                info.set_location(debug_info.get_location(loc).unwrap())
            }
            if let Some(tid) = source_var.type_id {
                info.set_type_id(tid)
            }
            info
        })
    }
}

/// Assembly operation metadata keyed by a source/debug MAST occurrence.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct DebugSourceAsmOp {
    /// Operation index local to the reduced execution node.
    pub op_idx: u32,
    /// Source location index in the locations table
    pub location_idx: Option<DebugLocIdx>,
    /// Assembly context name index in the strings table
    pub context_name_idx: DebugStringIdx,
    /// Assembly operation text index in the strings table
    pub op_name_idx: DebugStringIdx,
    /// Number of VM cycles taken by the operation.
    pub num_cycles: u8,
}

impl DebugSourceAsmOp {
    pub fn to_assembly_op(&self, debug_info: &PackageDebugInfo) -> AssemblyOp {
        let location = self.location_idx.and_then(|loc| debug_info.get_location(loc));
        let context_name = debug_info[self.context_name_idx].clone();
        let op = debug_info[self.op_name_idx].clone();
        AssemblyOp::new(location, context_name, self.num_cycles, op)
    }
}

/// Debug variable metadata keyed by a source/debug MAST occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugSourceVar {
    /// Operation index local to the reduced execution node.
    pub op_idx: u32,
    /// Variable name as it appears in source code.
    pub name_idx: DebugStringIdx,
    /// Type information (encoded as type index in debug_info section)
    ///
    /// We do not use DebugTypeIdx here, as currently the relationship between this value
    /// and the `types` table in the debug info is indirect
    pub type_id: Option<u32>,
    /// If this is a function parameter, its 1-based index.
    pub arg_idx: Option<NonZeroU32>,
    /// Source file location (file:line:column).
    /// This should only be set when the location differs from the AssemblyOp location associated
    /// with the same instruction, to avoid package bloat.
    pub location_idx: Option<DebugLocIdx>,
    /// Where to find the variable's value at this point
    pub value_location: DebugVarLocation,
}

/// Inline-call metadata keyed by a source/debug MAST occurrence.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct DebugSourceInlineCall {
    /// Operation index local to the reduced execution node.
    pub op_idx: u32,
    /// Inlined callee function index in the debug functions table.
    pub callee_idx: DebugFunctionIdx,
    /// Call-site source location index in the debug locations table.
    pub loc_idx: DebugLocIdx,
}

// DEBUG ERROR MESSAGES
// ================================================================================================

/// Assertion error message keyed by its runtime error code.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct DebugErrorMessage {
    /// Runtime error code emitted by the assembled assertion operation.
    pub err_code: u64,
    /// String table index of the error message content
    pub message: DebugStringIdx,
}

// DEBUG TYPE INFO
// ================================================================================================

/// Type information for debug purposes.
///
/// This encodes the type of a variable or expression, enabling debuggers to properly
/// display values on the stack or in memory.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
        name_idx: DebugStringIdx,
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
        name_idx: DebugStringIdx,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct DebugFieldInfo {
    /// Name of the field (index into string table)
    pub name_idx: DebugStringIdx,
    /// Type of the field (index into type table)
    pub type_idx: DebugTypeIdx,
    /// Byte offset within the struct
    pub offset: u32,
}

/// Variant information within an enum type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct DebugVariantInfo {
    /// Name of the variant (index into string table).
    pub name_idx: DebugStringIdx,
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
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct DebugFileInfo {
    /// Full path to the source file (index into string table).
    pub path_idx: DebugStringIdx,
    /// Optional checksum of the file content for verification.
    ///
    /// When present, debuggers can use this to verify that the source file on disk
    /// matches the version used during compilation.
    ///
    /// Boxed to reduce the size of `DebugFileInfo` when checksums are not used.
    pub(super) checksum: [u8; 32],
}

impl DebugFileInfo {
    pub(crate) const EMPTY_CHECKSUM: [u8; 32] = [0u8; 32];

    /// Creates a new file info with a path.
    pub fn new(path_idx: DebugStringIdx) -> Self {
        Self { path_idx, checksum: Self::EMPTY_CHECKSUM }
    }

    /// Sets the checksum.
    pub fn with_checksum(mut self, checksum: [u8; 32]) -> Self {
        self.checksum = checksum;
        self
    }

    pub fn checksum(&self) -> Option<&[u8; 32]> {
        if self.checksum == Self::EMPTY_CHECKSUM {
            None
        } else {
            Some(&self.checksum)
        }
    }
}

// DEBUG FUNCTION INFO
// ================================================================================================

/// Debug information for a function.
///
/// Links source-level function information to the compiled MAST representation.
pub type DebugFunctionInfo = FunctionInfo<DebugSourceNodeId>;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct FunctionInfo<N: Idx> {
    /// The source occurrance this function is linked to, if known
    pub source_node: Option<N>,
    /// Name of the function (index into string table)
    pub name_idx: DebugStringIdx,
    /// Linkage name / mangled name (index into string table, optional)
    pub linkage_name_idx: Option<DebugStringIdx>,
    /// File containing this function (index into file table)
    pub file_idx: DebugFileIdx,
    /// Line number where the function starts (1-indexed)
    pub line: LineNumber,
    /// Column number where the function starts (1-indexed)
    pub column: ColumnNumber,
    /// Type of this function (index into type table, optional)
    pub type_idx: Option<DebugTypeIdx>,
    /// MAST root digest of this function.
    ///
    /// This links the debug info to the compiled code if `source_node` is unknown
    pub mast_root: Word,
}

impl<N: Idx> FunctionInfo<N> {
    /// Creates a new function info.
    pub fn new(
        source_node: Option<N>,
        name_idx: DebugStringIdx,
        file_idx: DebugFileIdx,
        line: LineNumber,
        column: ColumnNumber,
        mast_root: Word,
    ) -> Self {
        Self {
            source_node,
            name_idx,
            linkage_name_idx: None,
            file_idx,
            line,
            column,
            type_idx: None,
            mast_root,
        }
    }

    /// Sets the linkage name.
    pub fn with_linkage_name(mut self, linkage_name_idx: DebugStringIdx) -> Self {
        self.linkage_name_idx = Some(linkage_name_idx);
        self
    }

    /// Sets the type index.
    pub fn with_type(mut self, type_idx: DebugTypeIdx) -> Self {
        self.type_idx = Some(type_idx);
        self
    }
}

#[cfg(test)]
impl PackageDebugInfo {
    /// Corrupts a decoded file-table reference so package validation tests can exercise invalid
    /// serialized input that the public builder intentionally refuses to construct.
    pub(crate) fn set_file_path_index_for_test(
        &mut self,
        file_idx: DebugFileIdx,
        path_idx: DebugStringIdx,
    ) {
        self.files[file_idx].path_idx = path_idx;
    }

    /// Corrupts a decoded location-table reference for package validation tests.
    pub(crate) fn set_location_file_index_for_test(
        &mut self,
        location_idx: DebugLocIdx,
        file_idx: DebugFileIdx,
    ) {
        self.locations[location_idx].file_idx = file_idx;
    }

    /// Corrupts an error-message string reference for package validation tests.
    pub(crate) fn set_error_message_index_for_test(
        &mut self,
        message_idx: usize,
        string_idx: DebugStringIdx,
    ) {
        self.error_messages[message_idx].message = string_idx;
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use miden_debug_types::{ByteIndex, Location, Uri};

    use super::*;
    use crate::debug_info::PackageDebugInfoBuilder;

    fn source_node(
        exec_node: MastNodeId,
        children: Vec<DebugSourceNodeId>,
        op_start: u32,
        op_end: u32,
    ) -> DebugSourceNode {
        DebugSourceNode {
            exec_node,
            children,
            op_start,
            op_end,
            asm_ops: Vec::new(),
            debug_vars: Vec::new(),
            inline_calls: Vec::new(),
        }
    }

    #[test]
    fn file_uri_lookup_uses_the_stored_representation() {
        let mut builder = PackageDebugInfoBuilder::default();
        let uri = Uri::new("file:///src/main.masm");
        let file_idx = builder.add_file(uri.clone(), None);

        assert_eq!(builder.get_file_index_by_uri(&uri), Some(file_idx));

        let debug_info = builder.build();
        assert_eq!(debug_info.get_file_index_by_uri(&uri), Some(file_idx));
    }

    #[test]
    fn trimming_file_paths_does_not_mutate_shared_strings() {
        let absolute_path: Arc<str> = Arc::from("/workspace/src/main.masm");
        let trimmed_path: Arc<str> = Arc::from("src/main.masm");
        let mut builder = PackageDebugInfoBuilder::default();
        let file_a = builder.add_file(Uri::from(absolute_path.clone()), None);
        let file_b = builder.add_file(Uri::from(absolute_path.clone()), Some([1; 32]));
        let trimmed_path_idx = builder.add_string(trimmed_path.clone());
        assert!(builder.add_error_message(7, absolute_path.clone()));
        let mut debug_info = *builder.build();
        let mut trim_calls = 0;

        debug_info.trim_file_paths(|path| {
            trim_calls += 1;
            assert_eq!(path, absolute_path.as_ref());
            Some(trimmed_path.clone())
        });

        assert_eq!(trim_calls, 1, "a shared file path should only be trimmed once");
        assert_eq!(debug_info[file_a].path_idx, trimmed_path_idx);
        assert_eq!(debug_info[file_b].path_idx, trimmed_path_idx);
        assert_eq!(debug_info.error_message(7).as_deref(), Some(absolute_path.as_ref()));
        assert_eq!(debug_info.strings().len(), 2, "the existing trimmed string should be reused");
    }

    #[test]
    fn test_debug_source_map_inline_calls_are_keyed_by_source_operation() {
        let inline_a = DebugSourceInlineCall {
            op_idx: 3,
            callee_idx: DebugFunctionIdx::from(0),
            loc_idx: DebugLocIdx::from(0),
        };
        let inline_b = DebugSourceInlineCall {
            op_idx: 3,
            callee_idx: DebugFunctionIdx::from(1),
            loc_idx: DebugLocIdx::from(0),
        };
        let mut builder = PackageDebugInfoBuilder::default();
        let mut node_a = source_node(MastNodeId::new_unchecked(0), Vec::new(), 0, 4);
        node_a.inline_calls.push(inline_a);
        let source_a = builder.add_node(node_a).unwrap();
        let mut node_b = source_node(MastNodeId::new_unchecked(1), Vec::new(), 0, 4);
        node_b.inline_calls.push(inline_b);
        let source_b = builder.add_node(node_b).unwrap();
        let debug_info = builder.build();

        assert_eq!(
            debug_info.inline_calls_for_source_node(source_a).collect::<Vec<_>>(),
            vec![&inline_a]
        );
        assert_eq!(
            debug_info.inline_calls_for_source_node(source_b).collect::<Vec<_>>(),
            vec![&inline_b]
        );
        assert_eq!(
            debug_info.inline_calls_for_operation(source_a, 3).collect::<Vec<_>>(),
            vec![&inline_a],
        );
        assert!(debug_info.inline_calls_for_operation(source_a, 4).next().is_none());
    }

    #[test]
    fn test_package_source_debug_merge_remaps_execution_nodes_without_collapsing_sources() {
        use miden_core::{
            mast::{BasicBlockNodeBuilder, DenseMastForestBuilder, MastForest},
            operations::{DebugVarLocation, Operation},
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
            let mut builder = PackageDebugInfoBuilder::default();
            let source_node = DebugSourceNodeId::from(0);
            let uri = Uri::new(alloc::format!("{context}.masm"));
            let file_idx = builder.add_file(uri.clone(), None);
            let loc_idx =
                builder.add_location(Location::new(uri, ByteIndex::new(8), ByteIndex::new(9)));
            let name_idx = builder.add_string(Arc::from(alloc::format!("{context}_callee")));
            let callee_idx = builder.add_function(DebugFunctionInfo::new(
                Some(source_node),
                name_idx,
                file_idx,
                LineNumber::new(7).unwrap(),
                ColumnNumber::new(3).unwrap(),
                Word::default(),
            ));
            let context_name_idx = builder.add_string(context);
            let op_name_idx = builder.add_string("add");
            let var_name_idx = builder.add_string(var_name);
            let node = DebugSourceNode {
                exec_node: block,
                children: Vec::new(),
                op_start: 0,
                op_end: 1,
                asm_ops: vec![DebugSourceAsmOp {
                    op_idx: 0,
                    location_idx: None,
                    context_name_idx,
                    op_name_idx,
                    num_cycles: 1,
                }],
                debug_vars: vec![DebugSourceVar {
                    op_idx: 0,
                    name_idx: var_name_idx,
                    type_id: None,
                    arg_idx: None,
                    location_idx: None,
                    value_location: DebugVarLocation::Stack(0),
                }],
                inline_calls: vec![DebugSourceInlineCall { op_idx: 0, callee_idx, loc_idx }],
            };
            assert_eq!(builder.add_node(node).unwrap(), source_node);
            builder.add_root(source_node);
            *builder.build()
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
        assert_eq!(merged_debug.nodes().len(), 2);
        assert_eq!(merged_debug.roots().len(), 2);
        assert!(merged_debug.nodes().iter().all(|node| node.exec_node == merged_a));

        let source_a = merged_debug.roots()[0];
        let source_b = merged_debug.roots()[1];
        assert_ne!(source_a, source_b);
        assert_eq!(
            merged_debug
                [merged_debug.first_asm_op_for_source_node(source_a).unwrap().context_name_idx]
                .as_ref(),
            "alias_a",
        );
        assert_eq!(
            merged_debug
                [merged_debug.first_asm_op_for_source_node(source_b).unwrap().context_name_idx]
                .as_ref(),
            "alias_b",
        );
        assert_eq!(
            merged_debug
                .debug_vars_for_operation(source_a, 0)
                .map(|row| merged_debug[row.name_idx].as_ref())
                .collect::<Vec<_>>(),
            alloc::vec!["x"],
        );
        assert_eq!(
            merged_debug
                .debug_vars_for_operation(source_b, 0)
                .map(|row| merged_debug[row.name_idx].as_ref())
                .collect::<Vec<_>>(),
            alloc::vec!["y"],
        );
        let inline_a = merged_debug.inline_calls_for_operation(source_a, 0).collect::<Vec<_>>();
        let inline_b = merged_debug.inline_calls_for_operation(source_b, 0).collect::<Vec<_>>();
        assert_eq!(inline_a.len(), 1);
        assert_eq!(inline_b.len(), 1);

        let call_loc_a = merged_debug.locations()[inline_a[0].loc_idx];
        let function_a = merged_debug.get_function(inline_a[0].callee_idx).unwrap();
        let file_a = merged_debug.get_file(function_a.file_idx).unwrap();
        let path_a = merged_debug.get_string(file_a.path_idx).unwrap();
        let function_name_a = merged_debug.get_string(function_a.name_idx).unwrap();
        assert_eq!(path_a.as_ref(), "alias_a.masm");
        assert_eq!(function_name_a.as_ref(), "alias_a_callee");
        assert_eq!(function_a.file_idx, call_loc_a.file_idx);

        let call_loc_b = merged_debug.locations()[inline_b[0].loc_idx];
        let function_b = merged_debug.get_function(inline_b[0].callee_idx).unwrap();
        let file_b = merged_debug.get_file(function_b.file_idx).unwrap();
        let path_b = merged_debug.get_string(file_b.path_idx).unwrap();
        let function_name_b = merged_debug.get_string(function_b.name_idx).unwrap();
        assert_eq!(path_b.as_ref(), "alias_b.masm");
        assert_eq!(function_name_b.as_ref(), "alias_b_callee");
        assert_eq!(function_b.file_idx, call_loc_b.file_idx);
    }

    #[test]
    fn test_package_source_debug_merge_remaps_first_input_execution_nodes() {
        use miden_core::{
            mast::{
                BasicBlockNodeBuilder, DenseMastForestBuilder, ExternalNodeBuilder, MastForest,
            },
            operations::Operation,
        };

        let mut source_builder = DenseMastForestBuilder::new();
        let block = source_builder
            .push_node(BasicBlockNodeBuilder::new(alloc::vec![Operation::Add]))
            .unwrap();
        source_builder.mark_root(block);
        let (source_forest, source_remapping) = source_builder.finish_with_id_map().unwrap();
        let block = source_remapping.get(block).unwrap();

        // External nodes are finalized before basic blocks, forcing the first forest's block ID to
        // move in the merged forest.
        let mut other_builder = DenseMastForestBuilder::new();
        let external = other_builder.push_node(ExternalNodeBuilder::new(Word::default())).unwrap();
        other_builder.mark_root(external);
        let (other_forest, _) = other_builder.finish_with_id_map().unwrap();

        let (_merged_forest, root_map) =
            MastForest::merge([&source_forest, &other_forest]).unwrap();
        let merged_block = root_map.map_node(0, &block).unwrap();
        assert_ne!(merged_block, block, "test setup must renumber the first forest's block");

        let mut debug_builder = PackageDebugInfoBuilder::default();
        let source_root = debug_builder.add_node(source_node(block, Vec::new(), 0, 1)).unwrap();
        debug_builder.add_root(source_root);
        let debug_info = debug_builder.build();

        let merged_debug =
            PackageDebugInfo::merge_source_debug([(0, debug_info.as_ref())], &root_map).unwrap();

        assert_eq!(merged_debug[source_root].exec_node, merged_block);
    }

    #[test]
    fn test_package_source_debug_merge_supports_forward_and_cyclic_type_references() {
        use miden_core::mast::MastForestRootMap;

        let mut base_builder = PackageDebugInfoBuilder::default();
        let base_type = base_builder.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U8));
        assert_eq!(base_type, DebugTypeIdx::from(0));
        let base = base_builder.build();

        let mut cyclic_builder = PackageDebugInfoBuilder::default();
        let first = cyclic_builder
            .add_type(DebugTypeInfo::Pointer { pointee_type_idx: DebugTypeIdx::from(1) });
        let second = cyclic_builder
            .add_type(DebugTypeInfo::Pointer { pointee_type_idx: DebugTypeIdx::from(0) });
        assert_eq!(first, DebugTypeIdx::from(0));
        assert_eq!(second, DebugTypeIdx::from(1));
        let cyclic = cyclic_builder.build();

        let merged = PackageDebugInfo::merge_source_debug(
            [(0, base.as_ref()), (1, cyclic.as_ref())],
            &MastForestRootMap::default(),
        )
        .unwrap();

        let merged_first = DebugTypeIdx::from(1);
        let merged_second = DebugTypeIdx::from(2);
        assert_eq!(
            merged[merged_first],
            DebugTypeInfo::Pointer { pointee_type_idx: merged_second }
        );
        assert_eq!(
            merged[merged_second],
            DebugTypeInfo::Pointer { pointee_type_idx: merged_first }
        );
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

        let mut debug_builder = PackageDebugInfoBuilder::default();
        let context_name_idx = debug_builder.add_string("callee");
        let op_name_idx = debug_builder.add_string("add");
        let mut child = source_node(callee, Vec::new(), 0, 1);
        child.asm_ops.push(DebugSourceAsmOp {
            op_idx: 0,
            location_idx: None,
            context_name_idx,
            op_name_idx,
            num_cycles: 1,
        });
        let child_source = debug_builder.add_node(child).unwrap();
        let root_source =
            debug_builder.add_node(source_node(call, vec![child_source], 0, 1)).unwrap();
        debug_builder.add_root(root_source);
        let debug_info = debug_builder.build();

        let (_merged_forest, root_map) = MastForest::merge([&forest]).unwrap();
        let merged_callee = root_map.map_node(0, &callee).unwrap();

        let merged_debug =
            PackageDebugInfo::merge_source_debug([(0, debug_info.as_ref())], &root_map).unwrap();
        let merged_child =
            merged_debug.child_source_node(merged_debug.roots()[0], 0).unwrap().unwrap().0;
        assert_eq!(merged_debug[merged_child].exec_node, merged_callee);
        assert_eq!(
            merged_debug[merged_debug
                .first_asm_op_for_source_node(merged_child)
                .unwrap()
                .context_name_idx]
                .as_ref(),
            "callee",
        );
    }

    #[test]
    fn test_source_debug_lookup_uses_source_node_identity() {
        let exec_node = MastNodeId::new_unchecked(7);
        let mut builder = PackageDebugInfoBuilder::default();
        let add_idx = builder.add_string("add");
        let mul_idx = builder.add_string("mul");
        let alias_a_idx = builder.add_string("alias_a");
        let alias_b_idx = builder.add_string("alias_b");
        let alias_b_later_idx = builder.add_string("alias_b_later");
        let x_idx = builder.add_string("x");
        let y_idx = builder.add_string("y");
        let mut node_a = source_node(exec_node, Vec::new(), 0, 1);
        node_a.asm_ops.push(DebugSourceAsmOp {
            op_idx: 0,
            location_idx: None,
            context_name_idx: alias_a_idx,
            op_name_idx: add_idx,
            num_cycles: 1,
        });
        node_a.debug_vars.push(DebugSourceVar {
            op_idx: 0,
            name_idx: x_idx,
            type_id: None,
            arg_idx: None,
            location_idx: None,
            value_location: DebugVarLocation::Stack(0),
        });
        let source_a = builder.add_node(node_a).unwrap();
        let mut node_b = source_node(exec_node, Vec::new(), 0, 3);
        node_b.asm_ops.extend([
            DebugSourceAsmOp {
                op_idx: 0,
                location_idx: None,
                context_name_idx: alias_b_idx,
                op_name_idx: add_idx,
                num_cycles: 1,
            },
            DebugSourceAsmOp {
                op_idx: 2,
                location_idx: None,
                context_name_idx: alias_b_later_idx,
                op_name_idx: mul_idx,
                num_cycles: 1,
            },
        ]);
        node_b.debug_vars.push(DebugSourceVar {
            op_idx: 0,
            name_idx: y_idx,
            type_id: None,
            arg_idx: None,
            location_idx: None,
            value_location: DebugVarLocation::Stack(1),
        });
        let source_b = builder.add_node(node_b).unwrap();
        builder.add_root(source_a);
        builder.add_root(source_b);
        let debug_info = builder.build();

        assert_eq!(debug_info.nodes().iter().filter(|node| node.exec_node == exec_node).count(), 2);
        assert_eq!(debug_info.source_node(source_a).unwrap().exec_node, exec_node);
        let asm_a = debug_info.asm_op_for_operation(source_a, 0).unwrap();
        let asm_b = debug_info.asm_op_for_operation(source_b, 0).unwrap();
        assert_eq!(debug_info[asm_a.context_name_idx].as_ref(), "alias_a");
        assert_eq!(debug_info[asm_b.context_name_idx].as_ref(), "alias_b");
        assert_eq!(
            debug_info[debug_info.first_asm_op_for_source_node(source_b).unwrap().context_name_idx]
                .as_ref(),
            "alias_b",
        );
        let vars_b = debug_info.debug_vars_for_operation(source_b, 0).collect::<Vec<_>>();
        assert_eq!(vars_b.len(), 1);
        assert_eq!(debug_info[vars_b[0].name_idx].as_ref(), "y");
    }

    #[test]
    fn test_source_graph_navigation_uses_child_indices() {
        let root_exec = MastNodeId::new_unchecked(7);
        let child_exec = MastNodeId::new_unchecked(8);
        let other_exec = MastNodeId::new_unchecked(9);
        let mut builder = PackageDebugInfoBuilder::default();
        let child_a = builder.add_node(source_node(child_exec, Vec::new(), 0, 1)).unwrap();
        let child_b = builder.add_node(source_node(child_exec, Vec::new(), 0, 1)).unwrap();
        let root = builder.add_node(source_node(root_exec, vec![child_a, child_b], 0, 1)).unwrap();
        let other_root = builder.add_node(source_node(root_exec, Vec::new(), 0, 1)).unwrap();
        builder.add_root(root);

        assert_eq!(
            builder.debug_info().unique_source_root_for_exec_node(root_exec).unwrap(),
            Some(root)
        );
        assert_eq!(
            builder.debug_info().unique_source_root_for_exec_node(other_exec).unwrap(),
            None
        );
        assert_eq!(builder.debug_info().child_source_node(root, 0).unwrap().unwrap().0, child_a);
        assert_eq!(builder.debug_info().child_source_node(root, 1).unwrap().unwrap().0, child_b);
        assert!(builder.debug_info().child_source_node(root, 2).unwrap().is_none());
        assert_eq!(
            builder.debug_info().child_source_node(DebugSourceNodeId::from(99), 0),
            Err(DebugSourceGraphLookupError::MissingSourceNode {
                source_node: DebugSourceNodeId::from(99),
            }),
        );

        builder.add_root(other_root);
        let package_debug = builder.build();
        assert_eq!(
            package_debug.unique_source_root_for_exec_node(root_exec),
            Err(DebugSourceGraphLookupError::AmbiguousRoot { exec_node: root_exec }),
        );
        assert_eq!(package_debug.child_source_node(root, 1).unwrap().unwrap().0, child_b);
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
