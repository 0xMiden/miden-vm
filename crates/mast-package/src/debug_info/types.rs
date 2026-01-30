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
//! Debuggers can use this information along with `DebugVar` decorators in the MAST
//! to provide source-level variable inspection, stepping, and call stack visualization.

use alloc::{string::String, vec::Vec};

use miden_debug_types::{ColumnNumber, LineNumber};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// DEBUG TYPES SECTION
// ================================================================================================

/// The version of the debug_types section format.
pub const DEBUG_TYPES_VERSION: u8 = 1;

/// Debug types section containing type definitions for a MASP package.
///
/// This section stores type information (primitives, structs, arrays, pointers,
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
    pub strings: Vec<String>,
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
    pub fn add_string(&mut self, s: impl Into<String>) -> u32 {
        let s = s.into();
        if let Some(idx) = self.strings.iter().position(|existing| existing == &s) {
            return idx as u32;
        }
        let idx = self.strings.len() as u32;
        self.strings.push(s);
        idx
    }

    /// Gets a string by index.
    pub fn get_string(&self, idx: u32) -> Option<&str> {
        self.strings.get(idx as usize).map(String::as_str)
    }

    /// Adds a type to the type table and returns its index.
    pub fn add_type(&mut self, ty: DebugTypeInfo) -> u32 {
        let idx = self.types.len() as u32;
        self.types.push(ty);
        idx
    }

    /// Gets a type by index.
    pub fn get_type(&self, idx: u32) -> Option<&DebugTypeInfo> {
        self.types.get(idx as usize)
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
    pub strings: Vec<String>,
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
    pub fn add_string(&mut self, s: impl Into<String>) -> u32 {
        let s = s.into();
        if let Some(idx) = self.strings.iter().position(|existing| existing == &s) {
            return idx as u32;
        }
        let idx = self.strings.len() as u32;
        self.strings.push(s);
        idx
    }

    /// Gets a string by index.
    pub fn get_string(&self, idx: u32) -> Option<&str> {
        self.strings.get(idx as usize).map(String::as_str)
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
    pub strings: Vec<String>,
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
    pub fn add_string(&mut self, s: impl Into<String>) -> u32 {
        let s = s.into();
        if let Some(idx) = self.strings.iter().position(|existing| existing == &s) {
            return idx as u32;
        }
        let idx = self.strings.len() as u32;
        self.strings.push(s);
        idx
    }

    /// Gets a string by index.
    pub fn get_string(&self, idx: u32) -> Option<&str> {
        self.strings.get(idx as usize).map(String::as_str)
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
        pointee_type_idx: u32,
    },
    /// An array type
    Array {
        /// The element type (index into type table)
        element_type_idx: u32,
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
        return_type_idx: Option<u32>,
        /// Parameter types (indices into type table)
        param_type_indices: Vec<u32>,
    },
    /// An unknown or opaque type
    Unknown,
}

/// Primitive type variants supported by the debug info format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum DebugPrimitiveType {
    /// Void type (0 bytes)
    Void = 0,
    /// Boolean (1 byte)
    Bool = 1,
    /// Signed 8-bit integer
    I8 = 2,
    /// Unsigned 8-bit integer
    U8 = 3,
    /// Signed 16-bit integer
    I16 = 4,
    /// Unsigned 16-bit integer
    U16 = 5,
    /// Signed 32-bit integer
    I32 = 6,
    /// Unsigned 32-bit integer
    U32 = 7,
    /// Signed 64-bit integer
    I64 = 8,
    /// Unsigned 64-bit integer
    U64 = 9,
    /// Signed 128-bit integer
    I128 = 10,
    /// Unsigned 128-bit integer
    U128 = 11,
    /// 32-bit floating point
    F32 = 12,
    /// 64-bit floating point
    F64 = 13,
    /// Miden field element (64-bit, but with field semantics)
    Felt = 14,
    /// Miden word (4 field elements)
    Word = 15,
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
            Self::Word => 32,
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
            Self::I128 | Self::U128 | Self::Word => 4,
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
    pub type_idx: u32,
    /// Byte offset within the struct
    pub offset: u32,
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
    pub checksum: Option<[u8; 32]>,
}

impl DebugFileInfo {
    /// Creates a new file info with a path.
    pub fn new(path_idx: u32) -> Self {
        Self { path_idx, checksum: None }
    }

    /// Sets the checksum.
    pub fn with_checksum(mut self, checksum: [u8; 32]) -> Self {
        self.checksum = Some(checksum);
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
    pub type_idx: Option<u32>,
    /// MAST root digest of this function (if known).
    /// This links the debug info to the compiled code.
    pub mast_root: Option<[u8; 32]>,
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
    pub fn with_type(mut self, type_idx: u32) -> Self {
        self.type_idx = Some(type_idx);
        self
    }

    /// Sets the MAST root digest.
    pub fn with_mast_root(mut self, mast_root: [u8; 32]) -> Self {
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
    pub type_idx: u32,
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
    pub fn new(name_idx: u32, type_idx: u32, line: LineNumber, column: ColumnNumber) -> Self {
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

        let idx1 = section.add_string("test.rs");
        let idx2 = section.add_string("main.rs");
        let idx3 = section.add_string("test.rs"); // Duplicate

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0); // Should return same index
        assert_eq!(section.strings.len(), 2);
    }

    #[test]
    fn test_debug_sources_section_string_dedup() {
        let mut section = DebugSourcesSection::new();

        let idx1 = section.add_string("test.rs");
        let idx2 = section.add_string("main.rs");
        let idx3 = section.add_string("test.rs"); // Duplicate

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0); // Should return same index
        assert_eq!(section.strings.len(), 2);
    }

    #[test]
    fn test_debug_functions_section_string_dedup() {
        let mut section = DebugFunctionsSection::new();

        let idx1 = section.add_string("foo");
        let idx2 = section.add_string("bar");
        let idx3 = section.add_string("foo"); // Duplicate

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0); // Should return same index
        assert_eq!(section.strings.len(), 2);
    }

    #[test]
    fn test_primitive_type_sizes() {
        assert_eq!(DebugPrimitiveType::Void.size_in_bytes(), 0);
        assert_eq!(DebugPrimitiveType::I32.size_in_bytes(), 4);
        assert_eq!(DebugPrimitiveType::I64.size_in_bytes(), 8);
        assert_eq!(DebugPrimitiveType::Felt.size_in_bytes(), 8);
        assert_eq!(DebugPrimitiveType::Word.size_in_bytes(), 32);

        assert_eq!(DebugPrimitiveType::Void.size_in_felts(), 0);
        assert_eq!(DebugPrimitiveType::I32.size_in_felts(), 1);
        assert_eq!(DebugPrimitiveType::I64.size_in_felts(), 2);
        assert_eq!(DebugPrimitiveType::Word.size_in_felts(), 4);
    }

    #[test]
    fn test_primitive_type_roundtrip() {
        for discriminant in 0..=15 {
            let ty = DebugPrimitiveType::from_discriminant(discriminant).unwrap();
            assert_eq!(ty as u8, discriminant);
        }
        assert!(DebugPrimitiveType::from_discriminant(16).is_none());
    }
}
