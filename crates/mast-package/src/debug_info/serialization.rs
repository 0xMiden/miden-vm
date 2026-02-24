//! Serialization and deserialization for the debug_info section.

use alloc::sync::Arc;

use miden_core::{
    Word,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use miden_debug_types::{ColumnNumber, LineNumber};

use super::{
    DEBUG_FUNCTIONS_VERSION, DEBUG_SOURCES_VERSION, DEBUG_TYPES_VERSION, DebugFieldInfo,
    DebugFileInfo, DebugFunctionInfo, DebugFunctionsSection, DebugInlinedCallInfo,
    DebugPrimitiveType, DebugSourcesSection, DebugTypeIdx, DebugTypeInfo, DebugTypesSection,
    DebugVariableInfo,
};

// DEBUG TYPES SECTION SERIALIZATION
// ================================================================================================

impl Serializable for DebugTypesSection {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.version);

        // Write string table
        target.write_usize(self.strings.len());
        for s in &self.strings {
            write_string(target, s);
        }

        // Write type table
        target.write_usize(self.types.len());
        for ty in &self.types {
            ty.write_into(target);
        }
    }
}

impl Deserializable for DebugTypesSection {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let version = source.read_u8()?;
        if version != DEBUG_TYPES_VERSION {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "unsupported debug_types version: {version}, expected {DEBUG_TYPES_VERSION}"
            )));
        }

        let strings_len = source.read_usize()?;
        let mut strings = alloc::vec::Vec::with_capacity(strings_len);
        for _ in 0..strings_len {
            strings.push(read_string(source)?);
        }

        let types_len = source.read_usize()?;
        let types = source.read_many_iter(types_len)?.collect::<Result<_, _>>()?;

        Ok(Self { version, strings, types })
    }
}

// DEBUG SOURCES SECTION SERIALIZATION
// ================================================================================================

impl Serializable for DebugSourcesSection {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.version);

        // Write string table
        target.write_usize(self.strings.len());
        for s in &self.strings {
            write_string(target, s);
        }

        // Write file table
        target.write_usize(self.files.len());
        for file in &self.files {
            file.write_into(target);
        }
    }
}

impl Deserializable for DebugSourcesSection {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let version = source.read_u8()?;
        if version != DEBUG_SOURCES_VERSION {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "unsupported debug_sources version: {version}, expected {DEBUG_SOURCES_VERSION}"
            )));
        }

        let strings_len = source.read_usize()?;
        let mut strings = alloc::vec::Vec::with_capacity(strings_len);
        for _ in 0..strings_len {
            strings.push(read_string(source)?);
        }

        let files_len = source.read_usize()?;
        let files = source.read_many_iter(files_len)?.collect::<Result<_, _>>()?;

        Ok(Self { version, strings, files })
    }
}

// DEBUG FUNCTIONS SECTION SERIALIZATION
// ================================================================================================

impl Serializable for DebugFunctionsSection {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.version);

        // Write string table
        target.write_usize(self.strings.len());
        for s in &self.strings {
            write_string(target, s);
        }

        // Write function table
        target.write_usize(self.functions.len());
        for func in &self.functions {
            func.write_into(target);
        }
    }
}

impl Deserializable for DebugFunctionsSection {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let version = source.read_u8()?;
        if version != DEBUG_FUNCTIONS_VERSION {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "unsupported debug_functions version: {version}, expected {DEBUG_FUNCTIONS_VERSION}"
            )));
        }

        let strings_len = source.read_usize()?;
        let mut strings = alloc::vec::Vec::with_capacity(strings_len);
        for _ in 0..strings_len {
            strings.push(read_string(source)?);
        }

        let functions_len = source.read_usize()?;
        let functions = source.read_many_iter(functions_len)?.collect::<Result<_, _>>()?;

        Ok(Self { version, strings, functions })
    }
}

// DEBUG TYPE INFO SERIALIZATION
// ================================================================================================

// Type tags for serialization
const TYPE_TAG_PRIMITIVE: u8 = 0;
const TYPE_TAG_POINTER: u8 = 1;
const TYPE_TAG_ARRAY: u8 = 2;
const TYPE_TAG_STRUCT: u8 = 3;
const TYPE_TAG_FUNCTION: u8 = 4;
const TYPE_TAG_UNKNOWN: u8 = 5;

impl Serializable for DebugTypeInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Primitive(prim) => {
                target.write_u8(TYPE_TAG_PRIMITIVE);
                target.write_u8(*prim as u8);
            },
            Self::Pointer { pointee_type_idx } => {
                target.write_u8(TYPE_TAG_POINTER);
                target.write_u32(pointee_type_idx.as_u32());
            },
            Self::Array { element_type_idx, count } => {
                target.write_u8(TYPE_TAG_ARRAY);
                target.write_u32(element_type_idx.as_u32());
                target.write_bool(count.is_some());
                if let Some(count) = count {
                    target.write_u32(*count);
                }
            },
            Self::Struct { name_idx, size, fields } => {
                target.write_u8(TYPE_TAG_STRUCT);
                target.write_u32(*name_idx);
                target.write_u32(*size);
                target.write_usize(fields.len());
                for field in fields {
                    field.write_into(target);
                }
            },
            Self::Function { return_type_idx, param_type_indices } => {
                target.write_u8(TYPE_TAG_FUNCTION);
                target.write_bool(return_type_idx.is_some());
                if let Some(idx) = return_type_idx {
                    target.write_u32(idx.as_u32());
                }
                target.write_usize(param_type_indices.len());
                for idx in param_type_indices {
                    target.write_u32(idx.as_u32());
                }
            },
            Self::Unknown => {
                target.write_u8(TYPE_TAG_UNKNOWN);
            },
        }
    }
}

impl Deserializable for DebugTypeInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let tag = source.read_u8()?;
        match tag {
            TYPE_TAG_PRIMITIVE => {
                let prim_tag = source.read_u8()?;
                let prim = DebugPrimitiveType::from_discriminant(prim_tag).ok_or_else(|| {
                    DeserializationError::InvalidValue(alloc::format!(
                        "invalid primitive type tag: {prim_tag}"
                    ))
                })?;
                Ok(Self::Primitive(prim))
            },
            TYPE_TAG_POINTER => {
                let pointee_type_idx = DebugTypeIdx::from(source.read_u32()?);
                Ok(Self::Pointer { pointee_type_idx })
            },
            TYPE_TAG_ARRAY => {
                let element_type_idx = DebugTypeIdx::from(source.read_u32()?);
                let has_count = source.read_bool()?;
                let count = if has_count { Some(source.read_u32()?) } else { None };
                Ok(Self::Array { element_type_idx, count })
            },
            TYPE_TAG_STRUCT => {
                let name_idx = source.read_u32()?;
                let size = source.read_u32()?;
                let fields_len = source.read_usize()?;
                let fields = source.read_many_iter(fields_len)?.collect::<Result<_, _>>()?;
                Ok(Self::Struct { name_idx, size, fields })
            },
            TYPE_TAG_FUNCTION => {
                let has_return = source.read_bool()?;
                let return_type_idx = if has_return {
                    Some(DebugTypeIdx::from(source.read_u32()?))
                } else {
                    None
                };
                let params_len = source.read_usize()?;
                let mut param_type_indices = alloc::vec::Vec::with_capacity(params_len);
                for _ in 0..params_len {
                    param_type_indices.push(DebugTypeIdx::from(source.read_u32()?));
                }
                Ok(Self::Function { return_type_idx, param_type_indices })
            },
            TYPE_TAG_UNKNOWN => Ok(Self::Unknown),
            _ => Err(DeserializationError::InvalidValue(alloc::format!("invalid type tag: {tag}"))),
        }
    }
}

// DEBUG FIELD INFO SERIALIZATION
// ================================================================================================

impl Serializable for DebugFieldInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.name_idx);
        target.write_u32(self.type_idx.as_u32());
        target.write_u32(self.offset);
    }
}

impl Deserializable for DebugFieldInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name_idx = source.read_u32()?;
        let type_idx = DebugTypeIdx::from(source.read_u32()?);
        let offset = source.read_u32()?;
        Ok(Self { name_idx, type_idx, offset })
    }
}

// DEBUG FILE INFO SERIALIZATION
// ================================================================================================

impl Serializable for DebugFileInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.path_idx);

        target.write_bool(self.checksum.is_some());
        if let Some(checksum) = &self.checksum {
            target.write_bytes(checksum.as_ref());
        }
    }
}

impl Deserializable for DebugFileInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let path_idx = source.read_u32()?;

        let has_checksum = source.read_bool()?;
        let checksum = if has_checksum {
            let bytes = source.read_slice(32)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(alloc::boxed::Box::new(arr))
        } else {
            None
        };

        Ok(Self { path_idx, checksum })
    }
}

// DEBUG FUNCTION INFO SERIALIZATION
// ================================================================================================

impl Serializable for DebugFunctionInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.name_idx);

        target.write_bool(self.linkage_name_idx.is_some());
        if let Some(idx) = self.linkage_name_idx {
            target.write_u32(idx);
        }

        target.write_u32(self.file_idx);
        target.write_u32(self.line.to_u32());
        target.write_u32(self.column.to_u32());

        target.write_bool(self.type_idx.is_some());
        if let Some(idx) = self.type_idx {
            target.write_u32(idx.as_u32());
        }

        target.write_bool(self.mast_root.is_some());
        if let Some(root) = &self.mast_root {
            root.write_into(target);
        }

        // Write variables
        target.write_usize(self.variables.len());
        for var in &self.variables {
            var.write_into(target);
        }

        // Write inlined calls
        target.write_usize(self.inlined_calls.len());
        for call in &self.inlined_calls {
            call.write_into(target);
        }
    }
}

impl Deserializable for DebugFunctionInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name_idx = source.read_u32()?;

        let has_linkage_name = source.read_bool()?;
        let linkage_name_idx = if has_linkage_name {
            Some(source.read_u32()?)
        } else {
            None
        };

        let file_idx = source.read_u32()?;
        let line_raw = source.read_u32()?;
        let column_raw = source.read_u32()?;
        let line = LineNumber::new(line_raw).unwrap_or_default();
        let column = ColumnNumber::new(column_raw).unwrap_or_default();

        let has_type = source.read_bool()?;
        let type_idx = if has_type {
            Some(DebugTypeIdx::from(source.read_u32()?))
        } else {
            None
        };

        let has_mast_root = source.read_bool()?;
        let mast_root = if has_mast_root {
            Some(Word::read_from(source)?)
        } else {
            None
        };

        // Read variables
        let vars_len = source.read_usize()?;
        let variables = source.read_many_iter(vars_len)?.collect::<Result<_, _>>()?;

        // Read inlined calls
        let calls_len = source.read_usize()?;
        let inlined_calls = source.read_many_iter(calls_len)?.collect::<Result<_, _>>()?;

        Ok(Self {
            name_idx,
            linkage_name_idx,
            file_idx,
            line,
            column,
            type_idx,
            mast_root,
            variables,
            inlined_calls,
        })
    }
}

// DEBUG VARIABLE INFO SERIALIZATION
// ================================================================================================

impl Serializable for DebugVariableInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.name_idx);
        target.write_u32(self.type_idx.as_u32());
        target.write_u32(self.arg_index);
        target.write_u32(self.line.to_u32());
        target.write_u32(self.column.to_u32());
        target.write_u32(self.scope_depth);
    }
}

impl Deserializable for DebugVariableInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name_idx = source.read_u32()?;
        let type_idx = DebugTypeIdx::from(source.read_u32()?);
        let arg_index = source.read_u32()?;
        let line_raw = source.read_u32()?;
        let column_raw = source.read_u32()?;
        let line = LineNumber::new(line_raw).unwrap_or_default();
        let column = ColumnNumber::new(column_raw).unwrap_or_default();
        let scope_depth = source.read_u32()?;
        Ok(Self {
            name_idx,
            type_idx,
            arg_index,
            line,
            column,
            scope_depth,
        })
    }
}

// DEBUG INLINED CALL INFO SERIALIZATION
// ================================================================================================

impl Serializable for DebugInlinedCallInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.callee_idx);
        target.write_u32(self.file_idx);
        target.write_u32(self.line.to_u32());
        target.write_u32(self.column.to_u32());
    }
}

impl Deserializable for DebugInlinedCallInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let callee_idx = source.read_u32()?;
        let file_idx = source.read_u32()?;
        let line_raw = source.read_u32()?;
        let column_raw = source.read_u32()?;
        let line = LineNumber::new(line_raw).unwrap_or_default();
        let column = ColumnNumber::new(column_raw).unwrap_or_default();
        Ok(Self { callee_idx, file_idx, line, column })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn write_string<W: ByteWriter>(target: &mut W, s: &str) {
    let bytes = s.as_bytes();
    target.write_usize(bytes.len());
    target.write_bytes(bytes);
}

fn read_string<R: ByteReader>(source: &mut R) -> Result<Arc<str>, DeserializationError> {
    let len = source.read_usize()?;
    let bytes = source.read_slice(len)?;
    let s = core::str::from_utf8(bytes).map_err(|err| {
        DeserializationError::InvalidValue(alloc::format!("invalid utf-8 in string: {err}"))
    })?;
    Ok(Arc::from(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: Serializable + Deserializable + PartialEq + core::fmt::Debug>(value: &T) {
        let mut bytes = alloc::vec::Vec::new();
        value.write_into(&mut bytes);
        let result = T::read_from(&mut miden_core::serde::SliceReader::new(&bytes)).unwrap();
        assert_eq!(value, &result);
    }

    #[test]
    fn test_debug_types_section_roundtrip() {
        let mut section = DebugTypesSection::new();

        // Add primitive types
        let i32_type_idx = section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I32));
        let felt_type_idx = section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Felt));

        // Add a pointer type
        section.add_type(DebugTypeInfo::Pointer { pointee_type_idx: i32_type_idx });

        // Add an array type
        section.add_type(DebugTypeInfo::Array {
            element_type_idx: felt_type_idx,
            count: Some(4),
        });

        // Add a struct type
        let x_idx = section.add_string(Arc::from("x"));
        let y_idx = section.add_string(Arc::from("y"));
        let point_idx = section.add_string(Arc::from("Point"));
        section.add_type(DebugTypeInfo::Struct {
            name_idx: point_idx,
            size: 16,
            fields: alloc::vec![
                DebugFieldInfo {
                    name_idx: x_idx,
                    type_idx: felt_type_idx,
                    offset: 0,
                },
                DebugFieldInfo {
                    name_idx: y_idx,
                    type_idx: felt_type_idx,
                    offset: 8,
                },
            ],
        });

        roundtrip(&section);
    }

    #[test]
    fn test_debug_sources_section_roundtrip() {
        let mut section = DebugSourcesSection::new();

        let path_idx = section.add_string(Arc::from("test.rs"));
        section.add_file(DebugFileInfo::new(path_idx));

        let path2_idx = section.add_string(Arc::from("main.rs"));
        section.add_file(DebugFileInfo::new(path2_idx).with_checksum([42u8; 32]));

        roundtrip(&section);
    }

    #[test]
    fn test_debug_functions_section_roundtrip() {
        let mut section = DebugFunctionsSection::new();

        let name_idx = section.add_string(Arc::from("test_function"));

        let line = LineNumber::new(10).unwrap();
        let column = ColumnNumber::new(1).unwrap();
        let mut func = DebugFunctionInfo::new(name_idx, 0, line, column);
        let var_name_idx = section.add_string(Arc::from("x"));
        let var_line = LineNumber::new(10).unwrap();
        let var_column = ColumnNumber::new(5).unwrap();
        func.add_variable(
            DebugVariableInfo::new(var_name_idx, DebugTypeIdx::from(0), var_line, var_column)
                .with_arg_index(1),
        );
        section.add_function(func);

        roundtrip(&section);
    }

    #[test]
    fn test_empty_sections_roundtrip() {
        roundtrip(&DebugTypesSection::new());
        roundtrip(&DebugSourcesSection::new());
        roundtrip(&DebugFunctionsSection::new());
    }

    #[test]
    fn test_all_primitive_types_roundtrip() {
        let mut section = DebugTypesSection::new();

        for prim in [
            DebugPrimitiveType::Void,
            DebugPrimitiveType::Bool,
            DebugPrimitiveType::I8,
            DebugPrimitiveType::U8,
            DebugPrimitiveType::I16,
            DebugPrimitiveType::U16,
            DebugPrimitiveType::I32,
            DebugPrimitiveType::U32,
            DebugPrimitiveType::I64,
            DebugPrimitiveType::U64,
            DebugPrimitiveType::I128,
            DebugPrimitiveType::U128,
            DebugPrimitiveType::F32,
            DebugPrimitiveType::F64,
            DebugPrimitiveType::Felt,
            DebugPrimitiveType::Word,
        ] {
            section.add_type(DebugTypeInfo::Primitive(prim));
        }

        roundtrip(&section);
    }

    #[test]
    fn test_function_type_roundtrip() {
        let ty = DebugTypeInfo::Function {
            return_type_idx: Some(DebugTypeIdx::from(0)),
            param_type_indices: alloc::vec![
                DebugTypeIdx::from(1),
                DebugTypeIdx::from(2),
                DebugTypeIdx::from(3)
            ],
        };
        roundtrip(&ty);

        let void_fn = DebugTypeInfo::Function {
            return_type_idx: None,
            param_type_indices: alloc::vec![],
        };
        roundtrip(&void_fn);
    }

    #[test]
    fn test_file_info_with_checksum_roundtrip() {
        let file = DebugFileInfo::new(0).with_checksum([42u8; 32]);
        roundtrip(&file);
    }

    #[test]
    fn test_function_with_mast_root_roundtrip() {
        let line1 = LineNumber::new(1).unwrap();
        let col1 = ColumnNumber::new(1).unwrap();
        let mut func = DebugFunctionInfo::new(0, 0, line1, col1)
            .with_linkage_name(1)
            .with_type(DebugTypeIdx::from(2))
            .with_mast_root(Word::default());

        let var_line = LineNumber::new(5).unwrap();
        let var_col = ColumnNumber::new(10).unwrap();
        func.add_variable(
            DebugVariableInfo::new(0, DebugTypeIdx::from(0), var_line, var_col)
                .with_arg_index(1)
                .with_scope_depth(2),
        );

        let call_line = LineNumber::new(20).unwrap();
        let call_col = ColumnNumber::new(5).unwrap();
        func.add_inlined_call(DebugInlinedCallInfo::new(0, 0, call_line, call_col));

        roundtrip(&func);
    }
}
