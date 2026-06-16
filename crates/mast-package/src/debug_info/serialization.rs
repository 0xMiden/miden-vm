//! Serialization and deserialization for the debug_info section.

use alloc::{string::String, sync::Arc, vec::Vec};

use miden_core::{
    Word,
    mast::MastNodeId,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use miden_debug_types::{ByteIndex, ColumnNumber, LineNumber, Location, Uri};

use super::{
    DEBUG_ERROR_MESSAGES_VERSION, DEBUG_FUNCTIONS_VERSION, DEBUG_SOURCE_GRAPH_VERSION,
    DEBUG_SOURCE_MAP_VERSION, DEBUG_SOURCES_VERSION, DEBUG_TYPES_VERSION, DebugErrorMessage,
    DebugErrorMessagesSection, DebugFieldInfo, DebugFileInfo, DebugFunctionInfo,
    DebugFunctionsSection, DebugPrimitiveType, DebugSourceAsmOp, DebugSourceGraphSection,
    DebugSourceMapSection, DebugSourceNode, DebugSourceNodeId, DebugSourceVar, DebugSourcesSection,
    DebugTypeIdx, DebugTypeInfo, DebugTypesSection, DebugVariantInfo,
};

// DEBUG TYPES SECTION SERIALIZATION
// ================================================================================================

impl Serializable for DebugTypesSection {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.version);

        // Write string table
        target.write_usize(self.strings.len());
        for s in &self.strings {
            s.as_ref().write_into(target);
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

        // Manual bounds check required: read_string is a local helper, not Deserializable,
        // so we can't use read_many_iter. Each string serializes to at least 1 byte (the
        // varint length prefix), so max_alloc(1) bounds the vector pre-allocation.
        let strings_len = source.read_usize()?;
        let max_strings = source.max_alloc(1);
        if strings_len > max_strings {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "debug_types strings count {strings_len} exceeds budget {max_strings}"
            )));
        }
        let mut strings = Vec::with_capacity(strings_len);
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
            s.as_ref().write_into(target);
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

        // Manual bounds check required: read_string is a local helper, not Deserializable,
        // so we can't use read_many_iter. Each string serializes to at least 1 byte (the
        // varint length prefix), so max_alloc(1) bounds the vector pre-allocation.
        let strings_len = source.read_usize()?;
        let max_strings = source.max_alloc(1);
        if strings_len > max_strings {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "debug_sources strings count {strings_len} exceeds budget {max_strings}"
            )));
        }
        let mut strings = Vec::with_capacity(strings_len);
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
            s.as_ref().write_into(target);
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

        // Manual bounds check required: read_string is a local helper, not Deserializable,
        // so we can't use read_many_iter. Each string serializes to at least 1 byte (the
        // varint length prefix), so max_alloc(1) bounds the vector pre-allocation.
        let strings_len = source.read_usize()?;
        let max_strings = source.max_alloc(1);
        if strings_len > max_strings {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "debug_functions strings count {strings_len} exceeds budget {max_strings}"
            )));
        }
        let mut strings = Vec::with_capacity(strings_len);
        for _ in 0..strings_len {
            strings.push(read_string(source)?);
        }

        let functions_len = source.read_usize()?;
        let functions = source.read_many_iter(functions_len)?.collect::<Result<_, _>>()?;

        Ok(Self { version, strings, functions })
    }
}

// DEBUG SOURCE GRAPH SECTION SERIALIZATION
// ================================================================================================

impl Serializable for DebugSourceNode {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.exec_node.into());
        self.children.write_into(target);
        target.write_u32(self.op_start);
        target.write_u32(self.op_end);
    }
}

impl Deserializable for DebugSourceNode {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            exec_node: MastNodeId::new_unchecked(source.read_u32()?),
            children: Vec::<DebugSourceNodeId>::read_from(source)?,
            op_start: source.read_u32()?,
            op_end: source.read_u32()?,
        })
    }

    fn min_serialized_size() -> usize {
        12 + Vec::<DebugSourceNodeId>::min_serialized_size()
    }
}

impl Serializable for DebugSourceGraphSection {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.version());
        self.nodes().write_into(target);
        self.roots().write_into(target);
    }
}

impl Deserializable for DebugSourceGraphSection {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let version = source.read_u8()?;
        if version != DEBUG_SOURCE_GRAPH_VERSION {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "unsupported debug_source_graph version: {version}, expected {DEBUG_SOURCE_GRAPH_VERSION}"
            )));
        }

        let nodes = Vec::<DebugSourceNode>::read_from(source)?;
        let roots = Vec::<DebugSourceNodeId>::read_from(source)?;
        Ok(Self::from_parts(nodes, roots))
    }
}

// DEBUG SOURCE MAP SECTION SERIALIZATION
// ================================================================================================

impl Serializable for DebugSourceAsmOp {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.source_node.write_into(target);
        target.write_u32(self.op_idx);
        write_location(&self.location, target);
        self.context_name.write_into(target);
        self.op.write_into(target);
        target.write_u8(self.num_cycles);
    }
}

impl Deserializable for DebugSourceAsmOp {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let source_node = DebugSourceNodeId::read_from(source)?;
        let op_idx = source.read_u32()?;
        let location = read_location(source)?;
        let context_name = String::read_from(source)?;
        let op = String::read_from(source)?;
        let num_cycles = source.read_u8()?;
        Ok(Self {
            source_node,
            op_idx,
            location,
            context_name,
            op,
            num_cycles,
        })
    }

    fn min_serialized_size() -> usize {
        DebugSourceNodeId::min_serialized_size() + 4 + 1 + 1 + 1 + 1
    }
}

impl Serializable for DebugSourceVar {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.source_node.write_into(target);
        target.write_u32(self.op_idx);
        self.var.write_into(target);
    }
}

impl Deserializable for DebugSourceVar {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            source_node: DebugSourceNodeId::read_from(source)?,
            op_idx: source.read_u32()?,
            var: Deserializable::read_from(source)?,
        })
    }

    fn min_serialized_size() -> usize {
        DebugSourceNodeId::min_serialized_size() + 4
    }
}

impl Serializable for DebugSourceMapSection {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.version());
        target.write_usize(self.locations().len());
        for location in self.locations() {
            write_required_location(location, target);
        }

        target.write_usize(self.asm_ops().len());
        for asm_op in self.asm_ops() {
            write_source_asm_op(asm_op, self.locations(), target);
        }

        self.debug_vars().write_into(target);
    }
}

impl Deserializable for DebugSourceMapSection {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let version = source.read_u8()?;
        if version != DEBUG_SOURCE_MAP_VERSION {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "unsupported debug_source_map version: {version}, expected {DEBUG_SOURCE_MAP_VERSION}"
            )));
        }

        let locations_len = source.read_usize()?;
        let max_locations = source.max_alloc(MIN_REQUIRED_LOCATION_SERIALIZED_SIZE);
        if locations_len > max_locations {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "debug_source_map locations count {locations_len} exceeds budget {max_locations}"
            )));
        }
        let mut locations = Vec::with_capacity(locations_len);
        for _ in 0..locations_len {
            locations.push(read_required_location(source)?);
        }

        let asm_ops_len = source.read_usize()?;
        let max_asm_ops = source.max_alloc(DebugSourceAsmOp::min_serialized_size());
        if asm_ops_len > max_asm_ops {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "debug_source_map asm op count {asm_ops_len} exceeds budget {max_asm_ops}"
            )));
        }
        let mut asm_ops = Vec::with_capacity(asm_ops_len);
        for _ in 0..asm_ops_len {
            asm_ops.push(read_source_asm_op(source, &locations)?);
        }

        let debug_vars = Vec::<DebugSourceVar>::read_from(source)?;
        Ok(Self::from_parts(asm_ops, debug_vars))
    }
}

fn write_source_asm_op<W: ByteWriter>(
    asm_op: &DebugSourceAsmOp,
    locations: &[Location],
    target: &mut W,
) {
    asm_op.source_node.write_into(target);
    target.write_u32(asm_op.op_idx);
    if let Some(location) = asm_op.location.as_ref() {
        target.write_bool(true);
        let location_idx = locations
            .iter()
            .position(|candidate| candidate == location)
            .expect("debug source map location table should contain every row location");
        target.write_u32(location_idx as u32);
    } else {
        target.write_bool(false);
    }
    asm_op.context_name.write_into(target);
    asm_op.op.write_into(target);
    target.write_u8(asm_op.num_cycles);
}

fn read_source_asm_op<R: ByteReader>(
    source: &mut R,
    locations: &[Location],
) -> Result<DebugSourceAsmOp, DeserializationError> {
    let source_node = DebugSourceNodeId::read_from(source)?;
    let op_idx = source.read_u32()?;
    let location = if source.read_bool()? {
        let location_idx = source.read_u32()? as usize;
        Some(locations.get(location_idx).cloned().ok_or_else(|| {
            DeserializationError::InvalidValue(alloc::format!(
                "debug source asm op location index {location_idx} out of bounds for {} locations",
                locations.len()
            ))
        })?)
    } else {
        None
    };
    let context_name = String::read_from(source)?;
    let op = String::read_from(source)?;
    let num_cycles = source.read_u8()?;
    Ok(DebugSourceAsmOp::new(
        source_node,
        op_idx,
        location,
        context_name,
        op,
        num_cycles,
    ))
}

// DEBUG ERROR MESSAGES SECTION SERIALIZATION
// ================================================================================================

impl Serializable for DebugErrorMessage {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u64(self.err_code);
        self.message.as_ref().write_into(target);
    }
}

impl Deserializable for DebugErrorMessage {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            err_code: source.read_u64()?,
            message: read_string(source)?,
        })
    }

    fn min_serialized_size() -> usize {
        8 + 1
    }
}

impl Serializable for DebugErrorMessagesSection {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.version());
        self.messages().write_into(target);
    }
}

impl Deserializable for DebugErrorMessagesSection {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let version = source.read_u8()?;
        if version != DEBUG_ERROR_MESSAGES_VERSION {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "unsupported debug_error_messages version: {version}, expected {DEBUG_ERROR_MESSAGES_VERSION}"
            )));
        }

        let messages = Vec::<DebugErrorMessage>::read_from(source)?;
        Ok(Self::from_parts(messages))
    }
}

fn write_location<W: ByteWriter>(location: &Option<Location>, target: &mut W) {
    if let Some(location) = location {
        target.write_bool(true);
        write_required_location(location, target);
    } else {
        target.write_bool(false);
    }
}

fn read_location<R: ByteReader>(source: &mut R) -> Result<Option<Location>, DeserializationError> {
    if !source.read_bool()? {
        return Ok(None);
    }

    let uri = Uri::read_from(source)?;
    let start = ByteIndex::new(source.read_u32()?);
    let end = ByteIndex::new(source.read_u32()?);
    Ok(Some(Location::new(uri, start, end)))
}

const MIN_REQUIRED_LOCATION_SERIALIZED_SIZE: usize = 9;

fn write_required_location<W: ByteWriter>(location: &Location, target: &mut W) {
    location.uri.write_into(target);
    target.write_u32(location.start.to_u32());
    target.write_u32(location.end.to_u32());
}

fn read_required_location<R: ByteReader>(source: &mut R) -> Result<Location, DeserializationError> {
    let uri = Uri::read_from(source)?;
    let start = ByteIndex::new(source.read_u32()?);
    let end = ByteIndex::new(source.read_u32()?);
    Ok(Location::new(uri, start, end))
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
const TYPE_TAG_ENUM: u8 = 6;

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
            Self::Enum {
                name_idx,
                size,
                discriminant_type_idx,
                variants,
            } => {
                target.write_u8(TYPE_TAG_ENUM);
                target.write_u32(*name_idx);
                target.write_u32(*size);
                target.write_u32(discriminant_type_idx.as_u32());
                target.write_usize(variants.len());
                for variant in variants {
                    variant.write_into(target);
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
                let param_type_indices = Vec::<DebugTypeIdx>::read_from(source)?;
                Ok(Self::Function { return_type_idx, param_type_indices })
            },
            TYPE_TAG_ENUM => {
                let name_idx = source.read_u32()?;
                let size = source.read_u32()?;
                let discriminant_type_idx = DebugTypeIdx::from(source.read_u32()?);
                let variants_len = source.read_usize()?;
                let variants = source.read_many_iter(variants_len)?.collect::<Result<_, _>>()?;
                Ok(Self::Enum {
                    name_idx,
                    size,
                    discriminant_type_idx,
                    variants,
                })
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

// DEBUG VARIANT INFO SERIALIZATION
// ================================================================================================

impl Serializable for DebugVariantInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.name_idx);
        target.write_bool(self.type_idx.is_some());
        if let Some(type_idx) = self.type_idx {
            target.write_u32(type_idx.as_u32());
        }
        target.write_bool(self.payload_offset.is_some());
        if let Some(payload_offset) = self.payload_offset {
            target.write_u32(payload_offset);
        }
        target.write_u64((self.discriminant >> 64) as u64);
        target.write_u64(self.discriminant as u64);
    }
}

impl Deserializable for DebugVariantInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name_idx = source.read_u32()?;
        let type_idx = if source.read_bool()? {
            Some(DebugTypeIdx::from(source.read_u32()?))
        } else {
            None
        };
        let payload_offset = if source.read_bool()? {
            Some(source.read_u32()?)
        } else {
            None
        };
        let hi = source.read_u64()? as u128;
        let lo = source.read_u64()? as u128;
        Ok(Self {
            name_idx,
            type_idx,
            payload_offset,
            discriminant: (hi << 64) | lo,
        })
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

        Ok(Self {
            name_idx,
            linkage_name_idx,
            file_idx,
            line,
            column,
            type_idx,
            mast_root,
        })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

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
    use miden_core::operations::{DebugVarInfo, DebugVarLocation};

    use super::*;

    struct FixedBudgetReader<'a> {
        inner: miden_core::serde::SliceReader<'a>,
        max_bytes: usize,
    }

    impl<'a> FixedBudgetReader<'a> {
        fn new(bytes: &'a [u8], max_bytes: usize) -> Self {
            Self {
                inner: miden_core::serde::SliceReader::new(bytes),
                max_bytes,
            }
        }
    }

    impl<'a> ByteReader for FixedBudgetReader<'a> {
        fn read_u8(&mut self) -> Result<u8, DeserializationError> {
            self.inner.read_u8()
        }

        fn peek_u8(&self) -> Result<u8, DeserializationError> {
            self.inner.peek_u8()
        }

        fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
            self.inner.read_slice(len)
        }

        fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
            self.inner.read_array()
        }

        fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError> {
            self.inner.check_eor(num_bytes)
        }

        fn has_more_bytes(&self) -> bool {
            self.inner.has_more_bytes()
        }

        fn max_alloc(&self, element_size: usize) -> usize {
            if element_size == 0 {
                usize::MAX
            } else {
                self.max_bytes.checked_div(element_size).unwrap_or(0)
            }
        }
    }

    fn section_with_strings(version: u8, strings_len: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.write_u8(version);
        bytes.write_usize(strings_len);
        for _ in 0..strings_len {
            "".write_into(&mut bytes);
        }
        bytes.write_usize(0);
        bytes
    }

    fn function_type_bytes(params_len: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.write_u8(TYPE_TAG_FUNCTION);
        bytes.write_bool(false);
        bytes.write_usize(params_len);
        for _ in 0..params_len {
            bytes.write_u32(0);
        }
        bytes
    }

    fn roundtrip<T: Serializable + Deserializable + PartialEq + core::fmt::Debug>(value: &T) {
        let mut bytes = Vec::new();
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

        // Add an enum type
        let status_idx = section.add_string(Arc::from("Status"));
        let ok_idx = section.add_string(Arc::from("Ok"));
        let err_idx = section.add_string(Arc::from("Err"));
        section.add_type(DebugTypeInfo::Enum {
            name_idx: status_idx,
            size: 8,
            discriminant_type_idx: i32_type_idx,
            variants: alloc::vec![
                DebugVariantInfo {
                    name_idx: ok_idx,
                    type_idx: None,
                    payload_offset: None,
                    discriminant: 0,
                },
                DebugVariantInfo {
                    name_idx: err_idx,
                    type_idx: Some(felt_type_idx),
                    payload_offset: Some(8),
                    discriminant: 1,
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
        let func = DebugFunctionInfo::new(name_idx, 0, line, column);
        section.add_function(func);

        roundtrip(&section);
    }

    #[test]
    fn test_debug_source_graph_section_roundtrip() {
        let section = DebugSourceGraphSection::from_parts(
            alloc::vec![
                DebugSourceNode::new(MastNodeId::new_unchecked(0), alloc::vec![], 0, 1),
                DebugSourceNode::new(
                    MastNodeId::new_unchecked(1),
                    alloc::vec![DebugSourceNodeId::from(0)],
                    1,
                    3,
                ),
            ],
            alloc::vec![DebugSourceNodeId::from(1)],
        );

        roundtrip(&section);
    }

    #[test]
    fn test_debug_source_map_section_roundtrip() {
        let source_node = DebugSourceNodeId::from(0);
        let section = DebugSourceMapSection::from_parts(
            alloc::vec![DebugSourceAsmOp::new(
                source_node,
                2,
                None,
                "test::ctx".into(),
                "add".into(),
                1,
            )],
            alloc::vec![DebugSourceVar::new(
                source_node,
                2,
                DebugVarInfo::new("x", DebugVarLocation::Stack(0)),
            )],
        );

        roundtrip(&section);
    }

    #[test]
    fn test_debug_source_map_locations_are_deduplicated() {
        let source_node = DebugSourceNodeId::from(0);
        let location =
            Location::new(Uri::new("file://test.masm"), ByteIndex::new(10), ByteIndex::new(14));
        let section = DebugSourceMapSection::from_parts(
            alloc::vec![
                DebugSourceAsmOp::new(
                    source_node,
                    0,
                    Some(location.clone()),
                    "test::ctx".into(),
                    "push.1".into(),
                    1,
                ),
                DebugSourceAsmOp::new(
                    source_node,
                    1,
                    Some(location.clone()),
                    "test::ctx".into(),
                    "add".into(),
                    1,
                ),
            ],
            alloc::vec![],
        );

        assert_eq!(section.locations(), &[location]);

        let bytes = section.to_bytes();
        let deserialized = DebugSourceMapSection::read_from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.locations(), section.locations());
        assert_eq!(deserialized.asm_ops(), section.asm_ops());
    }

    #[test]
    fn test_debug_error_messages_section_roundtrip() {
        let section = DebugErrorMessagesSection::from_parts(alloc::vec![DebugErrorMessage::new(
            42,
            Arc::from("assertion message"),
        )]);

        roundtrip(&section);
        assert_eq!(section.message(42).as_deref(), Some("assertion message"));
    }

    #[test]
    fn test_empty_sections_roundtrip() {
        roundtrip(&DebugTypesSection::new());
        roundtrip(&DebugSourcesSection::new());
        roundtrip(&DebugFunctionsSection::new());
        roundtrip(&DebugSourceGraphSection::new());
        roundtrip(&DebugSourceMapSection::new());
        roundtrip(&DebugErrorMessagesSection::new());
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
            DebugPrimitiveType::U256,
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
        let func = DebugFunctionInfo::new(0, 0, line1, col1)
            .with_linkage_name(1)
            .with_type(DebugTypeIdx::from(2))
            .with_mast_root(Word::default());

        roundtrip(&func);
    }

    #[test]
    fn test_debug_functions_v1_is_rejected() {
        let bytes = section_with_strings(1, 0);
        let mut reader = miden_core::serde::SliceReader::new(&bytes);
        let err = DebugFunctionsSection::read_from(&mut reader).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("unsupported debug_functions version: 1"));
    }

    #[test]
    fn test_debug_section_string_bounds() {
        let types_bytes = section_with_strings(DEBUG_TYPES_VERSION, 2);
        let sources_bytes = section_with_strings(DEBUG_SOURCES_VERSION, 2);
        let functions_bytes = section_with_strings(DEBUG_FUNCTIONS_VERSION, 2);

        let mut reader = FixedBudgetReader::new(&types_bytes, 1);
        let err = DebugTypesSection::read_from(&mut reader).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("exceeds budget"));

        let mut reader = FixedBudgetReader::new(&sources_bytes, 1);
        let err = DebugSourcesSection::read_from(&mut reader).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("exceeds budget"));

        let mut reader = FixedBudgetReader::new(&functions_bytes, 1);
        let err = DebugFunctionsSection::read_from(&mut reader).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("exceeds budget"));

        let types_ok = section_with_strings(DEBUG_TYPES_VERSION, 1);
        let sources_ok = section_with_strings(DEBUG_SOURCES_VERSION, 1);
        let functions_ok = section_with_strings(DEBUG_FUNCTIONS_VERSION, 1);

        let mut reader = FixedBudgetReader::new(&types_ok, 1);
        assert_eq!(DebugTypesSection::read_from(&mut reader).unwrap().strings.len(), 1);

        let mut reader = FixedBudgetReader::new(&sources_ok, 1);
        assert_eq!(DebugSourcesSection::read_from(&mut reader).unwrap().strings.len(), 1);

        let mut reader = FixedBudgetReader::new(&functions_ok, 1);
        assert_eq!(DebugFunctionsSection::read_from(&mut reader).unwrap().strings.len(), 1);
    }

    #[test]
    fn test_function_params_bounds() {
        let too_many = function_type_bytes(2);
        let mut reader = FixedBudgetReader::new(&too_many, 4);
        let err = DebugTypeInfo::read_from(&mut reader).unwrap_err();
        assert!(matches!(err, DeserializationError::InvalidValue(_)));

        let ok = function_type_bytes(1);
        let mut reader = FixedBudgetReader::new(&ok, 4);
        let ty = DebugTypeInfo::read_from(&mut reader).unwrap();
        match ty {
            DebugTypeInfo::Function { param_type_indices, .. } => {
                assert_eq!(param_type_indices.len(), 1);
            },
            _ => panic!("expected function type"),
        }
    }
}
