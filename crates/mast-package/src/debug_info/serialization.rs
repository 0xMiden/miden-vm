//! Serialization and deserialization for the debug_info section.

use alloc::{sync::Arc, vec::Vec};
use core::{alloc::Layout, ptr::NonNull};

use miden_assembly_syntax::ast::DebugVarLocation;
use miden_core::{
    Felt, Word,
    mast::MastNodeId,
    serde::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        read_bounded_len,
    },
};
use miden_debug_types::{ColumnIndex, LineIndex};
use miden_utils_indexing::IndexVec;
use zerocopy::{Immutable, IntoBytes, KnownLayout};

use super::{
    DEBUG_INFO_VERSION, DebugErrorMessage, DebugFieldInfo, DebugFileIdx, DebugFileInfo,
    DebugFunctionIdx, DebugFunctionInfo, DebugLoc, DebugLocIdx, DebugPrimitiveType,
    DebugSourceAsmOp, DebugSourceInlineCall, DebugSourceNode, DebugSourceNodeId, DebugSourceVar,
    DebugStringIdx, DebugTypeIdx, DebugTypeInfo, DebugVariantInfo, OptionalIndex, PackageDebugInfo,
};

/// Base alignment for copied payloads. The assertions below ensure that this is sufficient for
/// every row type decoded directly from the payload.
const POD_BUFFER_ALIGNMENT: usize = align_of::<u64>();

const _: () = {
    assert!(align_of::<DebugFileInfo>() <= POD_BUFFER_ALIGNMENT);
    assert!(align_of::<DebugLoc>() <= POD_BUFFER_ALIGNMENT);
    assert!(align_of::<WireDebugFunctionInfo>() <= POD_BUFFER_ALIGNMENT);
    assert!(align_of::<DebugSourceNodeId>() <= POD_BUFFER_ALIGNMENT);
    assert!(align_of::<DebugErrorMessage>() <= POD_BUFFER_ALIGNMENT);
    assert!(align_of::<DebugSourceAsmOp>() <= POD_BUFFER_ALIGNMENT);
};

/// Wire form of [`DebugFunctionInfo`]. The domain type cannot be decoded from arbitrary bytes
/// because its field elements must be validated before constructing a [`Word`].
#[repr(C, align(8))]
#[derive(Clone, Copy, zerocopy::FromBytes, Immutable, IntoBytes, KnownLayout)]
struct WireDebugFunctionInfo {
    mast_root: [u64; 4],
    source_node: OptionalIndex<DebugSourceNodeId>,
    type_idx: OptionalIndex<DebugTypeIdx>,
    linkage_name_idx: OptionalIndex<DebugStringIdx>,
    name_idx: DebugStringIdx,
    file_idx: DebugFileIdx,
    line: LineIndex,
    column: ColumnIndex,
}

// PACKAGE DEBUG INFO SERIALIZATION
// ================================================================================================

/// Fixed-size tables are padded to their row alignment and written as `zerocopy`-certified rows.
/// Deserialization copies each payload into an aligned allocation because the padding preserves row
/// alignment only when measured from an aligned payload base. The function table uses an explicit
/// wire row because its field elements require validation before constructing domain values.
#[cfg(target_endian = "little")]
impl Serializable for PackageDebugInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut output = Vec::<u8>::with_capacity(16 * 1024);

        self.strings.write_into(&mut output);

        output.write_u32(self.files().len().try_into().unwrap());
        write_pod_slice(self.files().as_slice(), &mut output);

        output.write_u32(self.locations().len().try_into().unwrap());
        write_pod_slice(self.locations().as_slice(), &mut output);

        self.types.write_into(&mut output);

        output.write_u32(self.functions().len().try_into().unwrap());
        pad_to_align::<WireDebugFunctionInfo>(&mut output);
        write_pod_rows(
            self.functions().iter().map(|row| {
                let mast_root = row.mast_root.into_elements().map(|felt| felt.as_canonical_u64());
                WireDebugFunctionInfo {
                    mast_root,
                    source_node: row.source_node,
                    type_idx: row.type_idx,
                    linkage_name_idx: row.linkage_name_idx,
                    name_idx: row.name_idx,
                    file_idx: row.file_idx,
                    line: row.line,
                    column: row.column,
                }
            }),
            &mut output,
        );

        self.nodes.write_into(&mut output);

        output.write_u32(self.roots().len().try_into().unwrap());
        write_pod_slice(self.roots(), &mut output);

        output.write_u32(self.error_messages().len().try_into().unwrap());
        write_pod_slice(self.error_messages(), &mut output);

        target.write_u8(self.version());
        target.write_usize(output.len());
        target.write_bytes(&output);
    }
}

#[cfg(target_endian = "little")]
impl Deserializable for PackageDebugInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let version = source.read_u8()?;
        if version != DEBUG_INFO_VERSION {
            return Err(DeserializationError::InvalidValue(format!(
                "unsupported debug_info version: {version}, expected {DEBUG_INFO_VERSION}"
            )));
        }

        let data_len = read_bounded_len(source, "package debug info", 1)?;
        let data = source.read_slice(data_len)?;
        let aligned = AlignedBytes::copy_from_slice(data, POD_BUFFER_ALIGNMENT)?;
        let mut source = PodSliceReader::new(aligned.as_slice());

        let strings =
            IndexVec::read_from_bounded_with(&mut source, "debug_info strings", 1, read_string)?;

        let files_len = source.read_u32()?;
        let files = source.read_pod_rows::<DebugFileInfo>(files_len as usize, "debug files")?;

        let locations_len = source.read_u32()?;
        let locations =
            source.read_pod_rows::<DebugLoc>(locations_len as usize, "debug locations")?;

        let types = IndexVec::read_from_bounded(&mut source, "debug_info types")?;

        let functions_len = source.read_u32()?;
        let functions = source.read_pod_rows_with::<WireDebugFunctionInfo, _, _>(
            functions_len as usize,
            "debug functions",
            |row| {
                Ok(DebugFunctionInfo {
                    mast_root: Word::new([
                        read_wire_felt(row.mast_root[0])?,
                        read_wire_felt(row.mast_root[1])?,
                        read_wire_felt(row.mast_root[2])?,
                        read_wire_felt(row.mast_root[3])?,
                    ]),
                    source_node: row.source_node,
                    type_idx: row.type_idx,
                    linkage_name_idx: row.linkage_name_idx,
                    name_idx: row.name_idx,
                    file_idx: row.file_idx,
                    line: row.line,
                    column: row.column,
                })
            },
        )?;

        let nodes = IndexVec::read_from_bounded(&mut source, "debug_info nodes")?;

        let roots_len = source.read_u32()? as usize;
        let roots = source.read_pod_rows::<DebugSourceNodeId>(roots_len, "debug source roots")?;

        let error_messages_len = source.read_u32()? as usize;
        let error_messages = source
            .read_pod_rows::<DebugErrorMessage>(error_messages_len, "debug error messages")?;

        let remaining_len = source.remaining_len();
        if remaining_len != 0 {
            return Err(DeserializationError::InvalidValue(format!(
                "expected {data_len} bytes to have been read, but {remaining_len} remain in the buffer"
            )));
        }

        Ok(PackageDebugInfo {
            version,
            strings,
            files: IndexVec::try_from(files).unwrap(),
            locations: IndexVec::try_from(locations).unwrap(),
            types,
            functions: IndexVec::try_from(functions).unwrap(),
            nodes,
            roots,
            error_messages,
        })
    }
}

// DEBUG SOURCE NODE SERIALIZATION
// ================================================================================================

/// Fixed-size child and assembly-op tables use the same certified row format as
/// [`PackageDebugInfo`].
#[cfg(target_endian = "little")]
impl Serializable for DebugSourceNode {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut output = Vec::<u8>::with_capacity(
            size_of::<DebugSourceNode>()
                + (self.asm_ops.len() * size_of::<DebugSourceAsmOp>())
                + (self.debug_vars.len() * size_of::<DebugSourceVar>())
                + (self.inline_calls.len() * size_of::<DebugSourceInlineCall>()),
        );

        output.write_u32(self.exec_node.into());

        output.write_u32(self.children.len().try_into().unwrap());
        write_pod_slice(self.children.as_slice(), &mut output);

        output.write_u32(self.op_start);
        output.write_u32(self.op_end);

        output.write_u32(self.asm_ops.len().try_into().unwrap());
        write_pod_slice(self.asm_ops.as_slice(), &mut output);

        self.debug_vars.write_into(&mut output);
        self.inline_calls.write_into(&mut output);

        target.write_usize(output.len());
        target.write_bytes(&output);
    }
}

#[cfg(target_endian = "little")]
impl Deserializable for DebugSourceNode {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let data_len = read_bounded_len(source, "debug source node", 1)?;
        let data = source.read_slice(data_len)?;
        let aligned = AlignedBytes::copy_from_slice(data, POD_BUFFER_ALIGNMENT)?;
        let mut source = PodSliceReader::new(aligned.as_slice());

        let exec_node = MastNodeId::new_unchecked(source.read_u32()?);

        let children_len = source.read_u32()? as usize;
        let children =
            source.read_pod_rows::<DebugSourceNodeId>(children_len, "debug source children")?;

        let op_start = source.read_u32()?;
        let op_end = source.read_u32()?;

        let asm_ops_len = source.read_u32()? as usize;
        let asm_ops =
            source.read_pod_rows::<DebugSourceAsmOp>(asm_ops_len, "debug assembly operations")?;

        let debug_vars = Vec::read_from(&mut source)?;
        let inline_calls = Vec::read_from(&mut source)?;

        let remaining_len = source.remaining_len();
        if remaining_len != 0 {
            return Err(DeserializationError::InvalidValue(format!(
                "expected {data_len} bytes to have been read, but {remaining_len} remain in the buffer"
            )));
        }

        Ok(Self {
            exec_node,
            children,
            op_start,
            op_end,
            asm_ops,
            debug_vars,
            inline_calls,
        })
    }

    fn min_serialized_size() -> usize {
        1 + DebugSourceNodeId::min_serialized_size()
            + Vec::<DebugSourceNodeId>::min_serialized_size()
            + 8
            + 1
            + Vec::<DebugSourceVar>::min_serialized_size()
            + Vec::<DebugSourceInlineCall>::min_serialized_size()
    }
}

// DEBUG SOURCE VARIABLE SERIALIZATION
// ================================================================================================

impl Serializable for DebugSourceVar {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.op_idx);
        self.name_idx.write_into(target);
        self.type_id.write_into(target);
        target.write_u32(self.arg_idx.map(core::num::NonZeroU32::get).unwrap_or_default());
        self.location_idx.write_into(target);
        self.value_location.write_into(target);
    }
}

impl Deserializable for DebugSourceVar {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let op_idx = source.read_u32()?;
        let name_idx = DebugStringIdx::read_from(source)?;
        let type_id = Option::<DebugTypeIdx>::read_from(source)?;
        let arg_idx = core::num::NonZeroU32::new(source.read_u32()?);
        let location_idx = Option::<DebugLocIdx>::read_from(source)?;
        let value_location = DebugVarLocation::read_from(source)?;
        Ok(Self {
            op_idx,
            name_idx,
            type_id,
            arg_idx,
            location_idx,
            value_location,
        })
    }

    fn min_serialized_size() -> usize {
        4 + DebugStringIdx::min_serialized_size()
            + 1
            + 4
            + 1
            + DebugVarLocation::min_serialized_size()
    }
}

// DEBUG INLINE CALL SERIALIZATION
// ================================================================================================

impl Serializable for DebugSourceInlineCall {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.op_idx);
        self.callee_idx.write_into(target);
        self.loc_idx.write_into(target);
    }
}

impl Deserializable for DebugSourceInlineCall {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let op_idx = source.read_u32()?;
        let callee_idx = DebugFunctionIdx::read_from(source)?;
        let loc_idx = DebugLocIdx::read_from(source)?;
        Ok(DebugSourceInlineCall { op_idx, callee_idx, loc_idx })
    }

    fn min_serialized_size() -> usize {
        4 + DebugFunctionIdx::min_serialized_size() + DebugLocIdx::min_serialized_size()
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
                pointee_type_idx.write_into(target);
            },
            Self::Array { element_type_idx, count } => {
                target.write_u8(TYPE_TAG_ARRAY);
                element_type_idx.write_into(target);
                target.write_bool(count.is_some());
                if let Some(count) = count {
                    target.write_u32(*count);
                }
            },
            Self::Struct { name_idx, size, fields } => {
                target.write_u8(TYPE_TAG_STRUCT);
                name_idx.write_into(target);
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
                    idx.write_into(target);
                }
                target.write_usize(param_type_indices.len());
                for idx in param_type_indices {
                    idx.write_into(target);
                }
            },
            Self::Enum {
                name_idx,
                size,
                discriminant_type_idx,
                variants,
            } => {
                target.write_u8(TYPE_TAG_ENUM);
                name_idx.write_into(target);
                target.write_u32(*size);
                discriminant_type_idx.write_into(target);
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
                let name_idx = DebugStringIdx::read_from(source)?;
                let size = source.read_u32()?;
                let fields_len = read_bounded_len(source, "debug struct fields", 1)?;
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
                let param_type_indices =
                    read_debug_type_indices(source, "debug function parameters")?;
                Ok(Self::Function { return_type_idx, param_type_indices })
            },
            TYPE_TAG_ENUM => {
                let name_idx = DebugStringIdx::read_from(source)?;
                let size = source.read_u32()?;
                let discriminant_type_idx = DebugTypeIdx::from(source.read_u32()?);
                let variants_len = read_bounded_len(source, "debug enum variants", 1)?;
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

    fn min_serialized_size() -> usize {
        // The unknown type consists solely of its tag. All other variants are larger.
        1
    }
}

// DEBUG FIELD INFO SERIALIZATION
// ================================================================================================

impl Serializable for DebugFieldInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.name_idx.write_into(target);
        self.type_idx.write_into(target);
        target.write_u32(self.offset);
    }
}

impl Deserializable for DebugFieldInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name_idx = DebugStringIdx::read_from(source)?;
        let type_idx = DebugTypeIdx::from(source.read_u32()?);
        let offset = source.read_u32()?;
        Ok(Self { name_idx, type_idx, offset })
    }
}

// DEBUG VARIANT INFO SERIALIZATION
// ================================================================================================

impl Serializable for DebugVariantInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.name_idx.write_into(target);
        target.write_bool(self.type_idx.is_some());
        if let Some(type_idx) = self.type_idx {
            type_idx.write_into(target);
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
        let name_idx = DebugStringIdx::read_from(source)?;
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

    fn min_serialized_size() -> usize {
        // The minimum encoding has no payload type or offset: one string-table index, two
        // one-byte option discriminants, and the two halves of the discriminant value.
        DebugStringIdx::min_serialized_size()
            + 2 * u8::min_serialized_size()
            + 2 * u64::min_serialized_size()
    }
}

// DEBUG FILE INFO SERIALIZATION
// ================================================================================================

impl Serializable for DebugFileInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.path_idx.write_into(target);
        self.checksum.write_into(target);
    }
}

impl Deserializable for DebugFileInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let path_idx = DebugStringIdx::read_from(source)?;

        let bytes = source.read_slice(32)?;
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(bytes);

        Ok(Self { path_idx, checksum })
    }

    fn min_serialized_size() -> usize {
        DebugStringIdx::min_serialized_size() + size_of::<[u8; 32]>()
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Owns a byte allocation with the alignment required by the certified POD row types.
struct AlignedBytes {
    ptr: Option<NonNull<u8>>,
    layout: Layout,
}

impl AlignedBytes {
    fn copy_from_slice(source: &[u8], alignment: usize) -> Result<Self, DeserializationError> {
        let layout = Layout::from_size_align(source.len(), alignment).map_err(|_| {
            DeserializationError::InvalidValue(format!(
                "debug info payload size {} is too large",
                source.len()
            ))
        })?;
        if source.is_empty() {
            return Ok(Self { ptr: None, layout });
        }

        // SAFETY: `layout` is non-zero and valid in this branch.
        let ptr = unsafe { alloc::alloc::alloc(layout) };
        let Some(ptr) = NonNull::new(ptr) else {
            alloc::alloc::handle_alloc_error(layout)
        };
        // SAFETY: `ptr` owns `source.len()` writable bytes and does not overlap `source`.
        unsafe {
            ptr.as_ptr().copy_from_nonoverlapping(source.as_ptr(), source.len());
        }
        Ok(Self { ptr: Some(ptr), layout })
    }

    fn as_slice(&self) -> &[u8] {
        let Some(ptr) = self.ptr else {
            return &[];
        };
        // SAFETY: `ptr` was allocated with `self.layout`, every byte was initialized by the copy in
        // `copy_from_slice`, and the allocation remains owned by `self` for the returned borrow.
        unsafe { core::slice::from_raw_parts(ptr.as_ptr(), self.layout.size()) }
    }
}

impl Drop for AlignedBytes {
    fn drop(&mut self) {
        if let Some(ptr) = self.ptr {
            // SAFETY: `ptr` was allocated with this exact layout and has not been freed.
            unsafe {
                alloc::alloc::dealloc(ptr.as_ptr(), self.layout);
            }
        }
    }
}

struct PodSliceReader<'a> {
    source: &'a [u8],
    pos: usize,
}

impl<'a> PodSliceReader<'a> {
    fn new(source: &'a [u8]) -> Self {
        Self { source, pos: 0 }
    }

    fn remaining_len(&self) -> usize {
        self.source.len() - self.pos
    }

    fn read_pod_rows<T>(&mut self, len: usize, label: &str) -> Result<Vec<T>, DeserializationError>
    where
        T: Copy + zerocopy::FromBytes + Immutable + KnownLayout,
    {
        self.skip_alignment_padding::<T>()?;
        let byte_len = len.checked_mul(size_of::<T>()).ok_or_else(|| {
            DeserializationError::InvalidValue(alloc::format!(
                "{label} row count {len} overflows row size {}",
                size_of::<T>()
            ))
        })?;
        let bytes = self.read_slice(byte_len)?;
        let rows: &[T] = <[T] as zerocopy::FromBytes>::ref_from_bytes(bytes).map_err(|_| {
            DeserializationError::InvalidValue(alloc::format!(
                "{label} bytes do not form aligned POD rows"
            ))
        })?;
        Ok(rows.to_vec())
    }

    fn read_pod_rows_with<T, U, F>(
        &mut self,
        len: usize,
        label: &str,
        map: F,
    ) -> Result<Vec<U>, DeserializationError>
    where
        T: Copy + zerocopy::FromBytes + Immutable + KnownLayout,
        F: FnMut(T) -> Result<U, DeserializationError>,
    {
        self.skip_alignment_padding::<T>()?;
        let byte_len = len.checked_mul(size_of::<T>()).ok_or_else(|| {
            DeserializationError::InvalidValue(alloc::format!(
                "{label} row count {len} overflows row size {}",
                size_of::<T>()
            ))
        })?;
        let bytes = self.read_slice(byte_len)?;
        let rows: &[T] = <[T] as zerocopy::FromBytes>::ref_from_bytes(bytes).map_err(|_| {
            DeserializationError::InvalidValue(alloc::format!(
                "{label} bytes do not form aligned POD rows"
            ))
        })?;
        rows.iter().copied().map(map).collect()
    }

    fn skip_alignment_padding<T>(&mut self) -> Result<(), DeserializationError> {
        let padding_required = self.pos.next_multiple_of(align_of::<T>()) - self.pos;
        self.pos += padding_required;
        if self.pos > self.source.len() {
            Err(DeserializationError::UnexpectedEOF)
        } else {
            Ok(())
        }
    }
}

impl ByteReader for PodSliceReader<'_> {
    fn max_alloc(&self, element_size: usize) -> usize {
        self.remaining_len().checked_div(element_size).unwrap_or(usize::MAX)
    }

    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        self.check_eor(1)?;
        let result = self.source[self.pos];
        self.pos += 1;
        Ok(result)
    }

    fn peek_u8(&self) -> Result<u8, DeserializationError> {
        self.check_eor(1)?;
        Ok(self.source[self.pos])
    }

    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        self.check_eor(len)?;
        let result = &self.source[self.pos..self.pos + len];
        self.pos += len;
        Ok(result)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        self.check_eor(N)?;
        let mut result = [0_u8; N];
        result.copy_from_slice(&self.source[self.pos..self.pos + N]);
        self.pos += N;
        Ok(result)
    }

    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError> {
        self.pos
            .checked_add(num_bytes)
            .filter(|end| *end <= self.source.len())
            .map(|_| ())
            .ok_or(DeserializationError::UnexpectedEOF)
    }

    fn has_more_bytes(&self) -> bool {
        self.remaining_len() != 0
    }
}

fn pad_to_align<T>(output: &mut Vec<u8>) {
    let padding_required = output.len().next_multiple_of(align_of::<T>()) - output.len();
    output.resize(output.len() + padding_required, 0);
}

fn write_pod_slice<T: IntoBytes + Immutable>(slice: &[T], target: &mut Vec<u8>) {
    pad_to_align::<T>(target);
    target.write_bytes(slice.as_bytes());
}

fn write_pod_rows<T, I>(rows: I, target: &mut Vec<u8>)
where
    T: IntoBytes + Immutable,
    I: IntoIterator<Item = T>,
{
    let rows: Vec<T> = rows.into_iter().collect();
    target.write_bytes(rows.as_bytes());
}

fn read_wire_felt(value: u64) -> Result<Felt, DeserializationError> {
    Felt::new(value).map_err(|err| {
        DeserializationError::InvalidValue(alloc::format!(
            "invalid field element in debug function MAST root: {err}"
        ))
    })
}

fn read_string<R: ByteReader>(source: &mut R) -> Result<Arc<str>, DeserializationError> {
    let len = read_bounded_len(source, "debug string bytes", 1)?;
    let bytes = source.read_slice(len)?;
    let s = core::str::from_utf8(bytes).map_err(|err| {
        DeserializationError::InvalidValue(alloc::format!("invalid utf-8 in string: {err}"))
    })?;
    Ok(Arc::from(s))
}

fn read_debug_type_indices<R: ByteReader>(
    source: &mut R,
    label: &str,
) -> Result<Vec<DebugTypeIdx>, DeserializationError> {
    let len = read_bounded_len(source, label, DebugTypeIdx::min_serialized_size())?;
    source.read_many_iter(len)?.collect::<Result<_, _>>()
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use miden_assembly_syntax::ast::DebugVarLocation;
    use miden_core::{Felt, Word};
    use miden_debug_types::{ByteIndex, ColumnNumber, LineNumber, Location, Uri};

    use super::*;
    use crate::debug_info::{DebugFileIdx, PackageDebugInfoBuilder};

    struct FixedBudgetReader<'a> {
        inner: miden_core::serde::SliceReader<'a>,
        max_bytes: usize,
        largest_requested_element_size: Cell<usize>,
    }

    impl<'a> FixedBudgetReader<'a> {
        fn new(bytes: &'a [u8], max_bytes: usize) -> Self {
            Self {
                inner: miden_core::serde::SliceReader::new(bytes),
                max_bytes,
                largest_requested_element_size: Cell::new(0),
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
            self.largest_requested_element_size
                .set(self.largest_requested_element_size.get().max(element_size));
            if element_size == 0 {
                usize::MAX
            } else {
                self.max_bytes.checked_div(element_size).unwrap_or(0)
            }
        }
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
    fn pod_row_reader_rejects_byte_length_overflow() {
        let mut reader = PodSliceReader::new(&[]);
        let result = reader.read_pod_rows::<DebugErrorMessage>(usize::MAX, "test error messages");
        let error = result.unwrap_err();

        let DeserializationError::InvalidValue(message) = error else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("overflows row size"));
    }

    #[test]
    fn pod_row_reader_decodes_certified_rows() {
        let expected = DebugErrorMessage::new(42, DebugStringIdx::from(7));
        let mut aligned = [0_u64; 2];
        aligned.as_mut_bytes()[..size_of::<DebugErrorMessage>()]
            .copy_from_slice(expected.as_bytes());
        let mut reader = PodSliceReader::new(aligned.as_bytes());
        let decoded = reader.read_pod_rows::<DebugErrorMessage>(1, "test error messages").unwrap();

        assert_eq!(decoded, [expected]);
    }

    #[test]
    fn debug_variant_min_serialized_size_is_accepted_by_slice_reader() {
        let variant = DebugVariantInfo {
            name_idx: DebugStringIdx::from(0),
            type_idx: None,
            payload_offset: None,
            discriminant: 0,
        };
        let mut bytes = Vec::new();
        variant.write_into(&mut bytes);

        assert_eq!(bytes.len(), DebugVariantInfo::min_serialized_size());

        let mut reader = miden_core::serde::SliceReader::new(&bytes);
        let mut variants = reader.read_many_iter::<DebugVariantInfo>(1).unwrap();
        assert_eq!(variants.next().unwrap().unwrap(), variant);
        assert!(variants.next().is_none());
    }

    #[test]
    fn debug_type_initial_capacity_is_bounded_by_in_memory_size() {
        const PAYLOAD_BYTES: usize = 256;

        let mut bytes = Vec::new();
        bytes.write_usize(PAYLOAD_BYTES);
        bytes.resize(bytes.len() + PAYLOAD_BYTES, u8::MAX);
        let mut reader = FixedBudgetReader::new(&bytes, PAYLOAD_BYTES);

        let result =
            IndexVec::<DebugTypeIdx, DebugTypeInfo>::read_from_bounded(&mut reader, "debug types");

        assert!(result.is_err(), "the first invalid type tag should stop decoding");
        assert_eq!(
            reader.largest_requested_element_size.get(),
            size_of::<DebugTypeInfo>(),
            "the speculative capacity must be bounded using the in-memory row size",
        );
    }

    #[test]
    fn package_debug_info_trailing_data_error_reports_remaining_bytes() {
        const TRAILING: &[u8] = &[0xaa, 0xbb, 0xcc];

        let serialized = PackageDebugInfo::default().to_bytes();
        let mut reader = miden_core::serde::SliceReader::new(&serialized);
        let version = reader.read_u8().unwrap();
        let data_len = reader.read_usize().unwrap();
        let data = reader.read_slice(data_len).unwrap().to_vec();
        assert!(!reader.has_more_bytes());

        let mut malformed = Vec::new();
        malformed.write_u8(version);
        malformed.write_usize(data_len + TRAILING.len());
        malformed.write_bytes(&data);
        malformed.write_bytes(TRAILING);

        let error =
            PackageDebugInfo::read_from(&mut miden_core::serde::SliceReader::new(&malformed))
                .unwrap_err();
        let DeserializationError::InvalidValue(message) = error else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("but 3 remain in the buffer"), "{message}");
    }

    #[test]
    fn debug_source_node_trailing_data_error_reports_remaining_bytes() {
        const TRAILING: &[u8] = &[0xaa, 0xbb];

        let source_node = DebugSourceNode {
            exec_node: MastNodeId::new_unchecked(0),
            children: Vec::new(),
            op_start: 0,
            op_end: 0,
            asm_ops: Vec::new(),
            debug_vars: Vec::new(),
            inline_calls: Vec::new(),
        };
        let serialized = source_node.to_bytes();
        let mut reader = miden_core::serde::SliceReader::new(&serialized);
        let data_len = reader.read_usize().unwrap();
        let data = reader.read_slice(data_len).unwrap().to_vec();
        assert!(!reader.has_more_bytes());

        let mut malformed = Vec::new();
        malformed.write_usize(data_len + TRAILING.len());
        malformed.write_bytes(&data);
        malformed.write_bytes(TRAILING);

        let error =
            DebugSourceNode::read_from(&mut miden_core::serde::SliceReader::new(&malformed))
                .unwrap_err();
        let DeserializationError::InvalidValue(message) = error else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("but 2 remain in the buffer"), "{message}");
    }

    fn roundtrip_debug_info(value: &PackageDebugInfo) -> PackageDebugInfo {
        let bytes = value.to_bytes();
        let result =
            PackageDebugInfo::read_from(&mut miden_core::serde::SliceReader::new(bytes.as_slice()))
                .unwrap();
        assert_eq!(result.version(), value.version());
        assert_eq!(result.strings(), value.strings());
        assert_eq!(result.files(), value.files());
        assert_eq!(result.locations(), value.locations());
        assert_eq!(result.types(), value.types());
        assert_eq!(result.functions(), value.functions());
        assert_eq!(result.nodes().as_slice(), value.nodes().as_slice());
        assert_eq!(result.roots(), value.roots());
        assert_eq!(result.error_messages(), value.error_messages());
        result
    }

    #[test]
    fn test_debug_types_roundtrip() {
        let mut builder = PackageDebugInfoBuilder::default();

        let i32_type_idx = builder.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I32));
        let felt_type_idx = builder.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Felt));
        builder.add_type(DebugTypeInfo::Pointer { pointee_type_idx: i32_type_idx });
        builder.add_type(DebugTypeInfo::Array {
            element_type_idx: felt_type_idx,
            count: Some(4),
        });

        let x_idx = builder.add_string("x");
        let y_idx = builder.add_string("y");
        let point_idx = builder.add_string("Point");
        builder.add_type(DebugTypeInfo::Struct {
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

        let status_idx = builder.add_string("Status");
        let ok_idx = builder.add_string("Ok");
        let err_idx = builder.add_string("Err");
        builder.add_type(DebugTypeInfo::Enum {
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

        let debug_info = *builder.build();
        let result = roundtrip_debug_info(&debug_info);
        assert_eq!(result.strings(), debug_info.strings());
        assert_eq!(result.types(), debug_info.types());
    }

    #[test]
    fn test_debug_sources_roundtrip() {
        let mut builder = PackageDebugInfoBuilder::default();
        builder.add_file(Uri::new("test.rs"), None);
        builder.add_file(Uri::new("main.rs"), Some([42u8; 32]));

        let debug_info = *builder.build();
        let result = roundtrip_debug_info(&debug_info);
        assert_eq!(result.strings(), debug_info.strings());
        assert_eq!(result.files(), debug_info.files());
        assert_eq!(result.files()[DebugFileIdx::from(1)].checksum(), Some(&[42u8; 32]));
    }

    #[test]
    fn test_debug_functions_roundtrip() {
        let mut builder = PackageDebugInfoBuilder::default();
        let name_idx = builder.add_string("test_function");
        let file_idx = builder.add_file(Uri::new("test.masm"), None);
        let line = LineNumber::new(10).unwrap();
        let column = ColumnNumber::new(1).unwrap();
        builder.add_function(DebugFunctionInfo::new(
            None,
            name_idx,
            file_idx,
            line,
            column,
            Word::default(),
        ));

        let debug_info = *builder.build();
        let result = roundtrip_debug_info(&debug_info);
        assert_eq!(result.functions(), debug_info.functions());
    }

    #[test]
    fn debug_function_v2_wire_bytes_are_stable() {
        const EXPECTED_ROW: [u8; size_of::<WireDebugFunctionInfo>()] = [
            1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 11, 0, 0, 0, 13,
            0, 0, 0, 15, 0, 0, 0, 17, 0, 0, 0, 19, 0, 0, 0,
        ];

        let function = DebugFunctionInfo {
            mast_root: Word::new([
                Felt::new(1).unwrap(),
                Felt::new(2).unwrap(),
                Felt::new(3).unwrap(),
                Felt::new(4).unwrap(),
            ]),
            source_node: Some(DebugSourceNodeId::from(7)).into(),
            type_idx: Some(DebugTypeIdx::from(9)).into(),
            linkage_name_idx: Some(DebugStringIdx::from(11)).into(),
            name_idx: DebugStringIdx::from(13),
            file_idx: DebugFileIdx::from(15),
            line: LineIndex::from(17),
            column: ColumnIndex::from(19),
        };
        let mut builder = PackageDebugInfoBuilder::default();
        builder.add_function(function);
        let debug_info = builder.build();

        let bytes = debug_info.to_bytes();
        assert_eq!(bytes[0], 2);
        assert!(
            bytes.windows(EXPECTED_ROW.len()).any(|window| window == EXPECTED_ROW),
            "serialized debug info did not contain the expected function row",
        );

        let decoded =
            PackageDebugInfo::read_from(&mut miden_core::serde::SliceReader::new(&bytes)).unwrap();
        assert_eq!(decoded.functions(), [function]);
    }

    #[test]
    fn test_debug_source_graph_roundtrip() {
        let mut builder = PackageDebugInfoBuilder::default();
        let child = builder
            .add_node(DebugSourceNode {
                exec_node: MastNodeId::new_unchecked(0),
                children: alloc::vec![],
                op_start: 0,
                op_end: 1,
                asm_ops: alloc::vec![],
                debug_vars: alloc::vec![],
                inline_calls: alloc::vec![],
            })
            .unwrap();
        let root = builder
            .add_node(DebugSourceNode {
                exec_node: MastNodeId::new_unchecked(1),
                children: alloc::vec![child],
                op_start: 1,
                op_end: 3,
                asm_ops: alloc::vec![],
                debug_vars: alloc::vec![],
                inline_calls: alloc::vec![],
            })
            .unwrap();
        builder.add_root(root);

        let debug_info = *builder.build();
        let result = roundtrip_debug_info(&debug_info);
        assert_eq!(result.nodes().as_slice(), debug_info.nodes().as_slice());
        assert_eq!(result.roots(), debug_info.roots());
    }

    #[test]
    fn test_debug_source_metadata_roundtrip() {
        let mut builder = PackageDebugInfoBuilder::default();
        let location =
            Location::new(Uri::new("file://test.masm"), ByteIndex::new(10), ByteIndex::new(14));
        let location_idx = builder.add_location(location);
        let file_idx = builder.debug_info().locations()[location_idx].file_idx;
        let context_name_idx = builder.add_string("test::ctx");
        let op_name_idx = builder.add_string("add");
        let var_name_idx = builder.add_string("x");
        let function_name_idx = builder.add_string("callee");
        let function_idx = builder.add_function(DebugFunctionInfo::new(
            None,
            function_name_idx,
            file_idx,
            LineNumber::new(10).unwrap(),
            ColumnNumber::new(5).unwrap(),
            Word::default(),
        ));

        let root = builder
            .add_node(DebugSourceNode {
                exec_node: MastNodeId::new_unchecked(0),
                children: alloc::vec![],
                op_start: 0,
                op_end: 3,
                asm_ops: alloc::vec![DebugSourceAsmOp::new(
                    2,
                    Some(location_idx),
                    context_name_idx,
                    op_name_idx,
                    1,
                )],
                debug_vars: alloc::vec![DebugSourceVar {
                    op_idx: 2,
                    name_idx: var_name_idx,
                    type_id: None,
                    arg_idx: None,
                    location_idx: None,
                    value_location: DebugVarLocation::Stack(0),
                }],
                inline_calls: alloc::vec![DebugSourceInlineCall {
                    op_idx: 2,
                    callee_idx: function_idx,
                    loc_idx: location_idx,
                }],
            })
            .unwrap();
        builder.add_root(root);

        let debug_info = *builder.build();
        let result = roundtrip_debug_info(&debug_info);
        assert_eq!(result.nodes().as_slice(), debug_info.nodes().as_slice());
        assert_eq!(result.locations(), debug_info.locations());
        assert_eq!(result.functions(), debug_info.functions());
        assert_eq!(result.get_string(context_name_idx).as_deref(), Some("test::ctx"));
        assert_eq!(result.get_location(location_idx), debug_info.get_location(location_idx));
    }

    #[test]
    fn test_debug_source_locations_are_deduplicated() {
        let mut builder = PackageDebugInfoBuilder::default();
        let location =
            Location::new(Uri::new("file://test.masm"), ByteIndex::new(10), ByteIndex::new(14));
        let first_location_idx = builder.add_location(location.clone());
        let second_location_idx = builder.add_location(location);
        assert_eq!(first_location_idx, second_location_idx);
        assert_eq!(builder.debug_info().locations().len(), 1);

        let context_name_idx = builder.add_string("test::ctx");
        let push_name_idx = builder.add_string("push.1");
        let add_name_idx = builder.add_string("add");
        let root = builder
            .add_node(DebugSourceNode {
                exec_node: MastNodeId::new_unchecked(0),
                children: alloc::vec![],
                op_start: 0,
                op_end: 2,
                asm_ops: alloc::vec![
                    DebugSourceAsmOp::new(
                        0,
                        Some(first_location_idx),
                        context_name_idx,
                        push_name_idx,
                        1,
                    ),
                    DebugSourceAsmOp::new(
                        1,
                        Some(second_location_idx),
                        context_name_idx,
                        add_name_idx,
                        1,
                    ),
                ],
                debug_vars: alloc::vec![],
                inline_calls: alloc::vec![],
            })
            .unwrap();
        builder.add_root(root);

        let debug_info = *builder.build();
        let result = roundtrip_debug_info(&debug_info);
        assert_eq!(result.locations().len(), 1);
        assert_eq!(
            result.source_node(root).unwrap().asm_ops,
            debug_info.source_node(root).unwrap().asm_ops
        );
    }

    #[test]
    fn test_debug_source_strings_are_deduplicated() {
        let mut builder = PackageDebugInfoBuilder::default();
        let context_name_idx = builder.add_string("test::ctx");
        let same_context_name_idx = builder.add_string("test::ctx");
        let add_name_idx = builder.add_string("add");
        let same_add_name_idx = builder.add_string("add");
        let mul_name_idx = builder.add_string("mul");
        let other_context_idx = builder.add_string("test::other");
        assert_eq!(context_name_idx, same_context_name_idx);
        assert_eq!(add_name_idx, same_add_name_idx);

        let root = builder
            .add_node(DebugSourceNode {
                exec_node: MastNodeId::new_unchecked(0),
                children: alloc::vec![],
                op_start: 0,
                op_end: 3,
                asm_ops: alloc::vec![
                    DebugSourceAsmOp::new(0, None, context_name_idx, add_name_idx, 1,),
                    DebugSourceAsmOp::new(1, None, same_context_name_idx, mul_name_idx, 1,),
                    DebugSourceAsmOp::new(2, None, other_context_idx, same_add_name_idx, 1,),
                ],
                debug_vars: alloc::vec![],
                inline_calls: alloc::vec![],
            })
            .unwrap();
        builder.add_root(root);

        let debug_info = *builder.build();
        let result = roundtrip_debug_info(&debug_info);
        assert_eq!(result.strings(), debug_info.strings());
        assert_eq!(
            result.source_node(root).unwrap().asm_ops,
            debug_info.source_node(root).unwrap().asm_ops
        );
    }

    #[test]
    fn test_debug_error_messages_roundtrip() {
        let mut builder = PackageDebugInfoBuilder::default();
        assert!(builder.add_error_message(42, Arc::from("assertion message")));

        let debug_info = *builder.build();
        let result = roundtrip_debug_info(&debug_info);
        assert_eq!(result.error_messages(), debug_info.error_messages());
        assert_eq!(result.error_message(42).as_deref(), Some("assertion message"));
    }

    #[test]
    fn test_empty_debug_info_roundtrip() {
        let debug_info = PackageDebugInfo::default();
        let result = roundtrip_debug_info(&debug_info);
        assert!(result.strings().is_empty());
        assert!(result.files().is_empty());
        assert!(result.locations().is_empty());
        assert!(result.types().is_empty());
        assert!(result.functions().is_empty());
        assert!(result.nodes().is_empty());
        assert!(result.roots().is_empty());
        assert!(result.error_messages().is_empty());
    }

    #[test]
    fn test_all_primitive_types_roundtrip() {
        let mut builder = PackageDebugInfoBuilder::default();

        for primitive in [
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
            builder.add_type(DebugTypeInfo::Primitive(primitive));
        }

        let debug_info = *builder.build();
        let result = roundtrip_debug_info(&debug_info);
        assert_eq!(result.types(), debug_info.types());
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
        let file = DebugFileInfo::new(DebugStringIdx::from(0)).with_checksum([42u8; 32]);
        roundtrip(&file);
    }

    #[test]
    fn test_debug_info_v1_is_rejected() {
        let bytes = [1];
        let mut reader = miden_core::serde::SliceReader::new(&bytes);
        let error = PackageDebugInfo::read_from(&mut reader).unwrap_err();
        let DeserializationError::InvalidValue(message) = error else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("unsupported debug_info version: 1"));
    }

    #[test]
    fn test_debug_info_payload_bounds() {
        let bytes = PackageDebugInfo::default().to_bytes();

        let mut reader = FixedBudgetReader::new(&bytes, 1);
        let error = PackageDebugInfo::read_from(&mut reader).unwrap_err();
        let DeserializationError::InvalidValue(message) = error else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("package debug info"));
        assert!(message.contains("exceeds budget"));

        let mut reader = FixedBudgetReader::new(&bytes, bytes.len());
        let result = PackageDebugInfo::read_from(&mut reader).unwrap();
        assert!(result.nodes().is_empty());
    }

    #[test]
    fn test_debug_info_rejects_truncated_string_table() {
        let mut payload = Vec::new();
        payload.write_usize(2);

        let mut bytes = Vec::new();
        bytes.write_u8(DEBUG_INFO_VERSION);
        bytes.write_usize(payload.len());
        bytes.write_bytes(&payload);

        let mut reader = miden_core::serde::SliceReader::new(&bytes);
        let error = PackageDebugInfo::read_from(&mut reader).unwrap_err();
        let DeserializationError::InvalidValue(message) = error else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("debug_info strings count 2"));
        assert!(message.contains("exceeds budget"));
    }

    #[test]
    fn test_function_params_bounds() {
        let too_many = function_type_bytes(2);
        let mut reader = FixedBudgetReader::new(&too_many, 4);
        let error = DebugTypeInfo::read_from(&mut reader).unwrap_err();
        assert!(matches!(error, DeserializationError::InvalidValue(_)));

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
