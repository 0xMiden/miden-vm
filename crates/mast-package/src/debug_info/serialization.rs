//! Serialization and deserialization for the debug_info section.

use alloc::{sync::Arc, vec::Vec};
use core::{alloc::Layout, ptr::NonNull};

use miden_core::{
    mast::MastNodeId,
    operations::DebugVarLocation,
    serde::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        read_bounded_len,
    },
};
use miden_utils_indexing::IndexVec;

use super::{
    DEBUG_INFO_VERSION, DebugErrorMessage, DebugFieldInfo, DebugFileInfo, DebugFunctionIdx,
    DebugFunctionInfo, DebugLoc, DebugLocIdx, DebugPrimitiveType, DebugSourceAsmOp,
    DebugSourceInlineCall, DebugSourceNode, DebugSourceNodeId, DebugSourceVar, DebugStringIdx,
    DebugTypeIdx, DebugTypeInfo, DebugVariantInfo, PackageDebugInfo,
};

/// The minimum alignment required for buffers containing directly decoded debug-info rows.
const DEBUG_INFO_BUFFER_ALIGNMENT: usize = max_alignment(
    max_alignment(
        max_alignment(align_of::<DebugFileInfo>(), align_of::<DebugLoc>()),
        max_alignment(align_of::<DebugFunctionInfo>(), align_of::<DebugSourceNodeId>()),
    ),
    max_alignment(align_of::<DebugErrorMessage>(), align_of::<DebugSourceAsmOp>()),
);

const fn max_alignment(lhs: usize, rhs: usize) -> usize {
    if lhs > rhs { lhs } else { rhs }
}

const _: () = {
    assert!(DEBUG_INFO_BUFFER_ALIGNMENT.is_power_of_two());
    assert!(DEBUG_INFO_BUFFER_ALIGNMENT >= align_of::<DebugFileInfo>());
    assert!(DEBUG_INFO_BUFFER_ALIGNMENT >= align_of::<DebugLoc>());
    assert!(DEBUG_INFO_BUFFER_ALIGNMENT >= align_of::<DebugFunctionInfo>());
    assert!(DEBUG_INFO_BUFFER_ALIGNMENT >= align_of::<DebugSourceNodeId>());
    assert!(DEBUG_INFO_BUFFER_ALIGNMENT >= align_of::<DebugErrorMessage>());
    assert!(DEBUG_INFO_BUFFER_ALIGNMENT >= align_of::<DebugSourceAsmOp>());
};

// PACKAGE DEBUG INFO SERIALIZATION
// ================================================================================================

/// [PackageDebugInfo] is a very rich and information-dense structure, and so we need to use a few
/// unsafe tricks in order to keep the (de)serialization performance within a reasonable bound).
/// Most notably, we attempt to (de)serialize entire rows/tables of data to/from memory directly to
/// the output buffer without invoking per-element (de)serializers. This allows us to avoid a
/// significant amount of overhead, but the tradeoff is that it is much more fragile and highly
/// unsafe - we mitigate this by imposing specific restrictions on types which can be serialized
/// this way (primarily, the type must be `Copy`).
///
/// In order to ensure we can deserialize the data using the same process (copying data out of the
/// buffer into memory directly), we ensure that the output data is padded in such a way that when
/// extracted to an aligned buffer in memory, we are guaranteed to be able to directly reference
/// the encoded rows as a slice of the desired type, and uphold the requirements Rust imposes on
/// references.
impl Serializable for PackageDebugInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // We serialize to a temporary buffer in memory with a starting size of 16k
        //
        // This allows us to emit padding bytes to keep specific parts of the serialized data
        // aligned according to the required minimum alignment requirements of that data so that
        // we can construct direct references to it during deserialization.
        let mut output = Vec::<u8>::with_capacity(16 * 1024);

        self.strings.write_into(&mut output);

        output.write_u32(self.files().len().try_into().unwrap());
        pad_to_align::<DebugFileInfo>(&mut output);
        unsafe {
            copy_slice_memory_to_output(self.files().as_slice(), &mut output);
        }

        output.write_u32(self.locations().len().try_into().unwrap());
        pad_to_align::<DebugLoc>(&mut output);
        unsafe {
            copy_slice_memory_to_output(self.locations().as_slice(), &mut output);
        }

        self.types.write_into(&mut output);

        output.write_u32(self.functions().len().try_into().unwrap());
        pad_to_align::<DebugFunctionInfo>(&mut output);
        unsafe {
            copy_slice_memory_to_output(self.functions(), &mut output);
        }

        self.nodes.write_into(&mut output);

        output.write_u32(self.roots().len().try_into().unwrap());
        pad_to_align::<DebugSourceNodeId>(&mut output);
        unsafe {
            copy_slice_memory_to_output(self.roots(), &mut output);
        }

        output.write_u32(self.error_messages().len().try_into().unwrap());
        pad_to_align::<DebugErrorMessage>(&mut output);
        unsafe {
            copy_slice_memory_to_output(self.error_messages(), &mut output);
        }

        target.write_u8(self.version());
        target.write_usize(output.len());
        target.write_bytes(&output);
    }
}

impl Deserializable for PackageDebugInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let version = source.read_u8()?;
        if version != DEBUG_INFO_VERSION {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "unsupported debug_info version: {version}, expected {DEBUG_INFO_VERSION}"
            )));
        }

        // Read the serialized data into a temporary allocation specifically aligned so that we
        // can construct references directly into it for certain rows/tables. It is not safe to do
        // so unless we guarantee the alignment of the entire buffer, because our padding bytes
        // are emitted based relative to the start of the buffer.
        let data_len = read_bounded_len(source, "package debug info", 1)?;
        let data = source.read_slice(data_len)?;
        // Copy the data to an allocation whose base alignment satisfies every row type decoded
        // directly from this buffer. The owner retains the allocation layout so it can deallocate
        // the buffer with the same layout later.
        let data = AlignedBytes::copy_from_slice(data, DEBUG_INFO_BUFFER_ALIGNMENT)?;

        let mut source = AlignedSliceReader::new(data.as_slice());

        let strings =
            IndexVec::read_from_bounded_with(&mut source, "debug_info strings", 1, read_string)?;

        let files_len = source.read_u32()?;
        let files = source.read_aligned_slice_of::<DebugFileInfo>(files_len as usize)?.to_vec();

        let locations_len = source.read_u32()?;
        let locations = source.read_aligned_slice_of::<DebugLoc>(locations_len as usize)?.to_vec();

        let types = IndexVec::read_from_bounded(&mut source, "debug_info types")?;

        let functions_len = source.read_u32()?;
        let functions = source
            .read_aligned_slice_of::<DebugFunctionInfo>(functions_len as usize)?
            .to_vec();

        let nodes = IndexVec::read_from_bounded(&mut source, "debug_info nodes")?;

        let roots_len = source.read_u32()? as usize;
        let roots = source.read_aligned_slice_of::<DebugSourceNodeId>(roots_len)?.to_vec();

        let error_messages_len = source.read_u32()? as usize;
        let error_messages =
            source.read_aligned_slice_of::<DebugErrorMessage>(error_messages_len)?.to_vec();

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

/// We use the same techniques with [DebugSourceNode] as [PackageDebugInfo] itself, as it is a
/// complex record in the debug info, the largest, and contains multiple sub-tables of data linked
/// to the node.
///
/// See the doc on the `Serializable` impl of `PackageDebugInfo` for details
impl Serializable for DebugSourceNode {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // We serialize to a temporary buffer in memory with sufficient minimum capacity to hold
        // a single DebugSourceNode.
        //
        // This allows us to emit padding bytes to keep specific parts of the serialized data
        // aligned according to the required minimum alignment requirements of that data so that
        // we can construct direct references to it during deserialization.
        let mut output = Vec::<u8>::with_capacity(
            size_of::<DebugSourceNode>()
                + (self.asm_ops.len() * size_of::<DebugSourceAsmOp>())
                + (self.debug_vars.len() * size_of::<DebugSourceVar>())
                + (self.inline_calls.len() * size_of::<DebugSourceInlineCall>()),
        );

        output.write_u32(self.exec_node.into());

        output.write_u32(self.children.len().try_into().unwrap());
        pad_to_align::<DebugSourceNodeId>(&mut output);
        unsafe {
            copy_slice_memory_to_output(self.children.as_slice(), &mut output);
        }

        output.write_u32(self.op_start);
        output.write_u32(self.op_end);

        output.write_u32(self.asm_ops.len().try_into().unwrap());
        pad_to_align::<DebugSourceAsmOp>(&mut output);
        unsafe {
            copy_slice_memory_to_output(self.asm_ops.as_slice(), &mut output);
        }

        self.debug_vars.write_into(&mut output);
        self.inline_calls.write_into(&mut output);

        target.write_usize(output.len());
        target.write_bytes(&output);
    }
}

impl Deserializable for DebugSourceNode {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // Read the serialized data into a temporary allocation specifically aligned so that we
        // can construct references directly into it for certain rows/tables. It is not safe to do
        // so unless we guarantee the alignment of the entire buffer, because our padding bytes
        // are emitted based relative to the start of the buffer.
        let data_len = read_bounded_len(source, "debug source node", 1)?;
        let data = source.read_slice(data_len)?;
        // Keep the same base-alignment guarantee as the package-level buffer so every directly
        // decoded row remains aligned even if new row types are shared between the two payloads.
        let data = AlignedBytes::copy_from_slice(data, DEBUG_INFO_BUFFER_ALIGNMENT)?;

        let mut source = AlignedSliceReader::new(data.as_slice());

        let exec_node = MastNodeId::new_unchecked(source.read_u32()?);

        let children_len = source.read_u32()? as usize;
        let children = source.read_aligned_slice_of::<DebugSourceNodeId>(children_len)?.to_vec();

        let op_start = source.read_u32()?;
        let op_end = source.read_u32()?;

        let asm_ops_len = source.read_u32()? as usize;
        let asm_ops = source.read_aligned_slice_of::<DebugSourceAsmOp>(asm_ops_len)?.to_vec();

        let debug_vars = Vec::read_from(&mut source)?;
        let inline_calls = Vec::read_from(&mut source)?;

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
        let type_id = Option::<u32>::read_from(source)?;
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

/// An owned byte buffer whose allocation layout is preserved until deallocation.
struct AlignedBytes {
    ptr: Option<NonNull<u8>>,
    layout: Layout,
}

impl AlignedBytes {
    fn copy_from_slice(source: &[u8], alignment: usize) -> Result<Self, DeserializationError> {
        let layout = Layout::from_size_align(source.len(), alignment).map_err(|_| {
            DeserializationError::InvalidValue(format!(
                "debug info payload size {} is too large: unable to allocate aligned buffer of sufficient size",
                source.len()
            ))
        })?;

        if source.is_empty() {
            return Ok(Self { ptr: None, layout });
        }

        // SAFETY: `layout` has non-zero size in this branch and was constructed successfully above.
        let ptr = unsafe { alloc::alloc::alloc(layout) };
        let Some(ptr) = NonNull::new(ptr) else {
            alloc::alloc::handle_alloc_error(layout)
        };
        // SAFETY: `ptr` points to a newly allocated block of `source.len()` bytes and therefore
        // does not overlap `source`. Both pointers are valid for reads/writes of
        // `source.len()` bytes.
        unsafe {
            ptr.as_ptr().copy_from_nonoverlapping(source.as_ptr(), source.len());
        }

        Ok(Self { ptr: Some(ptr), layout })
    }

    fn as_slice(&self) -> &[u8] {
        let Some(ptr) = self.ptr else {
            return &[];
        };
        // SAFETY: `ptr` was allocated for `layout` and remains owned by `self`, so it is valid for
        // reads of `layout.size()` bytes for the lifetime of this borrow.
        unsafe { core::slice::from_raw_parts(ptr.as_ptr(), self.layout.size()) }
    }
}

impl Drop for AlignedBytes {
    fn drop(&mut self) {
        if let Some(ptr) = self.ptr {
            // SAFETY: `ptr` was allocated with this exact layout in `copy_from_slice`, has not been
            // deallocated, and is never present for the zero-sized layout.
            unsafe {
                alloc::alloc::dealloc(ptr.as_ptr(), self.layout);
            }
        }
    }
}

struct AlignedSliceReader<'a> {
    source: &'a [u8],
    pos: usize,
}

impl<'a> AlignedSliceReader<'a> {
    /// Creates a new slice reader from the specified slice.
    fn new(source: &'a [u8]) -> Self {
        AlignedSliceReader { source, pos: 0 }
    }

    fn read_aligned_slice_of<T>(&mut self, len: usize) -> Result<&[T], DeserializationError> {
        self.skip_alignment_padding::<T>()?;
        let byte_len = len.checked_mul(size_of::<T>()).ok_or_else(|| {
            DeserializationError::InvalidValue(alloc::format!(
                "aligned slice count {len} overflows element size {}",
                size_of::<T>()
            ))
        })?;
        if len == 0 {
            return Ok(&[]);
        }
        let bytes = self.read_slice(byte_len)?;
        let ptr = bytes.as_ptr().cast::<T>();
        if !ptr.is_aligned() {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "aligned slice at byte offset {} does not satisfy alignment {}",
                self.pos - byte_len,
                align_of::<T>(),
            )));
        }
        // SAFETY: The byte range was bounds-checked above, starts at an address aligned for `T`,
        // and spans exactly `len * size_of::<T>()` bytes. The high-throughput wire format
        // separately requires callers to use row types whose encoded bytes are valid values
        // of `T`.
        Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
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

impl ByteReader for AlignedSliceReader<'_> {
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
        self.pos < self.source.len()
    }
}

fn pad_to_align<T>(output: &mut Vec<u8>) {
    let padding_required = output.len().next_multiple_of(align_of::<T>()) - output.len();
    for _ in 0..padding_required {
        output.write_u8(0);
    }
}

unsafe fn copy_slice_memory_to_output<T: Copy>(slice: &[T], output: &mut Vec<u8>) {
    unsafe {
        let ptr = slice.as_ptr() as *const u8;
        let slice_layout = Layout::array::<T>(slice.len()).unwrap();
        let range = slice.as_ptr_range();
        let actual_size = range.end.byte_offset_from_unsigned(range.start);
        let layout_size = slice_layout.size();
        assert!(
            actual_size >= layout_size,
            "expected layout of slice of len {} ({layout_size} bytes) to be <= {actual_size} bytes",
            slice.len()
        );
        let bytes = core::slice::from_raw_parts(ptr, actual_size);
        output.write_bytes(bytes);
    }
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
    use miden_core::{Word, operations::DebugVarLocation};
    use miden_debug_types::{ByteIndex, ColumnNumber, LineNumber, Location, Uri};

    use super::*;
    use crate::debug_info::{DebugFileIdx, PackageDebugInfoBuilder};

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
    fn aligned_bytes_preserves_contents_and_required_alignment() {
        let payload = [1, 2, 3, 4, 5];
        let data = AlignedBytes::copy_from_slice(&payload, DEBUG_INFO_BUFFER_ALIGNMENT).unwrap();

        assert_eq!(data.as_slice(), payload);
        assert_eq!(data.as_slice().as_ptr().addr() % DEBUG_INFO_BUFFER_ALIGNMENT, 0);
    }

    #[test]
    fn aligned_bytes_handles_empty_payload() {
        let data = AlignedBytes::copy_from_slice(&[], DEBUG_INFO_BUFFER_ALIGNMENT).unwrap();

        assert!(data.ptr.is_none());
        assert!(data.as_slice().is_empty());
        assert_eq!(data.layout.size(), 0);
        assert_eq!(data.layout.align(), DEBUG_INFO_BUFFER_ALIGNMENT);
    }

    #[test]
    fn aligned_slice_reader_rejects_byte_length_overflow() {
        let mut reader = AlignedSliceReader::new(&[]);
        let error = reader.read_aligned_slice_of::<u64>(usize::MAX).unwrap_err();

        let DeserializationError::InvalidValue(message) = error else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("overflows element size"));
    }

    #[test]
    fn aligned_slice_reader_supports_maximum_row_alignment() {
        let bytes = [0u8; size_of::<DebugErrorMessage>()];
        let data = AlignedBytes::copy_from_slice(&bytes, DEBUG_INFO_BUFFER_ALIGNMENT).unwrap();
        let mut reader = AlignedSliceReader::new(data.as_slice());

        assert_eq!(reader.read_aligned_slice_of::<DebugErrorMessage>(1).unwrap().len(), 1);
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
        assert!(message.contains("exceeds remaining input"));
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
