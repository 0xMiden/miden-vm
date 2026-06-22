use alloc::{alloc::Layout, collections::VecDeque};
use core::cmp::{self, Ordering};

use smallvec::{SmallVec, smallvec};

use super::*;

const FELT_SIZE: usize = core::mem::size_of::<u32>();
const WORD_SIZE: usize = core::mem::size_of::<[u32; 4]>();

impl Type {
    /// Convert this type into a vector of types corresponding to how this type
    /// will be represented in memory.
    ///
    /// The largest "part" size is 32 bits, so types that fit in 32 bits remain
    /// unchanged. For types larger than 32 bits, they will be broken up into parts
    /// that do fit in 32 bits, preserving accurate types to the extent possible.
    /// For types smaller than 32 bits, they will be merged into packed structs no
    /// larger than 32 bits, to preserve the type information, and make it possible
    /// to reason about how to extract parts of the original type.
    ///
    /// For an example, a struct of type `{ *ptr, u8, u8 }` will be encoded on the
    /// operand stack as `[*ptr, {u8, u8}]`, where the first value is the 32-bit pointer
    /// field, and the remaining fields are encoded as a 16-bit struct in the second value.
    pub fn to_raw_parts(self) -> Option<SmallVec<[Type; 4]>> {
        match self {
            Type::Unknown => None,
            ty => {
                let mut parts = SmallVec::<[Type; 4]>::default();
                let (part, mut rest) = ty.split(4);
                parts.push(part);
                while let Some(ty) = rest.take() {
                    let (part, remaining) = ty.split(4);
                    parts.push(part);
                    rest = remaining;
                }
                Some(parts)
            }
        }
    }

    /// Split this type into two parts:
    ///
    /// * The first part is no more than `n` bytes in size, and may contain the type itself if it
    ///   fits
    /// * The second part is None if the first part is smaller than or equal in size to the
    ///   requested split size
    /// * The second part is Some if there is data left in the original type after the split. This
    ///   part will be a type that attempts to preserve, to the extent possible, the original type
    ///   structure, but will fall back to an array of bytes if a larger type must be split down
    ///   the middle somewhere.
    pub fn split(self, n: usize) -> (Type, Option<Type>) {
        if n == 0 {
            return (self, None);
        }

        let size_in_bytes = self.size_in_bytes();
        if n >= size_in_bytes {
            return (self, None);
        }

        // The type is larger than the split size
        match self {
            ty @ (Self::U256
            | Self::I128
            | Self::U128
            | Self::I64
            | Self::U64
            | Self::F64
            | Self::Felt
            | Self::I32
            | Self::U32
            | Self::Ptr(_)
            | Self::I16
            | Self::U16
            | Self::Function(_)
            | Self::Enum(_)) => {
                let len = ty.size_in_bytes();
                let remaining = len - n;
                match (n, remaining) {
                    (0, _) | (_, 0) => unreachable!(),
                    (1, 1) => (Type::U8, Some(Type::U8)),
                    (1, remaining) => {
                        (Type::U8, Some(Type::from(ArrayType::new(Type::U8, remaining))))
                    }
                    (taken, 1) => (Type::from(ArrayType::new(Type::U8, taken)), Some(Type::U8)),
                    (taken, remaining) => (
                        Type::from(ArrayType::new(Type::U8, taken)),
                        Some(Type::from(ArrayType::new(Type::U8, remaining))),
                    ),
                }
            }
            Self::Array(array_type) => match &*array_type {
                ArrayType {
                    ty: elem_ty,
                    len: 1,
                } => elem_ty.clone().split(n),
                ArrayType {
                    ty: elem_ty,
                    len: array_len,
                } => {
                    let elem_size = elem_ty.size_in_bytes();
                    if n >= elem_size {
                        // The requested split consumes 1 or more elements..
                        let take = n / elem_size;
                        let extra = n % elem_size;
                        if extra == 0 {
                            // The split is on an element boundary
                            let split = match take {
                                1 => (*elem_ty).clone(),
                                _ => Self::from(ArrayType::new(elem_ty.clone(), take)),
                            };
                            let rest = match array_len - take {
                                0 => unreachable!(),
                                1 => elem_ty.clone(),
                                len => Self::from(ArrayType::new(elem_ty.clone(), len)),
                            };
                            (split, Some(rest))
                        } else {
                            // The element type must be split somewhere in order to get the input type
                            // down to the requested size
                            let (partial1, partial2) = (*elem_ty).clone().split(elem_size - extra);
                            match array_len - take {
                                0 => unreachable!(),
                                1 => {
                                    let taken = Self::from(ArrayType::new(elem_ty.clone(), take));
                                    let split = Self::from(StructType::new_with_repr(
                                        TypeRepr::packed(1),
                                        [taken, partial1],
                                    ));
                                    (split, partial2)
                                }
                                remaining => {
                                    let remaining_input =
                                        Self::from(ArrayType::new(elem_ty.clone(), remaining));
                                    let taken = Self::from(ArrayType::new(elem_ty.clone(), take));
                                    let split = Self::from(StructType::new_with_repr(
                                        TypeRepr::packed(1),
                                        [taken, partial1],
                                    ));
                                    let rest = Self::from(StructType::new_with_repr(
                                        TypeRepr::packed(1),
                                        [partial2.unwrap(), remaining_input],
                                    ));
                                    (split, Some(rest))
                                }
                            }
                        }
                    } else {
                        // The requested split consumes less than one element
                        let (partial1, partial2) = (*elem_ty).clone().split(n);
                        let remaining_input = match array_len - 1 {
                            0 => unreachable!(),
                            1 => (*elem_ty).clone(),
                            len => Self::from(ArrayType::new(elem_ty.clone(), len - 1)),
                        };
                        let rest = Self::from(StructType::new_with_repr(
                            TypeRepr::packed(1),
                            [partial2.unwrap(), remaining_input],
                        ));
                        (partial1, Some(rest))
                    }
                }
            },
            Self::Struct(struct_ty) => match &*struct_ty {
                StructType {
                    repr: TypeRepr::Transparent,
                    fields,
                    ..
                } => {
                    let underlying = fields
                        .into_iter()
                        .find(|f| !f.ty.is_zst())
                        .expect("invalid type: expected non-zero sized field");
                    underlying.ty.clone().split(n)
                }
                struct_ty => {
                    let original_repr = struct_ty.repr;
                    let original_size = struct_ty.size;
                    let mut fields = VecDeque::from_iter(struct_ty.fields.iter().cloned());
                    let mut split = StructType {
                        name: None,
                        repr: original_repr,
                        size: 0,
                        fields: smallvec![],
                    };
                    let mut remaining = StructType {
                        name: None,
                        repr: TypeRepr::packed(1),
                        size: 0,
                        fields: smallvec![],
                    };
                    let mut needed: u32 = n.try_into().expect(
                        "invalid type split: number of bytes is larger than what is representable \
                         in memory",
                    );
                    let mut current_offset = 0u32;
                    while let Some(mut field) = fields.pop_front() {
                        let padding = field.offset - current_offset;
                        // If the padding was exactly what was needed, add it to the `split`
                        // struct, and then place the remaining fields in a new struct
                        let original_offset = field.offset;
                        if padding == needed {
                            split.size += needed;
                            // Handle the edge case where padding is at the front of the struct
                            if split.fields.is_empty() {
                                split.fields.push(StructField {
                                    name: None,
                                    index: 0,
                                    align: 1,
                                    offset: 0,
                                    ty: Type::from(ArrayType::new(Type::U8, needed as usize)),
                                });
                            }
                            let mut prev_offset = original_offset;
                            let mut field_offset = 0;
                            field.index = 0;
                            field.offset = field_offset;
                            remaining.repr = TypeRepr::Default;
                            remaining.size = original_size - split.size;
                            remaining.fields.reserve(1 + fields.len());
                            field_offset += field.ty.size_in_bytes() as u32;
                            remaining.fields.push(field);
                            for (index, mut field) in fields.into_iter().enumerate() {
                                field.index = (index + 1) as u8;
                                let align_offset = field.offset - prev_offset;
                                let field_size = field.ty.size_in_bytes() as u32;
                                prev_offset = field.offset + field_size;
                                field.offset = field_offset + align_offset;
                                field_offset += align_offset;
                                field_offset += field_size;
                                remaining.fields.push(field);
                            }
                            break;
                        }

                        // If the padding is more than was needed, we fill out the rest of the
                        // request by padding the size of the `split` struct, and then adjust
                        // the remaining struct to account for the leftover padding.
                        if padding > needed {
                            // The struct size must match the requested split size
                            split.size += needed;
                            // Handle the edge case where padding is at the front of the struct
                            if split.fields.is_empty() {
                                split.fields.push(StructField {
                                    name: None,
                                    index: 0,
                                    align: 1,
                                    offset: 0,
                                    ty: Type::from(ArrayType::new(Type::U8, needed as usize)),
                                });
                            }
                            // What's left must account for what has been split off
                            let leftover_padding = u16::try_from(padding - needed).expect(
                                "invalid type: padding is larger than maximum allowed alignment",
                            );
                            let effective_alignment = leftover_padding.prev_power_of_two();
                            let align_offset = leftover_padding % effective_alignment;
                            let default_alignment = cmp::max(
                                fields.iter().map(|f| f.align).max().unwrap_or(1),
                                field.align,
                            );
                            let repr = match default_alignment.cmp(&effective_alignment) {
                                Ordering::Equal => TypeRepr::Default,
                                Ordering::Greater => TypeRepr::packed(effective_alignment),
                                Ordering::Less => TypeRepr::align(effective_alignment),
                            };
                            let mut prev_offset = original_offset;
                            let mut field_offset = align_offset as u32;
                            field.index = 0;
                            field.offset = field_offset;
                            remaining.repr = repr;
                            remaining.size = original_size - split.size;
                            remaining.fields.reserve(1 + fields.len());
                            field_offset += field.ty.size_in_bytes() as u32;
                            remaining.fields.push(field);
                            for (index, mut field) in fields.into_iter().enumerate() {
                                field.index = (index + 1) as u8;
                                let align_offset = field.offset - prev_offset;
                                let field_size = field.ty.size_in_bytes() as u32;
                                prev_offset = field.offset + field_size;
                                field.offset = field_offset + align_offset;
                                field_offset += align_offset;
                                field_offset += field_size;
                                remaining.fields.push(field);
                            }
                            break;
                        }

                        // The padding must be less than what was needed, so consume it, and
                        // then process the current field for the rest of the request
                        split.size += padding;
                        needed -= padding;
                        current_offset += padding;
                        let field_size = field.ty.size_in_bytes() as u32;
                        // If the field fully satisifies the remainder of the request, then
                        // finalize the `split` struct, and place remaining fields in a trailing
                        // struct with an appropriate repr
                        if field_size == needed {
                            split.size += field_size;
                            field.offset = current_offset;
                            split.fields.push(field);

                            debug_assert!(
                                !fields.is_empty(),
                                "expected struct that is the exact size of the split request to \
                                 have been handled elsewhere"
                            );

                            remaining.repr = original_repr;
                            remaining.size = original_size - split.size;
                            remaining.fields.reserve(fields.len());
                            let mut prev_offset = current_offset + field_size;
                            let mut field_offset = 0;
                            for (index, mut field) in fields.into_iter().enumerate() {
                                field.index = index as u8;
                                let align_offset = field.offset - prev_offset;
                                let field_size = field.ty.size_in_bytes() as u32;
                                prev_offset = field.offset + field_size;
                                field.offset = field_offset + align_offset;
                                field_offset += align_offset;
                                field_offset += field_size;
                                remaining.fields.push(field);
                            }
                            break;
                        }

                        // If the field is larger than what is needed, we have to split it
                        if field_size > needed {
                            split.size += needed;

                            // Add the portion needed to `split`
                            let index = field.index;
                            let offset = current_offset;
                            let align = field.align;
                            let (partial1, partial2) = field.ty.split(needed as usize);
                            // The second half of the split will always be a type
                            let partial2 = partial2.unwrap();
                            split.fields.push(StructField {
                                name: None,
                                index,
                                offset,
                                align,
                                ty: partial1,
                            });

                            // Build a struct with the remaining fields and trailing partial field
                            let mut prev_offset = current_offset + needed;
                            let mut field_offset = needed + partial2.size_in_bytes() as u32;
                            remaining.size = original_size - split.size;
                            remaining.fields.reserve(1 + fields.len());
                            remaining.fields.push(StructField {
                                name: None,
                                index: 0,
                                offset: 1,
                                align: 1,
                                ty: partial2,
                            });
                            for (index, mut field) in fields.into_iter().enumerate() {
                                field.index = (index + 1) as u8;
                                let align_offset = field.offset - prev_offset;
                                let field_size = field.ty.size_in_bytes() as u32;
                                prev_offset = field.offset + needed + field_size;
                                field.offset = field_offset + align_offset;
                                field_offset += align_offset;
                                field_offset += field_size;
                                remaining.fields.push(field);
                            }
                            break;
                        }

                        // We need to process more fields for this request (i.e. field_size < needed)
                        needed -= field_size;
                        split.size += field_size;
                        field.offset = current_offset;
                        current_offset += field_size;
                        split.fields.push(field);
                    }

                    let split = if split.fields.len() > 1 {
                        Type::from(split)
                    } else {
                        split.fields.pop().map(|f| f.ty).unwrap()
                    };
                    match remaining.fields.len() {
                        0 => (split, None),
                        1 => (split, remaining.fields.pop().map(|f| f.ty)),
                        _ => (split, Some(remaining.into())),
                    }
                }
            },
            Type::List(_) => {
                todo!("invalid type: list has no defined representation yet, so cannot be split")
            }
            // These types either have no size, or are 1 byte in size, so must have
            // been handled above when checking if the size of the type is <= the
            // requested split size
            Self::Unknown | Self::Never | Self::I1 | Self::U8 | Self::I8 => {
                unreachable!()
            }
        }
    }

    /// Returns the minimum alignment, in bytes, of this type
    pub fn min_alignment(&self) -> usize {
        match self {
            // These types don't have a meaningful alignment, so choose byte-aligned
            Self::Unknown | Self::Never => 1,
            // Felts must be naturally aligned to a 32-bit boundary (4 bytes)
            Self::Felt => 4,
            // 256-bit and 128-bit integers must be word-aligned
            Self::U256 | Self::I128 | Self::U128 => 16,
            // 64-bit integers and floats must be element-aligned
            Self::I64 | Self::U64 | Self::F64 => 4,
            // 32-bit integers and pointers must be element-aligned
            Self::I32 | Self::U32 | Self::Ptr(_) | Self::Function(..) => 4,
            // 16-bit integers can be naturally aligned
            Self::I16 | Self::U16 => 2,
            // 8-bit integers and booleans can be naturally aligned
            Self::I8 | Self::U8 | Self::I1 => 1,
            // Structs use the minimum alignment of their first field, or 1 if a zero-sized type
            Self::Struct(struct_ty) => struct_ty.min_alignment(),
            // Enums use the minimum alignment of their largest variant, or 1 if a zero-sized type
            Self::Enum(enum_ty) => enum_ty.min_alignment(),
            // Arrays use the minimum alignment of their element type
            Self::Array(array_ty) => array_ty.min_alignment(),
            // Lists use the minimum alignment of their element type
            Self::List(element_ty) => element_ty.min_alignment(),
        }
    }

    /// Returns the size in bits of this type, without alignment padding.
    pub fn size_in_bits(&self) -> usize {
        match self {
            // These types have no representation in memory
            Self::Unknown | Self::Never => 0,
            // Booleans are represented as i1
            Self::I1 => 1,
            // Integers are naturally sized
            Self::I8 | Self::U8 => 8,
            Self::I16 | Self::U16 => 16,
            // Field elements have a range that is almost 64 bits, but because
            // our byte-addressable memory model only sees each element as a 32-bit
            // chunk, we treat field elements in this model as 32-bit values. This
            // has no effect on their available range, just how much memory they are
            // assumed to require for storage.
            Self::I32 | Self::U32 | Self::Felt => 32,
            Self::I64 | Self::U64 | Self::F64 => 64,
            Self::I128 | Self::U128 => 128,
            Self::U256 => 256,
            // Raw pointers  are 32-bits, the same size as the native integer width, u32
            Self::Ptr(_) | Self::Function(_) => 32,
            // Packed structs have no alignment padding between fields
            Self::Struct(struct_ty) => struct_ty.size as usize * 8,
            Self::Enum(enum_ty) => enum_ty.size_in_bits(),
            Self::Array(array_ty) => array_ty.size_in_bits(),
            Type::List(_) => todo!(
                "invalid type: list has no defined representation yet, so its size cannot be \
                 determined"
            ),
        }
    }

    /// Returns the minimum number of bytes required to store a value of this type
    pub fn size_in_bytes(&self) -> usize {
        let bits = self.size_in_bits();
        (bits / 8) + (!bits.is_multiple_of(8)) as usize
    }

    /// Same as `size_in_bytes`, but with sufficient padding to guarantee alignment of the value.
    pub fn aligned_size_in_bytes(&self) -> usize {
        let align = self.min_alignment();
        let size = self.size_in_bytes();
        // Zero-sized types have no alignment
        if size == 0 {
            return 0;
        }

        // Assuming that a pointer is allocated with the worst possible alignment,
        // i.e. it is not aligned on a power-of-two boundary, we can ensure that there
        // is enough space to align the pointer to the required minimum alignment and
        // still fit it in the allocated block of memory without overflowing its bounds,
        // by adding `align` to size.
        //
        // We panic if padding the size overflows `usize`.
        //
        // So let's say we have a type with a min alignment of 16, and size of 24. If
        // we add 16 to 24, we get 40. We then allocate a block of memory of 40 bytes,
        // the pointer of which happens to be at address 0x01. If we align that pointer
        // to 0x10 (the next closest aligned address within the block we allocated),
        // that consumes 15 bytes of the 40 we have, leaving us with 25 bytes to hold
        // our 24 byte value.
        size.checked_add(align)
            .expect("type cannot meet its minimum alignment requirement due to its size")
    }

    /// Returns the size in field elements of this type
    pub fn size_in_felts(&self) -> usize {
        let bytes = self.size_in_bytes();
        let trailing = bytes % FELT_SIZE;
        (bytes / FELT_SIZE) + ((trailing > 0) as usize)
    }

    /// Returns the size in words of this type
    pub fn size_in_words(&self) -> usize {
        let bytes = self.size_in_bytes();
        let trailing = bytes % WORD_SIZE;
        (bytes / WORD_SIZE) + ((trailing > 0) as usize)
    }

    /// Returns the layout of this type in memory
    pub fn layout(&self) -> Layout {
        Layout::from_size_align(self.size_in_bytes(), self.min_alignment())
            .expect("invalid layout: the size, when padded for alignment, overflows isize")
    }

    /// Returns true if this type can be loaded on to the operand stack
    ///
    /// The rule for "loadability" is a bit arbitrary, but the purpose is to
    /// force users of the IR to either pass large values by reference, or calculate
    /// the addresses of the individual fields needed from a large structure or array,
    /// and issue loads/stores against those instead.
    ///
    /// In effect, we reject loads of values that are larger than a single word, as that
    /// is the largest value which can be worked with on the operand stack of the Miden VM.
    pub fn is_loadable(&self) -> bool {
        self.size_in_words() <= WORD_SIZE
    }
}

#[cfg(test)]
mod tests {
    use smallvec::smallvec;

    use crate::*;

    #[test]
    fn struct_type_test() {
        let ptr_ty = Type::from(PointerType::new(Type::U32));
        // A struct with default alignment and padding between fields
        let struct_ty = StructType::new([ptr_ty.clone(), Type::U8, Type::I32]);
        assert_eq!(struct_ty.min_alignment(), ptr_ty.min_alignment());
        assert_eq!(struct_ty.size(), 12);
        assert_eq!(
            struct_ty.get(0),
            &StructField {
                name: None,
                index: 0,
                align: 4,
                offset: 0,
                ty: ptr_ty.clone()
            }
        );
        assert_eq!(
            struct_ty.get(1),
            &StructField {
                name: None,
                index: 1,
                align: 1,
                offset: 4,
                ty: Type::U8
            }
        );
        assert_eq!(
            struct_ty.get(2),
            &StructField {
                name: None,
                index: 2,
                align: 4,
                offset: 8,
                ty: Type::I32
            }
        );

        // A struct with no alignment requirement, and no alignment padding between fields
        let struct_ty =
            StructType::new_with_repr(TypeRepr::packed(1), [ptr_ty.clone(), Type::U8, Type::I32]);
        assert_eq!(struct_ty.min_alignment(), 1);
        assert_eq!(struct_ty.size(), 9);
        assert_eq!(
            struct_ty.get(0),
            &StructField {
                name: None,
                index: 0,
                align: 1,
                offset: 0,
                ty: ptr_ty.clone()
            }
        );
        assert_eq!(
            struct_ty.get(1),
            &StructField {
                name: None,
                index: 1,
                align: 1,
                offset: 4,
                ty: Type::U8
            }
        );
        assert_eq!(
            struct_ty.get(2),
            &StructField {
                name: None,
                index: 2,
                align: 1,
                offset: 5,
                ty: Type::I32
            }
        );

        // A struct with larger-than-default alignment, but default alignment for the fields
        let struct_ty =
            StructType::new_with_repr(TypeRepr::align(8), [ptr_ty.clone(), Type::U8, Type::I32]);
        assert_eq!(struct_ty.min_alignment(), 8);
        assert_eq!(struct_ty.size(), 16);
        assert_eq!(
            struct_ty.get(0),
            &StructField {
                name: None,
                index: 0,
                align: 4,
                offset: 0,
                ty: ptr_ty.clone()
            }
        );
        assert_eq!(
            struct_ty.get(1),
            &StructField {
                name: None,
                index: 1,
                align: 1,
                offset: 4,
                ty: Type::U8
            }
        );
        assert_eq!(
            struct_ty.get(2),
            &StructField {
                name: None,
                index: 2,
                align: 4,
                offset: 8,
                ty: Type::I32
            }
        );
    }

    #[test]
    fn type_to_raw_parts_test() {
        let ty = Type::from(ArrayType::new(Type::U8, 5));
        assert_eq!(
            ty.to_raw_parts(),
            Some(smallvec![Type::from(ArrayType::new(Type::U8, 4)), Type::U8,])
        );

        let ty = Type::from(ArrayType::new(Type::I16, 3));
        assert_eq!(
            ty.to_raw_parts(),
            Some(smallvec![Type::from(ArrayType::new(Type::I16, 2)), Type::I16,])
        );

        let ptr_ty = Type::from(PointerType::new(Type::U32));

        // Default struct
        let ty = Type::from(StructType::new([ptr_ty.clone(), Type::U8, Type::I32]));
        assert_eq!(ty.to_raw_parts(), Some(smallvec![ptr_ty.clone(), Type::U8, Type::I32,]));

        // Packed struct
        let ty = Type::from(StructType::new_with_repr(
            TypeRepr::packed(1),
            [ptr_ty.clone(), Type::U8, Type::I32],
        ));
        let partial_ty = Type::from(StructType::new_with_repr(
            TypeRepr::packed(1),
            [Type::U8, Type::from(ArrayType::new(Type::U8, 3))],
        ));
        assert_eq!(ty.to_raw_parts(), Some(smallvec![ptr_ty.clone(), partial_ty, Type::U8]));
    }
}
