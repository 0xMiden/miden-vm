use alloc::{format, string::String};

use miden_serde_utils::*;
use smallvec::SmallVec;

use crate::*;

/// Provides [FunctionType] serialization support via the miden-serde-utils serializer.
///
/// This is a temporary implementation to allow type information to be serialized with libraries,
/// but in a future release we'll either rely on the `serde` serialization for these types, or
/// provide the serialization implementation in midenc-hir-type instead
impl Serializable for FunctionType {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.abi as u8);
        target.write_usize(self.params().len());
        target.write_many(self.params().iter());
        target.write_usize(self.results().len());
        target.write_many(self.results().iter());
    }
}

/// Provides [FunctionType] deserialization support via the miden-serde-utils serializer.
///
/// This is a temporary implementation to allow type information to be serialized with libraries,
/// but in a future release we'll either rely on the `serde` serialization for these types, or
/// provide the serialization implementation in midenc-hir-type instead
impl Deserializable for FunctionType {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::read_from_with_depth(source, MAX_TYPE_NESTING)
    }
}

impl FunctionType {
    fn read_from_with_depth<R: ByteReader>(
        source: &mut R,
        depth: usize,
    ) -> Result<Self, DeserializationError> {
        let abi = match source.read_u8()? {
            0 => CallConv::Fast,
            1 => CallConv::C,
            2 => CallConv::Wasm,
            3 => CallConv::ComponentModel,
            invalid => {
                return Err(DeserializationError::InvalidValue(format!(
                    "invalid CallConv tag: {invalid}"
                )));
            }
        };

        let arity = source.read_usize()?;
        // Each type serializes to at least one byte (tag), so max_alloc(1) bounds pre-allocation.
        let max_params = source.max_alloc(1);
        if arity > max_params {
            return Err(DeserializationError::InvalidValue(format!(
                "function params count {arity} exceeds budget {max_params}"
            )));
        }
        let mut params = SmallVec::<[Type; 4]>::with_capacity(arity);
        for _ in 0..arity {
            let ty = Type::read_from_with_depth(source, depth)?;
            params.push(ty);
        }

        let num_results = source.read_usize()?;
        // Each type serializes to at least one byte (tag), so max_alloc(1) bounds pre-allocation.
        let max_results = source.max_alloc(1);
        if num_results > max_results {
            return Err(DeserializationError::InvalidValue(format!(
                "function results count {num_results} exceeds budget {max_results}"
            )));
        }
        let mut results = SmallVec::<[Type; 1]>::with_capacity(num_results);
        for _ in 0..num_results {
            let ty = Type::read_from_with_depth(source, depth)?;
            results.push(ty);
        }

        Ok(Self {
            abi,
            params,
            results,
        })
    }
}

/// Provides [Type] serialization support via the miden-serde-utils serializer.
///
/// This is a temporary implementation to allow type information to be serialized with libraries,
/// but in a future release we'll either rely on the `serde` serialization for these types, or
/// provide the serialization implementation in midenc-hir-type instead
impl Serializable for Type {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Type::Unknown => target.write_u8(0),
            Type::Never => target.write_u8(1),
            Type::I1 => target.write_u8(2),
            Type::I8 => target.write_u8(3),
            Type::U8 => target.write_u8(4),
            Type::I16 => target.write_u8(5),
            Type::U16 => target.write_u8(6),
            Type::I32 => target.write_u8(7),
            Type::U32 => target.write_u8(8),
            Type::I64 => target.write_u8(9),
            Type::U64 => target.write_u8(10),
            Type::I128 => target.write_u8(11),
            Type::U128 => target.write_u8(12),
            Type::U256 => target.write_u8(13),
            Type::F64 => target.write_u8(14),
            Type::Felt => target.write_u8(15),
            Type::Ptr(ty) => {
                target.write_u8(16);
                match ty.addrspace {
                    AddressSpace::Byte => target.write_u8(0),
                    AddressSpace::Element => target.write_u8(1),
                }
                ty.pointee().write_into(target);
            }
            Type::Struct(ty) => {
                target.write_u8(17);
                if let Some(name) = ty.name() {
                    target.write_bool(true);
                    target.write_usize(name.len());
                    target.write_bytes(name.as_bytes());
                } else {
                    target.write_bool(false);
                }
                match ty.repr() {
                    TypeRepr::Default => target.write_u8(0),
                    TypeRepr::Align(align) => {
                        target.write_u8(1);
                        target.write_u16(align.get());
                    }
                    TypeRepr::Packed(align) => {
                        target.write_u8(2);
                        target.write_u16(align.get());
                    }
                    TypeRepr::Transparent => target.write_u8(3),
                    TypeRepr::BigEndian => target.write_u8(4),
                }
                target.write_u8(ty.len() as u8);
                for field in ty.fields() {
                    if let Some(name) = field.name.as_ref() {
                        target.write_bool(true);
                        target.write_usize(name.len());
                        target.write_bytes(name.as_bytes());
                    } else {
                        target.write_bool(false);
                    }
                    field.ty.write_into(target);
                }
            }
            Type::Array(ty) => {
                target.write_u8(18);
                target.write_usize(ty.len);
                ty.ty.write_into(target);
            }
            Type::List(ty) => {
                target.write_u8(19);
                ty.write_into(target);
            }
            Type::Function(ty) => {
                target.write_u8(20);
                ty.write_into(target);
            }
            Type::Enum(ty) => {
                target.write_u8(21);
                target.write_usize(ty.name().len());
                target.write_bytes(ty.name().as_bytes());
                ty.discriminant().write_into(target);
                target.write_usize(ty.variants().len());
                let discriminant_size_in_bits = ty.discriminant().size_in_bits();
                for variant in ty.variants() {
                    target.write_usize(variant.name.len());
                    target.write_bytes(variant.name.as_bytes());
                    if let Some(value_ty) = variant.value.as_ref() {
                        target.write_bool(true);
                        value_ty.write_into(target);
                    } else {
                        target.write_bool(false);
                    }
                    if let Some(discrim_value) = variant.discriminant_value {
                        target.write_bool(true);
                        match discriminant_size_in_bits {
                            n if n <= 8 => target.write_u8(discrim_value as u8),
                            n if n <= 16 => target.write_u16(discrim_value as u16),
                            n if n <= 32 => target.write_u32(discrim_value as u32),
                            n if n <= 64 => target.write_u64(discrim_value as u64),
                            _ => target.write_u128(discrim_value),
                        }
                    } else {
                        target.write_bool(false);
                    }
                }
            }
        }
    }
}

// Bounds recursive type nesting during deserialization to prevent adversarially deep types from
// exhausting stack or budgets; 128 is far beyond realistic type depth while keeping parsing safe.
const MAX_TYPE_NESTING: usize = 128;

impl Type {
    /// Provides [Type] deserialization support via the miden-serde-utils serializer.
    ///
    /// This is a temporary implementation to allow type information to be serialized with libraries,
    /// but in a future release we'll either rely on the `serde` serialization for these types, or
    /// provide the serialization implementation in midenc-hir-type instead
    fn read_from_with_depth<R: ByteReader>(
        source: &mut R,
        depth: usize,
    ) -> Result<Self, DeserializationError> {
        use alloc::string::ToString;
        use core::num::NonZeroU16;

        let tag = source.read_u8()?;
        let is_recursive = matches!(tag, 16..=21);
        if is_recursive && depth == 0 {
            return Err(DeserializationError::InvalidValue(String::from(
                "type nesting exceeds limit",
            )));
        }
        let next_depth = depth.saturating_sub(1);
        let ty = match tag {
            0 => Type::Unknown,
            1 => Type::Never,
            2 => Type::I1,
            3 => Type::I8,
            4 => Type::U8,
            5 => Type::I16,
            6 => Type::U16,
            7 => Type::I32,
            8 => Type::U32,
            9 => Type::I64,
            10 => Type::U64,
            11 => Type::I128,
            12 => Type::U128,
            13 => Type::U256,
            14 => Type::F64,
            15 => Type::Felt,
            16 => {
                let addrspace = match source.read_u8()? {
                    0 => AddressSpace::Byte,
                    1 => AddressSpace::Element,
                    invalid => {
                        return Err(DeserializationError::InvalidValue(format!(
                            "invalid AddressSpace tag: {invalid}"
                        )));
                    }
                };
                let pointee = Type::read_from_with_depth(source, next_depth)?;
                Type::Ptr(Arc::new(PointerType { addrspace, pointee }))
            }
            17 => {
                let name = if source.read_bool()? {
                    Some(Arc::<str>::from(String::read_from(source)?.into_boxed_str()))
                } else {
                    None
                };
                let repr = match source.read_u8()? {
                    0 => TypeRepr::Default,
                    1 => {
                        let align = NonZeroU16::new(source.read_u16()?).ok_or_else(|| {
                            DeserializationError::InvalidValue(
                                "invalid type repr: alignment must be a non-zero value".to_string(),
                            )
                        })?;
                        TypeRepr::Align(align)
                    }
                    2 => {
                        let align = NonZeroU16::new(source.read_u16()?).ok_or_else(|| {
                            DeserializationError::InvalidValue(
                                "invalid type repr: packed alignment must be a non-zero value"
                                    .to_string(),
                            )
                        })?;
                        TypeRepr::Packed(align)
                    }
                    3 => TypeRepr::Transparent,
                    4 => TypeRepr::BigEndian,
                    invalid => {
                        return Err(DeserializationError::InvalidValue(format!(
                            "invalid TypeRepr tag: {invalid}"
                        )));
                    }
                };
                let num_fields = source.read_u8()?;
                let mut fields = SmallVec::<[NameAndType; 4]>::with_capacity(num_fields as usize);
                for _ in 0..num_fields {
                    let name = if source.read_bool()? {
                        Some(Arc::<str>::from(String::read_from(source)?.into_boxed_str()))
                    } else {
                        None
                    };
                    let ty = Type::read_from_with_depth(source, next_depth)?;
                    fields.push(NameAndType { name, ty });
                }
                Type::Struct(Arc::new(StructType::from_parts(name, repr, fields)))
            }
            18 => {
                let arity = source.read_usize()?;
                let ty = Type::read_from_with_depth(source, next_depth)?;
                Type::Array(Arc::new(ArrayType { ty, len: arity }))
            }
            19 => {
                let ty = Type::read_from_with_depth(source, next_depth)?;
                Type::List(Arc::new(ty))
            }
            20 => Type::Function(Arc::new(FunctionType::read_from_with_depth(source, next_depth)?)),
            21 => {
                let name = Arc::<str>::from(String::read_from(source)?.into_boxed_str());
                let discriminant = Type::read_from_with_depth(source, next_depth)?;
                if !discriminant.is_integer() || matches!(discriminant, Type::U256) {
                    return Err(DeserializationError::InvalidValue(
                        InvalidEnumTypeError::InvalidDiscriminantType(discriminant).to_string(),
                    ));
                }
                let discriminant_size_in_bits = discriminant.size_in_bits();
                let num_variants = source.read_usize()?;
                let mut variants = SmallVec::<[Variant; 4]>::new_const();
                for _ in 0..num_variants {
                    let name = Arc::<str>::from(String::read_from(source)?.into_boxed_str());
                    let value_ty = if source.read_bool()? {
                        Some(Type::read_from_with_depth(source, next_depth)?)
                    } else {
                        None
                    };
                    let discriminant_value = if source.read_bool()? {
                        Some(match discriminant_size_in_bits {
                            n if n <= 8 => source.read_u8()? as u128,
                            n if n <= 16 => source.read_u16()? as u128,
                            n if n <= 32 => source.read_u32()? as u128,
                            n if n <= 64 => source.read_u64()? as u128,
                            _ => source.read_u128()?,
                        })
                    } else {
                        None
                    };
                    variants.push(Variant {
                        name,
                        value: value_ty,
                        discriminant_value,
                    });
                }

                let enum_ty = EnumType::new(name, discriminant, variants)
                    .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;
                Type::Enum(Arc::new(enum_ty))
            }
            invalid => {
                return Err(DeserializationError::InvalidValue(format!(
                    "invalid Type tag: {invalid}"
                )));
            }
        };
        Ok(ty)
    }
}

impl Deserializable for Type {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::read_from_with_depth(source, MAX_TYPE_NESTING)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, vec::Vec};

    use miden_serde_utils::{BudgetedReader, ByteWriter, SliceReader};

    use super::*;

    #[test]
    fn function_type_rejects_over_budget_params() {
        let mut bytes = Vec::new();
        bytes.write_u8(0);
        bytes.write_usize(5);
        let mut reader = BudgetedReader::new(SliceReader::new(&bytes), 6);
        let err = FunctionType::read_from(&mut reader).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("function params count"));
    }

    #[test]
    fn function_type_rejects_over_budget_results() {
        let mut bytes = Vec::new();
        bytes.write_u8(0);
        bytes.write_usize(0);
        bytes.write_usize(4);
        let mut reader = BudgetedReader::new(SliceReader::new(&bytes), 6);
        let err = FunctionType::read_from(&mut reader).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("function results count"));
    }

    #[test]
    fn type_deserializer_rejects_excessive_nesting() {
        let mut bytes = Vec::new();
        for _ in 0..=MAX_TYPE_NESTING {
            bytes.write_u8(16);
            bytes.write_u8(0);
        }
        bytes.write_u8(15);

        let err = Type::read_from(&mut SliceReader::new(&bytes)).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("type nesting exceeds limit"));
    }

    #[test]
    fn type_deserializer_allows_max_nesting() {
        let mut bytes = Vec::new();
        for _ in 0..MAX_TYPE_NESTING {
            bytes.write_u8(16);
            bytes.write_u8(0);
        }
        bytes.write_u8(15);

        let ty = Type::read_from(&mut SliceReader::new(&bytes)).unwrap();
        assert!(matches!(ty, Type::Ptr(_)));
    }

    #[test]
    fn function_type_rejects_nested_over_limit() {
        let mut nested = Vec::new();
        for _ in 0..=MAX_TYPE_NESTING {
            nested.write_u8(16);
            nested.write_u8(0);
        }
        nested.write_u8(15);

        let mut bytes = Vec::new();
        bytes.write_u8(20);
        bytes.write_u8(0);
        bytes.write_usize(1);
        bytes.write_bytes(&nested);
        bytes.write_usize(0);

        let err = Type::read_from(&mut SliceReader::new(&bytes)).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("type nesting exceeds limit"));
    }

    #[test]
    fn function_type_allows_nested_at_limit() {
        let mut nested = Vec::new();
        for _ in 0..(MAX_TYPE_NESTING - 1) {
            nested.write_u8(16);
            nested.write_u8(0);
        }
        nested.write_u8(15);

        let mut bytes = Vec::new();
        bytes.write_u8(20);
        bytes.write_u8(0);
        bytes.write_usize(1);
        bytes.write_bytes(&nested);
        bytes.write_usize(0);

        let ty = Type::read_from(&mut SliceReader::new(&bytes)).unwrap();
        assert!(matches!(ty, Type::Function(_)));
    }

    fn write_str(buf: &mut Vec<u8>, s: &str) {
        buf.write_usize(s.len());
        buf.write_bytes(s.as_bytes());
    }

    fn nested_enum_bytes(depth: usize) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.write_u8(15);

        for i in 0..depth {
            let mut bytes = Vec::new();
            bytes.write_u8(21);
            write_str(&mut bytes, &format!("E{i}"));
            bytes.write_u8(4);
            bytes.write_usize(1);
            write_str(&mut bytes, &format!("V{i}"));
            bytes.write_bool(true);
            bytes.write_bytes(&inner);
            bytes.write_bool(false);
            inner = bytes;
        }

        inner
    }

    #[test]
    fn enum_type_rejects_nested_over_limit() {
        let bytes = nested_enum_bytes(MAX_TYPE_NESTING + 50);

        let err = Type::read_from(&mut SliceReader::new(&bytes)).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("type nesting exceeds limit"));
    }
}
