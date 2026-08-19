use alloc::{boxed::Box, format, string::String, vec::Vec};

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
        target.write_u8(self.abi.tag());
        if let CallConv::Extern(name) = &self.abi {
            name.write_into(target);
        }
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
            4 => CallConv::Extern(Arc::<str>::read_from(source)?),
            invalid => {
                return Err(DeserializationError::InvalidValue(format!(
                    "invalid CallConv tag: {invalid}"
                )));
            },
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

        Ok(Self { abi, params, results })
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
            },
            Type::Struct(StructRef::Rec(ty)) => write_recursive_group(ty, target),
            Type::Enum(EnumRef::Rec(ty)) => write_recursive_group(ty, target),
            Type::Struct(ty) => {
                let ty = ty.get();
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
                    },
                    TypeRepr::Packed(align) => {
                        target.write_u8(2);
                        target.write_u16(align.get());
                    },
                    TypeRepr::Transparent => target.write_u8(3),
                }
                target.write_u8(
                    u8::try_from(ty.len())
                        .expect("invalid struct: expected no more than 255 fields"),
                );
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
            },
            Type::Array(ty) => {
                target.write_u8(18);
                target.write_usize(ty.len);
                ty.ty.write_into(target);
            },
            Type::List(ty) => {
                target.write_u8(19);
                ty.write_into(target);
            },
            Type::Function(ty) => {
                target.write_u8(20);
                ty.write_into(target);
            },
            Type::Enum(ty) => {
                let ty = ty.get();
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
            },
            Type::Variadic => {
                target.write_u8(22);
            },
        }
    }
}

// RECURSIVE GROUP CODEC
// ================================================================================================

/// Tag for a recursive aggregate, which carries its whole definition group.
const TAG_RECURSIVE_GROUP: u8 = 23;
/// Tag for a back-reference to a definition of the enclosing group. Only valid inside a group
/// body; encountering it anywhere else would yield a type with an unbound back-reference.
const TAG_RECURSIVE_REF: u8 = 24;

fn write_str_with_len<W: ByteWriter>(name: &str, target: &mut W) {
    target.write_usize(name.len());
    target.write_bytes(name.as_bytes());
}

/// Encode a recursive aggregate as its whole group plus the index of the selected definition.
///
/// Definitions are written in canonical order, so the decoder can resolve a back-reference index
/// to a name from the headers alone, and can reject any encoding that is not canonical.
fn write_recursive_group<W: ByteWriter>(ty: &RecTypeRef, target: &mut W) {
    let defs = ty.defs();
    target.write_u8(TAG_RECURSIVE_GROUP);
    target.write_u16(defs.len() as u16);

    // Headers first, so a back-reference index can be resolved to a name while reading bodies.
    for def in defs {
        write_str_with_len(&def.name, target);
        target.write_u8(match def.kind {
            AggregateKind::Struct => 0,
            AggregateKind::Enum => 1,
        });
    }

    for def in defs {
        match &def.body {
            OpenAggregate::Struct(body) => write_open_struct_body(body, target),
            OpenAggregate::Enum(body) => write_open_enum_body(body, target),
        }
    }

    target.write_u16(ty.index());
}

fn write_open_struct_body<W: ByteWriter>(ty: &OpenStructType, target: &mut W) {
    match ty.name.as_ref() {
        Some(name) => {
            target.write_bool(true);
            write_str_with_len(name, target);
        },
        None => target.write_bool(false),
    }
    write_type_repr(ty.repr, target);
    // Layouts are recomputed on decode, so field offsets and sizes are not encoded.
    target.write_u8(
        u8::try_from(ty.fields.len()).expect("invalid struct: expected no more than 255 fields"),
    );
    for field in &ty.fields {
        match field.name.as_ref() {
            Some(name) => {
                target.write_bool(true);
                write_str_with_len(name, target);
            },
            None => target.write_bool(false),
        }
        write_open_type(&field.ty, target);
    }
}

fn write_open_enum_body<W: ByteWriter>(ty: &OpenEnumType, target: &mut W) {
    write_str_with_len(&ty.name, target);
    ty.discriminant.write_into(target);
    target.write_usize(ty.variants.len());
    let discriminant_size_in_bits = ty.discriminant.size_in_bits();
    for variant in &ty.variants {
        write_str_with_len(&variant.name, target);
        match variant.value.as_ref() {
            Some(value) => {
                target.write_bool(true);
                write_open_type(value, target);
            },
            None => target.write_bool(false),
        }
        match variant.discriminant_value {
            Some(value) => {
                target.write_bool(true);
                write_discriminant_value(value, discriminant_size_in_bits, target);
            },
            None => target.write_bool(false),
        }
    }
}

fn write_type_repr<W: ByteWriter>(repr: TypeRepr, target: &mut W) {
    match repr {
        TypeRepr::Default => target.write_u8(0),
        TypeRepr::Align(align) => {
            target.write_u8(1);
            target.write_u16(align.get());
        },
        TypeRepr::Packed(align) => {
            target.write_u8(2);
            target.write_u16(align.get());
        },
        TypeRepr::Transparent => target.write_u8(3),
    }
}

fn write_discriminant_value<W: ByteWriter>(value: u128, size_in_bits: usize, target: &mut W) {
    match size_in_bits {
        n if n <= 8 => target.write_u8(value as u8),
        n if n <= 16 => target.write_u16(value as u16),
        n if n <= 32 => target.write_u32(value as u32),
        n if n <= 64 => target.write_u64(value as u64),
        _ => target.write_u128(value),
    }
}

/// Encode an open type using the ordinary `Type` tags, with back-references as
/// [TAG_RECURSIVE_REF]. Closed subterms delegate to the ordinary encoder.
fn write_open_type<W: ByteWriter>(ty: &OpenType, target: &mut W) {
    match ty {
        OpenType::Closed(ty) => ty.write_into(target),
        OpenType::Var(index) => {
            target.write_u8(TAG_RECURSIVE_REF);
            target.write_u16(*index);
        },
        OpenType::Ptr(addrspace, pointee) => {
            target.write_u8(16);
            target.write_u8(match addrspace {
                AddressSpace::Byte => 0,
                AddressSpace::Element => 1,
            });
            write_open_type(pointee, target);
        },
        OpenType::Struct(body) => {
            target.write_u8(17);
            write_open_struct_body(body, target);
        },
        OpenType::Array(element, len) => {
            target.write_u8(18);
            target.write_usize(*len);
            write_open_type(element, target);
        },
        OpenType::List(element) => {
            target.write_u8(19);
            write_open_type(element, target);
        },
        OpenType::Function(ty) => {
            target.write_u8(20);
            target.write_u8(ty.abi.tag());
            if let CallConv::Extern(name) = &ty.abi {
                name.write_into(target);
            }
            target.write_usize(ty.params.len());
            for param in &ty.params {
                write_open_type(param, target);
            }
            target.write_usize(ty.results.len());
            for result in &ty.results {
                write_open_type(result, target);
            }
        },
        OpenType::Enum(body) => {
            target.write_u8(21);
            write_open_enum_body(body, target);
        },
    }
}

/// Decode a recursive group and rebuild it through [RecursiveTypeBuilder], which revalidates
/// guardedness and recomputes every layout from scratch.
fn read_recursive_group<R: ByteReader>(
    source: &mut R,
    depth: usize,
) -> Result<Type, DeserializationError> {
    use alloc::string::ToString;

    let count = source.read_u16()? as usize;
    if count == 0 {
        return Err(DeserializationError::InvalidValue(
            "invalid recursive type: group must contain at least one definition".to_string(),
        ));
    }
    if count > MAX_RECURSIVE_GROUP_SIZE {
        return Err(DeserializationError::InvalidValue(format!(
            "invalid recursive type: group has {count} definitions, but no more than              {MAX_RECURSIVE_GROUP_SIZE} are allowed"
        )));
    }
    // Each definition body is at least one byte, so the remaining input bounds the group.
    let budget = source.max_alloc(1);
    if count > budget {
        return Err(DeserializationError::InvalidValue(format!(
            "invalid recursive type: group of {count} definitions exceeds budget {budget}"
        )));
    }

    let mut names = SmallVec::<[Arc<str>; 4]>::with_capacity(count);
    let mut kinds = SmallVec::<[AggregateKind; 4]>::with_capacity(count);
    for _ in 0..count {
        names.push(Arc::<str>::from(String::read_from(source)?.into_boxed_str()));
        kinds.push(match source.read_u8()? {
            0 => AggregateKind::Struct,
            1 => AggregateKind::Enum,
            invalid => {
                return Err(DeserializationError::InvalidValue(format!(
                    "invalid recursive type: unknown aggregate kind tag {invalid}"
                )));
            },
        });
    }

    // Definitions are written in canonical order (sorted by name, names distinct). Enforcing that
    // on decode keeps the wire form unique for each type, so equal types cannot be encoded two
    // different ways.
    if names.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DeserializationError::InvalidValue(
            "invalid recursive type: definitions are not in canonical order".to_string(),
        ));
    }

    let mut builder = RecursiveTypeBuilder::new();
    for (index, name) in names.iter().enumerate() {
        match kinds[index] {
            AggregateKind::Struct => {
                let body = read_open_struct_body(source, &names, depth)?;
                builder.define_struct(name.clone(), body);
            },
            AggregateKind::Enum => {
                let body = read_open_enum_body(source, &names, depth)?;
                builder.define_enum(name.clone(), body);
            },
        }
    }

    let root = source.read_u16()? as usize;
    let root_name = names
        .get(root)
        .ok_or_else(|| {
            DeserializationError::InvalidValue(format!(
                "invalid recursive type: root index {root} is out of range"
            ))
        })?
        .clone();

    let mut built = builder
        .build()
        .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;

    let ty = built.remove(&root_name).ok_or_else(|| {
        DeserializationError::InvalidValue(
            "invalid recursive type: root definition was not produced".to_string(),
        )
    })?;

    // The encoded group must be exactly one strongly connected component. If it decomposed into
    // several, or into no recursion at all, the encoding did not describe a single group.
    let group_len = match &ty {
        Type::Struct(StructRef::Rec(rec)) | Type::Enum(EnumRef::Rec(rec)) => rec.group_len(),
        _ => 0,
    };
    if group_len != count {
        return Err(DeserializationError::InvalidValue(
            "invalid recursive type: definitions do not form a single recursive group".to_string(),
        ));
    }

    Ok(ty)
}

fn read_open_struct_body<R: ByteReader>(
    source: &mut R,
    names: &[Arc<str>],
    depth: usize,
) -> Result<StructTemplate, DeserializationError> {
    let name = if source.read_bool()? {
        Some(Arc::<str>::from(String::read_from(source)?.into_boxed_str()))
    } else {
        None
    };
    let repr = read_type_repr(source)?;
    let num_fields = source.read_u8()?;
    let mut fields = Vec::with_capacity(num_fields as usize);
    for _ in 0..num_fields {
        let field_name = if source.read_bool()? {
            Some(Arc::<str>::from(String::read_from(source)?.into_boxed_str()))
        } else {
            None
        };
        let ty = read_template(source, names, depth)?;
        fields.push(FieldTemplate { name: field_name, ty });
    }
    Ok(StructTemplate { name, repr, fields })
}

fn read_open_enum_body<R: ByteReader>(
    source: &mut R,
    names: &[Arc<str>],
    depth: usize,
) -> Result<EnumTemplate, DeserializationError> {
    use alloc::string::ToString;

    let name = Arc::<str>::from(String::read_from(source)?.into_boxed_str());
    let discriminant = Type::read_from_with_depth(source, depth)?;
    if !discriminant.is_integer() || matches!(discriminant, Type::U256) {
        return Err(DeserializationError::InvalidValue(
            InvalidEnumTypeError::InvalidDiscriminantType(discriminant).to_string(),
        ));
    }
    let discriminant_size_in_bits = discriminant.size_in_bits();
    let num_variants = source.read_usize()?;
    let max_variants = source.max_alloc(1);
    if num_variants > max_variants {
        return Err(DeserializationError::InvalidValue(format!(
            "enum variant count {num_variants} exceeds budget {max_variants}"
        )));
    }
    let mut variants = Vec::with_capacity(num_variants);
    for _ in 0..num_variants {
        let variant_name = Arc::<str>::from(String::read_from(source)?.into_boxed_str());
        let value = if source.read_bool()? {
            Some(read_template(source, names, depth)?)
        } else {
            None
        };
        let discriminant_value = if source.read_bool()? {
            Some(read_discriminant_value(source, discriminant_size_in_bits)?)
        } else {
            None
        };
        variants.push(VariantTemplate {
            name: variant_name,
            value,
            discriminant_value,
        });
    }
    Ok(EnumTemplate { name, discriminant, variants })
}

fn read_type_repr<R: ByteReader>(source: &mut R) -> Result<TypeRepr, DeserializationError> {
    use alloc::string::ToString;
    use core::num::NonZeroU16;

    Ok(match source.read_u8()? {
        0 => TypeRepr::Default,
        1 => TypeRepr::Align(NonZeroU16::new(source.read_u16()?).ok_or_else(|| {
            DeserializationError::InvalidValue(
                "invalid type repr: alignment must be a non-zero value".to_string(),
            )
        })?),
        2 => TypeRepr::Packed(NonZeroU16::new(source.read_u16()?).ok_or_else(|| {
            DeserializationError::InvalidValue(
                "invalid type repr: packed alignment must be a non-zero value".to_string(),
            )
        })?),
        3 => TypeRepr::Transparent,
        invalid => {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid TypeRepr tag: {invalid}"
            )));
        },
    })
}

fn read_discriminant_value<R: ByteReader>(
    source: &mut R,
    size_in_bits: usize,
) -> Result<u128, DeserializationError> {
    Ok(match size_in_bits {
        n if n <= 8 => source.read_u8()? as u128,
        n if n <= 16 => source.read_u16()? as u128,
        n if n <= 32 => source.read_u32()? as u128,
        n if n <= 64 => source.read_u64()? as u128,
        _ => source.read_u128()?,
    })
}

/// Read a type inside a group body, where a back-reference is permitted.
fn read_template<R: ByteReader>(
    source: &mut R,
    names: &[Arc<str>],
    depth: usize,
) -> Result<TypeTemplate, DeserializationError> {
    use alloc::string::ToString;

    let tag = source.peek_u8()?;
    if tag == TAG_RECURSIVE_REF {
        source.read_u8()?;
        let index = source.read_u16()? as usize;
        let name = names.get(index).ok_or_else(|| {
            DeserializationError::InvalidValue(format!(
                "invalid recursive type reference: index {index} is out of range"
            ))
        })?;
        return Ok(TypeTemplate::rec(name.clone()));
    }

    if depth == 0 && matches!(tag, 16..=21) {
        return Err(DeserializationError::InvalidValue("type nesting exceeds limit".to_string()));
    }
    let next_depth = depth.saturating_sub(1);

    Ok(match tag {
        16 => {
            source.read_u8()?;
            let addrspace = match source.read_u8()? {
                0 => AddressSpace::Byte,
                1 => AddressSpace::Element,
                invalid => {
                    return Err(DeserializationError::InvalidValue(format!(
                        "invalid AddressSpace tag: {invalid}"
                    )));
                },
            };
            TypeTemplate::Ptr(addrspace, Box::new(read_template(source, names, next_depth)?))
        },
        17 => {
            source.read_u8()?;
            TypeTemplate::Struct(Box::new(read_open_struct_body(source, names, next_depth)?))
        },
        18 => {
            source.read_u8()?;
            let len = source.read_usize()?;
            TypeTemplate::Array(Box::new(read_template(source, names, next_depth)?), len)
        },
        19 => {
            source.read_u8()?;
            TypeTemplate::List(Box::new(read_template(source, names, next_depth)?))
        },
        20 => {
            source.read_u8()?;
            let abi = read_call_conv(source)?;
            let arity = source.read_usize()?;
            let max_params = source.max_alloc(1);
            if arity > max_params {
                return Err(DeserializationError::InvalidValue(format!(
                    "function params count {arity} exceeds budget {max_params}"
                )));
            }
            let mut params = Vec::with_capacity(arity);
            for _ in 0..arity {
                params.push(read_template(source, names, next_depth)?);
            }
            let num_results = source.read_usize()?;
            let max_results = source.max_alloc(1);
            if num_results > max_results {
                return Err(DeserializationError::InvalidValue(format!(
                    "function results count {num_results} exceeds budget {max_results}"
                )));
            }
            let mut results = Vec::with_capacity(num_results);
            for _ in 0..num_results {
                results.push(read_template(source, names, next_depth)?);
            }
            TypeTemplate::Function(Box::new(FunctionTemplate { abi, params, results }))
        },
        21 => {
            source.read_u8()?;
            TypeTemplate::Enum(Box::new(read_open_enum_body(source, names, next_depth)?))
        },
        // Anything else is an ordinary, closed type.
        _ => TypeTemplate::Type(Type::read_from_with_depth(source, depth)?),
    })
}

fn read_call_conv<R: ByteReader>(source: &mut R) -> Result<CallConv, DeserializationError> {
    Ok(match source.read_u8()? {
        0 => CallConv::Fast,
        1 => CallConv::C,
        2 => CallConv::Wasm,
        3 => CallConv::ComponentModel,
        4 => CallConv::Extern(Arc::<str>::read_from(source)?),
        invalid => {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid CallConv tag: {invalid}"
            )));
        },
    })
}

// Bounds recursive type nesting during deserialization to prevent adversarially deep types from
// exhausting stack or budgets; 128 is far beyond realistic type depth while keeping parsing safe.
const MAX_TYPE_NESTING: usize = 128;

impl Type {
    /// Provides [Type] deserialization support via the miden-serde-utils serializer.
    ///
    /// This is a temporary implementation to allow type information to be serialized with
    /// libraries, but in a future release we'll either rely on the `serde` serialization for
    /// these types, or provide the serialization implementation in midenc-hir-type instead
    fn read_from_with_depth<R: ByteReader>(
        source: &mut R,
        depth: usize,
    ) -> Result<Self, DeserializationError> {
        use alloc::string::ToString;
        use core::num::NonZeroU16;

        let tag = source.read_u8()?;
        let is_recursive = matches!(tag, 16..=21 | TAG_RECURSIVE_GROUP);
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
                    },
                };
                let pointee = Type::read_from_with_depth(source, next_depth)?;
                Type::Ptr(Arc::new(PointerType { addrspace, pointee }))
            },
            17 => {
                let name = if source.read_bool()? {
                    Some(Arc::<str>::from(String::read_from(source)?.into_boxed_str()))
                } else {
                    None
                };
                let repr = match source.read_u8()? {
                    0 => TypeRepr::Default,
                    1 => {
                        let align = source.read_u16()?;
                        if !align.is_power_of_two() {
                            return Err(DeserializationError::InvalidValue(
                                "invalid type repr: alignment must be a power of two".to_string(),
                            ));
                        }
                        let align =
                            NonZeroU16::new(align).expect("power-of-two alignment is non-zero");
                        TypeRepr::Align(align)
                    },
                    2 => {
                        let align = source.read_u16()?;
                        if !align.is_power_of_two() {
                            return Err(DeserializationError::InvalidValue(
                                "invalid type repr: packed alignment must be a power of two"
                                    .to_string(),
                            ));
                        }
                        let align =
                            NonZeroU16::new(align).expect("power-of-two alignment is non-zero");
                        TypeRepr::Packed(align)
                    },
                    3 => TypeRepr::Transparent,
                    invalid => {
                        return Err(DeserializationError::InvalidValue(format!(
                            "invalid TypeRepr tag: {invalid}"
                        )));
                    },
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
                    if u32::try_from(ty.size_in_bytes()).is_err() {
                        return Err(DeserializationError::InvalidValue(
                            "invalid struct field: size exceeds u32::MAX bytes".to_string(),
                        ));
                    }
                    fields.push(NameAndType { name, ty });
                }
                if repr == TypeRepr::Transparent
                    && fields.iter().filter(|field| field.ty.size_in_bytes() != 0).count() > 1
                {
                    return Err(DeserializationError::InvalidValue(
                        "invalid transparent struct: expected at most one non-zero-sized field"
                            .to_string(),
                    ));
                }
                Type::from(StructType::from_parts(name, repr, fields))
            },
            18 => {
                let arity = source.read_usize()?;
                let ty = Type::read_from_with_depth(source, next_depth)?;
                let element_size = u64::try_from(ty.size_in_bytes()).unwrap_or(u64::MAX);
                let element_align = u64::try_from(ty.min_alignment()).unwrap_or(u64::MAX);
                let padded_element_size = element_size.checked_next_multiple_of(element_align);
                let size_in_bytes = padded_element_size.and_then(|padded_size| {
                    u64::try_from(arity).ok().and_then(|arity| padded_size.checked_mul(arity))
                });
                if size_in_bytes.is_none_or(|size| size > u64::from(u32::MAX)) {
                    return Err(DeserializationError::InvalidValue(
                        "invalid array: size exceeds u32::MAX bytes".to_string(),
                    ));
                }
                Type::Array(Arc::new(ArrayType { ty, len: arity }))
            },
            19 => {
                let ty = Type::read_from_with_depth(source, next_depth)?;
                Type::List(Arc::new(ty))
            },
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
                Type::from(enum_ty)
            },
            22 => Type::Variadic,
            TAG_RECURSIVE_GROUP => read_recursive_group(source, next_depth)?,
            TAG_RECURSIVE_REF => {
                return Err(DeserializationError::InvalidValue(String::from(
                    "invalid recursive type reference: a back-reference is only valid inside a \
                     recursive group body",
                )));
            },
            invalid => {
                return Err(DeserializationError::InvalidValue(format!(
                    "invalid Type tag: {invalid}"
                )));
            },
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
    use alloc::{format, sync::Arc, vec::Vec};

    use miden_serde_utils::{BudgetedReader, ByteWriter, SliceReader};

    use super::*;

    fn build_one(mut builder: RecursiveTypeBuilder, name: &str) -> Type {
        builder
            .build()
            .expect("should build")
            .remove(name)
            .expect("definition should exist")
    }

    fn round_trip(ty: &Type) -> Type {
        let mut bytes = Vec::new();
        ty.write_into(&mut bytes);
        Type::read_from(&mut SliceReader::new(&bytes)).expect("should decode")
    }

    #[test]
    fn self_recursive_struct_round_trips() {
        let mut builder = RecursiveTypeBuilder::new();
        builder.define_struct(
            "Node",
            StructTemplate::new(
                TypeRepr::Default,
                [
                    ("value", TypeTemplate::from(Type::U32)),
                    ("next", TypeTemplate::ptr(TypeTemplate::rec("Node"))),
                ],
            ),
        );
        let node = build_one(builder, "Node");

        assert_eq!(round_trip(&node), node);
    }

    #[test]
    fn mutually_recursive_structs_round_trip_from_either_root() {
        let mut builder = RecursiveTypeBuilder::new();
        builder
            .define_struct(
                "A",
                StructTemplate::new(
                    TypeRepr::Default,
                    [("b", TypeTemplate::ptr(TypeTemplate::rec("B")))],
                ),
            )
            .define_struct(
                "B",
                StructTemplate::new(
                    TypeRepr::Default,
                    [("a", TypeTemplate::ptr(TypeTemplate::rec("A")))],
                ),
            );
        let built = builder.build().expect("should build");
        let a = built.get("A").expect("A").clone();
        let b = built.get("B").expect("B").clone();

        assert_eq!(round_trip(&a), a);
        assert_eq!(round_trip(&b), b);
    }

    #[test]
    fn recursive_enum_round_trips() {
        let mut builder = RecursiveTypeBuilder::new();
        builder.define_enum(
            "List",
            EnumTemplate::new(
                "List",
                Type::U8,
                [
                    VariantTemplate::c_like("Nil", Some(0)),
                    VariantTemplate::new(
                        "Cons",
                        TypeTemplate::ptr(TypeTemplate::rec("List")),
                        Some(1),
                    ),
                ],
            ),
        );
        let list = build_one(builder, "List");

        assert_eq!(round_trip(&list), list);
    }

    #[test]
    fn a_recursive_type_nested_inside_an_ordinary_one_round_trips() {
        let mut builder = RecursiveTypeBuilder::new();
        builder.define_struct(
            "Node",
            StructTemplate::new(
                TypeRepr::Default,
                [("next", TypeTemplate::ptr(TypeTemplate::rec("Node")))],
            ),
        );
        let node = build_one(builder, "Node");
        let outer = Type::from(StructType::named(
            Arc::from("Outer"),
            [(Arc::from("head"), node), (Arc::from("count"), Type::U32)],
        ));

        assert_eq!(round_trip(&outer), outer);
    }

    #[test]
    fn a_back_reference_outside_a_group_body_is_rejected() {
        // Tag 24 is only meaningful while decoding a group body; encountering it at the root
        // would otherwise produce a type with an unbound back-reference.
        let mut bytes = Vec::new();
        bytes.write_u8(24);
        bytes.write_u16(0);

        let err = Type::read_from(&mut SliceReader::new(&bytes)).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("recursive type reference"), "unexpected message: {message}");
    }

    #[test]
    fn a_group_larger_than_the_cap_is_rejected_on_decode() {
        let count = MAX_RECURSIVE_GROUP_SIZE + 1;
        let mut bytes = Vec::new();
        bytes.write_u8(23);
        bytes.write_u16(count as u16);

        let err = Type::read_from(&mut SliceReader::new(&bytes)).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("recursive"), "unexpected message: {message}");
    }

    #[test]
    fn a_non_canonical_group_encoding_is_rejected() {
        // Definitions are always written sorted by name, so an encoding that is not sorted would
        // give a second wire form for a type that already has one.
        let mut bytes = Vec::new();
        bytes.write_u8(23);
        bytes.write_u16(2);
        for name in ["B", "A"] {
            bytes.write_usize(name.len());
            bytes.write_bytes(name.as_bytes());
            bytes.write_u8(0);
        }

        let err = Type::read_from(&mut SliceReader::new(&bytes)).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("canonical order"), "unexpected message: {message}");
    }

    #[test]
    fn an_empty_group_is_rejected() {
        let mut bytes = Vec::new();
        bytes.write_u8(23);
        bytes.write_u16(0);

        let err = Type::read_from(&mut SliceReader::new(&bytes)).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("at least one definition"), "unexpected message: {message}");
    }

    #[test]
    fn struct_type_round_trips_at_the_maximum_field_count() {
        let fields = core::iter::repeat_n(Type::U8, 255).collect::<Vec<_>>();
        let ty = Type::from(StructType::new(fields));

        let mut bytes = Vec::new();
        ty.write_into(&mut bytes);
        let decoded = Type::read_from(&mut SliceReader::new(&bytes)).unwrap();

        assert_eq!(decoded, ty);
    }

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
    fn list_type_has_fat_pointer_layout() {
        let ty = Type::List(Arc::new(Type::U8));

        assert_eq!(ty.min_alignment(), 4);
        assert_eq!(ty.size_in_bytes(), 8);
    }

    #[test]
    fn struct_type_allows_zero_sized_and_list_fields() {
        let mut bytes = Vec::new();
        bytes.write_u8(17);
        bytes.write_bool(false);
        bytes.write_u8(0);
        bytes.write_u8(2);
        bytes.write_bool(false);
        bytes.write_u8(1);
        bytes.write_bool(false);
        bytes.write_u8(19);
        bytes.write_u8(4);

        let ty = Type::read_from(&mut SliceReader::new(&bytes)).unwrap();
        let Type::Struct(struct_ty) = ty else {
            panic!("expected struct");
        };
        assert_eq!(struct_ty.get().fields().len(), 2);
        assert_eq!(struct_ty.size(), 8);
    }

    #[test]
    fn transparent_struct_allows_only_zero_sized_fields() {
        let mut bytes = Vec::new();
        bytes.write_u8(17);
        bytes.write_bool(false);
        bytes.write_u8(3);
        bytes.write_u8(1);
        bytes.write_bool(false);
        bytes.write_u8(1);

        let ty = Type::read_from(&mut SliceReader::new(&bytes)).unwrap();
        let Type::Struct(struct_ty) = ty else {
            panic!("expected struct");
        };
        assert_eq!(struct_ty.size(), 0);
    }

    #[test]
    fn array_type_allows_zero_sized_elements_at_large_arity() {
        let mut bytes = Vec::new();
        bytes.write_u8(18);
        bytes.write_usize(usize::MAX);
        bytes.write_u8(1);

        let ty = Type::read_from(&mut SliceReader::new(&bytes)).unwrap();
        assert!(ty.is_zst());
    }

    #[test]
    fn array_type_rejects_oversized_non_zero_elements() {
        let mut bytes = Vec::new();
        bytes.write_u8(18);
        bytes.write_usize(usize::MAX);
        bytes.write_u8(4);

        let err = Type::read_from(&mut SliceReader::new(&bytes)).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("invalid array"));
    }

    #[test]
    fn enum_type_allows_zero_sized_variant_payloads() {
        let mut bytes = Vec::new();
        bytes.write_u8(21);
        write_str(&mut bytes, "E");
        bytes.write_u8(4);
        bytes.write_usize(1);
        write_str(&mut bytes, "V");
        bytes.write_bool(true);
        bytes.write_u8(1);
        bytes.write_bool(false);

        let ty = Type::read_from(&mut SliceReader::new(&bytes)).unwrap();
        assert!(matches!(ty, Type::Enum(_)));
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
