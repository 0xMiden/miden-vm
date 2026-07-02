//! The serialization format of `Package` is as follows:
//!
//! #### Header
//! - `MAGIC_PACKAGE`, a 4-byte tag, followed by a NUL-byte, i.e. `b"\0"`
//! - `VERSION`, a 3-byte semantic version number, 1 byte for each component, i.e. MAJ.MIN.PATCH
//!
//! #### Metadata
//! - `name` (`String`)
//! - `version` ([`miden_assembly_syntax::Version`] serialized as a `String`)
//! - `description` (optional, `String`)
//! - `kind` (`u8`, see [`crate::TargetType`])
//!
//! #### Code
//! - `mast` (see [`miden_assembly_syntax::Library`])
//!
//! #### Manifest
//! - `manifest` (see [`crate::PackageManifest`])
//!
//! #### Custom Sections
//! - `sections` (a vector of zero or more [`crate::Section`])
//!
//! #### Reader trust policy
//!
//! Package deserialization has two independently important trust decisions:
//!
//! - whether the embedded [`MastForest`] must be recomputed and validated;
//! - whether package-owned debug sections may be exposed to callers.
//!
//! [`Package::read_from`] and [`Package::read_from_bytes`] are the normal untrusted readers. They
//! validate the embedded MAST forest and discard package-owned debug sections before returning the
//! package. Use them for bytes received across a trust boundary.
//!
//! [`Package::read_from_trusted`] and [`Package::read_from_bytes_trusted`] are for local
//! files/cache entries controlled by the same trusted build or execution system. They validate the
//! embedded MAST forest, but preserve package-owned debug sections so [`Package::debug_info`] can
//! decode them.
//!
//! [`Package::read_from_unchecked`] and [`Package::read_from_bytes_unchecked`] are also trusted
//! same-domain readers, but skip MAST validation. Use them only for bytes that were already
//! validated before being persisted by the same trusted system.
//!
//! Embedded kernel package bytes are stored in the opaque `kernel` custom section. Untrusted
//! package reads may carry those bytes, but decoding the embedded kernel through the package API
//! uses the untrusted reader and therefore strips any nested package-owned debug sections.

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::num::NonZeroU16;

use miden_assembly_syntax::ast::{
    self, AttributeSet, PathBuf,
    types::{
        AddressSpace, ArrayType, CallConv, EnumType, FunctionType, NameAndType, PointerType,
        StructType, Type, TypeRepr, Variant,
    },
};
use miden_core::{
    Word,
    mast::{MastForest, MastNodeExt, MastNodeId, UntrustedMastForest},
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};

use super::{
    ConstantExport, PackageId, PackageModule, PackageSubmodule, ProcedureExport, TargetType,
    TypeExport,
};
use crate::{
    Dependency, ManifestValidationError, Package, PackageExport, PackageManifest, Section,
    debug_info::DebugSourceNodeId,
};

// CONSTANTS
// ================================================================================================

/// Magic string for detecting that a file is serialized [`Package`]
const MAGIC_PACKAGE: &[u8; 5] = b"MASP\0";

/// The format version.
///
/// If future modifications are made to this format, the version should be incremented by 1.
const VERSION: [u8; 3] = [6, 0, 0];

/// Byte-read budget multiplier for package deserialization from a byte slice.
///
/// The budget is intentionally finite to reject malicious length prefixes, but larger than the
/// source length because collection deserialization uses conservative per-element size estimates.
const PACKAGE_BYTE_READ_BUDGET_MULTIPLIER: usize = 64;

// Bounds recursive type nesting during package deserialization to match midenc-hir-type's
// serializer while validating constructor preconditions before any layout code runs.
const MAX_PACKAGE_TYPE_NESTING: usize = 128;

// PACKAGE TYPE METADATA DESERIALIZATION
// ================================================================================================

fn read_package_function_type_metadata<R: ByteReader>(
    source: &mut R,
) -> Result<FunctionType, DeserializationError> {
    read_package_function_type_metadata_with_depth(source, MAX_PACKAGE_TYPE_NESTING)
}

fn read_package_function_type_metadata_with_depth<R: ByteReader>(
    source: &mut R,
    depth: usize,
) -> Result<FunctionType, DeserializationError> {
    let abi = match source.read_u8()? {
        0 => CallConv::Fast,
        1 => CallConv::C,
        2 => CallConv::Wasm,
        3 => CallConv::ComponentModel,
        invalid => {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid CallConv tag: {invalid}"
            )));
        },
    };

    let arity = source.read_usize()?;
    let max_params = source.max_alloc(1);
    if arity > max_params {
        return Err(DeserializationError::InvalidValue(format!(
            "function params count {arity} exceeds budget {max_params}"
        )));
    }
    let mut params = Vec::with_capacity(arity);
    for _ in 0..arity {
        params.push(read_package_type_metadata_with_depth(source, depth)?);
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
        results.push(read_package_type_metadata_with_depth(source, depth)?);
    }

    Ok(FunctionType::new(abi, params, results))
}

fn read_package_type_metadata<R: ByteReader>(source: &mut R) -> Result<Type, DeserializationError> {
    read_package_type_metadata_with_depth(source, MAX_PACKAGE_TYPE_NESTING)
}

fn read_package_type_metadata_with_depth<R: ByteReader>(
    source: &mut R,
    depth: usize,
) -> Result<Type, DeserializationError> {
    let tag = source.read_u8()?;
    let is_recursive = matches!(tag, 16..=21);
    if is_recursive && depth == 0 {
        return Err(DeserializationError::InvalidValue(String::from("type nesting exceeds limit")));
    }
    let next_depth = depth.saturating_sub(1);

    match tag {
        0 => Ok(Type::Unknown),
        1 => Ok(Type::Never),
        2 => Ok(Type::I1),
        3 => Ok(Type::I8),
        4 => Ok(Type::U8),
        5 => Ok(Type::I16),
        6 => Ok(Type::U16),
        7 => Ok(Type::I32),
        8 => Ok(Type::U32),
        9 => Ok(Type::I64),
        10 => Ok(Type::U64),
        11 => Ok(Type::I128),
        12 => Ok(Type::U128),
        13 => Ok(Type::U256),
        14 => Ok(Type::F64),
        15 => Ok(Type::Felt),
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
            let pointee = read_package_type_metadata_with_depth(source, next_depth)?;
            Ok(Type::Ptr(Arc::new(PointerType { addrspace, pointee })))
        },
        17 => read_package_struct_type_metadata(source, next_depth),
        18 => {
            let arity = source.read_usize()?;
            let ty = read_package_type_metadata_with_depth(source, next_depth)?;
            Ok(Type::Array(Arc::new(ArrayType { ty, len: arity })))
        },
        19 => {
            let ty = read_package_type_metadata_with_depth(source, next_depth)?;
            Ok(Type::List(Arc::new(ty)))
        },
        20 => {
            let function = read_package_function_type_metadata_with_depth(source, next_depth)?;
            Ok(Type::Function(Arc::new(function)))
        },
        21 => read_package_enum_type_metadata(source, next_depth),
        invalid => Err(DeserializationError::InvalidValue(format!("invalid Type tag: {invalid}"))),
    }
}

fn read_package_struct_type_metadata<R: ByteReader>(
    source: &mut R,
    next_depth: usize,
) -> Result<Type, DeserializationError> {
    let name = if source.read_bool()? {
        Some(Arc::<str>::from(String::read_from(source)?.into_boxed_str()))
    } else {
        None
    };
    let repr = match source.read_u8()? {
        0 => TypeRepr::Default,
        1 => TypeRepr::Align(read_package_type_alignment(source, "alignment")?),
        2 => TypeRepr::Packed(read_package_type_alignment(source, "packed alignment")?),
        3 => TypeRepr::Transparent,
        4 => TypeRepr::BigEndian,
        invalid => {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid TypeRepr tag: {invalid}"
            )));
        },
    };
    // Keep this in sync with midenc-hir-type's Type::Struct writer, which encodes the field
    // count as a single byte.
    let num_fields = source.read_u8()? as usize;
    let mut fields = Vec::with_capacity(num_fields);
    for _ in 0..num_fields {
        let name = if source.read_bool()? {
            Some(Arc::<str>::from(String::read_from(source)?.into_boxed_str()))
        } else {
            None
        };
        let ty = read_package_type_metadata_with_depth(source, next_depth)?;
        fields.push(NameAndType { name, ty });
    }

    validate_package_struct_layout(repr, fields.iter().map(|field| &field.ty))?;
    Ok(Type::Struct(Arc::new(StructType::from_parts(name, repr, fields))))
}

fn read_package_enum_type_metadata<R: ByteReader>(
    source: &mut R,
    next_depth: usize,
) -> Result<Type, DeserializationError> {
    let name = Arc::<str>::from(String::read_from(source)?.into_boxed_str());
    let discriminant = read_package_type_metadata_with_depth(source, next_depth)?;
    if !discriminant.is_integer() || matches!(discriminant, Type::U256) {
        return Err(DeserializationError::InvalidValue(format!(
            "invalid enum discriminant type: {discriminant}"
        )));
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
        let name = Arc::<str>::from(String::read_from(source)?.into_boxed_str());
        let value = if source.read_bool()? {
            Some(read_package_type_metadata_with_depth(source, next_depth)?)
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
        variants.push(Variant { name, value, discriminant_value });
    }

    for variant in variants.iter().filter_map(|variant| variant.value.as_ref()) {
        validate_package_struct_layout(TypeRepr::Default, [&discriminant, variant])?;
    }
    let enum_ty = EnumType::new(name, discriminant, variants)
        .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;
    Ok(Type::Enum(Arc::new(enum_ty)))
}

fn read_package_type_alignment<R: ByteReader>(
    source: &mut R,
    label: &str,
) -> Result<NonZeroU16, DeserializationError> {
    let align = source.read_u16()?;
    let align = NonZeroU16::new(align).ok_or_else(|| {
        DeserializationError::InvalidValue(format!("invalid type repr: {label} must be non-zero"))
    })?;
    if !align.get().is_power_of_two() {
        return Err(DeserializationError::InvalidValue(format!(
            "invalid type repr: {label} must be a power of two"
        )));
    }
    Ok(align)
}

fn validate_package_struct_layout<'a>(
    repr: TypeRepr,
    field_types: impl IntoIterator<Item = &'a Type>,
) -> Result<(), DeserializationError> {
    let fields = field_types
        .into_iter()
        .map(package_type_layout)
        .collect::<Result<Vec<_>, _>>()?;
    if repr.is_transparent() && fields.iter().filter(|field| field.size != 0).count() > 1 {
        return Err(DeserializationError::InvalidValue(
            "invalid transparent representation for struct".into(),
        ));
    }

    let default_align = fields.iter().map(|field| field.align).max().unwrap_or(1);
    let struct_align = match repr {
        TypeRepr::Align(align) => u64::from(align.get()).max(default_align),
        TypeRepr::Packed(align) => u64::from(align.get()).min(default_align),
        TypeRepr::Transparent | TypeRepr::Default | TypeRepr::BigEndian => default_align,
    };
    let mut offset = 0u64;
    for field in fields {
        let field_align = if let TypeRepr::Packed(align) = repr {
            u64::from(align.get()).min(field.align)
        } else {
            field.align
        };
        offset = align_up_checked(offset, field_align)?;
        offset = offset.checked_add(field.size).ok_or_else(|| {
            DeserializationError::InvalidValue("type layout size overflow".into())
        })?;
        if offset > u64::from(u32::MAX) {
            return Err(DeserializationError::InvalidValue(
                "type layout size exceeds supported range".into(),
            ));
        }
    }
    let size = align_up_checked(offset, struct_align)?;
    if size > u64::from(u32::MAX) {
        return Err(DeserializationError::InvalidValue(
            "type layout size exceeds supported range".into(),
        ));
    }

    Ok(())
}

#[derive(Clone, Copy)]
struct PackageTypeLayout {
    size: u64,
    align: u64,
}

fn package_type_layout(ty: &Type) -> Result<PackageTypeLayout, DeserializationError> {
    let layout = match ty {
        Type::Unknown | Type::Never => PackageTypeLayout { size: 0, align: 1 },
        Type::I1 | Type::I8 | Type::U8 => PackageTypeLayout { size: 1, align: 1 },
        Type::I16 | Type::U16 => PackageTypeLayout { size: 2, align: 2 },
        // Keep this in sync with midenc-hir-type's byte-addressable layout: felts have
        // a near-64-bit value range, but are stored as 32-bit memory chunks.
        Type::I32 | Type::U32 | Type::Felt | Type::Ptr(_) | Type::Function(_) => {
            PackageTypeLayout { size: 4, align: 4 }
        },
        Type::I64 | Type::U64 | Type::F64 => PackageTypeLayout { size: 8, align: 4 },
        Type::I128 | Type::U128 => PackageTypeLayout { size: 16, align: 16 },
        Type::U256 => PackageTypeLayout { size: 32, align: 16 },
        Type::Struct(struct_ty) => PackageTypeLayout {
            size: struct_ty.size() as u64,
            align: struct_ty.min_alignment() as u64,
        },
        Type::Enum(enum_ty) => PackageTypeLayout {
            size: enum_ty.size_in_bytes() as u64,
            align: enum_ty.min_alignment() as u64,
        },
        Type::Array(array_ty) => {
            let element = package_type_layout(array_ty.element_type())?;
            let size = match array_ty.len() {
                0 => 0,
                1 => element.size,
                len => {
                    let padded = align_up_checked(element.size, element.align)?;
                    let rest = padded.checked_mul((len - 1) as u64).ok_or_else(|| {
                        DeserializationError::InvalidValue("type layout size overflow".into())
                    })?;
                    element.size.checked_add(rest).ok_or_else(|| {
                        DeserializationError::InvalidValue("type layout size overflow".into())
                    })?
                },
            };
            PackageTypeLayout { size, align: element.align }
        },
        Type::List(_) => {
            return Err(DeserializationError::InvalidValue(
                "list type has no defined package layout".into(),
            ));
        },
    };

    if !layout.align.is_power_of_two() {
        return Err(DeserializationError::InvalidValue(
            "type alignment must be power of two".into(),
        ));
    }
    if layout.align > u64::from(u16::MAX) || layout.size > u64::from(u32::MAX) {
        return Err(DeserializationError::InvalidValue(
            "type layout exceeds supported range".into(),
        ));
    }
    Ok(layout)
}

fn align_up_checked(value: u64, align: u64) -> Result<u64, DeserializationError> {
    debug_assert!(align.is_power_of_two());
    let mask = align - 1;
    value
        .checked_add(mask)
        .map(|value| value & !mask)
        .ok_or_else(|| DeserializationError::InvalidValue("type layout size overflow".into()))
}

// PACKAGE SERIALIZATION/DESERIALIZATION
// ================================================================================================

impl Package {
    #[doc(hidden)]
    pub fn write_header_into<W: ByteWriter>(&self, target: &mut W) {
        // Write magic & version
        target.write_bytes(MAGIC_PACKAGE);
        target.write_bytes(&VERSION);

        // Write package name
        self.name.write_into(target);

        // Write package version
        self.version.to_string().write_into(target);

        // Write package description
        self.description.write_into(target);

        // Write package kind
        target.write_u8(self.kind.into());
    }

    #[doc(hidden)]
    pub fn write_trailer_into<W: ByteWriter>(&self, target: &mut W) {
        // Write manifest
        self.manifest.write_into(target);

        // Write custom sections
        target.write_usize(self.sections.len());
        for section in self.sections.iter() {
            section.write_into(target);
        }
    }

    /// Reads a trusted package from `source` without validating the embedded MAST forest.
    ///
    /// # Trust boundary
    ///
    /// This skips embedded MAST validation and trusts serialized node digests. Use it only for
    /// bytes that were already validated before being persisted by the same trusted system.
    ///
    /// Do not use this for user-controlled packages, network input, registry artifacts, or any
    /// other package that crosses a trust boundary. Use [`Package::read_from`] for those
    /// inputs.
    pub fn read_from_unchecked<R: ByteReader>(
        source: &mut R,
    ) -> Result<Self, DeserializationError> {
        let header = Self::read_header_from(source)?;
        let mast_forest = Self::read_mast_forest(source, false)?;
        Self::read_from_with_header_and_mast(source, header, mast_forest, true)
    }

    /// Reads trusted package bytes without validating the embedded MAST forest.
    ///
    /// # Trust boundary
    ///
    /// This skips embedded MAST validation and trusts serialized node digests. Use it only for
    /// bytes that were already validated before being persisted by the same trusted system.
    ///
    /// Do not use this for user-controlled packages, network input, registry artifacts, or any
    /// other package that crosses a trust boundary. Use [`Package::read_from_bytes`] for those
    /// inputs.
    pub fn read_from_bytes_unchecked(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut source = SliceReader::new(bytes);
        Self::read_from_unchecked(&mut source)
    }

    /// Reads a trusted local package while validating the embedded MAST forest.
    ///
    /// This keeps the same structural validation as [`Package::read_from`], but allows
    /// package-owned debug sections to be decoded as trusted metadata. Use this only for local
    /// files or cache artifacts controlled by this process or build system. Do not use this for
    /// inbound artifacts from an untrusted channel; use [`Package::read_from`] instead so debug
    /// sections are discarded before the package is exposed to callers.
    pub fn read_from_trusted<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let header = Self::read_header_from(source)?;
        let mast_forest = Self::read_mast_forest(source, true)?;
        Self::read_from_with_header_and_mast(source, header, mast_forest, true)
    }

    /// Reads trusted local package bytes while validating the embedded MAST forest.
    ///
    /// See [`Package::read_from_trusted`].
    pub fn read_from_bytes_trusted(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let budget = bytes.len().saturating_mul(PACKAGE_BYTE_READ_BUDGET_MULTIPLIER);
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), budget);
        Self::read_from_trusted(&mut reader)
    }

    fn read_mast_forest<R: ByteReader>(
        source: &mut R,
        validate_mast_forest: bool,
    ) -> Result<Arc<MastForest>, DeserializationError> {
        if validate_mast_forest {
            UntrustedMastForest::read_from(source)?.validate().map_err(|err| {
                DeserializationError::InvalidValue(format!(
                    "library contains an invalid untrusted MAST forest: {err}"
                ))
            })
        } else {
            MastForest::read_from(source)
        }
        .map(Arc::new)
    }
}

impl Serializable for Package {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.write_header_into(target);

        // Write MAST artifact
        self.mast.write_into(target);

        self.write_trailer_into(target);
    }
}

struct PackageHeader {
    name: PackageId,
    version: crate::Version,
    description: Option<String>,
    kind: TargetType,
}

impl Package {
    fn read_header_from<R: ByteReader>(
        source: &mut R,
    ) -> Result<PackageHeader, DeserializationError> {
        // Read and validate magic & version
        let magic: [u8; 5] = source.read_array()?;
        if magic != *MAGIC_PACKAGE {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid magic bytes. Expected '{MAGIC_PACKAGE:?}', got '{magic:?}'"
            )));
        }

        let version: [u8; 3] = source.read_array()?;
        if version != VERSION {
            return Err(DeserializationError::InvalidValue(format!(
                "unsupported version. Got '{version:?}', but only '{VERSION:?}' is supported"
            )));
        }

        // Read package name
        let name = PackageId::read_from(source)?;

        // Read package version
        let version = String::read_from(source)?
            .parse::<crate::Version>()
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;

        // Read package description
        let description = Option::<String>::read_from(source)?;

        // Read package kind
        let kind_tag = source.read_u8()?;
        let kind = TargetType::try_from(kind_tag)
            .map_err(|e| DeserializationError::InvalidValue(e.to_string()))?;

        Ok(PackageHeader { name, version, description, kind })
    }

    fn read_from_with_header_and_mast<R: ByteReader>(
        source: &mut R,
        header: PackageHeader,
        mast: Arc<MastForest>,
        debug_sections_trusted: bool,
    ) -> Result<Self, DeserializationError> {
        let PackageHeader { name, version, description, kind } = header;

        // Read manifest
        let manifest = PackageManifest::read_from_safe(source, &mast)?;

        // Read custom sections
        let mut sections = Vec::<Section>::read_from(source)?;
        if !debug_sections_trusted && sections.iter().any(|section| section.id.is_debug()) {
            log::warn!(
                "Package read ignored debug sections from an untrusted artifact; use Package::read_from_trusted for local cache/debug reads"
            );
            sections.retain(|section| !section.id.is_debug());
        }

        let mut package = Self {
            name,
            version,
            digest: Default::default(),
            description,
            kind,
            mast,
            manifest,
            sections,
            debug_sections_trusted,
        };

        package
            .recompute_mast_commitment()
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;

        Ok(package)
    }
}

impl Deserializable for Package {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let header = Self::read_header_from(source)?;

        // Read MAST artifact
        let mast = Self::read_mast_forest(source, true)?;

        Self::read_from_with_header_and_mast(source, header, mast, false)
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let budget = bytes.len().saturating_mul(PACKAGE_BYTE_READ_BUDGET_MULTIPLIER);
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), budget);
        Self::read_from(&mut reader)
    }
}

// PACKAGE MANIFEST SERIALIZATION/DESERIALIZATION
// ================================================================================================

#[cfg(feature = "serde")]
impl serde::Serialize for PackageManifest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use alloc::collections::BTreeMap;

        use miden_assembly_syntax::Path;
        use serde::ser::SerializeStruct;

        struct PackageExports<'a>(&'a BTreeMap<Arc<Path>, PackageExport>);

        impl serde::Serialize for PackageExports<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeSeq;

                let mut serializer = serializer.serialize_seq(Some(self.0.len()))?;
                for value in self.0.values() {
                    serializer.serialize_element(value)?;
                }
                serializer.end()
            }
        }

        struct PackageModules<'a>(&'a BTreeMap<Arc<Path>, PackageModule>);

        impl serde::Serialize for PackageModules<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeSeq;

                let mut serializer = serializer.serialize_seq(Some(self.0.len()))?;
                for value in self.0.values() {
                    serializer.serialize_element(value)?;
                }
                serializer.end()
            }
        }

        let mut serializer = serializer.serialize_struct("PackageManifest", 4)?;
        serializer.serialize_field("exports", &PackageExports(&self.exports))?;
        serializer.serialize_field("modules", &PackageModules(&self.modules))?;
        serializer.serialize_field("dependencies", &self.dependencies)?;
        serializer.serialize_field("entrypoint", &self.entrypoint)?;
        serializer.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PackageManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Exports,
            Modules,
            Dependencies,
            Entrypoint,
        }

        struct PackageManifestVisitor;

        impl<'de> serde::de::Visitor<'de> for PackageManifestVisitor {
            type Value = PackageManifest;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct PackageManifest")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let exports = seq
                    .next_element::<Vec<PackageExport>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let modules = seq
                    .next_element::<Vec<PackageModule>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let dependencies = seq
                    .next_element::<Vec<Dependency>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let entrypoint = seq
                    .next_element::<Option<PathBuf>>()
                    .map(|p| p.map(|p| p.map(Arc::<ast::Path>::from)))?;
                PackageManifest::new(exports)
                    .and_then(|manifest| manifest.with_modules(modules))
                    .and_then(|manifest| manifest.with_dependencies(dependencies))
                    .and_then(|manifest| {
                        if let Some(Some(entrypoint)) = entrypoint {
                            manifest.with_entrypoint(entrypoint)
                        } else {
                            Ok(manifest)
                        }
                    })
                    .map_err(serde::de::Error::custom)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut exports = None;
                let mut modules = None;
                let mut dependencies = None;
                let mut entrypoint = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Exports => {
                            if exports.is_some() {
                                return Err(serde::de::Error::duplicate_field("exports"));
                            }
                            exports = Some(map.next_value::<Vec<PackageExport>>()?);
                        },
                        Field::Modules => {
                            if modules.is_some() {
                                return Err(serde::de::Error::duplicate_field("modules"));
                            }
                            modules = Some(map.next_value::<Vec<PackageModule>>()?);
                        },
                        Field::Dependencies => {
                            if dependencies.is_some() {
                                return Err(serde::de::Error::duplicate_field("dependencies"));
                            }
                            dependencies = Some(map.next_value::<Vec<Dependency>>()?);
                        },
                        Field::Entrypoint => {
                            if entrypoint.is_some() {
                                return Err(serde::de::Error::duplicate_field("entrypoint"));
                            }
                            entrypoint = Some(
                                map.next_value::<Option<PathBuf>>()
                                    .map(|p| p.map(Arc::<ast::Path>::from))?,
                            );
                        },
                    }
                }
                let exports = exports.ok_or_else(|| serde::de::Error::missing_field("exports"))?;
                let modules = modules.ok_or_else(|| serde::de::Error::missing_field("modules"))?;
                let dependencies =
                    dependencies.ok_or_else(|| serde::de::Error::missing_field("dependencies"))?;
                PackageManifest::new(exports)
                    .and_then(|manifest| manifest.with_modules(modules))
                    .and_then(|manifest| manifest.with_dependencies(dependencies))
                    .and_then(|manifest| {
                        if let Some(Some(entrypoint)) = entrypoint {
                            manifest.with_entrypoint(entrypoint)
                        } else {
                            Ok(manifest)
                        }
                    })
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_struct(
            "PackageManifest",
            &["exports", "modules", "dependencies", "entrypoint"],
            PackageManifestVisitor,
        )
    }
}

impl Serializable for PackageManifest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write exports
        target.write_usize(self.num_exports());
        for export in self.exports() {
            export.write_into(target);
        }

        // Write module surfaces
        target.write_usize(self.num_modules());
        for module in self.modules() {
            module.write_into(target);
        }

        // Write dependencies
        target.write_usize(self.num_dependencies());
        for dep in self.dependencies() {
            dep.write_into(target);
        }

        // Write entrypoint
        if let Some(entrypoint) = self.entrypoint.as_ref() {
            target.write_bool(true);
            entrypoint.write_into(target);
        } else {
            target.write_bool(false);
        }
    }
}

impl PackageManifest {
    pub fn read_from_safe<R: ByteReader>(
        source: &mut R,
        mast: &MastForest,
    ) -> Result<Self, DeserializationError> {
        // Read exports
        let exports_len = source.read_usize()?;
        let max_exports = source.max_alloc(PackageExport::min_serialized_size());
        if exports_len > max_exports {
            return Err(DeserializationError::InvalidValue(format!(
                "requested {exports_len} elements but reader can provide at most {max_exports}"
            )));
        }
        let mut exports = Vec::with_capacity(exports_len);
        for _ in 0..exports_len {
            exports.push(PackageExport::read_from_safe(source, mast)?);
        }

        // Read module surfaces
        let modules_len = source.read_usize()?;
        let max_modules = source.max_alloc(PackageModule::min_serialized_size());
        if modules_len > max_modules {
            return Err(DeserializationError::InvalidValue(format!(
                "requested {modules_len} elements but reader can provide at most {max_modules}"
            )));
        }
        let modules = source.read_many_iter(modules_len)?.collect::<Result<Vec<_>, _>>()?;

        // Read dependencies
        let dependencies = Vec::<Dependency>::read_from(source)?;

        // Read entrypoint
        let entrypoint = if source.read_bool()? {
            Some(PathBuf::read_from(source).map(Arc::<ast::Path>::from)?)
        } else {
            None
        };

        PackageManifest::new(exports)
            .and_then(|manifest| manifest.with_modules(modules))
            .and_then(|manifest| manifest.with_dependencies(dependencies))
            .and_then(|manifest| {
                if let Some(entrypoint) = entrypoint {
                    manifest.with_entrypoint(entrypoint)
                } else {
                    Ok(manifest)
                }
            })
            .map_err(|error| DeserializationError::InvalidValue(error.to_string()))
    }
}

impl Deserializable for PackageManifest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // Read exports
        let exports_len = source.read_usize()?;
        let exports = source.read_many_iter(exports_len)?.collect::<Result<Vec<_>, _>>()?;

        // Read module surfaces
        let modules_len = source.read_usize()?;
        let modules = source.read_many_iter(modules_len)?.collect::<Result<Vec<_>, _>>()?;

        // Read dependencies
        let dependencies = Vec::<Dependency>::read_from(source)?;

        // Read entrypoint
        let entrypoint = if source.read_bool()? {
            Some(PathBuf::read_from(source).map(Arc::<ast::Path>::from)?)
        } else {
            None
        };

        PackageManifest::new(exports)
            .and_then(|manifest| manifest.with_modules(modules))
            .and_then(|manifest| manifest.with_dependencies(dependencies))
            .and_then(|manifest| {
                if let Some(entrypoint) = entrypoint {
                    manifest.with_entrypoint(entrypoint)
                } else {
                    Ok(manifest)
                }
            })
            .map_err(|error| DeserializationError::InvalidValue(error.to_string()))
    }
}

// PACKAGE MODULE SURFACE SERIALIZATION/DESERIALIZATION
// ================================================================================================

impl Serializable for PackageModule {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.path.write_into(target);
        target.write_usize(self.submodules.len());
        for submodule in self.submodules.iter() {
            submodule.write_into(target);
        }
    }
}

impl Deserializable for PackageModule {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let path = PathBuf::read_from(source)?.into_boxed_path().into();
        let submodules = Vec::<PackageSubmodule>::read_from(source)?;
        Ok(Self { path, submodules })
    }
}

impl Serializable for PackageSubmodule {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.name.write_into(target);
    }
}

impl Deserializable for PackageSubmodule {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name = ast::Ident::read_from(source)?;
        Ok(Self { name })
    }
}

// PACKAGE EXPORT SERIALIZATION/DESERIALIZATION
// ================================================================================================

impl Serializable for PackageExport {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.tag());
        match self {
            Self::Procedure(export) => export.write_into(target),
            Self::Constant(export) => export.write_into(target),
            Self::Type(export) => export.write_into(target),
        }
    }
}

impl PackageExport {
    pub fn read_from_safe<R: ByteReader>(
        source: &mut R,
        mast: &MastForest,
    ) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            1 => ProcedureExport::read_from_safe(source, mast).map(Self::Procedure),
            2 => ConstantExport::read_from(source).map(Self::Constant),
            3 => TypeExport::read_from(source).map(Self::Type),
            invalid => Err(DeserializationError::InvalidValue(format!(
                "unexpected PackageExport tag: '{invalid}'"
            ))),
        }
    }
}

impl Deserializable for PackageExport {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            1 => ProcedureExport::read_from(source).map(Self::Procedure),
            2 => ConstantExport::read_from(source).map(Self::Constant),
            3 => TypeExport::read_from(source).map(Self::Type),
            invalid => Err(DeserializationError::InvalidValue(format!(
                "unexpected PackageExport tag: '{invalid}'"
            ))),
        }
    }
}

impl Serializable for ProcedureExport {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.path.write_into(target);
        if let Some(node_id) = self.node {
            target.write_bool(true);
            target.write_u32(node_id.into());
        } else {
            target.write_bool(false);
        }
        if let Some(source_node) = self.source_node {
            target.write_bool(true);
            source_node.write_into(target);
        } else {
            target.write_bool(false);
        }
        self.digest.write_into(target);
        match self.signature.as_ref() {
            Some(sig) => {
                target.write_bool(true);
                sig.write_into(target);
            },
            None => {
                target.write_bool(false);
            },
        }
        self.attributes.write_into(target);
    }
}

impl ProcedureExport {
    pub fn read_from_safe<R: ByteReader>(
        source: &mut R,
        mast: &MastForest,
    ) -> Result<Self, DeserializationError> {
        let path = PathBuf::read_from(source)?.into_boxed_path().into();
        let node = if source.read_bool()? {
            let node_id = MastNodeId::from_u32_safe(source.read_u32()?, mast)?;
            if !mast.is_procedure_root(node_id) {
                return Err(DeserializationError::InvalidValue(
                    ManifestValidationError::InvalidProcedureExport { path }.to_string(),
                ));
            }
            Some(node_id)
        } else {
            None
        };
        let source_node = if source.read_bool()? {
            Some(DebugSourceNodeId::read_from(source)?)
        } else {
            None
        };
        let digest = Word::read_from(source)?;
        // Ensure that the digest associated with `node` matches the provided digest
        if let Some(node) = node
            && digest != mast[node].digest()
        {
            return Err(DeserializationError::InvalidValue(
                ManifestValidationError::InvalidProcedureExport { path }.to_string(),
            ));
        }
        let signature = if source.read_bool()? {
            Some(read_package_function_type_metadata(source)?)
        } else {
            None
        };
        let attributes = AttributeSet::read_from(source)?;
        Ok(Self {
            path,
            node,
            source_node,
            digest,
            signature,
            attributes,
        })
    }
}

impl Deserializable for ProcedureExport {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let path = PathBuf::read_from(source)?.into_boxed_path().into();
        let node = if source.read_bool()? {
            Some(MastNodeId::new_unchecked(source.read_u32()?))
        } else {
            None
        };
        let source_node = if source.read_bool()? {
            Some(DebugSourceNodeId::read_from(source)?)
        } else {
            None
        };
        let digest = Word::read_from(source)?;
        let signature = if source.read_bool()? {
            Some(read_package_function_type_metadata(source)?)
        } else {
            None
        };
        let attributes = AttributeSet::read_from(source)?;
        Ok(Self {
            path,
            node,
            source_node,
            digest,
            signature,
            attributes,
        })
    }
}

impl Serializable for ConstantExport {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.path.write_into(target);
        self.value.write_into(target);
    }
}

impl Deserializable for ConstantExport {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let path = PathBuf::read_from(source)?.into_boxed_path().into();
        let value = ast::ConstantValue::read_from(source)?;
        Ok(Self { path, value })
    }
}

impl Serializable for TypeExport {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.path.write_into(target);
        self.ty.write_into(target);
    }
}

impl Deserializable for TypeExport {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let path = PathBuf::read_from(source)?.into_boxed_path().into();
        let ty = read_package_type_metadata(source)?;
        Ok(Self { path, ty })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use alloc::format;
    use alloc::{
        string::{String, ToString},
        sync::Arc,
        vec,
        vec::Vec,
    };
    use core::{assert_matches, num::NonZeroU16};
    use std::collections::BTreeMap;
    #[cfg(feature = "std")]
    use std::fs;

    use miden_assembly_syntax::ast::{
        Ident, Path as AstPath, PathBuf, ProcedureName,
        types::{
            AddressSpace, ArrayType, CallConv, EnumType, FunctionType, NameAndType, PointerType,
            StructType, Type, TypeRepr, Variant,
        },
    };
    use miden_core::{
        Felt, Word,
        advice::AdviceMap,
        mast::{
            BasicBlockNodeBuilder, ExternalNodeBuilder, MastForest, MastForestContributor,
            MastNode, MastNodeExt, MastNodeId,
        },
        operations::Operation,
        serde::{
            BudgetedReader, ByteWriter, Deserializable, DeserializationError, Serializable,
            SliceReader,
        },
        utils::IndexVec,
    };

    use super::{
        MAGIC_PACKAGE, PACKAGE_BYTE_READ_BUDGET_MULTIPLIER, Package, PackageManifest, Section,
        VERSION, package_type_layout,
    };
    use crate::{
        Dependency, ManifestValidationError, PackageExport, PackageId, PackageModule,
        PackageSubmodule, ProcedureExport, SectionId, TargetType, TypeExport,
        debug_info::{
            DebugSourceAsmOp, DebugSourceGraphSection, DebugSourceMapSection, DebugSourceNode,
            DebugSourceNodeId,
        },
    };

    fn build_forest() -> (MastForest, MastNodeId) {
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        forest.make_root(node_id);
        (forest, node_id)
    }

    fn absolute_path(name: &str) -> Arc<AstPath> {
        let path = PathBuf::new(name).expect("invalid path");
        let path = path.as_path().to_absolute().unwrap().into_owned();
        Arc::from(path.into_boxed_path())
    }

    fn build_package_exports() -> (Arc<MastForest>, Vec<PackageExport>) {
        let (forest, node_id) = build_forest();
        let path = absolute_path("test::proc");
        let export =
            ProcedureExport::new(Arc::clone(&path), Some(node_id), forest[node_id].digest(), None);

        (Arc::new(forest), vec![PackageExport::Procedure(export)])
    }

    fn build_package() -> Package {
        let (mast, exports) = build_package_exports();

        Package::create(
            PackageId::from("test_pkg"),
            crate::Version::new(0, 0, 0),
            TargetType::Library,
            mast,
            exports,
            None,
        )
        .expect("test package should be valid")
    }

    fn build_package_with_external_dependency(dependency_digest: Word) -> Package {
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        forest.make_root(node_id);
        ExternalNodeBuilder::new(dependency_digest)
            .add_to_forest(&mut forest)
            .expect("failed to build external node");

        let path = absolute_path("test::proc");
        let export =
            ProcedureExport::new(Arc::clone(&path), Some(node_id), forest[node_id].digest(), None);

        Package::create(
            PackageId::from("test_pkg"),
            crate::Version::new(0, 0, 0),
            TargetType::Library,
            Arc::new(forest),
            [PackageExport::Procedure(export)],
            None,
        )
        .expect("test package should be valid")
    }

    fn build_package_with_debug_info() -> Package {
        let mut nodes = IndexVec::<MastNodeId, MastNode>::new();
        let node = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .build()
            .expect("failed to build basic block");
        let digest = node.digest();
        let node_id = nodes.push(node.into()).expect("failed to add basic block");
        let source_node = DebugSourceNodeId::from(0);

        let mast = Arc::new(
            MastForest::from_raw_parts(nodes, vec![node_id], AdviceMap::default())
                .expect("forest should be valid"),
        );
        let path = absolute_path("test::proc");
        let exports = vec![PackageExport::Procedure(
            ProcedureExport::new(path, Some(node_id), digest, None)
                .with_source_node(Some(source_node)),
        )];
        let mut package = Package::create(
            PackageId::from("test_pkg"),
            crate::Version::new(0, 0, 0),
            TargetType::Library,
            mast,
            exports,
            None,
        )
        .expect("test package should be valid");
        let source_graph = DebugSourceGraphSection::from_parts(
            vec![DebugSourceNode::new(node_id, Vec::new(), 0, 1)],
            vec![source_node],
        );
        let source_map = DebugSourceMapSection::from_parts(
            vec![DebugSourceAsmOp::new(source_node, 0, None, "trusted".into(), "add".into(), 1)],
            Vec::new(),
        );
        package
            .sections
            .push(Section::new(SectionId::DEBUG_SOURCE_GRAPH, source_graph.to_bytes()));
        package
            .sections
            .push(Section::new(SectionId::DEBUG_SOURCE_MAP, source_map.to_bytes()));
        package
    }

    fn build_dependency() -> Dependency {
        Dependency {
            name: PackageId::from("dep"),
            kind: TargetType::Library,
            version: crate::Version::new(1, 0, 0),
            digest: Default::default(),
        }
    }

    fn package_bytes_with_sections_count(count: usize) -> Vec<u8> {
        let package = build_package();
        let mut bytes = Vec::new();

        bytes.write_bytes(MAGIC_PACKAGE);
        bytes.write_bytes(&VERSION);
        package.name.write_into(&mut bytes);
        package.version.to_string().write_into(&mut bytes);
        package.description.write_into(&mut bytes);
        bytes.write_u8(package.kind.into());
        package.mast.write_into(&mut bytes);
        package.manifest.write_into(&mut bytes);
        bytes.write_usize(count);

        bytes
    }

    #[test]
    fn package_serialization_roundtrip() {
        use proptest::{
            prelude::*,
            test_runner::{Config, TestRunner},
        };

        // since the test is quite expensive, 128 cases should be enough to cover all edge cases
        // (default is 256)
        let cases = 128;
        TestRunner::new(Config::with_cases(cases))
            .run(&any::<Package>(), move |package| {
                let bytes = package.to_bytes();
                let deserialized = Package::read_from_bytes(&bytes).unwrap();
                let mut expected = package;
                expected.sections.retain(|section| !section.id.is_debug());
                prop_assert_eq!(expected.to_bytes(), deserialized.to_bytes());
                Ok(())
            })
            .unwrap_or_else(|err| {
                panic!("{err}");
            });
    }

    #[test]
    fn executable_package_entrypoint_roundtrips() {
        let (forest, node_id) = build_forest();
        let entrypoint =
            Arc::from(AstPath::exec_path().join(ProcedureName::MAIN_PROC_NAME).into_boxed_path());
        let export = ProcedureExport::new(
            Arc::clone(&entrypoint),
            Some(node_id),
            forest[node_id].digest(),
            None,
        );
        let package = Package::create(
            PackageId::from("test_pkg"),
            crate::Version::new(0, 0, 0),
            TargetType::Executable,
            Arc::new(forest),
            [PackageExport::Procedure(export)],
            None,
        )
        .expect("executable package should be valid");

        let deserialized = Package::read_from_bytes(&package.to_bytes())
            .expect("executable package should deserialize without duplicate entrypoint errors");

        assert_eq!(deserialized.manifest.entrypoint(), Some(entrypoint));
    }

    #[test]
    fn package_checked_deserialization_discards_untrusted_debug_sections() {
        let package = build_package_with_debug_info();
        let bytes = package.to_bytes();

        let deserialized = Package::read_from_bytes(&bytes).unwrap();

        assert!(
            !deserialized.sections.iter().any(|section| section.id.is_debug()),
            "untrusted package reads should discard debug sections"
        );
        assert!(deserialized.debug_info().unwrap().is_none());
        let debug_source_map_id = SectionId::DEBUG_SOURCE_MAP.as_str().as_bytes();
        assert!(
            !deserialized
                .to_bytes()
                .windows(debug_source_map_id.len())
                .any(|window| window == debug_source_map_id),
            "discarded debug sections should not be reserialized"
        );
    }

    #[test]
    fn package_trusted_deserialization_preserves_trusted_debug_sections() {
        let package = build_package_with_debug_info();
        let bytes = package.to_bytes();

        let deserialized = Package::read_from_bytes_trusted(&bytes).unwrap();

        assert!(
            deserialized
                .sections
                .iter()
                .any(|section| section.id == SectionId::DEBUG_SOURCE_MAP)
        );
        assert!(deserialized.debug_info().unwrap().is_some());
    }

    #[test]
    fn package_unchecked_deserialization_preserves_trusted_debug_sections() {
        let package = build_package_with_debug_info();
        let bytes = package.to_bytes();

        let deserialized = Package::read_from_bytes_unchecked(&bytes).unwrap();

        assert!(
            deserialized
                .sections
                .iter()
                .any(|section| section.id == SectionId::DEBUG_SOURCE_MAP)
        );
        assert!(deserialized.debug_info().unwrap().is_some());
    }

    #[cfg(feature = "std")]
    #[test]
    fn package_deserialize_from_file_discards_untrusted_debug_sections() {
        let package = build_package_with_debug_info();
        let path = std::env::temp_dir().join(format!(
            "miden-package-deserialize-{}-{}.masp",
            std::process::id(),
            "debug-sections"
        ));
        package.write_to_file(&path).unwrap();

        let deserialized = Package::deserialize_from_file(&path).unwrap();
        fs::remove_file(&path).unwrap();

        assert!(
            !deserialized.sections.iter().any(|section| section.id.is_debug()),
            "untrusted package file reads should discard debug sections"
        );
        assert!(deserialized.debug_info().unwrap().is_none());
    }

    #[cfg(feature = "std")]
    #[test]
    fn package_deserialize_from_file_trusted_preserves_trusted_debug_sections() {
        let package = build_package_with_debug_info();
        let path = std::env::temp_dir().join(format!(
            "miden-package-deserialize-{}-{}.masp",
            std::process::id(),
            "trusted-debug-sections"
        ));
        package.write_to_file(&path).unwrap();

        let deserialized = Package::deserialize_from_file_trusted(&path).unwrap();
        fs::remove_file(&path).unwrap();

        assert!(
            deserialized
                .sections
                .iter()
                .any(|section| section.id == SectionId::DEBUG_SOURCE_MAP)
        );
        assert!(deserialized.debug_info().unwrap().is_some());
    }

    #[test]
    fn package_content_digest_changes_when_identity_fields_change() {
        let package = build_package();
        let digest = package.content_digest();

        let renamed = Package {
            name: PackageId::from("renamed_pkg"),
            ..package.clone()
        };
        assert_ne!(digest, renamed.content_digest());

        let versioned = Package {
            version: crate::Version::new(1, 2, 3),
            ..package.clone()
        };
        assert_ne!(digest, versioned.content_digest());

        let executable = Package { kind: TargetType::Executable, ..package };
        assert_ne!(digest, executable.content_digest());
    }

    #[test]
    fn package_content_digest_changes_when_manifest_changes() {
        let package = build_package();
        let digest = package.content_digest();

        let mut with_dependency = package;
        with_dependency
            .manifest
            .add_dependency(Dependency {
                name: PackageId::from("dep_pkg"),
                kind: TargetType::Library,
                version: crate::Version::new(1, 0, 0),
                digest: Word::from([1_u32, 2, 3, 4]),
            })
            .expect("test dependency should be unique");
        assert_ne!(digest, with_dependency.content_digest());
    }

    #[test]
    fn package_digest_changes_when_external_dependencies_change() {
        let first = build_package_with_external_dependency(Word::new([
            Felt::new_unchecked(1),
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ]));
        let second = build_package_with_external_dependency(Word::new([
            Felt::new_unchecked(2),
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ]));

        assert_eq!(first.interface_digest(), second.interface_digest());
        assert_ne!(first.digest(), second.digest());
        assert_ne!(first.content_digest(), second.content_digest());
    }

    #[test]
    fn package_digest_changes_when_advice_map_changes() {
        let first = build_package().with_advice_map(AdviceMap::from_iter([(
            Word::from([Felt::new_unchecked(1), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            vec![Felt::new_unchecked(10)],
        )]));
        let second = build_package().with_advice_map(AdviceMap::from_iter([(
            Word::from([Felt::new_unchecked(2), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            vec![Felt::new_unchecked(10)],
        )]));

        assert_eq!(first.interface_digest(), second.interface_digest());
        assert_ne!(first.digest(), second.digest());
        assert_ne!(first.content_digest(), second.content_digest());
    }

    #[test]
    fn package_content_digest_changes_when_account_component_metadata_changes() {
        let package = build_package();
        let digest = package.content_digest();

        let with_metadata = Package {
            sections: vec![Section::new(SectionId::ACCOUNT_COMPONENT_METADATA, vec![1, 2, 3, 4])],
            ..package.clone()
        };
        assert_ne!(digest, with_metadata.content_digest());

        let with_different_metadata = Package {
            sections: vec![Section::new(SectionId::ACCOUNT_COMPONENT_METADATA, vec![4, 3, 2, 1])],
            ..package
        };
        assert_ne!(with_metadata.content_digest(), with_different_metadata.content_digest());
    }

    #[test]
    fn package_content_digest_ignores_description_and_opaque_custom_sections_for_now() {
        let package = build_package();
        let digest = package.content_digest();

        let described = Package {
            description: Some(String::from("human-facing package description")),
            ..package.clone()
        };
        assert_eq!(digest, described.content_digest());

        let with_section = Package {
            sections: vec![Section::new(
                SectionId::custom("opaque").expect("valid custom section id"),
                vec![1, 2, 3, 4],
            )],
            ..package
        };
        assert_eq!(digest, with_section.content_digest());
    }

    #[test]
    fn package_manifest_rejects_over_budget_dependencies() {
        let mut bytes = Vec::new();
        bytes.write_usize(0);
        bytes.write_usize(0);
        bytes.write_usize(2);

        let mut reader = BudgetedReader::new(SliceReader::new(&bytes), 2);
        let err = PackageManifest::read_from(&mut reader).unwrap_err();
        assert!(matches!(err, DeserializationError::InvalidValue(_)));
    }

    #[test]
    fn package_rejects_over_budget_sections() {
        let bytes = package_bytes_with_sections_count(2);
        let mut reader = BudgetedReader::new(SliceReader::new(&bytes), bytes.len());
        let err = Package::read_from(&mut reader).unwrap_err();
        assert!(matches!(err, DeserializationError::InvalidValue(_)));
    }

    #[test]
    fn type_export_rejects_non_power_of_two_struct_alignment() {
        let mut bytes = Vec::new();
        absolute_path("test::Ty").write_into(&mut bytes);
        bytes.write_u8(17); // Type::Struct
        bytes.write_bool(false); // no struct name
        bytes.write_u8(1); // TypeRepr::Align
        bytes.write_u16(3); // non-power-of-two alignment
        bytes.write_u8(0); // no fields

        let mut reader = SliceReader::new(&bytes);
        let err = TypeExport::read_from(&mut reader)
            .expect_err("non-power-of-two struct alignment should be rejected");
        assert_matches!(
            err,
            DeserializationError::InvalidValue(message) if message.contains("power of two")
        );
    }

    #[test]
    fn package_type_layout_matches_felt_memory_model() {
        let layout = package_type_layout(&Type::Felt).unwrap();
        assert_eq!(layout.size, 4);
        assert_eq!(layout.align, 4);
    }

    #[test]
    fn type_export_roundtrips_representative_package_types() {
        for ty in representative_package_types() {
            let export = TypeExport { path: absolute_path("test::Ty"), ty };
            let bytes = export.to_bytes();

            let decoded =
                TypeExport::read_from_bytes(&bytes).expect("type export should roundtrip");

            assert_eq!(bytes, decoded.to_bytes());
        }
    }

    #[test]
    fn procedure_export_roundtrips_representative_signatures() {
        for cc in [CallConv::Fast, CallConv::C, CallConv::Wasm, CallConv::ComponentModel] {
            let signature = FunctionType::new(
                cc,
                [
                    Type::Felt,
                    pointer_type(AddressSpace::Byte, Type::U32),
                    array_type(Type::U16, 3),
                ],
                [struct_type(TypeRepr::Default), enum_type()],
            );
            let export = ProcedureExport::new(
                absolute_path("test::proc"),
                None,
                Word::default(),
                Some(signature),
            );
            let bytes = export.to_bytes();

            let decoded = ProcedureExport::read_from_bytes(&bytes)
                .expect("procedure export should roundtrip");

            assert_eq!(bytes, decoded.to_bytes());
        }
    }

    fn representative_package_types() -> Vec<Type> {
        let mut types = vec![
            Type::Unknown,
            Type::Never,
            Type::I1,
            Type::I8,
            Type::U8,
            Type::I16,
            Type::U16,
            Type::I32,
            Type::U32,
            Type::I64,
            Type::U64,
            Type::I128,
            Type::U128,
            Type::U256,
            Type::F64,
            Type::Felt,
            pointer_type(AddressSpace::Byte, Type::Felt),
            pointer_type(AddressSpace::Element, Type::U32),
            array_type(Type::U16, 3),
            Type::List(Arc::new(Type::I32)),
            Type::Function(Arc::new(FunctionType::new(
                CallConv::ComponentModel,
                [Type::Felt, pointer_type(AddressSpace::Byte, Type::U32)],
                [array_type(Type::U8, 4)],
            ))),
            enum_type(),
            multi_field_struct_type(),
        ];

        for repr in [
            TypeRepr::Default,
            TypeRepr::Align(NonZeroU16::new(8).unwrap()),
            TypeRepr::Packed(NonZeroU16::new(1).unwrap()),
            TypeRepr::Transparent,
            TypeRepr::BigEndian,
        ] {
            types.push(struct_type(repr));
        }

        types
    }

    fn pointer_type(addrspace: AddressSpace, pointee: Type) -> Type {
        Type::Ptr(Arc::new(PointerType { addrspace, pointee }))
    }

    fn array_type(ty: Type, len: usize) -> Type {
        Type::Array(Arc::new(ArrayType { ty, len }))
    }

    fn struct_type(repr: TypeRepr) -> Type {
        let fields = vec![NameAndType {
            name: Some(Arc::from("value")),
            ty: Type::Felt,
        }];
        Type::Struct(Arc::new(StructType::from_parts(Some(Arc::from("Wrapper")), repr, fields)))
    }

    fn multi_field_struct_type() -> Type {
        let fields = vec![
            NameAndType {
                name: Some(Arc::from("left")),
                ty: Type::Felt,
            },
            NameAndType {
                name: Some(Arc::from("right")),
                ty: array_type(Type::U8, 4),
            },
        ];
        Type::Struct(Arc::new(StructType::from_parts(
            Some(Arc::from("Pair")),
            TypeRepr::Default,
            fields,
        )))
    }

    fn enum_type() -> Type {
        Type::Enum(Arc::new(
            EnumType::new(
                Arc::from("Choice"),
                Type::U8,
                vec![
                    Variant {
                        name: Arc::from("None"),
                        value: None,
                        discriminant_value: Some(0),
                    },
                    Variant {
                        name: Arc::from("Some"),
                        value: Some(Type::U16),
                        discriminant_value: Some(1),
                    },
                ],
            )
            .expect("valid enum type"),
        ))
    }

    #[test]
    fn package_read_from_bytes_rejects_fuzzed_oom_payload() {
        // This fuzz payload encodes counts large enough to cause excessive allocation or read work.
        // If this starts succeeding, package byte-slice deserialization is no longer budgeted.
        let payload = [
            0x4d, 0x41, 0x53, 0x50, 0x00, 0x04, 0x00, 0x00, 0x11, 0x74, 0x65, 0x73, 0x74, 0x5f,
            0x70, 0x6b, 0x67, 0x0b, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x00, 0x00, 0x4d, 0x41, 0x53,
            0x54, 0x00, 0x00, 0x00, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x17, 0x03, 0x22,
            0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x30, 0x2f, 0x08, 0x0a, 0x21, 0xa9, 0xb6, 0xf6, 0x1a, 0x52, 0x30, 0xc5,
            0x64, 0xc7, 0xdb, 0x4d, 0x83, 0x0b, 0x32, 0x58, 0x89, 0x88, 0xb2, 0x78, 0x69, 0xbb,
            0x23, 0xa6, 0x18, 0x9c, 0xc9, 0x35, 0x2d, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x00, 0x0c, 0x00, 0x3a, 0x3a, 0x74, 0x65, 0x73,
            0x74, 0x3a, 0x3a, 0x70, 0x72, 0x6f, 0x63, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03,
            0x0f, 0x03, 0x0f, 0x01, 0x00, 0x00, 0x17, 0x03, 0x22, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x9c, 0xc9, 0x35, 0x2d, 0x01, 0x00, 0x03, 0x0f, 0x03,
            0x0f, 0x01, 0x01, 0x01,
        ];

        let result = Package::read_from_bytes(&payload);
        assert!(result.is_err());

        // Wrapped fuzz inputs must use the generic budgeted entry point; otherwise the outer
        // collection length can drive unbounded work before the inner package fails.
        let mut vec_payload = vec![0];
        vec_payload.extend_from_slice(&1000u64.to_le_bytes());
        let budget = vec_payload.len().saturating_mul(PACKAGE_BYTE_READ_BUDGET_MULTIPLIER);
        let result = Vec::<Package>::read_from_bytes_with_budget(&vec_payload, budget);
        assert!(result.is_err());

        let mut option_payload = vec![1];
        option_payload.extend_from_slice(&payload);
        let budget = option_payload.len().saturating_mul(PACKAGE_BYTE_READ_BUDGET_MULTIPLIER);
        let result = Option::<Package>::read_from_bytes_with_budget(&option_payload, budget);
        assert!(result.is_err());
    }

    /// Verifies that deserializing a library rejects procedure exports whose `MastNodeId` is not a
    /// procedure root in the underlying MAST forest (issue #2831).
    #[test]
    fn package_rejects_non_root_export() {
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        let digest = forest[node_id].digest();

        let path = absolute_path("test::proc");
        let exports = vec![PackageExport::Procedure(ProcedureExport::new(
            Arc::clone(&path),
            Some(node_id),
            digest,
            None,
        ))];

        let package = Package {
            name: PackageId::from("test_pkg"),
            version: crate::Version::new(0, 0, 0),
            digest,
            description: None,
            kind: TargetType::Library,
            mast: Arc::new(forest),
            manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
            sections: Default::default(),
            debug_sections_trusted: true,
        };

        // Manually serialize the tampered package: forest + one export referencing a non-root node.
        let mut tampered_bytes = Vec::new();
        package.write_into(&mut tampered_bytes);

        // Deserializing should fail because the export references a non-root node.
        let result = Package::read_from_bytes(&tampered_bytes);
        assert!(
            result.is_err(),
            "deserialization should reject exports referencing non-root nodes"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("node id and digest do not correspond to a procedure root"),
            "error should mention missing procedure root, got: {err_msg}"
        );
    }

    #[test]
    fn package_manifest_new_rejects_duplicate_export_paths() {
        let path = absolute_path("test::proc");
        let exports = vec![
            PackageExport::Procedure(ProcedureExport::new(
                path.clone(),
                None,
                Word::default(),
                None,
            )),
            PackageExport::Procedure(ProcedureExport::new(
                path.clone(),
                None,
                Word::default(),
                None,
            )),
        ];

        let err = PackageManifest::new(exports)
            .expect_err("duplicate export paths should be rejected by constructors");
        assert_matches!(err, ManifestValidationError::DuplicateExport(err_path) if err_path == path);
    }

    #[test]
    fn package_manifest_roundtrips_module_surfaces() {
        let export = PackageExport::Procedure(ProcedureExport::new(
            absolute_path("test::api::foo"),
            None,
            Word::default(),
            None,
        ));
        let module = PackageModule::new(
            absolute_path("test"),
            [PackageSubmodule::new(Ident::new("api").unwrap())],
        );
        let child = PackageModule::new(absolute_path("test::api"), []);

        let manifest = PackageManifest::new([export])
            .and_then(|manifest| manifest.with_modules([module, child]))
            .expect("manifest should be valid");
        let bytes = manifest.to_bytes();
        let decoded = PackageManifest::read_from_bytes(&bytes).expect("manifest should roundtrip");

        let root = decoded
            .get_module(absolute_path("test").as_ref())
            .expect("root module surface should be present");
        assert_eq!(root.submodules().len(), 1);
        assert_eq!(root.submodules()[0].name.as_str(), "api");
        assert!(decoded.get_module(absolute_path("test::api").as_ref()).is_some());
    }

    #[test]
    fn package_manifest_add_dependency_rejects_duplicate_dependencies() {
        let mut manifest = PackageManifest {
            exports: Default::default(),
            modules: Default::default(),
            dependencies: Default::default(),
            entrypoint: None,
        };
        let dependency = build_dependency();

        manifest
            .add_dependency(dependency.clone())
            .expect("first dependency should be accepted");
        let err = manifest
            .add_dependency(dependency)
            .expect_err("duplicate dependencies should be rejected by helpers");
        assert_matches!(err, ManifestValidationError::DuplicateDependency(pkgid) if pkgid == "dep");
    }

    #[test]
    fn package_manifest_rejects_duplicate_export_paths() {
        let path = absolute_path("test::proc");
        let export =
            PackageExport::Procedure(ProcedureExport::new(path, None, Word::default(), None));

        let mut bytes = Vec::new();
        bytes.write_usize(2);
        export.write_into(&mut bytes);
        export.write_into(&mut bytes);
        bytes.write_usize(0);
        bytes.write_usize(0);
        bytes.write_bool(false);

        let mut reader = SliceReader::new(&bytes);
        let err = PackageManifest::read_from(&mut reader)
            .expect_err("duplicate export paths should be rejected during deserialization");
        assert!(matches!(err, DeserializationError::InvalidValue(_)));
    }

    #[test]
    fn package_manifest_rejects_duplicate_dependencies() {
        let dependency = build_dependency();

        let mut bytes = Vec::new();
        bytes.write_usize(0);
        bytes.write_usize(0);
        bytes.write_usize(2);
        dependency.write_into(&mut bytes);
        dependency.write_into(&mut bytes);
        bytes.write_bool(false);

        let mut reader = SliceReader::new(&bytes);
        let err = PackageManifest::read_from(&mut reader)
            .expect_err("duplicate dependencies should be rejected during deserialization");
        assert!(matches!(err, DeserializationError::InvalidValue(_)));
    }

    #[test]
    fn package_manifest_deserialization_rejects_malformed_quoted_procedure_leaf() {
        let bad = Arc::<AstPath>::from(AstPath::validate(r#"::foo::"bad name""#).unwrap());
        let exports = BTreeMap::from_iter([(
            bad.clone(),
            PackageExport::Procedure(ProcedureExport::new(bad, None, Default::default(), None)),
        )]);

        let manifest = PackageManifest {
            exports,
            modules: Default::default(),
            dependencies: Default::default(),
            entrypoint: None,
        };

        let bytes = manifest.to_bytes();

        let err = PackageManifest::read_from_bytes(&bytes).expect_err(
            "expected malformed procedure export leaf name rejection during deserialization",
        );
        let message = alloc::format!("{err}");
        assert_matches!(
            message,
            msg if msg.contains("invalid export path '::foo::\"bad name\"': invalid item path component"),
        );
    }

    #[test]
    fn package_manifest_deserialization_rejects_malformed_quoted_constant_leaf() {
        let bad = Arc::<AstPath>::from(AstPath::validate(r#"::foo::"bad name""#).unwrap());
        let exports = BTreeMap::from_iter([(
            bad.clone(),
            PackageExport::Constant(crate::ConstantExport {
                path: bad,
                value: miden_assembly_syntax::ast::ConstantValue::Int(
                    miden_debug_types::Span::unknown(1u32.into()),
                ),
            }),
        )]);

        let manifest = PackageManifest {
            exports,
            modules: Default::default(),
            dependencies: Default::default(),
            entrypoint: None,
        };

        let bytes = manifest.to_bytes();

        let err = PackageManifest::read_from_bytes(&bytes).expect_err(
            "expected malformed constant export leaf name rejection during deserialization",
        );
        let message = alloc::format!("{err}");
        assert_matches!(
            message,
            msg if msg.contains("invalid export path '::foo::\"bad name\"': invalid item path component"),
        );
    }

    #[test]
    fn package_manifest_deserialization_rejects_malformed_quoted_type_leaf() {
        let bad = Arc::<AstPath>::from(AstPath::validate(r#"::foo::"bad name""#).unwrap());
        let exports = BTreeMap::from_iter([(
            bad.clone(),
            PackageExport::Type(TypeExport { path: bad, ty: Type::Felt }),
        )]);

        let manifest = PackageManifest {
            exports,
            modules: Default::default(),
            dependencies: Default::default(),
            entrypoint: None,
        };

        let bytes = manifest.to_bytes();

        let err = PackageManifest::read_from_bytes(&bytes).expect_err(
            "expected malformed type export leaf name rejection during deserialization",
        );
        let message = alloc::format!("{err}");
        assert_matches!(
            message,
            msg if msg.contains("invalid export path '::foo::\"bad name\"': invalid item path component"),
        );
    }

    #[test]
    fn regression_package_deserialisation_rejects_spoofed_mast_node_digests() {
        // Build mast for:
        //
        // pub proc p
        //     push.1
        // end
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::from_u32(1))])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        let digest = forest[node_id].digest();

        let path = absolute_path("lib::p");
        let exports = vec![PackageExport::Procedure(ProcedureExport::new(
            Arc::clone(&path),
            Some(node_id),
            digest,
            None,
        ))];

        let package = Package {
            name: PackageId::from("lib"),
            version: crate::Version::new(0, 0, 0),
            digest,
            description: None,
            kind: TargetType::Library,
            mast: Arc::new(forest),
            manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
            sections: Default::default(),
            debug_sections_trusted: true,
        };

        let (bytes, _) =
            build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-library-digest");
        let err = Package::read_from_bytes(&bytes)
            .expect_err("expected package deserialization to reject inconsistent node digests");
        assert!(
            err.to_string().contains("invalid untrusted MAST forest"),
            "expected untrusted-MAST validation failure, got: {err}"
        );
        assert!(
            err.to_string().contains("hash mismatch for node"),
            "expected digest mismatch failure, got: {err}"
        );
    }

    #[test]
    fn unchecked_package_deserialisation_rejects_spoofed_mast_node_digests() {
        // Build mast for:
        //
        // pub proc p
        //     push.1
        // end
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::from_u32(1))])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        let digest = forest[node_id].digest();

        let path = absolute_path("lib::p");
        let exports = vec![PackageExport::Procedure(ProcedureExport::new(
            Arc::clone(&path),
            Some(node_id),
            digest,
            None,
        ))];

        let package = Package {
            name: PackageId::from("lib"),
            version: crate::Version::new(0, 0, 0),
            digest,
            description: None,
            kind: TargetType::Library,
            mast: Arc::new(forest),
            manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
            sections: Default::default(),
            debug_sections_trusted: true,
        };

        let (bytes, _spoofed_digest) =
            build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-library-digest");
        let err = Package::read_from_bytes_unchecked(&bytes)
            .expect_err("expected package deserialization to reject inconsistent node digests");
        assert!(
            err.to_string()
                .contains("declared node id and digest do not correspond to a procedure root"),
            "expected package manifest validation failure, got: {err}"
        );
    }

    #[test]
    fn regression_kernel_package_deserialisation_rejects_spoofed_mast_node_digests() {
        // Build mast for:
        //
        // pub proc k1
        //     push.1
        // end
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::from_u32(1))])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        let digest = forest[node_id].digest();

        let path = absolute_path("$kernel::k1");
        let exports = vec![PackageExport::Procedure(ProcedureExport::new(
            Arc::clone(&path),
            Some(node_id),
            digest,
            None,
        ))];

        let package = Package {
            name: PackageId::from("kernel"),
            version: crate::Version::new(0, 0, 0),
            digest,
            description: None,
            kind: TargetType::Kernel,
            mast: Arc::new(forest),
            manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
            sections: Default::default(),
            debug_sections_trusted: true,
        };

        let (bytes, _) =
            build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-kernel-digest");
        let err = Package::read_from_bytes(&bytes).expect_err(
            "expected kernel package deserialization to reject inconsistent node digests",
        );
        assert!(
            err.to_string().contains("invalid untrusted MAST forest"),
            "expected untrusted-MAST validation failure, got: {err}"
        );
        assert!(
            err.to_string().contains("hash mismatch for node"),
            "expected digest mismatch failure, got: {err}"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn package_deserialize_from_file_rejects_spoofed_kernel_mast_node_digests() {
        // Build mast for:
        //
        // pub proc k1
        //     push.1
        // end
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::from_u32(1))])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        let digest = forest[node_id].digest();

        let path = absolute_path("$kernel::k1");
        let exports = vec![PackageExport::Procedure(ProcedureExport::new(
            Arc::clone(&path),
            Some(node_id),
            digest,
            None,
        ))];

        let package = Package {
            name: PackageId::from("kernel"),
            version: crate::Version::new(0, 0, 0),
            digest,
            description: None,
            kind: TargetType::Kernel,
            mast: Arc::new(forest),
            manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
            sections: Default::default(),
            debug_sections_trusted: true,
        };

        let (bytes, _) =
            build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-kernel-digest");
        let file_path = std::env::temp_dir().join(format!(
            "miden-package-deserialize-{}-{}.masp",
            std::process::id(),
            "spoofed-kernel-digest"
        ));
        fs::write(&file_path, bytes).expect("failed to write tampered package file");

        let err = Package::deserialize_from_file(&file_path)
            .expect_err("expected file deserialization to reject inconsistent node digests");
        fs::remove_file(&file_path).unwrap();

        assert!(
            err.to_string().contains("invalid untrusted MAST forest"),
            "expected untrusted-MAST validation failure, got: {err}"
        );
        assert!(
            err.to_string().contains("hash mismatch for node"),
            "expected digest mismatch failure, got: {err}"
        );
    }

    #[test]
    fn unchecked_kernel_package_deserialisation_accepts_spoofed_mast_node_digests() {
        // Build mast for:
        //
        // pub proc k1
        //     push.1
        // end
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::from_u32(1))])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        let digest = forest[node_id].digest();

        let path = absolute_path("$kernel::k1");
        let exports = vec![PackageExport::Procedure(ProcedureExport::new(
            Arc::clone(&path),
            Some(node_id),
            digest,
            None,
        ))];

        let package = Package {
            name: PackageId::from("kernel"),
            version: crate::Version::new(0, 0, 0),
            digest,
            description: None,
            kind: TargetType::Kernel,
            mast: Arc::new(forest),
            manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
            sections: Default::default(),
            debug_sections_trusted: true,
        };

        let (bytes, _spoofed_digest) =
            build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-kernel-digest");
        let err = Package::read_from_bytes_unchecked(&bytes).expect_err(
            "expected unchecked kernel deserialization to reject inconsistent node digests",
        );
        assert!(
            err.to_string()
                .contains("declared node id and digest do not correspond to a procedure root"),
            "expected package manifest validation failure, got: {err}"
        );
    }

    fn read_usize_vint64(bytes: &[u8], offset: &mut usize) -> usize {
        // This test patches raw bytes in place, so it needs byte offsets that
        // ByteReader::read_usize does not expose.
        let first_byte = bytes.get(*offset).copied().expect("out-of-bounds vint64 peek");
        let length = first_byte.trailing_zeros() as usize + 1;

        if length == 9 {
            *offset += 1;
            let end = (*offset).checked_add(8).expect("offset overflow while reading vint64");
            let chunk: [u8; 8] = bytes[*offset..end].try_into().expect("out-of-bounds vint64");
            *offset = end;
            let value = u64::from_le_bytes(chunk);
            usize::try_from(value).expect("encoded usize does not fit host usize")
        } else {
            let end = (*offset).checked_add(length).expect("offset overflow while reading vint64");
            let mut encoded = [0u8; 8];
            encoded[..length].copy_from_slice(&bytes[*offset..end]);
            *offset = end;
            let value = u64::from_le_bytes(encoded) >> length;
            usize::try_from(value).expect("encoded usize does not fit host usize")
        }
    }

    fn locate_first_node_hash(bytes: &[u8]) -> (usize, usize) {
        // Header: magic[4] + flags[1] + version[3]
        let mut offset = 0usize;
        offset += 4;
        offset += 1;
        offset += 3;

        let internal_node_count = read_usize_vint64(bytes, &mut offset);
        let external_node_count = read_usize_vint64(bytes, &mut offset);
        let node_count = internal_node_count
            .checked_add(external_node_count)
            .expect("node count overflow");

        // Roots: len (usize) + elements (u32 LE)
        let roots_len = read_usize_vint64(bytes, &mut offset);
        offset += roots_len * 4;

        // Basic block data: len (usize) + bytes
        let bb_len = read_usize_vint64(bytes, &mut offset);
        offset += bb_len;

        offset += node_count * 8;
        offset += external_node_count * 32;

        (offset, internal_node_count)
    }

    fn build_package_bytes_with_spoofed_first_node_digest(
        lib: &Package,
        spoof_seed: &str,
    ) -> (Vec<u8>, Word) {
        use miden_core::serde::Serializable;

        // Serialize the MastForest normally so the byte layout is stable.
        let forest = lib.mast_forest().as_ref();
        let original_digest = forest[MastNodeId::new_unchecked(0)].digest();
        let mut output_bytes = Vec::new();
        lib.write_header_into(&mut output_bytes);
        let forest_offset = output_bytes.len();
        forest.write_into(&mut output_bytes);

        let (node_hashes_start, node_count) =
            locate_first_node_hash(&output_bytes[forest_offset..]);
        assert!(node_count > 0, "expected at least one node info entry");

        // Patch node 0 digest in-place.
        let spoofed_digest = miden_core::utils::hash_string_to_word(spoof_seed);
        assert_ne!(spoofed_digest, original_digest, "spoofed digest must differ");

        let mut spoofed_digest_bytes = Vec::new();
        spoofed_digest.write_into(&mut spoofed_digest_bytes);
        assert_eq!(spoofed_digest_bytes.len(), 32, "Word must serialize to 32 bytes");

        let node0_digest_offset = forest_offset + node_hashes_start;
        output_bytes[node0_digest_offset..node0_digest_offset + 32]
            .copy_from_slice(&spoofed_digest_bytes);

        lib.write_trailer_into(&mut output_bytes);

        (output_bytes, spoofed_digest)
    }
}
