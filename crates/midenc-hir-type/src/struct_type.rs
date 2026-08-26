use alloc::sync::Arc;
use core::{fmt, num::NonZeroU16};

use smallvec::SmallVec;

use super::{Alignable, Type};

/// This represents a structured aggregate type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StructType {
    /// An optional display name for this struct type
    pub(crate) name: Option<Arc<str>>,
    /// The representation to use for this type
    pub(crate) repr: TypeRepr,
    /// The computed size of this struct
    pub(crate) size: u32,
    /// The fields of this struct, in the original order specified
    ///
    /// The actual order of fields in the final layout is determined by the index
    /// associated with each field, not the index in this vector, although for `repr(C)`
    /// structs they will be the same
    pub(crate) fields: SmallVec<[StructField; 2]>,
}

/// This represents metadata about a field of a [StructType]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StructField {
    /// An optional display name for this field
    pub name: Option<Arc<str>>,
    /// The index of this field in the final layout
    pub index: u8,
    /// The specified alignment for this field
    pub align: u16,
    /// The offset of this field relative to the base of the struct
    pub offset: u32,
    /// The type of this field
    pub ty: Type,
}

/// This represents metadata about how a structured type will be represented in memory
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TypeRepr {
    /// This corresponds to the C ABI representation for a given type
    #[default]
    Default,
    /// This modifies the default representation, by raising the minimum alignment.
    ///
    /// The alignment must be a power of two, e.g. 32, and values from 1 to 2^16 are allowed.
    ///
    /// The alignment must be greater than the default minimum alignment of the type
    /// or this representation has no effect.
    Align(NonZeroU16),
    /// This modifies the default representation, by lowering the minimum alignment of
    /// a type, and in the case of structs, changes the alignments of the fields to be
    /// the smaller of the specified alignment and the default alignment. This has the
    /// effect of changing the layout of a struct.
    ///
    /// Notably, `Packed(1)` will result in a struct that has no alignment requirement,
    /// and no padding between fields.
    ///
    /// The alignment must be a power of two, e.g. 32, and values from 1 to 2^16 are allowed.
    ///
    /// The alignment must be smaller than the default alignment, or this representation
    /// has no effect.
    Packed(NonZeroU16),
    /// This may only be used on structs with no more than one non-zero sized field, and
    /// indicates that the representation of that field should be used for the struct.
    Transparent,
}

impl TypeRepr {
    /// Construct a packed representation with the given alignment
    #[inline]
    pub fn packed(align: u16) -> Self {
        Self::Packed(
            NonZeroU16::new(align).expect("invalid alignment: expected value in range 1..=65535"),
        )
    }

    /// Construct a representation with the given minimum alignment
    #[inline]
    pub fn align(align: u16) -> Self {
        Self::Align(
            NonZeroU16::new(align).expect("invalid alignment: expected value in range 1..=65535"),
        )
    }

    /// Return true if this type representation is transparent
    pub fn is_transparent(&self) -> bool {
        matches!(self, Self::Transparent)
    }

    /// Return true if this type representation is packed
    pub fn is_packed(&self) -> bool {
        matches!(self, Self::Packed(_))
    }

    /// Get the custom alignment given for this type representation, if applicable
    pub fn min_alignment(&self) -> Option<usize> {
        match self {
            Self::Packed(align) | Self::Align(align) => Some(align.get() as usize),
            _ => None,
        }
    }
}

/// A wrapper around [Type] which permits a [Type] to be optionally named.
pub struct NameAndType {
    pub name: Option<Arc<str>>,
    pub ty: Type,
}

impl From<Type> for NameAndType {
    fn from(ty: Type) -> Self {
        Self { name: None, ty }
    }
}

impl From<(Arc<str>, Type)> for NameAndType {
    fn from((name, ty): (Arc<str>, Type)) -> Self {
        Self { name: Some(name), ty }
    }
}

impl StructType {
    /// Create a new struct with default representation, i.e. a struct with representation of
    /// `TypeRepr::Packed(1)`.
    #[inline]
    pub fn new<I>(fields: I) -> Self
    where
        I: IntoIterator,
        <I as IntoIterator>::Item: Into<NameAndType>,
    {
        Self::from_parts(None, TypeRepr::Default, fields)
    }

    /// Create a new struct with default representation, i.e. a struct with representation of
    /// `TypeRepr::Packed(1)`.
    #[inline]
    pub fn named<I>(name: Arc<str>, fields: I) -> Self
    where
        I: IntoIterator,
        <I as IntoIterator>::Item: Into<NameAndType>,
    {
        Self::from_parts(Some(name), TypeRepr::Default, fields)
    }

    /// Create a new struct with the given representation.
    ///
    /// This function will panic if the rules of the given representation are violated.
    pub fn new_with_repr<I>(repr: TypeRepr, fields: I) -> Self
    where
        I: IntoIterator,
        <I as IntoIterator>::Item: Into<NameAndType>,
    {
        Self::from_parts(None, repr, fields)
    }

    /// Create a new struct from the given name, repr, and fields.
    ///
    /// This function will panic if the rules of the given representation are violated.
    pub fn from_parts<I>(name: Option<Arc<str>>, repr: TypeRepr, fields: I) -> Self
    where
        I: IntoIterator,
        <I as IntoIterator>::Item: Into<NameAndType>,
    {
        let tys = fields.into_iter().map(Into::into).collect::<SmallVec<[_; 2]>>();
        // NOTE: `StructField::index` is a `u8`, so 256 fields would be representable here, but
        // the field count is encoded as a `u8` on the wire, where 256 truncates to 0. Cap the
        // count at 255 so that every constructible struct can round-trip.
        assert!(
            u8::try_from(tys.len()).is_ok(),
            "invalid struct: expected no more than 255 fields"
        );
        let mut fields = SmallVec::<[_; 2]>::with_capacity(tys.len());
        let size = match repr {
            TypeRepr::Transparent => {
                let mut offset = 0u32;
                for (index, NameAndType { name, ty }) in tys.into_iter().enumerate() {
                    let index: u8 =
                        index.try_into().expect("invalid struct: expected no more than 255 fields");
                    let field_size: u32 = ty
                        .size_in_bytes()
                        .try_into()
                        .expect("invalid type: size is larger than 2^32 bytes");
                    if field_size == 0 {
                        fields.push(StructField { name, index, align: 1, offset, ty });
                    } else {
                        let align = ty.min_alignment().try_into().expect(
                            "invalid struct field alignment: expected power of two between 1 and \
                             2^16",
                        );
                        assert_eq!(
                            offset, 0,
                            "invalid transparent representation for struct: repr(transparent) is \
                             only valid for structs with a single non-zero sized field"
                        );
                        fields.push(StructField { name, index, align, offset, ty });
                        offset += field_size;
                    }
                }
                offset
            },
            repr => {
                let mut offset = 0u32;
                let default_align: u16 =
                    tys.iter().map(|t| t.ty.min_alignment()).max().unwrap_or(1).try_into().expect(
                        "invalid struct field alignment: expected power of two between 1 and 2^16",
                    );
                let align = match repr {
                    TypeRepr::Align(align) => core::cmp::max(align.get(), default_align),
                    TypeRepr::Packed(align) => core::cmp::min(align.get(), default_align),
                    TypeRepr::Transparent | TypeRepr::Default => default_align,
                };

                for (index, NameAndType { name, ty }) in tys.into_iter().enumerate() {
                    let index: u8 =
                        index.try_into().expect("invalid struct: expected no more than 255 fields");
                    let field_size: u32 = ty
                        .size_in_bytes()
                        .try_into()
                        .expect("invalid type: size is larger than 2^32 bytes");
                    let default_align: u16 = ty.min_alignment().try_into().expect(
                        "invalid struct field alignment: expected power of two between 1 and 2^16",
                    );
                    let align: u16 = match repr {
                        TypeRepr::Packed(align) => core::cmp::min(align.get(), default_align),
                        _ => default_align,
                    };
                    offset += offset.align_offset(align as u32);
                    fields.push(StructField { name, index, align, offset, ty });
                    offset += field_size;
                }
                offset.align_up(align as u32)
            },
        };

        Self { name, repr, size, fields }
    }

    /// Reassemble a struct from already-computed layout metadata.
    ///
    /// This is how a recursive definition's open body is closed: the layout was computed once at
    /// construction, so re-deriving it here would be both wasteful and a chance to disagree.
    pub(crate) fn from_raw_parts(
        name: Option<Arc<str>>,
        repr: TypeRepr,
        size: u32,
        fields: SmallVec<[StructField; 2]>,
    ) -> Self {
        Self { name, repr, size, fields }
    }

    /// The raw, byte-valued size of this struct, as stored.
    #[inline]
    pub(crate) fn size_raw(&self) -> u32 {
        self.size
    }

    /// Get the name of this struct, if provided.
    #[inline]
    pub fn name(&self) -> Option<Arc<str>> {
        self.name.clone()
    }

    /// Get the [TypeRepr] for this struct
    #[inline]
    pub const fn repr(&self) -> TypeRepr {
        self.repr
    }

    /// Get the minimum alignment for this struct
    pub fn min_alignment(&self) -> usize {
        self.repr
            .min_alignment()
            .unwrap_or_else(|| self.fields.iter().map(|f| f.align as usize).max().unwrap_or(1))
    }

    /// Get the total size in bytes required to hold this struct, including alignment padding
    #[inline]
    pub fn size(&self) -> usize {
        self.size as usize
    }

    /// Get the struct field at `index`, relative to declaration order.
    pub fn get(&self, index: usize) -> &StructField {
        &self.fields[index]
    }

    /// Get the struct fields as a slice
    pub fn fields(&self) -> &[StructField] {
        self.fields.as_slice()
    }

    /// Returns true if this struct has no fields
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Get the length of this struct (i.e. number of fields)
    pub fn len(&self) -> usize {
        self.fields.len()
    }
}

impl TryFrom<Type> for StructType {
    type Error = Type;

    fn try_from(ty: Type) -> Result<Self, Self::Error> {
        match ty {
            // A recursive struct unfolds one level; see `StructRef::get`.
            Type::Struct(ty) => Ok(ty.get().into_owned()),
            other => Err(other),
        }
    }
}

impl fmt::Display for StructType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use miden_formatting::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

impl miden_formatting::prettier::PrettyPrint for StructType {
    fn render(&self) -> miden_formatting::prettier::Document {
        use miden_formatting::prettier::*;

        let name = match self.name.clone() {
            None => Document::Empty,
            Some(name) => display(name) + const_text(" "),
        };
        let header = match self.repr.render() {
            Document::Empty => const_text("struct ") + name,
            repr => const_text("struct ") + name + const_text("#[repr(") + repr + const_text(")] "),
        };

        let singleline = self.fields.iter().enumerate().fold(Document::Empty, |acc, (i, field)| {
            if i > 0 {
                acc + const_text(", ") + field.render()
            } else {
                field.render()
            }
        });
        let multiline = indent(
            4,
            self.fields.iter().enumerate().fold(Document::Empty, |acc, (i, field)| {
                if i > 0 {
                    acc + nl() + field.render()
                } else {
                    nl() + field.render()
                }
            }),
        );
        let body = const_text("{") + (singleline | multiline) + const_text("}");

        header + body
    }
}

impl fmt::Display for StructField {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.ty, f)
    }
}

impl miden_formatting::prettier::PrettyPrint for StructField {
    fn render(&self) -> miden_formatting::prettier::Document {
        use miden_formatting::prettier::*;

        if let Some(name) = self.name.clone() {
            display(name) + const_text(" : ") + self.ty.render()
        } else {
            self.ty.render()
        }
    }
}

impl fmt::Display for TypeRepr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use miden_formatting::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

impl miden_formatting::prettier::PrettyPrint for TypeRepr {
    fn render(&self) -> miden_formatting::prettier::Document {
        use alloc::format;

        use miden_formatting::prettier::*;
        match self {
            Self::Default => Document::Empty,
            Self::Transparent => const_text("transparent"),
            Self::Align(align) => text(format!("align({align})")),
            Self::Packed(align) => text(format!("packed({align})")),
        }
    }
}
