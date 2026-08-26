#![no_std]
#![deny(warnings)]

extern crate alloc;

mod alignable;
mod array_type;
mod enum_type;
mod function_type;
mod layout;
mod pointer_type;
mod recursive;
#[cfg(feature = "serde")]
mod serialization;
mod struct_type;

use alloc::{borrow::Cow, boxed::Box, sync::Arc};
use core::fmt;

use miden_formatting::prettier::PrettyPrint;

pub use self::{
    alignable::Alignable, array_type::ArrayType, enum_type::*, function_type::*, pointer_type::*,
    recursive::*, struct_type::*,
};

/// Represents the type of a value in the HIR type system
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    /// This indicates a failure to type a value, or a value which is untypable
    Unknown,
    /// This type is the bottom type, and represents divergence, akin to Rust's Never/! type
    Never,
    /// This type represents a variadic type parameter, i.e. it can represent zero or more values
    /// of arbitrary type.
    ///
    /// It is only valid in function types, and must always be in trailing position, i.e. if mixed
    /// with other types, it must come last in the list, as shown below:
    ///
    /// ## Valid
    ///
    /// * `fn (...)`
    /// * `fn () -> ...`
    /// * `fn (...) -> ...`
    /// * `fn (i8, ...)`
    /// * `fn () -> (i8, ...)`
    /// * `fn (i8, ...) -> (i8, ...)`
    ///
    /// ## Invalid
    ///
    /// * `fn (..., ...)`
    /// * `fn () -> (..., ...)`
    /// * `fn (..., i8)`
    /// * `fn (i8, ..., i8)`
    /// * `fn () -> (..., i8)`
    Variadic,
    /// A 1-bit integer, i.e. a boolean value.
    ///
    /// When the bit is 1, the value is true; 0 is false.
    I1,
    /// An 8-bit signed integer.
    I8,
    /// An 8-bit unsigned integer.
    U8,
    /// A 16-bit signed integer.
    I16,
    /// A 16-bit unsigned integer.
    U16,
    /// A 32-bit signed integer.
    I32,
    /// A 32-bit unsigned integer.
    U32,
    /// A 64-bit signed integer.
    I64,
    /// A 64-bit unsigned integer.
    U64,
    /// A 128-bit signed integer.
    I128,
    /// A 128-bit unsigned integer.
    U128,
    /// A 256-bit unsigned integer.
    U256,
    /// A 64-bit IEEE-754 floating-point value.
    ///
    /// NOTE: These are currently unsupported in practice, but is reserved here for future use.
    F64,
    /// A field element corresponding to the native Miden field (currently the Goldilocks field)
    Felt,
    /// A pointer to a value in a byte-addressable address space.
    ///
    /// Pointers of this type are _not_ equivalent to element addresses as referred to in the
    /// Miden Assembly documentation, but do have a straightforward conversion.
    Ptr(Arc<PointerType>),
    /// A compound type of fixed shape and size
    ///
    /// This matches both ordinary and recursive structs; see [StructRef].
    Struct(StructRef),
    /// A tagged type enumeration with a fixed number of variants
    ///
    /// This matches both ordinary and recursive enums; see [EnumRef].
    Enum(EnumRef),
    /// A vector of fixed size
    Array(Arc<ArrayType>),
    /// A dynamically sized list of values of the given type.
    ///
    /// This is represented as a fat pointer, i.e. `{ len: u32, ptr: *T }`, and is therefore
    /// 8 bytes in size with an alignment of 4. Its layout does not depend on the element type.
    ///
    /// NOTE: This primarily exists to support the Wasm Canonical ABI.
    List(Arc<Type>),
    /// A reference to a function with the given type signature
    Function(Arc<FunctionType>),
}

/// A struct type, which may be ordinary or recursive.
///
/// Recursive structs are kept inside [`Type::Struct`] rather than given their own [Type] variant
/// so that shape tests such as [`Type::is_struct`], and any `match` arm selecting a struct, keep
/// working unchanged and correctly include recursive types. Reading a struct's *contents* goes
/// through [`StructRef::get`], which is where the recursive case has to be considered.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StructRef {
    /// An ordinary struct.
    Plain(Arc<StructType>),
    /// A recursive struct: one definition of a recursive group.
    Rec(RecTypeRef),
}

impl StructRef {
    /// Read this struct's definition.
    ///
    /// This is borrowed for an ordinary struct, and owned for a recursive one, where it is the
    /// one-level unfolding of the definition. Every field type of the result is an ordinary,
    /// closed [Type].
    ///
    /// NOTE: The unfolded form of a recursive struct is a transient view, not a canonical value:
    /// it does not compare equal to the recursive type it came from. Do not store it as the
    /// representation of a type.
    pub fn get(&self) -> Cow<'_, StructType> {
        match self {
            Self::Plain(ty) => Cow::Borrowed(ty),
            Self::Rec(ty) => Cow::Owned(ty.unfold_struct()),
        }
    }

    /// The name of this struct, if it has one. Never unfolds.
    pub fn name(&self) -> Option<Arc<str>> {
        match self {
            Self::Plain(ty) => ty.name(),
            Self::Rec(ty) => ty.name(),
        }
    }

    /// The representation of this struct. Never unfolds.
    pub fn repr(&self) -> TypeRepr {
        match self {
            Self::Plain(ty) => ty.repr(),
            Self::Rec(ty) => ty.struct_repr(),
        }
    }

    /// The size in bytes of this struct, including alignment padding. Never unfolds.
    pub fn size(&self) -> usize {
        match self {
            Self::Plain(ty) => ty.size(),
            Self::Rec(ty) => ty.layout().size_in_bytes(),
        }
    }

    /// The minimum alignment of this struct. Never unfolds.
    pub fn min_alignment(&self) -> usize {
        match self {
            Self::Plain(ty) => ty.min_alignment(),
            Self::Rec(ty) => ty.layout().min_alignment(),
        }
    }

    /// Whether this struct is zero-sized. Never unfolds.
    pub fn is_zst(&self) -> bool {
        match self {
            Self::Plain(ty) => ty.fields().iter().all(|f| f.ty.is_zst()),
            Self::Rec(ty) => ty.layout().is_zst(),
        }
    }

    /// Whether this struct is recursive.
    #[inline]
    pub fn is_recursive(&self) -> bool {
        matches!(self, Self::Rec(_))
    }

    /// The recursive definition this struct refers to, if it is recursive.
    #[inline]
    pub fn as_recursive(&self) -> Option<&RecTypeRef> {
        match self {
            Self::Rec(ty) => Some(ty),
            Self::Plain(_) => None,
        }
    }
}

/// An enum type, which may be ordinary or recursive. See [StructRef] for the rationale.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EnumRef {
    /// An ordinary enum.
    Plain(Arc<EnumType>),
    /// A recursive enum: one definition of a recursive group.
    Rec(RecTypeRef),
}

impl EnumRef {
    /// Read this enum's definition. See [`StructRef::get`] for the borrowing and canonicity rules.
    pub fn get(&self) -> Cow<'_, EnumType> {
        match self {
            Self::Plain(ty) => Cow::Borrowed(ty),
            Self::Rec(ty) => Cow::Owned(ty.unfold_enum()),
        }
    }

    /// The name of this enum. Never unfolds.
    pub fn name(&self) -> Arc<str> {
        match self {
            Self::Plain(ty) => ty.name().clone(),
            // An enum definition always carries a name.
            Self::Rec(ty) => ty.name().expect("an enum always has a name"),
        }
    }

    /// The size in bytes of this enum. Never unfolds.
    pub fn size_in_bytes(&self) -> usize {
        match self {
            Self::Plain(ty) => ty.size_in_bytes(),
            Self::Rec(ty) => ty.layout().size_in_bytes(),
        }
    }

    /// The size in bits of this enum. Never unfolds.
    pub fn size_in_bits(&self) -> usize {
        match self {
            Self::Plain(ty) => ty.size_in_bits(),
            Self::Rec(ty) => ty.layout().size_in_bytes() * 8,
        }
    }

    /// The minimum alignment of this enum. Never unfolds.
    pub fn min_alignment(&self) -> usize {
        match self {
            Self::Plain(ty) => ty.min_alignment(),
            Self::Rec(ty) => ty.layout().min_alignment(),
        }
    }

    /// Whether this enum is zero-sized. Never unfolds.
    pub fn is_zst(&self) -> bool {
        match self {
            Self::Plain(ty) => ty.is_zst(),
            Self::Rec(ty) => ty.layout().is_zst(),
        }
    }

    /// Whether this enum is recursive.
    #[inline]
    pub fn is_recursive(&self) -> bool {
        matches!(self, Self::Rec(_))
    }

    /// The recursive definition this enum refers to, if it is recursive.
    #[inline]
    pub fn as_recursive(&self) -> Option<&RecTypeRef> {
        match self {
            Self::Rec(ty) => Some(ty),
            Self::Plain(_) => None,
        }
    }
}

impl PrettyPrint for StructRef {
    fn render(&self) -> miden_formatting::prettier::Document {
        match self {
            Self::Plain(ty) => ty.render(),
            // A recursive struct renders by name, so that printing terminates.
            Self::Rec(ty) => miden_formatting::prettier::text(match ty.name() {
                Some(name) => alloc::format!("struct {name}"),
                None => alloc::string::String::from("struct <anon>"),
            }),
        }
    }
}

impl PrettyPrint for EnumRef {
    fn render(&self) -> miden_formatting::prettier::Document {
        match self {
            Self::Plain(ty) => ty.render(),
            Self::Rec(_) => {
                miden_formatting::prettier::text(alloc::format!("enum {}", self.name()))
            },
        }
    }
}

impl Type {
    /// Returns true if this type is a zero-sized type, which includes:
    ///
    /// * Types with no size, e.g. `Never`
    /// * Zero-sized arrays
    /// * Arrays with a zero-sized element type
    /// * Structs composed of nothing but zero-sized fields
    pub fn is_zst(&self) -> bool {
        match self {
            Self::Unknown => false,
            Self::Never => true,
            Self::Variadic => false,
            Self::Array(ty) => ty.is_zst(),
            Self::Struct(struct_ty) => struct_ty.is_zst(),
            Self::Enum(enum_ty) => enum_ty.is_zst(),
            Self::I1
            | Self::I8
            | Self::U8
            | Self::I16
            | Self::U16
            | Self::I32
            | Self::U32
            | Self::I64
            | Self::U64
            | Self::I128
            | Self::U128
            | Self::U256
            | Self::F64
            | Self::Felt
            | Self::Ptr(_)
            | Self::List(_)
            | Self::Function(_) => false,
        }
    }

    /// Returns true if this type is any numeric type
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            Self::I1
                | Self::I8
                | Self::U8
                | Self::I16
                | Self::U16
                | Self::I32
                | Self::U32
                | Self::I64
                | Self::U64
                | Self::I128
                | Self::U128
                | Self::U256
                | Self::F64
                | Self::Felt
        )
    }

    /// Returns true if this type is any integral type
    pub fn is_integer(&self) -> bool {
        matches!(
            self,
            Self::I1
                | Self::I8
                | Self::U8
                | Self::I16
                | Self::U16
                | Self::I32
                | Self::U32
                | Self::I64
                | Self::U64
                | Self::I128
                | Self::U128
                | Self::U256
                | Self::Felt
        )
    }

    /// Returns true if this type is any signed integral type
    pub fn is_signed_integer(&self) -> bool {
        matches!(self, Self::I8 | Self::I16 | Self::I32 | Self::I64 | Self::I128)
    }

    /// Returns true if this type is any unsigned integral type
    pub fn is_unsigned_integer(&self) -> bool {
        matches!(self, Self::I1 | Self::U8 | Self::U16 | Self::U32 | Self::U64 | Self::U128)
    }

    /// Get this type as its unsigned integral twin, e.g. i32 becomes u32.
    ///
    /// This function will panic if the type is not an integer type, or has no unsigned
    /// representation
    pub fn as_unsigned(&self) -> Type {
        match self {
            Self::I8 | Self::U8 => Self::U8,
            Self::I16 | Self::U16 => Self::U16,
            Self::I32 | Self::U32 => Self::U32,
            Self::I64 | Self::U64 => Self::U64,
            Self::I128 | Self::U128 => Self::U128,
            Self::Felt => Self::Felt,
            ty => panic!("invalid conversion to unsigned integer type: {ty} is not an integer"),
        }
    }

    /// Get this type as its signed integral twin, e.g. u32 becomes i32.
    ///
    /// This function will panic if the type is not an integer type, or has no signed representation
    pub fn as_signed(&self) -> Type {
        match self {
            Self::I8 | Self::U8 => Self::I8,
            Self::I16 | Self::U16 => Self::I16,
            Self::I32 | Self::U32 => Self::I32,
            Self::I64 | Self::U64 => Self::I64,
            Self::I128 | Self::U128 => Self::I128,
            Self::Felt => {
                panic!("invalid conversion to signed integer type: felt has no signed equivalent")
            },
            ty => panic!("invalid conversion to signed integer type: {ty} is not an integer"),
        }
    }

    /// Returns true if this type is a floating-point type
    #[inline]
    pub fn is_float(&self) -> bool {
        matches!(self, Self::F64)
    }

    /// Returns true if this type is the field element type
    #[inline]
    pub fn is_felt(&self) -> bool {
        matches!(self, Self::Felt)
    }

    /// Returns true if this type is a pointer type
    #[inline]
    pub fn is_pointer(&self) -> bool {
        matches!(self, Self::Ptr(_))
    }

    /// Returns the type of the pointee, if this type is a pointer type
    #[inline]
    pub fn pointee(&self) -> Option<&Type> {
        match self {
            Self::Ptr(ty) => Some(ty.pointee()),
            _ => None,
        }
    }

    /// Returns true if this type is a struct type
    #[inline]
    pub fn is_struct(&self) -> bool {
        matches!(self, Self::Struct(_))
    }

    /// Returns true if this type is an array type
    #[inline]
    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    /// Returns true if this type is a dynamically-sized vector/list type
    #[inline]
    pub fn is_list(&self) -> bool {
        matches!(self, Self::List(_))
    }

    /// Returns true if this type is a function reference type
    #[inline]
    pub fn is_function(&self) -> bool {
        matches!(self, Self::Function(_))
    }
}

impl From<StructType> for Type {
    #[inline]
    fn from(ty: StructType) -> Type {
        Type::Struct(StructRef::Plain(Arc::new(ty)))
    }
}

impl From<Box<StructType>> for Type {
    #[inline]
    fn from(ty: Box<StructType>) -> Type {
        Type::Struct(StructRef::Plain(Arc::from(ty)))
    }
}

impl From<Arc<StructType>> for Type {
    #[inline]
    fn from(ty: Arc<StructType>) -> Type {
        Type::Struct(StructRef::Plain(ty))
    }
}

impl From<EnumType> for Type {
    #[inline]
    fn from(ty: EnumType) -> Type {
        Type::Enum(EnumRef::Plain(Arc::new(ty)))
    }
}

impl From<Arc<EnumType>> for Type {
    #[inline]
    fn from(ty: Arc<EnumType>) -> Type {
        Type::Enum(EnumRef::Plain(ty))
    }
}

impl From<ArrayType> for Type {
    #[inline]
    fn from(ty: ArrayType) -> Type {
        Type::Array(Arc::new(ty))
    }
}

impl From<Box<ArrayType>> for Type {
    #[inline]
    fn from(ty: Box<ArrayType>) -> Type {
        Type::Array(Arc::from(ty))
    }
}

impl From<Arc<ArrayType>> for Type {
    #[inline]
    fn from(ty: Arc<ArrayType>) -> Type {
        Type::Array(ty)
    }
}

impl From<PointerType> for Type {
    #[inline]
    fn from(ty: PointerType) -> Type {
        Type::Ptr(Arc::new(ty))
    }
}

impl From<Box<PointerType>> for Type {
    #[inline]
    fn from(ty: Box<PointerType>) -> Type {
        Type::Ptr(Arc::from(ty))
    }
}

impl From<Arc<PointerType>> for Type {
    #[inline]
    fn from(ty: Arc<PointerType>) -> Type {
        Type::Ptr(ty)
    }
}

impl From<FunctionType> for Type {
    #[inline]
    fn from(ty: FunctionType) -> Type {
        Type::Function(Arc::new(ty))
    }
}

impl From<Box<FunctionType>> for Type {
    #[inline]
    fn from(ty: Box<FunctionType>) -> Type {
        Type::Function(Arc::from(ty))
    }
}

impl From<Arc<FunctionType>> for Type {
    #[inline]
    fn from(ty: Arc<FunctionType>) -> Type {
        Type::Function(ty)
    }
}

impl fmt::Display for Type {
    /// Print this type for display using the provided module context
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.pretty_print(f)
    }
}

impl PrettyPrint for Type {
    fn render(&self) -> miden_formatting::prettier::Document {
        use miden_formatting::prettier::*;

        match self {
            Self::Unknown => const_text("?"),
            Self::Never => const_text("!"),
            Self::Variadic => const_text("..."),
            Self::I1 => const_text("i1"),
            Self::I8 => const_text("i8"),
            Self::U8 => const_text("u8"),
            Self::I16 => const_text("i16"),
            Self::U16 => const_text("u16"),
            Self::I32 => const_text("i32"),
            Self::U32 => const_text("u32"),
            Self::I64 => const_text("i64"),
            Self::U64 => const_text("u64"),
            Self::I128 => const_text("i128"),
            Self::U128 => const_text("u128"),
            Self::U256 => const_text("u256"),
            Self::F64 => const_text("f64"),
            Self::Felt => const_text("felt"),
            Self::Ptr(ptr_ty) => ptr_ty.render(),
            Self::Struct(struct_ty) => struct_ty.render(),
            Self::Enum(enum_ty) => enum_ty.render(),
            Self::Array(array_ty) => array_ty.render(),
            Self::List(ty) => const_text("list<") + ty.render() + const_text(">"),
            Self::Function(ty) => ty.render(),
        }
    }
}
