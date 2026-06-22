#![no_std]
#![deny(warnings)]

extern crate alloc;

mod alignable;
mod array_type;
mod enum_type;
mod function_type;
mod layout;
mod pointer_type;
#[cfg(feature = "serde")]
mod serialization;
mod struct_type;

use alloc::{boxed::Box, sync::Arc};
use core::fmt;

use miden_formatting::prettier::PrettyPrint;

pub use self::{
    alignable::Alignable, array_type::ArrayType, enum_type::*, function_type::*, pointer_type::*,
    struct_type::*,
};

/// Represents the type of a value in the HIR type system
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Type {
    /// This indicates a failure to type a value, or a value which is untypable
    Unknown,
    /// This type is the bottom type, and represents divergence, akin to Rust's Never/! type
    Never,
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
    Struct(Arc<StructType>),
    /// A tagged type enumeration with a fixed number of variants
    Enum(Arc<EnumType>),
    /// A vector of fixed size
    Array(Arc<ArrayType>),
    /// A dynamically sized list of values of the given type
    ///
    /// NOTE: Currently this only exists to support the Wasm Canonical ABI,
    /// but it has no defined represenation yet, so in practice cannot be
    /// used in most places except during initial translation in the Wasm frontend.
    List(Arc<Type>),
    /// A reference to a function with the given type signature
    Function(Arc<FunctionType>),
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
            Self::Array(ty) => ty.is_zst(),
            Self::Struct(struct_ty) => struct_ty.fields.iter().all(|f| f.ty.is_zst()),
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
            }
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
        Type::Struct(Arc::new(ty))
    }
}

impl From<Box<StructType>> for Type {
    #[inline]
    fn from(ty: Box<StructType>) -> Type {
        Type::Struct(Arc::from(ty))
    }
}

impl From<Arc<StructType>> for Type {
    #[inline]
    fn from(ty: Arc<StructType>) -> Type {
        Type::Struct(ty)
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
