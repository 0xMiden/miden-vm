use core::{fmt, iter::FusedIterator};

use miden_formatting::prettier::PrettyPrint;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use smallvec::{SmallVec, smallvec};

use crate::*;

/// The error type returned when attempting to construct an invalid [EnumType]
#[derive(Debug, thiserror::Error)]
pub enum InvalidEnumTypeError {
    #[error("invalid discriminant type '{0}': expected integer type")]
    InvalidDiscriminantType(Type),
    #[error(
        "invalid enum variant '{variant}': discriminant value is out of range for \
         {discriminant_ty}, preceding variant had value {value_of_preceding_variant}"
    )]
    InvalidImplicitDiscriminantValue {
        variant: Arc<str>,
        discriminant_ty: Type,
        value_of_preceding_variant: u128,
    },
    #[error(
        "invalid enum variant '{variant}': discriminant value {value} is out of range for \
         {discriminant_ty}"
    )]
    InvalidDiscriminantValue {
        variant: Arc<str>,
        discriminant_ty: Type,
        value: u128,
    },
    #[error("invalid enum variant: '{variant}' cannot be defined twice in the same enum")]
    DuplicateVariant { variant: Arc<str> },
    #[error(
        "invalid enum variant '{variant}': discriminant value has already been claimed by a \
         previous discriminant"
    )]
    DuplicateDiscriminantValue { variant: Arc<str>, value: u128 },
}

/// An enum type is a special type that takes one of two forms:
///
/// 1. C-like enumeration of named integer values, where the discriminant is the integral type
/// 2. Rust-like enumeration over the variant types, tagged with a value of the discriminant type
///
/// In 1, the variants are all of the same type as the discriminant. In 2, the variants may each be
/// different shape.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EnumType {
    /// The name of the enumeration itself.
    pub(crate) name: Arc<str>,
    /// The type of the discriminant value.
    ///
    /// This must _always_ be an integral type, but no larger than 128 bits at this time.
    pub(crate) discriminant: Type,
    /// The set of variants that represent this enum.
    ///
    /// An enum with no variants is considered a phantom type (i.e. it has no actual representation
    /// and can thus be ignored).
    pub(crate) variants: SmallVec<[Variant; 4]>,
    /// The payload offsets for each variant based on its alignment requirements
    pub(crate) offsets: SmallVec<[u32; 4]>,
    /// The computed size of this enum type
    ///
    /// The size is the maximum, taking into consideration all variants + discriminant.
    pub(crate) size: u32,
    /// The computed alignment of this enum type
    ///
    /// The alignement is the maximum, taking into consideration all variants + discriminant.
    pub(crate) align: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Variant {
    /// The name of this variant
    pub name: Arc<str>,
    /// The value of the discriminant, stored as a value of the largest valid integral type.
    ///
    /// The value can always be safely be truncated to the actual discriminant type.
    ///
    /// If unspecified, it is inferred from context (either derived from the variant index, or
    /// from the last discriminant with a specified value).
    pub discriminant_value: Option<u128>,
    /// The type of the value representing this variant.
    ///
    /// When `None`, this variant is represented solely by the discriminant, and has no distinct
    /// value type of its own.
    pub value: Option<Type>,
}

impl Variant {
    /// Constructs an enum variant named `name`, and whose payload value is of type `ty`.
    ///
    /// Callers may optionally provide an explicit discriminant value.
    ///
    /// NOTE: Variants must have unique discriminants.
    pub const fn new(name: Arc<str>, ty: Type, discriminant: Option<u128>) -> Self {
        Self {
            name,
            discriminant_value: discriminant,
            value: Some(ty),
        }
    }

    /// Constructs an enum variant for a C-like enumeration, providing the name and discriminant
    /// value for that variant.
    ///
    /// C-like enum variants have no payload value, i.e. the value of the enum is the discriminant
    /// value.
    pub const fn c_like(name: Arc<str>, discriminant: Option<u128>) -> Self {
        Self {
            name,
            discriminant_value: discriminant,
            value: None,
        }
    }
}

impl EnumType {
    /// Construct a new [EnumType] with the given name, discriminant type, and variants.
    pub fn new<I>(
        name: Arc<str>,
        discriminant: Type,
        variants: I,
    ) -> Result<Self, InvalidEnumTypeError>
    where
        I: IntoIterator<Item = Variant>,
    {
        let variants = variants.into_iter().collect::<SmallVec<[_; 4]>>();
        if variants.is_empty() {
            return Self::phantom(name, discriminant);
        }

        // Catch duplicate variants
        {
            let mut variants = variants.iter();
            while let Some(variant) = variants.next() {
                if variants.as_slice().iter().any(|v| variant.name == v.name) {
                    return Err(InvalidEnumTypeError::DuplicateVariant {
                        variant: variant.name.clone(),
                    });
                }
            }
        }

        // Validate the discriminant type
        if !discriminant.is_integer() || matches!(discriminant, Type::U256) {
            return Err(InvalidEnumTypeError::InvalidDiscriminantType(discriminant));
        }

        // Validate the discriminants
        let discriminants = Discriminator {
            discriminant_ty: &discriminant,
            last_discriminant: None,
            iterator: variants.iter(),
        };
        for (i, result) in discriminants.enumerate() {
            let value = result?;
            if variants
                .iter()
                .enumerate()
                .any(|(j, v)| i != j && v.discriminant_value.is_some_and(|vd| vd == value))
            {
                return Err(InvalidEnumTypeError::DuplicateDiscriminantValue {
                    variant: variants[i].name.clone(),
                    value,
                });
            }
        }

        // Compute the offsets of each variant and identify the largest variant for later
        let mut offsets: SmallVec<[_; 4]> = smallvec![0u32; variants.len()];
        let mut largest_variant = None::<Type>;
        for (i, variant) in variants.iter().enumerate() {
            if let Some(value_ty) = variant.value.as_ref() {
                let layout = StructType::new([discriminant.clone(), value_ty.clone()]);
                offsets[i] = layout.fields()[1].offset;
                match largest_variant.as_mut() {
                    Some(largest_variant)
                        if value_ty.aligned_size_in_bytes()
                            > largest_variant.aligned_size_in_bytes() =>
                    {
                        *largest_variant = value_ty.clone();
                    }
                    Some(_) => (),
                    None => {
                        largest_variant = Some(value_ty.clone());
                    }
                }
            }
        }

        // Derive the size and alignment of this enum type from the largest variant we found
        let (size, align) = match largest_variant {
            Some(ty) => {
                let struct_ty = StructType::new([discriminant.clone(), ty]);
                let size = struct_ty.size();
                let align = struct_ty.min_alignment();
                (size, align)
            }
            None => {
                let size = discriminant.size_in_bytes();
                let align = discriminant.min_alignment();
                (size, align)
            }
        };

        Ok(Self {
            name,
            discriminant,
            variants,
            offsets,
            size: size as u32,
            align: align as u32,
        })
    }

    /// Construct a new [EnumType] representing a phantom type with the given name and discriminant
    pub fn phantom(name: Arc<str>, discriminant: Type) -> Result<Self, InvalidEnumTypeError> {
        // Validate the discriminant type
        if !discriminant.is_integer() || matches!(discriminant, Type::U256) {
            return Err(InvalidEnumTypeError::InvalidDiscriminantType(discriminant));
        }

        Ok(Self {
            name,
            discriminant,
            variants: smallvec![],
            offsets: smallvec![],
            size: 0,
            align: 1,
        })
    }

    /// Returns the name of this enum type
    #[inline]
    pub fn name(&self) -> &Arc<str> {
        &self.name
    }

    /// Returns the discriminant type for this enum
    #[inline]
    pub fn discriminant(&self) -> &Type {
        &self.discriminant
    }

    /// Returns the variants of this enum
    #[inline]
    pub fn variants(&self) -> &[Variant] {
        &self.variants
    }

    /// Returns an iterator over the variants of this enumeration with their offset from the base
    /// of the enum (i.e. given a pointer to a value of this type, the offset can be used to derive
    /// a pointer to the variant value type).
    pub fn variant_offsets(&self) -> impl ExactSizeIterator<Item = (u32, &Variant)> {
        self.offsets.iter().copied().zip(self.variants.iter())
    }

    /// Returns an iterator over the discriminant values of this enum.
    ///
    /// The order of values produced by this iterator is identical to the order of the variants.
    ///
    /// Discriminant values are computed as follows:
    ///
    /// * Variants either have an explicit discriminant value set, or receive a discriminant value
    ///   derived from the preceding variant by adding `1` to it.
    /// * If the first variant has no explicit value, the discriminant value range begins at `0`.
    /// * If the the end of the valid discriminant value range is reached before the last variant,
    ///   this function will panic with an assertion pointing to the invalid variant.
    pub fn discriminant_values(&self) -> impl ExactSizeIterator<Item = u128> {
        Discriminator {
            discriminant_ty: &self.discriminant,
            last_discriminant: None,
            iterator: self.variants.iter(),
        }
        .map(|result| result.expect("invalid enum type"))
    }

    /// Returns true if this type has no variants, and thus no physical in-memory representation.
    #[inline]
    pub fn is_phantom(&self) -> bool {
        self.variants.is_empty()
    }

    /// Returns true if this type has no physical in-memory representation, i.e. it is a phantom
    #[inline]
    pub fn is_zst(&self) -> bool {
        self.is_phantom()
    }

    /// Returns true if this enum type is a C-like enum, i.e. where the type is equivalent to the
    /// discriminant value type.
    pub fn is_c_like(&self) -> bool {
        !self.is_phantom() && self.variants.iter().all(|v| v.value.is_none())
    }

    /// Returns the size in bytes of this type, without alignment padding.
    pub fn size_in_bytes(&self) -> usize {
        self.size as usize
    }

    /// Returns the size in bits of this type, without alignment padding.
    pub fn size_in_bits(&self) -> usize {
        8 * self.size as usize
    }

    /// Returns the minimum alignment, in bytes, of this type
    pub fn min_alignment(&self) -> usize {
        self.align as usize
    }
}

impl fmt::Display for EnumType {
    /// Print this type for display using the provided module context
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.pretty_print(f)
    }
}

impl PrettyPrint for EnumType {
    fn render(&self) -> miden_formatting::prettier::Document {
        use miden_formatting::prettier::*;

        let header = const_text("enum ")
            + display(self.name.clone())
            + const_text(" : ")
            + self.discriminant.render();

        let singleline =
            self.variants.iter().enumerate().fold(Document::Empty, |acc, (i, variant)| {
                if i > 0 {
                    acc + const_text(", ") + variant.render()
                } else {
                    variant.render()
                }
            });
        let multiline = indent(
            4,
            self.variants.iter().enumerate().fold(Document::Empty, |acc, (i, variant)| {
                if i > 0 {
                    acc + nl() + variant.render()
                } else {
                    nl() + variant.render()
                }
            }),
        );
        let body = const_text("{") + (singleline | multiline) + const_text("}");

        header + body
    }
}

impl fmt::Display for Variant {
    /// Print this type for display using the provided module context
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.pretty_print(f)
    }
}

impl PrettyPrint for Variant {
    fn render(&self) -> miden_formatting::prettier::Document {
        use miden_formatting::prettier::*;

        let variant = match self.value.as_ref() {
            None => display(self.name.clone()),
            Some(ty) => {
                display(self.name.clone()) + const_text("(") + ty.render() + const_text(")")
            }
        };

        if let Some(tag) = self.discriminant_value {
            variant + const_text(" = ") + display(tag)
        } else {
            variant
        }
    }
}

struct Discriminator<'a> {
    discriminant_ty: &'a Type,
    last_discriminant: Option<u128>,
    iterator: core::slice::Iter<'a, Variant>,
}

impl<'a> Iterator for Discriminator<'a> {
    type Item = Result<u128, InvalidEnumTypeError>;

    fn next(&mut self) -> Option<Self::Item> {
        let variant = self.iterator.next()?;
        let last = self.last_discriminant.unwrap_or(0);
        let next = if let Some(next) = variant.discriminant_value {
            self.last_discriminant = Some(next);
            next
        } else {
            let next = match self.last_discriminant {
                None => Ok(0),
                Some(last) => last.checked_add(1).ok_or_else(|| {
                    InvalidEnumTypeError::InvalidImplicitDiscriminantValue {
                        variant: variant.name.clone(),
                        discriminant_ty: self.discriminant_ty.clone(),
                        value_of_preceding_variant: last,
                    }
                }),
            };
            match next {
                Ok(next) => {
                    self.last_discriminant = Some(next);
                    next
                }
                Err(err) => return Some(Err(err)),
            }
        };

        let used_bits = (128 - next.leading_zeros()) as usize;
        if used_bits > self.discriminant_ty.size_in_bits() {
            if variant.discriminant_value.is_some() {
                return Some(Err(InvalidEnumTypeError::InvalidDiscriminantValue {
                    variant: variant.name.clone(),
                    discriminant_ty: self.discriminant_ty.clone(),
                    value: next,
                }));
            } else {
                return Some(Err(InvalidEnumTypeError::InvalidImplicitDiscriminantValue {
                    variant: variant.name.clone(),
                    discriminant_ty: self.discriminant_ty.clone(),
                    value_of_preceding_variant: last,
                }));
            }
        }

        Some(Ok(next))
    }

    #[inline(always)]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iterator.size_hint()
    }
}

impl<'a> FusedIterator for Discriminator<'a> {}

impl<'a> ExactSizeIterator for Discriminator<'a> {
    #[inline(always)]
    fn len(&self) -> usize {
        self.iterator.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phantom_enum_type() {
        let ty = EnumType::new("T".into(), Type::U32, []).unwrap();
        assert!(ty.is_phantom());
        assert!(ty.is_zst());
        assert!(!ty.is_c_like());
        assert_eq!(ty.size_in_bytes(), 0);
        assert_eq!(ty.size_in_bits(), 0);
        assert_eq!(ty.min_alignment(), 1);
    }

    #[test]
    fn c_like_enum_types() {
        let ty = EnumType::new(
            "Bool".into(),
            Type::I1,
            [
                Variant::c_like("True".into(), Some(1)),
                Variant::c_like("False".into(), Some(0)),
            ],
        )
        .unwrap();
        assert!(!ty.is_phantom());
        assert!(!ty.is_zst());
        assert!(ty.is_c_like());
        assert_eq!(ty.size_in_bytes(), 1);
        assert_eq!(ty.size_in_bits(), 8);
        assert_eq!(ty.min_alignment(), 1);
        assert_eq!(ty.variants()[0].discriminant_value, Some(1));
        assert_eq!(ty.variants()[1].discriminant_value, Some(0));
        let mut offsets = ty.variant_offsets();
        assert_eq!(offsets.next().map(|(off, _)| off), Some(0));
        assert_eq!(offsets.next().map(|(off, _)| off), Some(0));

        let ty = EnumType::new(
            "Triple".into(),
            Type::U32,
            [
                Variant::c_like("One".into(), None),
                Variant::c_like("Two".into(), Some(3)),
                Variant::c_like("Three".into(), None),
            ],
        )
        .unwrap();
        assert!(!ty.is_phantom());
        assert!(!ty.is_zst());
        assert!(ty.is_c_like());
        assert_eq!(ty.size_in_bytes(), 4);
        assert_eq!(ty.size_in_bits(), 32);
        assert_eq!(ty.min_alignment(), 4);
        let mut discriminants = ty.discriminant_values();
        assert_eq!(discriminants.next(), Some(0));
        assert_eq!(discriminants.next(), Some(3));
        assert_eq!(discriminants.next(), Some(4));
    }

    #[test]
    fn rust_like_enum_type() {
        let ty = EnumType::new(
            "T".into(),
            Type::U8,
            [
                Variant::c_like("A".into(), None),
                Variant::new("B".into(), Type::U32, Some(3)),
                Variant::new("C".into(), StructType::new([Type::U32, Type::U64]).into(), None),
            ],
        )
        .unwrap();

        assert!(!ty.is_phantom());
        assert!(!ty.is_zst());
        assert!(!ty.is_c_like());
        assert_eq!(ty.size_in_bytes(), 16);
        assert_eq!(ty.size_in_bits(), 128);
        assert_eq!(ty.min_alignment(), 4);
        let mut discriminants = ty.discriminant_values();
        assert_eq!(discriminants.next(), Some(0));
        assert_eq!(discriminants.next(), Some(3));
        assert_eq!(discriminants.next(), Some(4));
        let mut offsets = ty.variant_offsets();
        assert_eq!(offsets.next().map(|(off, _)| off), Some(0));
        assert_eq!(offsets.next().map(|(off, _)| off), Some(4));
        assert_eq!(offsets.next().map(|(off, _)| off), Some(4));
    }

    #[test]
    #[should_panic = "'A' cannot be defined twice in the same enum"]
    fn duplicate_variants_are_caught() {
        EnumType::new(
            "T".into(),
            Type::U32,
            [Variant::c_like("A".into(), None), Variant::c_like("A".into(), None)],
        )
        .unwrap_or_else(|err| panic!("{err}"));
    }

    #[test]
    #[should_panic = "discriminant value has already been claimed"]
    fn duplicate_discriminant_values_are_caught() {
        EnumType::new(
            "T".into(),
            Type::U32,
            [Variant::c_like("A".into(), Some(1)), Variant::c_like("B".into(), Some(1))],
        )
        .unwrap_or_else(|err| panic!("{err}"));
    }

    #[test]
    #[should_panic = "discriminant value 256 is out of range for u8"]
    fn out_of_range_discriminant_values_are_caught() {
        EnumType::new("T".into(), Type::U8, [Variant::c_like("A".into(), Some(256))])
            .unwrap_or_else(|err| panic!("{err}"));
    }

    #[test]
    #[should_panic = "discriminant value is out of range for u8, preceding variant had value 255"]
    fn out_of_range_implicit_discriminant_values_are_caught() {
        EnumType::new(
            "T".into(),
            Type::U8,
            [Variant::c_like("A".into(), Some(255)), Variant::c_like("B".into(), None)],
        )
        .unwrap_or_else(|err| panic!("{err}"));
    }
}
