use super::{Alignable, Type};

/// A fixed-size, homogenous vector type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ArrayType {
    pub ty: Type,
    pub len: usize,
}

impl ArrayType {
    /// Create a new [ArrayType] of length `len` and element type of `ty`
    pub fn new(ty: Type, len: usize) -> Self {
        Self { ty, len }
    }

    /// Get the size of this array type
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Get the element type of this array type
    pub fn element_type(&self) -> &Type {
        &self.ty
    }

    /// Returns true if this array type represents a zero-sized type
    pub fn is_zst(&self) -> bool {
        self.len == 0 || self.ty.is_zst()
    }

    /// Returns the minimum alignment required by this type
    pub fn min_alignment(&self) -> usize {
        self.ty.min_alignment()
    }

    /// Returns the size in bits of this array type
    pub fn size_in_bits(&self) -> usize {
        match self.len {
            // Zero-sized arrays have no size in memory
            0 => 0,
            // An array of one element is the same as just the element
            1 => self.ty.size_in_bits(),
            // All other arrays require alignment padding between elements
            n => {
                let min_align = self.ty.min_alignment() * 8;
                let element_size = self.ty.size_in_bits();
                let padded_element_size = element_size.align_up(min_align);
                element_size + (padded_element_size * (n - 1))
            }
        }
    }
}

impl core::fmt::Display for ArrayType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use miden_formatting::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

impl miden_formatting::prettier::PrettyPrint for ArrayType {
    fn render(&self) -> miden_formatting::prettier::Document {
        use miden_formatting::prettier::*;

        const_text("[") + self.ty.render() + const_text("; ") + self.len.render() + const_text("]")
    }
}
