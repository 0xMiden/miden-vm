mod abi;

use core::fmt;

use smallvec::SmallVec;

pub use self::abi::CallConv;
use super::Type;

/// This represents the type of a function, i.e. it's parameters and results, and expected calling
/// convention.
///
/// Function types are reference types, i.e. they are always implicitly a handle/pointer to a
/// function, not a function value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FunctionType {
    /// The calling convention/ABI of the function represented by this type
    pub abi: CallConv,
    /// The parameter types of this function
    pub params: SmallVec<[Type; 4]>,
    /// The result types of this function
    pub results: SmallVec<[Type; 1]>,
}
impl FunctionType {
    /// Create a new function type with the given calling/convention ABI
    pub fn new<P: IntoIterator<Item = Type>, R: IntoIterator<Item = Type>>(
        abi: CallConv,
        params: P,
        results: R,
    ) -> Self {
        Self {
            abi,
            params: params.into_iter().collect(),
            results: results.into_iter().collect(),
        }
    }

    /// Set the calling convention/ABI for this function type
    pub fn with_calling_convention(mut self, abi: CallConv) -> Self {
        self.abi = abi;
        self
    }

    /// The calling convention/ABI represented by this function type
    pub fn calling_convention(&self) -> CallConv {
        self.abi
    }

    /// The number of parameters expected by the function
    pub fn arity(&self) -> usize {
        self.params.len()
    }

    /// The types of the function parameters as a slice
    pub fn params(&self) -> &[Type] {
        self.params.as_slice()
    }

    /// The types of the function results as a slice
    pub fn results(&self) -> &[Type] {
        self.results.as_slice()
    }
}

impl fmt::Display for FunctionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use miden_formatting::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

impl miden_formatting::prettier::PrettyPrint for FunctionType {
    fn render(&self) -> miden_formatting::prettier::Document {
        use alloc::format;

        use miden_formatting::prettier::*;

        let abi = const_text("extern") + text(format!(" \"{}\" ", &self.abi));

        let params = self.params.iter().enumerate().fold(const_text("("), |acc, (i, param)| {
            if i > 0 {
                acc + const_text(", ") + param.render()
            } else {
                acc + param.render()
            }
        }) + const_text(")");

        let without_results = abi + const_text("fn") + params;
        if self.results.is_empty() {
            return without_results;
        }

        let results = self.results.iter().enumerate().fold(Document::Empty, |acc, (i, item)| {
            if i > 0 {
                acc + const_text(", ") + item.render()
            } else {
                item.render()
            }
        });

        without_results + const_text(" -> ") + results
    }
}
