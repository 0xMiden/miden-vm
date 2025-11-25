pub mod eval;
mod expr;
mod value;

use alloc::string::String;
use core::fmt;

use miden_debug_types::{SourceSpan, Span, Spanned};

pub use self::{
    eval::{ConstEnvironment, ConstEvalError},
    expr::{ConstantExpr, ConstantOp, HashKind},
    value::ConstantValue,
};
use crate::ast::{DocString, Ident, Visibility};

// CONSTANT
// ================================================================================================

/// Represents a constant definition in Miden Assembly syntax, i.e. `const.FOO = 1 + 1`.
#[derive(Clone)]
pub struct Constant {
    /// The source span of the definition.
    pub span: SourceSpan,
    /// The documentation string attached to this definition.
    pub docs: Option<DocString>,
    /// The visibility of this constant
    pub visibility: Visibility,
    /// The name of the constant.
    pub name: Ident,
    /// The expression associated with the constant.
    pub value: ConstantExpr,
}

impl Constant {
    /// Creates a new [Constant] from the given source span, name, and value.
    pub fn new(span: SourceSpan, visibility: Visibility, name: Ident, value: ConstantExpr) -> Self {
        Self {
            span,
            docs: None,
            visibility,
            name,
            value,
        }
    }

    /// Adds documentation to this constant declaration.
    pub fn with_docs(mut self, docs: Option<Span<String>>) -> Self {
        self.docs = docs.map(DocString::new);
        self
    }

    /// Returns the documentation associated with this item.
    pub fn docs(&self) -> Option<Span<&str>> {
        self.docs.as_ref().map(|docstring| docstring.as_spanned_str())
    }

    /// Get the name of this constant
    pub fn name(&self) -> &Ident {
        &self.name
    }
}

impl fmt::Debug for Constant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Constant")
            .field("docs", &self.docs)
            .field("visibility", &self.visibility)
            .field("name", &self.name)
            .field("value", &self.value)
            .finish()
    }
}

impl crate::prettier::PrettyPrint for Constant {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let mut doc = self
            .docs
            .as_ref()
            .map(|docstring| docstring.render())
            .unwrap_or(Document::Empty);

        doc += flatten(const_text("const") + const_text(" ") + display(&self.name));
        doc += const_text(" = ");

        doc + self.value.render() + nl()
    }
}

impl Eq for Constant {}

impl PartialEq for Constant {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.value == other.value
    }
}

impl Spanned for Constant {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl From<ConstantValue> for ConstantExpr {
    fn from(value: ConstantValue) -> Self {
        match value {
            ConstantValue::Int(value) => Self::Int(value),
            ConstantValue::String(value) => Self::String(value),
            ConstantValue::Word(value) => Self::Word(value),
            ConstantValue::Hash(kind, value) => Self::Hash(kind, value),
        }
    }
}
