pub mod eval;
mod expr;
#[cfg(test)]
mod tests;
mod value;

use alloc::string::String;
use core::fmt;

use miden_core::events::EventId;
use miden_debug_types::{SourceSpan, Span, Spanned};

pub use self::{
    eval::{ConstEnvironment, ConstEvalError},
    expr::{ConstantExpr, ConstantOp, HashKind},
    value::ConstantValue,
};
use crate::ast::{DocString, Ident, TypeExpr, Visibility};

// CONSTANT DECLARATION
// ================================================================================================

/// A constant declaration in Miden Assembly, i.e. `const FOO = 1 + 1`.
///
/// Its kind is derived from the current value expression and optional annotation, see
/// [`Self::kind`]. Aliases are not resolved when determining the kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstantDecl {
    definition: ConstantDefinition,
    /// Kept independently of the kind for validation and diagnostics.
    ty: Option<TypeExpr>,
}

/// The syntactic kind of a constant declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstantKind {
    /// Without an annotation and not an event or string expression.
    Untyped,
    /// With an annotation and not an event or string expression.
    Typed,
    /// An event hash expression, i.e. `event("...")`.
    Event,
    /// A string literal.
    String,
}

impl ConstantDecl {
    /// Creates an unannotated constant declaration.
    pub fn new(span: SourceSpan, visibility: Visibility, name: Ident, value: ConstantExpr) -> Self {
        Self {
            definition: ConstantDefinition::new(span, visibility, name, value),
            ty: None,
        }
    }

    /// Like [`Self::new`], with a type annotation.
    pub fn new_with_ty(
        span: SourceSpan,
        visibility: Visibility,
        name: Ident,
        value: ConstantExpr,
        ty: TypeExpr,
    ) -> Self {
        Self {
            definition: ConstantDefinition::new(span, visibility, name, value),
            ty: Some(ty),
        }
    }

    /// Returns the kind of the current expression without resolving aliases or evaluating it.
    ///
    /// Event and string expressions take precedence over annotations, which are retained even
    /// when they conflict with the expression.
    pub fn kind(&self) -> ConstantKind {
        match self.value() {
            ConstantExpr::Hash(HashKind::Event, _) => ConstantKind::Event,
            ConstantExpr::String(_) => ConstantKind::String,
            _ if self.ty.is_some() => ConstantKind::Typed,
            _ => ConstantKind::Untyped,
        }
    }

    /// Returns the event id for an event hash expression, or `None` for any other expression.
    ///
    /// Aliases are not resolved.
    pub fn event_id(&self) -> Option<EventId> {
        match self.value() {
            ConstantExpr::Hash(HashKind::Event, name) => Some(EventId::from_name(name.as_str())),
            _ => None,
        }
    }

    /// Returns the constant's definition, without its optional type annotation.
    pub fn definition(&self) -> &ConstantDefinition {
        &self.definition
    }

    /// Returns a mutable reference to the constant's definition.
    pub fn definition_mut(&mut self) -> &mut ConstantDefinition {
        &mut self.definition
    }

    /// Sets the documentation attached to this declaration.
    pub fn with_docs(mut self, docs: Option<Span<String>>) -> Self {
        *self.definition_mut().docs_mut() = docs.map(DocString::new);
        self
    }

    /// Returns the constant's name.
    pub fn name(&self) -> &Ident {
        self.definition().name()
    }

    /// Returns the constant's visibility.
    pub fn visibility(&self) -> Visibility {
        self.definition().visibility()
    }

    /// Returns the documentation attached to this declaration, if any.
    pub fn docs(&self) -> Option<Span<&str>> {
        self.definition().docs()
    }

    /// Returns the constant's value expression.
    pub fn value(&self) -> &ConstantExpr {
        self.definition().value()
    }

    /// Returns a mutable reference to the constant's value expression.
    pub fn value_mut(&mut self) -> &mut ConstantExpr {
        self.definition_mut().value_mut()
    }

    /// Returns the declared type annotation, if any.
    pub fn ty(&self) -> Option<&TypeExpr> {
        self.ty.as_ref()
    }
}

impl Spanned for ConstantDecl {
    fn span(&self) -> SourceSpan {
        self.definition().span()
    }
}

impl From<ConstantDefinition> for ConstantDecl {
    fn from(definition: ConstantDefinition) -> Self {
        Self { definition, ty: None }
    }
}

impl crate::prettier::PrettyPrint for ConstantDecl {
    fn render(&self) -> crate::prettier::Document {
        self.definition().render_with_ty(self.ty())
    }
}

// CONSTANT DEFINITION
// ================================================================================================

/// Represents a constant definition in Miden Assembly syntax, i.e. `const FOO = 1 + 1`.
#[derive(Clone)]
pub struct ConstantDefinition {
    span: SourceSpan,
    docs: Option<DocString>,
    visibility: Visibility,
    name: Ident,
    value: ConstantExpr,
}

impl ConstantDefinition {
    /// Creates a constant definition without a type annotation.
    pub fn new(span: SourceSpan, visibility: Visibility, name: Ident, value: ConstantExpr) -> Self {
        Self {
            span,
            docs: None,
            visibility,
            name,
            value,
        }
    }

    /// Sets the documentation attached to this definition.
    pub fn with_docs(mut self, docs: Option<Span<String>>) -> Self {
        self.docs = docs.map(DocString::new);
        self
    }

    /// Returns the documentation attached to this definition, if any.
    pub fn docs(&self) -> Option<Span<&str>> {
        self.docs.as_ref().map(|docstring| docstring.as_spanned_str())
    }

    /// Returns mutable access to this definition's documentation.
    pub fn docs_mut(&mut self) -> &mut Option<DocString> {
        &mut self.docs
    }

    /// Returns the name of this definition.
    pub fn name(&self) -> &Ident {
        &self.name
    }

    /// Returns mutable access to this definition's name.
    pub fn name_mut(&mut self) -> &mut Ident {
        &mut self.name
    }

    /// Returns this definition's visibility.
    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// Returns this definition's value expression.
    pub fn value(&self) -> &ConstantExpr {
        &self.value
    }

    /// Returns mutable access to this definition's value expression.
    pub fn value_mut(&mut self) -> &mut ConstantExpr {
        &mut self.value
    }

    fn render_with_ty(&self, ty: Option<&TypeExpr>) -> crate::prettier::Document {
        use crate::prettier::*;

        let mut doc = self.docs.as_ref().map(PrettyPrint::render).unwrap_or(Document::Empty);

        if self.visibility.is_public() {
            doc += display(self.visibility) + const_text(" ");
        }
        doc += flatten(const_text("const") + const_text(" ") + display(&self.name));
        if let Some(ty) = ty {
            doc += const_text(": ") + ty.render();
        }
        doc += const_text(" = ");

        doc + self.value.render() + nl()
    }
}

impl fmt::Debug for ConstantDefinition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ConstantDefinition")
            .field("docs", &self.docs)
            .field("visibility", &self.visibility)
            .field("name", &self.name)
            .field("value", &self.value)
            .finish()
    }
}

impl crate::prettier::PrettyPrint for ConstantDefinition {
    fn render(&self) -> crate::prettier::Document {
        self.render_with_ty(None)
    }
}

impl Eq for ConstantDefinition {}

impl PartialEq for ConstantDefinition {
    fn eq(&self, other: &Self) -> bool {
        self.visibility == other.visibility && self.name == other.name && self.value == other.value
    }
}

impl Spanned for ConstantDefinition {
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
