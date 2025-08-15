use alloc::{boxed::Box, string::String, sync::Arc};
use core::fmt;

use miden_core::FieldElement;
use miden_debug_types::{SourceSpan, Span, Spanned};

use super::DocString;
use crate::{
    Felt,
    ast::Ident,
    parser::{ParsingError, WordValue},
};

// CONSTANT
// ================================================================================================

/// Represents a constant definition in Miden Assembly syntax, i.e. `const.FOO = 1 + 1`.
#[derive(Clone)]
pub struct Constant {
    /// The source span of the definition.
    pub span: SourceSpan,
    /// The documentation string attached to this definition.
    pub docs: Option<DocString>,
    /// The name of the constant.
    pub name: Ident,
    /// The expression associated with the constant.
    pub value: ConstantExpr,
}

impl Constant {
    /// Creates a new [Constant] from the given source span, name, and value.
    pub fn new(span: SourceSpan, name: Ident, value: ConstantExpr) -> Self {
        Self { span, docs: None, name, value }
    }

    /// Adds documentation to this constant declaration.
    pub fn with_docs(mut self, docs: Option<Span<String>>) -> Self {
        self.docs = docs.map(DocString::new);
        self
    }
}

impl fmt::Debug for Constant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Constant")
            .field("docs", &self.docs)
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

        doc += flatten(const_text("const") + const_text(".") + display(&self.name));
        doc += const_text("=");

        doc + self.value.render()
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

// CONSTANT EXPRESSION
// ================================================================================================

/// Represents a constant expression or value in Miden Assembly syntax.
#[derive(Clone)]
pub enum ConstantExpr {
    /// A literal integer value.
    Literal(Span<Felt>),
    /// A reference to another constant.
    Var(Ident),
    /// An binary arithmetic operator.
    BinaryOp {
        span: SourceSpan,
        op: ConstantOp,
        lhs: Box<ConstantExpr>,
        rhs: Box<ConstantExpr>,
    },
    String(Ident),
    Word(Span<WordValue>),
    HashWord(Ident, WordValue),
}

impl ConstantExpr {
    /// Unwrap a literal value from this expression or panic.
    ///
    /// This is used in places where we expect the expression to have been folded to a value,
    /// otherwise a bug occurred.
    #[track_caller]
    pub fn expect_literal(&self) -> Felt {
        match self {
            Self::Literal(spanned) => spanned.into_inner(),
            other => panic!("expected constant expression to be a literal, got {other:#?}"),
        }
    }

    pub fn expect_string(&self) -> Arc<str> {
        match self {
            Self::String(spanned) => spanned.clone().into_inner(),
            other => panic!("expected constant expression to be a string, got {other:#?}"),
        }
    }

    /// Attempt to fold to a single value.
    ///
    /// This will only succeed if the expression has no references to other constants.
    ///
    /// # Errors
    /// Returns an error if an invalid expression is found while folding, such as division by zero.
    pub fn try_fold(self) -> Result<Self, ParsingError> {
        match self {
            Self::String(_)
            | Self::Literal(_)
            | Self::Var(_)
            | Self::Word(_)
            | Self::HashWord(..) => Ok(self),
            Self::BinaryOp { span, op, lhs, rhs } => {
                if rhs.is_literal() {
                    let rhs = Self::into_inner(rhs).try_fold()?;
                    match rhs {
                        Self::String(ident) => {
                            Err(ParsingError::StringInArithmeticExpression { span: ident.span() })
                        },
                        Self::Literal(rhs) => {
                            let lhs = Self::into_inner(lhs).try_fold()?;
                            match lhs {
                                Self::String(ident) => {
                                    Err(ParsingError::StringInArithmeticExpression {
                                        span: ident.span(),
                                    })
                                },
                                Self::Literal(lhs) => {
                                    let lhs = lhs.into_inner();
                                    let rhs = rhs.into_inner();
                                    let is_division =
                                        matches!(op, ConstantOp::Div | ConstantOp::IntDiv);
                                    let is_division_by_zero = is_division && rhs == Felt::ZERO;
                                    if is_division_by_zero {
                                        return Err(ParsingError::DivisionByZero { span });
                                    }
                                    match op {
                                        ConstantOp::Add => {
                                            Ok(Self::Literal(Span::new(span, lhs + rhs)))
                                        },
                                        ConstantOp::Sub => {
                                            Ok(Self::Literal(Span::new(span, lhs - rhs)))
                                        },
                                        ConstantOp::Mul => {
                                            Ok(Self::Literal(Span::new(span, lhs * rhs)))
                                        },
                                        ConstantOp::Div => {
                                            Ok(Self::Literal(Span::new(span, lhs / rhs)))
                                        },
                                        ConstantOp::IntDiv => Ok(Self::Literal(Span::new(
                                            span,
                                            Felt::new(lhs.as_int() / rhs.as_int()),
                                        ))),
                                    }
                                },
                                lhs => Ok(Self::BinaryOp {
                                    span,
                                    op,
                                    lhs: Box::new(lhs),
                                    rhs: Box::new(Self::Literal(rhs)),
                                }),
                            }
                        },
                        rhs => {
                            let lhs = Self::into_inner(lhs).try_fold()?;
                            Ok(Self::BinaryOp {
                                span,
                                op,
                                lhs: Box::new(lhs),
                                rhs: Box::new(rhs),
                            })
                        },
                    }
                } else {
                    let lhs = Self::into_inner(lhs).try_fold()?;
                    Ok(Self::BinaryOp { span, op, lhs: Box::new(lhs), rhs })
                }
            },
        }
    }

    fn is_literal(&self) -> bool {
        match self {
            Self::Literal(_) | Self::String(_) | Self::Word(_) | Self::HashWord(..) => true,
            Self::Var(_) => false,
            Self::BinaryOp { lhs, rhs, .. } => lhs.is_literal() && rhs.is_literal(),
        }
    }

    #[inline(always)]
    #[allow(clippy::boxed_local)]
    fn into_inner(self: Box<Self>) -> Self {
        *self
    }
}

impl Eq for ConstantExpr {}

impl PartialEq for ConstantExpr {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Literal(l), Self::Literal(y)) => l == y,
            (Self::Var(l), Self::Var(y)) => l == y,
            (Self::HashWord(l_s, l_h), Self::HashWord(r_s, r_h)) => l_s == r_s && l_h == r_h,
            (
                Self::BinaryOp { op: lop, lhs: llhs, rhs: lrhs, .. },
                Self::BinaryOp { op: rop, lhs: rlhs, rhs: rrhs, .. },
            ) => lop == rop && llhs == rlhs && lrhs == rrhs,
            _ => false,
        }
    }
}

impl core::hash::Hash for ConstantExpr {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::Literal(value) => value.as_int().hash(state),
            Self::String(value) => value.hash(state),
            Self::Word(value) => value.hash(state),
            Self::Var(value) => value.hash(state),
            Self::HashWord(string, hash) => {
                string.hash(state);
                hash.hash(state);
            },
            Self::BinaryOp { op, lhs, rhs, .. } => {
                op.hash(state);
                lhs.hash(state);
                rhs.hash(state);
            },
        }
    }
}

impl fmt::Debug for ConstantExpr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Literal(lit) => fmt::Debug::fmt(&**lit, f),
            Self::Word(w) => fmt::Debug::fmt(&**w, f),
            Self::Var(name) | Self::String(name) => fmt::Debug::fmt(&**name, f),
            Self::HashWord(str, hash) => fmt::Debug::fmt(&(str, hash), f),
            Self::BinaryOp { op, lhs, rhs, .. } => {
                f.debug_tuple(op.name()).field(lhs).field(rhs).finish()
            },
        }
    }
}

impl crate::prettier::PrettyPrint for ConstantExpr {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        match self {
            Self::Literal(literal) => display(literal),
            Self::Word(spanned) => spanned.render(),
            Self::Var(ident) | Self::String(ident) => display(ident),
            Self::HashWord(str, hash) => {
                flatten(display(str) + const_text("(") + display(hash) + const_text(")"))
            },
            Self::BinaryOp { op, lhs, rhs, .. } => {
                let single_line = lhs.render() + display(op) + rhs.render();
                let multi_line = lhs.render() + nl() + (display(op)) + rhs.render();
                single_line | multi_line
            },
        }
    }
}

impl Spanned for ConstantExpr {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Literal(spanned) => spanned.span(),
            Self::Word(spanned) => spanned.span(),
            Self::HashWord(spanned, _) => spanned.span(),
            Self::Var(spanned) | Self::String(spanned) => spanned.span(),
            Self::BinaryOp { span, .. } => *span,
        }
    }
}

// CONSTANT OPERATION
// ================================================================================================

/// Represents the set of binary arithmetic operators supported in Miden Assembly syntax.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ConstantOp {
    Add,
    Sub,
    Mul,
    Div,
    IntDiv,
}

impl ConstantOp {
    const fn name(&self) -> &'static str {
        match self {
            Self::Add => "Add",
            Self::Sub => "Sub",
            Self::Mul => "Mul",
            Self::Div => "Div",
            Self::IntDiv => "IntDiv",
        }
    }
}

impl fmt::Display for ConstantOp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Add => f.write_str("+"),
            Self::Sub => f.write_str("-"),
            Self::Mul => f.write_str("*"),
            Self::Div => f.write_str("/"),
            Self::IntDiv => f.write_str("//"),
        }
    }
}
