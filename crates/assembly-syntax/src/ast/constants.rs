use alloc::{boxed::Box, string::String, sync::Arc};
use core::fmt;

use miden_core::{
    FieldElement,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use miden_debug_types::{SourceSpan, Span, Spanned};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::PathBuf;
use crate::{
    Felt,
    ast::{DocString, Ident, Visibility},
    parser::{IntValue, ParsingError, WordValue},
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

// CONSTANT VALUE
// ================================================================================================

/// Represents a constant value in Miden Assembly syntax.
#[derive(Clone)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ConstantValue {
    /// A literal [`Felt`] value.
    Int(Span<IntValue>) = 1,
    /// A plain spanned string.
    String(Ident),
    /// A literal ['WordValue'].
    Word(Span<WordValue>),
    /// A spanned string with a [`HashKind`] showing to which type of value the given string should
    /// be hashed.
    Hash(HashKind, Ident),
}

impl Eq for ConstantValue {}

impl PartialEq for ConstantValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Int(l), Self::Int(y)) => l == y,
            (Self::Int(_), _) => false,
            (Self::Word(l), Self::Word(y)) => l == y,
            (Self::Word(_), _) => false,
            (Self::String(l), Self::String(y)) => l == y,
            (Self::String(_), _) => false,
            (Self::Hash(x_hk, x_i), Self::Hash(y_hk, y_i)) => x_i == y_i && x_hk == y_hk,
            (Self::Hash(..), _) => false,
        }
    }
}

impl core::hash::Hash for ConstantValue {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::Int(value) => value.hash(state),
            Self::Word(value) => value.hash(state),
            Self::String(value) => value.hash(state),
            Self::Hash(kind, value) => {
                kind.hash(state);
                value.hash(state);
            },
        }
    }
}

impl fmt::Debug for ConstantValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Int(lit) => fmt::Debug::fmt(&**lit, f),
            Self::Word(lit) => fmt::Debug::fmt(&**lit, f),
            Self::String(name) => fmt::Debug::fmt(&**name, f),
            Self::Hash(hash_kind, str) => fmt::Debug::fmt(&(str, hash_kind), f),
        }
    }
}

impl crate::prettier::PrettyPrint for ConstantValue {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        match self {
            Self::Int(literal) => display(literal),
            Self::Word(literal) => display(literal),
            Self::String(ident) => display(ident),
            Self::Hash(hash_kind, str) => {
                flatten(display(hash_kind) + const_text("(") + display(str) + const_text(")"))
            },
        }
    }
}

impl Spanned for ConstantValue {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Int(spanned) => spanned.span(),
            Self::Word(spanned) => spanned.span(),
            Self::String(spanned) => spanned.span(),
            Self::Hash(_, spanned) => spanned.span(),
        }
    }
}

impl ConstantValue {
    const fn tag(&self) -> u8 {
        // SAFETY: This is safe because we have given this enum a
        // primitive representation with #[repr(u8)], with the first
        // field of the underlying union-of-structs the discriminant
        //
        // See the section on "accessing the numeric value of the discriminant"
        // here: https://doc.rust-lang.org/std/mem/fn.discriminant.html
        unsafe { *(self as *const Self).cast::<u8>() }
    }
}

impl Serializable for ConstantValue {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.tag());
        match self {
            Self::Int(value) => value.inner().write_into(target),
            Self::String(id) => id.write_into(target),
            Self::Word(value) => value.inner().write_into(target),
            Self::Hash(kind, id) => {
                kind.write_into(target);
                id.write_into(target);
            },
        }
    }
}

impl Deserializable for ConstantValue {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            1 => IntValue::read_from(source).map(Span::unknown).map(Self::Int),
            2 => Ident::read_from(source).map(Self::String),
            3 => WordValue::read_from(source).map(Span::unknown).map(Self::Word),
            4 => {
                let kind = HashKind::read_from(source)?;
                let id = Ident::read_from(source)?;
                Ok(Self::Hash(kind, id))
            },
            invalid => Err(DeserializationError::InvalidValue(format!(
                "unexpected ConstantValue tag: '{invalid}'"
            ))),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for ConstantValue {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{arbitrary::any, prop_oneof, strategy::Strategy};

        prop_oneof![
            any::<IntValue>().prop_map(|n| Self::Int(Span::unknown(n))),
            any::<Ident>().prop_map(Self::String),
            any::<WordValue>().prop_map(|word| Self::Word(Span::unknown(word))),
            any::<(HashKind, Ident)>().prop_map(|(kind, s)| Self::Hash(kind, s)),
        ]
        .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// CONSTANT EXPRESSION
// ================================================================================================

/// Represents a constant expression or value in Miden Assembly syntax.
#[derive(Clone)]
#[repr(u8)]
pub enum ConstantExpr {
    /// A literal [`Felt`] value.
    Int(Span<IntValue>),
    /// A reference to another constant.
    Var(Span<PathBuf>),
    /// An binary arithmetic operator.
    BinaryOp {
        span: SourceSpan,
        op: ConstantOp,
        lhs: Box<ConstantExpr>,
        rhs: Box<ConstantExpr>,
    },
    /// A plain spanned string.
    String(Ident),
    /// A literal ['WordValue'].
    Word(Span<WordValue>),
    /// A spanned string with a [`HashKind`] showing to which type of value the given string should
    /// be hashed.
    Hash(HashKind, Ident),
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

impl ConstantExpr {
    /// Unwrap an [`IntValue`] from this expression or panic.
    ///
    /// This is used in places where we expect the expression to have been folded to an integer,
    /// otherwise a bug occurred.
    #[track_caller]
    pub fn expect_int(&self) -> IntValue {
        match self {
            Self::Int(spanned) => spanned.into_inner(),
            other => panic!("expected constant expression to be a literal, got {other:#?}"),
        }
    }

    /// Unwrap a [`Felt`] value from this expression or panic.
    ///
    /// This is used in places where we expect the expression to have been folded to a felt value,
    /// otherwise a bug occurred.
    #[track_caller]
    pub fn expect_felt(&self) -> Felt {
        match self {
            Self::Int(spanned) => Felt::new(spanned.inner().as_int()),
            other => panic!("expected constant expression to be a literal, got {other:#?}"),
        }
    }

    /// Unwrap a [`Arc<str>`] value from this expression or panic.
    ///
    /// This is used in places where we expect the expression to have been folded to a string value,
    /// otherwise a bug occurred.
    #[track_caller]
    pub fn expect_string(&self) -> Arc<str> {
        match self {
            Self::String(spanned) => spanned.clone().into_inner(),
            other => panic!("expected constant expression to be a string, got {other:#?}"),
        }
    }

    /// Unwrap a [ConstantValue] from this expression or panic.
    ///
    /// This is used in places where we expect the expression to have been folded to a concrete
    /// value, otherwise a bug occurred.
    #[track_caller]
    pub fn expect_value(&self) -> ConstantValue {
        match self {
            Self::Int(value) => ConstantValue::Int(*value),
            Self::String(value) => ConstantValue::String(value.clone()),
            Self::Word(value) => ConstantValue::Word(*value),
            other => panic!("expected constant expression to be a value, got {other:#?}"),
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
            Self::String(_) | Self::Word(_) | Self::Int(_) | Self::Var(_) | Self::Hash(..) => {
                Ok(self)
            },
            Self::BinaryOp { span, op, lhs, rhs } => {
                if rhs.is_literal() {
                    let rhs = Self::into_inner(rhs).try_fold()?;
                    match rhs {
                        Self::String(ident) => {
                            Err(ParsingError::StringInArithmeticExpression { span: ident.span() })
                        },
                        Self::Int(rhs) => {
                            let lhs = Self::into_inner(lhs).try_fold()?;
                            match lhs {
                                Self::String(ident) => {
                                    Err(ParsingError::StringInArithmeticExpression {
                                        span: ident.span(),
                                    })
                                },
                                Self::Int(lhs) => {
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
                                            Ok(Self::Int(Span::new(span, lhs + rhs)))
                                        },
                                        ConstantOp::Sub => {
                                            Ok(Self::Int(Span::new(span, lhs - rhs)))
                                        },
                                        ConstantOp::Mul => {
                                            Ok(Self::Int(Span::new(span, lhs * rhs)))
                                        },
                                        ConstantOp::Div => {
                                            Ok(Self::Int(Span::new(span, lhs / rhs)))
                                        },
                                        ConstantOp::IntDiv => {
                                            Ok(Self::Int(Span::new(span, lhs / rhs)))
                                        },
                                    }
                                },
                                lhs => Ok(Self::BinaryOp {
                                    span,
                                    op,
                                    lhs: Box::new(lhs),
                                    rhs: Box::new(Self::Int(rhs)),
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
            Self::Int(_) | Self::String(_) | Self::Word(_) | Self::Hash(..) => true,
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
            (Self::Int(x), Self::Int(y)) => x == y,
            (Self::Int(_), _) => false,
            (Self::Word(x), Self::Word(y)) => x == y,
            (Self::Word(_), _) => false,
            (Self::Var(x), Self::Var(y)) => x == y,
            (Self::Var(_), _) => false,
            (Self::String(x), Self::String(y)) => x == y,
            (Self::String(_), _) => false,
            (Self::Hash(x_hk, x_i), Self::Hash(y_hk, y_i)) => x_i == y_i && x_hk == y_hk,
            (Self::Hash(..), _) => false,
            (
                Self::BinaryOp { op: lop, lhs: llhs, rhs: lrhs, .. },
                Self::BinaryOp { op: rop, lhs: rlhs, rhs: rrhs, .. },
            ) => lop == rop && llhs == rlhs && lrhs == rrhs,
            (Self::BinaryOp { .. }, _) => false,
        }
    }
}

impl core::hash::Hash for ConstantExpr {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::Int(value) => value.hash(state),
            Self::Word(value) => value.hash(state),
            Self::String(value) => value.hash(state),
            Self::Var(value) => value.hash(state),
            Self::Hash(hash_kind, string) => {
                hash_kind.hash(state);
                string.hash(state);
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
            Self::Int(lit) => fmt::Debug::fmt(&**lit, f),
            Self::Word(lit) => fmt::Debug::fmt(&**lit, f),
            Self::Var(path) => fmt::Debug::fmt(path, f),
            Self::String(name) => fmt::Debug::fmt(&**name, f),
            Self::Hash(hash_kind, str) => fmt::Debug::fmt(&(str, hash_kind), f),
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
            Self::Int(literal) => display(literal),
            Self::Word(literal) => display(literal),
            Self::Var(path) => display(path),
            Self::String(ident) => display(ident),
            Self::Hash(hash_kind, str) => {
                flatten(display(hash_kind) + const_text("(") + display(str) + const_text(")"))
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
            Self::Int(spanned) => spanned.span(),
            Self::Word(spanned) => spanned.span(),
            Self::Hash(_, spanned) => spanned.span(),
            Self::Var(spanned) => spanned.span(),
            Self::String(spanned) => spanned.span(),
            Self::BinaryOp { span, .. } => *span,
        }
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for ConstantExpr {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{arbitrary::any, prop_oneof, strategy::Strategy};

        prop_oneof![
            any::<IntValue>().prop_map(|n| Self::Int(Span::unknown(n))),
            crate::arbitrary::path::constant_pathbuf_random_length(0)
                .prop_map(|p| Self::Var(Span::unknown(p))),
            any::<(ConstantOp, IntValue, IntValue)>().prop_map(|(op, lhs, rhs)| Self::BinaryOp {
                span: SourceSpan::UNKNOWN,
                op,
                lhs: Box::new(ConstantExpr::Int(Span::unknown(lhs))),
                rhs: Box::new(ConstantExpr::Int(Span::unknown(rhs))),
            }),
            any::<Ident>().prop_map(Self::String),
            any::<WordValue>().prop_map(|word| Self::Word(Span::unknown(word))),
            any::<(HashKind, Ident)>().prop_map(|(kind, s)| Self::Hash(kind, s)),
        ]
        .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// CONSTANT OPERATION
// ================================================================================================

/// Represents the set of binary arithmetic operators supported in Miden Assembly syntax.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

impl ConstantOp {
    const fn tag(&self) -> u8 {
        // SAFETY: This is safe because we have given this enum a
        // primitive representation with #[repr(u8)], with the first
        // field of the underlying union-of-structs the discriminant
        //
        // See the section on "accessing the numeric value of the discriminant"
        // here: https://doc.rust-lang.org/std/mem/fn.discriminant.html
        unsafe { *(self as *const Self).cast::<u8>() }
    }
}

impl Serializable for ConstantOp {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.tag());
    }
}

impl Deserializable for ConstantOp {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        const ADD: u8 = ConstantOp::Add.tag();
        const SUB: u8 = ConstantOp::Sub.tag();
        const MUL: u8 = ConstantOp::Mul.tag();
        const DIV: u8 = ConstantOp::Div.tag();
        const INT_DIV: u8 = ConstantOp::IntDiv.tag();

        match source.read_u8()? {
            ADD => Ok(Self::Add),
            SUB => Ok(Self::Sub),
            MUL => Ok(Self::Mul),
            DIV => Ok(Self::Div),
            INT_DIV => Ok(Self::IntDiv),
            invalid => Err(DeserializationError::InvalidValue(format!(
                "unexpected ConstantOp tag: '{invalid}'"
            ))),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for ConstantOp {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{
            prop_oneof,
            strategy::{Just, Strategy},
        };

        prop_oneof![
            Just(Self::Add),
            Just(Self::Sub),
            Just(Self::Mul),
            Just(Self::Div),
            Just(Self::IntDiv),
        ]
        .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// HASH KIND
// ================================================================================================

/// Represents the type of the final value to which some string value should be converted.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum HashKind {
    /// Reduce a string to a word using Blake3 hash function
    Word,
    /// Reduce a string to a felt using Blake3 hash function (via 64-bit reduction)
    Event,
}

impl HashKind {
    const fn tag(&self) -> u8 {
        // SAFETY: This is safe because we have given this enum a
        // primitive representation with #[repr(u8)], with the first
        // field of the underlying union-of-structs the discriminant
        //
        // See the section on "accessing the numeric value of the discriminant"
        // here: https://doc.rust-lang.org/std/mem/fn.discriminant.html
        unsafe { *(self as *const Self).cast::<u8>() }
    }
}

impl fmt::Display for HashKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Word => f.write_str("word"),
            Self::Event => f.write_str("event"),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for HashKind {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{
            prop_oneof,
            strategy::{Just, Strategy},
        };

        prop_oneof![Just(Self::Word), Just(Self::Event),].boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

impl Serializable for HashKind {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.tag());
    }
}

impl Deserializable for HashKind {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        const WORD: u8 = HashKind::Word.tag();
        const EVENT: u8 = HashKind::Event.tag();

        match source.read_u8()? {
            WORD => Ok(Self::Word),
            EVENT => Ok(Self::Event),
            invalid => Err(DeserializationError::InvalidValue(format!(
                "unexpected HashKind tag: '{invalid}'"
            ))),
        }
    }
}
