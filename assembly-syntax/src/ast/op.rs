use core::fmt;

use miden_debug_types::{SourceSpan, Span, Spanned};

use super::{Block, Instruction};

/// Represents the Miden Assembly instruction set syntax
///
/// This is separate from [Instruction] in order to distinguish control flow instructions and
/// instructions with block regions from the rest.
#[derive(Clone)]
#[repr(u8)]
pub enum Op {
    /// Represents a conditional branch
    ///
    /// Can be either `if`..`end`, or `if`..`else`..`end`.
    If {
        span: SourceSpan,
        /// This block is always present and non-empty
        then_blk: Block,
        /// This block will be empty if no `else` branch was present
        else_blk: Block,
    } = 0,
    /// Represents a condition-controlled loop
    While { span: SourceSpan, body: Block } = 1,
    /// Represents a counter-controlled loop.
    ///
    /// NOTE: The iteration count must be known at compile-time, so this is _not_ used for general
    /// `for`-style loops where the iteration count is dynamic.
    Repeat {
        span: SourceSpan,
        count: u32,
        body: Block,
    } = 2,
    /// A primitive operation, e.g. `add`
    Inst(Span<Instruction>) = 3,
}

impl crate::prettier::PrettyPrint for Op {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        match self {
            Self::If { then_blk, else_blk, .. } => {
                text("if.true") + then_blk.render() + text("else") + else_blk.render() + text("end")
            },
            Self::While { body, .. } => text("while.true") + body.render() + text("end"),
            Self::Repeat { count, body, .. } => {
                display(format!("repeat.{count}")) + body.render() + text("end")
            },
            Self::Inst(inst) => inst.render(),
        }
    }
}

impl fmt::Debug for Op {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::If { then_blk, else_blk, .. } => {
                f.debug_struct("If").field("then", then_blk).field("else", else_blk).finish()
            },
            Self::While { body, .. } => f.debug_tuple("While").field(body).finish(),
            Self::Repeat { count, body, .. } => {
                f.debug_struct("Repeat").field("count", count).field("body", body).finish()
            },
            Self::Inst(inst) => fmt::Debug::fmt(&**inst, f),
        }
    }
}

impl Eq for Op {}

impl PartialEq for Op {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::If { then_blk: lt, else_blk: le, .. },
                Self::If { then_blk: rt, else_blk: re, .. },
            ) => lt == rt && le == re,
            (Self::While { body: lbody, .. }, Self::While { body: rbody, .. }) => lbody == rbody,
            (
                Self::Repeat { count: lcount, body: lbody, .. },
                Self::Repeat { count: rcount, body: rbody, .. },
            ) => lcount == rcount && lbody == rbody,
            (Self::Inst(l), Self::Inst(r)) => l == r,
            _ => false,
        }
    }
}

impl Spanned for Op {
    fn span(&self) -> SourceSpan {
        match self {
            Self::If { span, .. } | Self::While { span, .. } | Self::Repeat { span, .. } => *span,
            Self::Inst(spanned) => spanned.span(),
        }
    }
}
