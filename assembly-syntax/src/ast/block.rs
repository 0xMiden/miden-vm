use alloc::vec::Vec;
use core::fmt;

use miden_debug_types::{SourceSpan, Span, Spanned};

use super::Op;

// BASIC BLOCK
// ================================================================================================

/// Represents a basic block in Miden Assembly syntax.
///
/// Blocks can be nested, see [Op] for details.
#[derive(Clone, Default)]
pub struct Block {
    span: SourceSpan,
    body: Vec<Op>,
}

impl Block {
    /// Creates a new [Block].
    pub fn new(span: SourceSpan, body: Vec<Op>) -> Self {
        Self { span, body }
    }

    /// Appends `op` to this block.
    pub fn push(&mut self, op: Op) {
        self.body.push(op);
    }

    /// Returns the number of ops in this block.
    ///
    /// NOTE: The count does not include nested ops,
    /// only those at the root of the block.
    pub fn len(&self) -> usize {
        self.body.len()
    }

    /// Returns true if this block is empty
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// Returns an iterator for the operations in this block.
    pub fn iter(&self) -> core::slice::Iter<'_, Op> {
        self.body.iter()
    }

    /// Returns a mutable iterator for the operations in this block.
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, Op> {
        self.body.iter_mut()
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(&self.body).finish()
    }
}

impl crate::prettier::PrettyPrint for Block {
    fn render(&self) -> crate::prettier::Document {
        use crate::{ast::Instruction, prettier::*};

        // If a block is empty, pretty-print it with a `nop` instruction
        let default_body = [Op::Inst(Span::new(self.span, Instruction::Nop))];
        let body = if self.body.is_empty() {
            default_body.as_slice().iter()
        } else {
            self.body.iter()
        }
        .map(PrettyPrint::render)
        .reduce(|acc, doc| acc + nl() + doc)
        .unwrap();

        indent(4, nl() + body) + nl()
    }
}

impl Spanned for Block {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl Eq for Block {}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.body == other.body
    }
}
