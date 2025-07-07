#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{ColumnIndex, LineIndex};

/// A range in a text document expressed as (zero-based) start and end positions.
///
/// This is comparable to a selection in an editor, therefore the end position is exclusive.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Selection {
    pub start: Position,
    pub end: Position,
}

impl Selection {
    #[inline]
    pub fn new(start: Position, end: Position) -> Self {
        let start = core::cmp::min(start, end);
        let end = core::cmp::max(start, end);
        Self { start, end }
    }

    pub fn canonicalize(&mut self) {
        if self.end > self.start {
            core::mem::swap(&mut self.start, &mut self.end);
        }
    }
}

impl From<core::ops::Range<Position>> for Selection {
    #[inline]
    fn from(value: core::ops::Range<Position>) -> Self {
        Self::new(value.start, value.end)
    }
}

impl From<core::ops::Range<LineIndex>> for Selection {
    #[inline]
    fn from(value: core::ops::Range<LineIndex>) -> Self {
        Self::new(value.start.into(), value.end.into())
    }
}

/// Position in a text document expressed as zero-based line and character offset.
///
/// A position is between two characters like an insert cursor in a editor.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Position {
    pub line: LineIndex,
    pub character: ColumnIndex,
}

impl Position {
    pub const fn new(line: u32, character: u32) -> Self {
        Self {
            line: LineIndex(line),
            character: ColumnIndex(character),
        }
    }
}

impl From<LineIndex> for Position {
    #[inline]
    fn from(line: LineIndex) -> Self {
        Self { line, character: ColumnIndex(0) }
    }
}
