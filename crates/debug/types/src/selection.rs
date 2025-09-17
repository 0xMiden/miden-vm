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
        if start <= end {
            Self { start, end }
        } else {
            Self { start: end, end: start }
        }
    }

    pub fn canonicalize(&mut self) {
        if self.start > self.end {
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
/// A position is between two characters like an insert cursor in an editor.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_new_orders_bounds_when_reversed() {
        let a = Position::new(10, 5);
        let b = Position::new(2, 3);
        let sel = Selection::new(a, b);
        assert!(sel.start <= sel.end);
        assert_eq!(sel.start, b);
        assert_eq!(sel.end, a);
    }

    #[test]
    fn selection_new_keeps_order_when_already_ordered() {
        let a = Position::new(2, 3);
        let b = Position::new(10, 5);
        let sel = Selection::new(a, b);
        assert_eq!(sel.start, a);
        assert_eq!(sel.end, b);
    }

    #[test]
    fn canonicalize_swaps_only_when_start_greater_than_end() {
        let a = Position::new(10, 5);
        let b = Position::new(2, 3);
        let mut sel = Selection { start: a, end: b };
        sel.canonicalize();
        assert!(sel.start <= sel.end);
        assert_eq!(sel.start, b);
        assert_eq!(sel.end, a);

        let mut sel2 = Selection { start: b, end: a };
        sel2.canonicalize();
        assert_eq!(sel2.start, b);
        assert_eq!(sel2.end, a);
    }
}
