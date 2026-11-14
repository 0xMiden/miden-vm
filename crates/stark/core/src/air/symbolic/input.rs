//! Field-independent addresses of the inputs to a two-row AIR relation.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RowOffset {
    Current,
    Next,
}
impl RowOffset {
    pub const fn index(self) -> usize {
        match self {
            Self::Current => 0,
            Self::Next => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BaseInput {
    Main { row: RowOffset, column: usize },
    Preprocessed { row: RowOffset, column: usize },
    Public { index: usize },
    Periodic { index: usize },
}
impl BaseInput {
    pub const fn index(self) -> usize {
        match self {
            Self::Main { column, .. } | Self::Preprocessed { column, .. } => column,
            Self::Public { index } | Self::Periodic { index } => index,
        }
    }
    pub(crate) const fn degree_multiple(self) -> usize {
        match self {
            Self::Public { .. } => 0,
            _ => 1,
        }
    }
    /// Diagnostic query for validated geometry; capacity uses the native degree profile.
    pub(crate) fn poly_degree(self, trace_len: usize, periodic_periods: &[usize]) -> usize {
        match self {
            Self::Main { .. } | Self::Preprocessed { .. } => trace_len.saturating_sub(1),
            Self::Public { .. } => 0,
            Self::Periodic { index } => trace_len - trace_len / periodic_periods[index],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuxInput {
    Trace { row: RowOffset, column: usize },
    Challenge { index: usize },
    Export { index: usize },
}
impl AuxInput {
    pub const fn index(self) -> usize {
        match self {
            Self::Trace { column, .. } => column,
            Self::Challenge { index } | Self::Export { index } => index,
        }
    }
    pub(crate) const fn degree_multiple(self) -> usize {
        match self {
            Self::Trace { .. } => 1,
            _ => 0,
        }
    }
    /// Diagnostic query for validated geometry; capacity uses the native degree profile.
    pub(crate) fn poly_degree(self, trace_len: usize) -> usize {
        match self {
            Self::Trace { .. } => trace_len.saturating_sub(1),
            Self::Challenge { .. } | Self::Export { .. } => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn addresses_keep_row_and_namespace() {
        let current = BaseInput::Main { row: RowOffset::Current, column: 3 };
        let next = BaseInput::Main { row: RowOffset::Next, column: 3 };
        assert_ne!(current, next);
        assert_eq!(next.index(), 3);
        assert_eq!(RowOffset::Current.index(), 0);
        assert_eq!(RowOffset::Next.index(), 1);
        assert_eq!(BaseInput::Public { index: 2 }.degree_multiple(), 0);
        assert_eq!(AuxInput::Trace { row: RowOffset::Next, column: 4 }.degree_multiple(), 1);
        assert_eq!(AuxInput::Challenge { index: 0 }.degree_multiple(), 0);
        assert_eq!(AuxInput::Export { index: 0 }.degree_multiple(), 0);
    }
}
