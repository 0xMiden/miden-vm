use core::fmt;

use crate::ast::{ImmU8, ImmU16, ImmU32};

// DEBUG OPTIONS
// ================================================================================================

/// A proxy for [miden_core::DebugOptions], but with [super::Immediate] values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DebugOptions {
    StackAll,
    StackTop(ImmU8),
    MemAll,
    MemInterval(ImmU32, ImmU32),
    LocalInterval(ImmU16, ImmU16),
    LocalRangeFrom(ImmU16),
    LocalAll,
    AdvStackTop(ImmU16),
}

impl crate::prettier::PrettyPrint for DebugOptions {
    fn render(&self) -> crate::prettier::Document {
        crate::prettier::display(self)
    }
}

impl fmt::Display for DebugOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StackAll => write!(f, "stack"),
            Self::StackTop(n) => write!(f, "stack.{n}"),
            Self::MemAll => write!(f, "mem"),
            Self::MemInterval(n, m) => write!(f, "mem.{n}.{m}"),
            Self::LocalAll => write!(f, "local"),
            Self::LocalRangeFrom(start) => write!(f, "local.{start}"),
            Self::LocalInterval(start, end) => {
                write!(f, "local.{start}.{end}")
            },
            Self::AdvStackTop(n) => write!(f, "adv_stack.{n}"),
        }
    }
}
