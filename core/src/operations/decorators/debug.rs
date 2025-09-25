use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// DEBUG OPTIONS
// ================================================================================================

/// Options of the `Debug` decorator.
///
/// These options define the debug info which gets printed out when the Debug decorator is
/// executed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DebugOptions {
    /// Print out the entire contents of the stack for the current execution context.
    StackAll,
    /// Prints out the top n items of the stack for the current context.
    StackTop(u8),
    /// Prints out the entire contents of RAM.
    MemAll,
    /// Prints out the contents of memory stored in the provided interval. Interval boundaries are
    /// both inclusive.
    ///
    /// First parameter specifies the interval starting address, second -- the ending address.
    MemInterval(u32, u32),
    /// Prints out locals stored in the provided interval of the currently executing procedure.
    /// Interval boundaries are both inclusive.
    ///
    /// First parameter specifies the starting address, second -- the ending address, and the third
    /// specifies the overall number of locals.
    LocalInterval(u16, u16, u16),
    /// Prints out the top n items of the advice stack for the current context.
    ///
    /// If `n = 0`, the entire stack is printed.
    AdvStackTop(u16),
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
            Self::LocalInterval(start, end, _) => {
                write!(f, "local.{start}.{end}")
            },
            Self::AdvStackTop(n) => write!(f, "adv_stack.{n}"),
        }
    }
}
