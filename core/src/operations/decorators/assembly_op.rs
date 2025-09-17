use alloc::string::String;
use core::fmt;

use miden_debug_types::Location;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// ASSEMBLY OP
// ================================================================================================

/// Contains information corresponding to an assembly instruction (only applicable in debug mode).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AssemblyOp {
    #[cfg_attr(feature = "serde", serde(default))]
    location: Option<Location>,
    context_name: String,
    op: String,
    num_cycles: u8,
    should_break: bool,
}

impl AssemblyOp {
    /// Returns [AssemblyOp] instantiated with the specified assembly instruction string and number
    /// of cycles it takes to execute the assembly instruction.
    pub fn new(
        location: Option<Location>,
        context_name: String,
        num_cycles: u8,
        op: String,
        should_break: bool,
    ) -> Self {
        Self {
            location,
            context_name,
            op,
            num_cycles,
            should_break,
        }
    }

    /// Returns the [Location] for this operation, if known
    pub fn location(&self) -> Option<&Location> {
        self.location.as_ref()
    }

    /// Returns the context name for this operation.
    pub fn context_name(&self) -> &str {
        &self.context_name
    }

    /// Returns the number of VM cycles taken to execute the assembly instruction of this decorator.
    pub const fn num_cycles(&self) -> u8 {
        self.num_cycles
    }

    /// Returns the assembly instruction corresponding to this decorator.
    pub fn op(&self) -> &str {
        &self.op
    }

    /// Returns `true` if there is a breakpoint for the current operation.
    pub const fn should_break(&self) -> bool {
        self.should_break
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Change cycles corresponding to an AsmOp decorator to the specified number of cycles.
    pub fn set_num_cycles(&mut self, num_cycles: u8) {
        self.num_cycles = num_cycles;
    }

    /// Change the [Location] of this [AssemblyOp]
    pub fn set_location(&mut self, location: Location) {
        self.location = Some(location);
    }
}

impl fmt::Display for AssemblyOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "context={}, operation={}, cost={}",
            self.context_name, self.op, self.num_cycles,
        )
    }
}
