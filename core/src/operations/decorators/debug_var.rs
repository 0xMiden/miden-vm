use alloc::{string::String, vec::Vec};
use core::fmt;

use miden_debug_types::FileLineCol;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// DEBUG VARIABLE INFO
// ================================================================================================

/// Debug information for tracking a source-level variable.
///
/// This decorator provides debuggers with information about where a variable's
/// value can be found at a particular point in the program execution.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct DebugVarInfo {
    /// Variable name as it appears in source code
    name: String,
    /// Type information (encoded as type index in debug_info section)
    type_id: Option<u32>,
    /// If this is a function parameter, its 1-based index
    arg_index: Option<u32>,
    /// Source file location (file:line:column)
    location: Option<FileLineCol>,
    /// Where to find the variable's value at this point
    value_location: DebugVarLocation,
}

impl DebugVarInfo {
    /// Creates a new [DebugVarInfo] with the specified variable name and location.
    pub fn new(name: String, value_location: DebugVarLocation) -> Self {
        Self {
            name,
            type_id: None,
            arg_index: None,
            location: None,
            value_location,
        }
    }

    /// Returns the variable name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the type ID if set.
    pub fn type_id(&self) -> Option<u32> {
        self.type_id
    }

    /// Sets the type ID for this variable.
    pub fn set_type_id(&mut self, type_id: u32) {
        self.type_id = Some(type_id);
    }

    /// Returns the argument index if this is a function parameter.
    pub fn arg_index(&self) -> Option<u32> {
        self.arg_index
    }

    /// Sets the argument index for this variable.
    pub fn set_arg_index(&mut self, arg_index: u32) {
        self.arg_index = Some(arg_index);
    }

    /// Returns the source location if set.
    pub fn location(&self) -> Option<&FileLineCol> {
        self.location.as_ref()
    }

    /// Sets the source location for this variable.
    pub fn set_location(&mut self, location: FileLineCol) {
        self.location = Some(location);
    }

    /// Returns where the variable's value can be found.
    pub fn value_location(&self) -> &DebugVarLocation {
        &self.value_location
    }
}

impl fmt::Display for DebugVarInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "var.{}", self.name)?;

        if let Some(arg_index) = self.arg_index {
            write!(f, "[arg{}]", arg_index)?;
        }

        write!(f, " = {}", self.value_location)?;

        if let Some(loc) = &self.location {
            write!(f, " {}", loc)?;
        }

        Ok(())
    }
}

// DEBUG VARIABLE LOCATION
// ================================================================================================

/// Describes where a variable's value can be found during execution.
///
/// This enum models the different ways a variable's value might be stored
/// during program execution, ranging from simple stack positions to complex
/// expressions.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub enum DebugVarLocation {
    /// Variable is at stack position N (0 = top of stack)
    Stack(u8),
    /// Variable is in memory at the given word address
    Memory(u32),
    /// Variable is a constant field element
    Const(u64),
    /// Variable is in a local slot at the given index
    Local(u16),
    /// Complex location described by expression bytes.
    /// This is used for variables that require computation to locate,
    /// such as struct fields or array elements.
    Expression(Vec<u8>),
}

impl fmt::Display for DebugVarLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stack(pos) => write!(f, "stack[{}]", pos),
            Self::Memory(addr) => write!(f, "mem[{}]", addr),
            Self::Const(val) => write!(f, "const({})", val),
            Self::Local(idx) => write!(f, "local[{}]", idx),
            Self::Expression(bytes) => {
                write!(f, "expr(")?;
                for (i, byte) in bytes.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{:02x}", byte)?;
                }
                write!(f, ")")
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use miden_debug_types::{ColumnNumber, LineNumber, Uri};

    #[test]
    fn debug_var_info_display_simple() {
        let var = DebugVarInfo::new("x".into(), DebugVarLocation::Stack(0));
        assert_eq!(var.to_string(), "var.x = stack[0]");
    }

    #[test]
    fn debug_var_info_display_with_arg() {
        let mut var = DebugVarInfo::new("param".into(), DebugVarLocation::Stack(2));
        var.set_arg_index(1);
        assert_eq!(var.to_string(), "var.param[arg1] = stack[2]");
    }

    #[test]
    fn debug_var_info_display_with_location() {
        let mut var = DebugVarInfo::new("y".into(), DebugVarLocation::Memory(100));
        var.set_location(FileLineCol::new(
            Uri::new("test.rs"),
            LineNumber::new(42).unwrap(),
            ColumnNumber::new(5).unwrap(),
        ));
        assert_eq!(var.to_string(), "var.y = mem[100] [test.rs@42:5]");
    }

    #[test]
    fn debug_var_location_display() {
        assert_eq!(DebugVarLocation::Stack(0).to_string(), "stack[0]");
        assert_eq!(DebugVarLocation::Memory(256).to_string(), "mem[256]");
        assert_eq!(DebugVarLocation::Const(42).to_string(), "const(42)");
        assert_eq!(DebugVarLocation::Local(3).to_string(), "local[3]");
        assert_eq!(
            DebugVarLocation::Expression(vec![0x10, 0x20, 0x30]).to_string(),
            "expr(10 20 30)"
        );
    }
}
