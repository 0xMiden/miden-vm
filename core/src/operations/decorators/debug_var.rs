use alloc::{sync::Arc, vec::Vec};
use core::{fmt, num::NonZeroU32};

use miden_crypto::field::PrimeField64;
use miden_debug_types::FileLineCol;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::Felt;

// DEBUG VARIABLE INFO
// ================================================================================================

/// Debug information for tracking a source-level variable.
///
/// This decorator provides debuggers with information about where a variable's
/// value can be found at a particular point in the program execution.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugVarInfo {
    /// Variable name as it appears in source code.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_arc_str"))]
    name: Arc<str>,
    /// Type information (encoded as type index in debug_info section)
    type_id: Option<u32>,
    /// If this is a function parameter, its 1-based index.
    arg_index: Option<NonZeroU32>,
    /// Source file location (file:line:column).
    /// This should only be set when the location differs from the AssemblyOp decorator
    /// location associated with the same instruction, to avoid package bloat.
    location: Option<FileLineCol>,
    /// Where to find the variable's value at this point
    value_location: DebugVarLocation,
}

impl DebugVarInfo {
    /// Creates a new [DebugVarInfo] with the specified variable name and location.
    pub fn new(name: impl Into<Arc<str>>, value_location: DebugVarLocation) -> Self {
        Self {
            name: name.into(),
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
    /// The index is 1-based.
    pub fn arg_index(&self) -> Option<NonZeroU32> {
        self.arg_index
    }

    /// Sets the argument index for this variable.
    ///
    /// # Panics
    /// Panics if `arg_index` is 0, since argument indices are 1-based.
    pub fn set_arg_index(&mut self, arg_index: u32) {
        self.arg_index =
            Some(NonZeroU32::new(arg_index).expect("argument index must be 1-based (non-zero)"));
    }

    /// Returns the source location if set.
    /// This is only set when the location differs from the AssemblyOp decorator location.
    pub fn location(&self) -> Option<&FileLineCol> {
        self.location.as_ref()
    }

    /// Sets the source location for this variable.
    /// Only set this when the location differs from the AssemblyOp decorator location
    /// to avoid package bloat.
    pub fn set_location(&mut self, location: FileLineCol) {
        self.location = Some(location);
    }

    /// Returns where the variable's value can be found.
    pub fn value_location(&self) -> &DebugVarLocation {
        &self.value_location
    }
}

/// Serde deserializer for `Arc<str>`.
#[cfg(feature = "serde")]
fn deserialize_arc_str<'de, D>(deserializer: D) -> Result<Arc<str>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use alloc::string::String;
    let s = String::deserialize(deserializer)?;
    Ok(Arc::from(s))
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
pub enum DebugVarLocation {
    /// Variable is at stack position N (0 = top of stack)
    Stack(u8),
    /// Variable is in memory at the given element address
    Memory(u32),
    /// Variable is a constant field element
    Const(Felt),
    /// Variable is in local memory at a signed offset from FMP.
    ///
    /// The actual memory address is computed as: `FMP + offset`
    /// where offset is typically negative (locals are below FMP).
    /// For example, with 3 locals: local[0] has offset -3, local[2] has offset -1.
    Local(i16),
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
            Self::Const(val) => write!(f, "const({})", val.as_canonical_u64()),
            Self::Local(offset) => write!(f, "FMP{:+}", offset),
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

    use miden_debug_types::{ColumnNumber, LineNumber, Uri};

    use super::*;

    #[test]
    fn debug_var_info_display_simple() {
        let var = DebugVarInfo::new("x", DebugVarLocation::Stack(0));
        assert_eq!(var.to_string(), "var.x = stack[0]");
    }

    #[test]
    fn debug_var_info_display_with_arg() {
        let mut var = DebugVarInfo::new("param", DebugVarLocation::Stack(2));
        var.set_arg_index(1);
        assert_eq!(var.to_string(), "var.param[arg1] = stack[2]");
    }

    #[test]
    fn debug_var_info_display_with_location() {
        let mut var = DebugVarInfo::new("y", DebugVarLocation::Memory(100));
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
        assert_eq!(DebugVarLocation::Const(Felt::new(42)).to_string(), "const(42)");
        assert_eq!(DebugVarLocation::Local(-3).to_string(), "FMP-3");
        assert_eq!(
            DebugVarLocation::Expression(vec![0x10, 0x20, 0x30]).to_string(),
            "expr(10 20 30)"
        );
    }
}
