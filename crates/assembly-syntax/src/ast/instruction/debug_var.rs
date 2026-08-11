use alloc::{format, sync::Arc};
use core::{fmt, num::NonZeroU32};

use miden_core::serde::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
use miden_debug_types::Location;

use crate::{
    Felt,
    ast::{TypeExpr, types::Type},
};

// DEBUG VARIABLE INFO
// ================================================================================================

/// Debug information for tracking a source-level variable.
///
/// This record provides debuggers with information about where a variable's
/// value can be found at a particular point in the program execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebugVarInfo {
    /// Variable name as it appears in source code.
    name: Arc<str>,
    /// The low-level structural type of this variable
    ty: Option<Type>,
    /// A type expression corresponding to how `type` was declared in the source code
    declared_type: Option<Arc<TypeExpr>>,
    /// If this is a function parameter, its 1-based index.
    arg_index: Option<NonZeroU32>,
    /// Source location.
    /// This should only be set when the location differs from the AssemblyOp location associated
    /// with the same instruction, to avoid package bloat.
    location: Option<Location>,
    /// Where to find the variable's value at this point
    value_location: DebugVarLocation,
}

impl DebugVarInfo {
    /// Creates a new [DebugVarInfo] with the specified variable name and location.
    pub fn new(name: impl Into<Arc<str>>, value_location: DebugVarLocation) -> Self {
        Self {
            name: name.into(),
            ty: None,
            declared_type: None,
            arg_index: None,
            location: None,
            value_location,
        }
    }

    /// Returns the variable name.
    pub fn name(&self) -> &Arc<str> {
        &self.name
    }

    /// Returns the type ID if set.
    pub fn ty(&self) -> Option<&Type> {
        self.ty.as_ref()
    }

    /// Returns the type ID if set.
    pub fn declared_type(&self) -> Option<Arc<TypeExpr>> {
        self.declared_type.clone()
    }

    /// Sets the type ID for this variable.
    pub fn set_ty(&mut self, ty: Type, declared_type: Option<Arc<TypeExpr>>) {
        self.ty = Some(ty);
        self.declared_type = declared_type;
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
    /// This is only set when the location differs from the AssemblyOp location.
    pub fn location(&self) -> Option<&Location> {
        self.location.as_ref()
    }

    /// Sets the source location for this variable.
    /// Only set this when the location differs from the AssemblyOp location
    /// to avoid package bloat.
    pub fn set_location(&mut self, location: Location) {
        self.location = Some(location);
    }

    /// Returns where the variable's value can be found.
    pub fn value_location(&self) -> &DebugVarLocation {
        &self.value_location
    }

    /// Replaces the value location in-place, preserving all other fields.
    pub fn set_value_location(&mut self, value_location: DebugVarLocation) {
        self.value_location = value_location;
    }
}

impl fmt::Display for DebugVarInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "var.{}", self.name)?;

        if let Some(arg_index) = self.arg_index {
            write!(f, "[arg{arg_index}]")?;
        }

        write!(f, " = {}", self.value_location)?;

        if let Some(loc) = &self.location {
            write!(f, " [{}@{}..{}]", loc.uri, loc.start, loc.end)?;
        }

        Ok(())
    }
}

// DEBUG VARIABLE LOCATION
// ================================================================================================

/// A frame base resolved into Miden execution coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DebugFrameBase {
    /// The base value is stored in local memory at this signed FMP-relative offset.
    Local(i16),
    /// The base value is stored at this Miden memory element address.
    Memory(u32),
}

/// Describes where a variable's value can be found during execution.
///
/// This enum models the different ways a variable's value might be stored
/// during program execution, ranging from simple stack positions to complex
/// expressions.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    /// For example, with 3 locals: local\[0\] has offset -3, local\[2\] has offset -1.
    Local(i16),
    /// The variable has no representable location at this program point.
    Unavailable,
    /// Variable is in Wasm linear memory at `value_of(base) + byte_offset`.
    ///
    /// The base is expressed entirely in Miden execution coordinates. Its runtime value and the
    /// offset are byte addresses; the debugger converts the resulting address to a Miden memory
    /// element address before reading the variable.
    ResolvedFrameBase {
        /// Resolved location containing the frame-base byte address.
        base: DebugFrameBase,
        /// Byte offset from the base (may be positive or negative).
        byte_offset: i64,
    },
}

impl fmt::Display for DebugVarLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stack(pos) => write!(f, "stack[{pos}]"),
            Self::Memory(addr) => write!(f, "mem[{addr}]"),
            Self::Const(val) => write!(f, "const({})", val.as_canonical_u64()),
            Self::Local(offset) => write!(f, "FMP{offset:+}"),
            Self::Unavailable => f.write_str("unavailable"),
            Self::ResolvedFrameBase { base, byte_offset } => match base {
                DebugFrameBase::Local(offset) => {
                    write!(f, "frame-base(FMP{offset:+}){byte_offset:+}")
                },
                DebugFrameBase::Memory(address) => {
                    write!(f, "frame-base(mem[{address}]){byte_offset:+}")
                },
            },
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for DebugVarLocation {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Stack(pos) => {
                target.write_u8(0);
                target.write_u8(*pos);
            },
            Self::Memory(addr) => {
                target.write_u8(1);
                target.write_u32(*addr);
            },
            Self::Const(felt) => {
                target.write_u8(2);
                target.write_u64(felt.as_canonical_u64());
            },
            Self::Local(offset) => {
                target.write_u8(3);
                target.write_bytes(&offset.to_le_bytes());
            },
            Self::Unavailable => {
                target.write_u8(4);
            },
            Self::ResolvedFrameBase { base, byte_offset } => {
                target.write_u8(5);
                match base {
                    DebugFrameBase::Local(offset) => {
                        target.write_u8(0);
                        target.write_bytes(&offset.to_le_bytes());
                    },
                    DebugFrameBase::Memory(address) => {
                        target.write_u8(1);
                        target.write_u32(*address);
                    },
                }
                target.write_bytes(&byte_offset.to_le_bytes());
            },
        }
    }
}

impl Deserializable for DebugVarLocation {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let tag = source.read_u8()?;
        match tag {
            0 => Ok(Self::Stack(source.read_u8()?)),
            1 => Ok(Self::Memory(source.read_u32()?)),
            2 => {
                let value = source.read_u64()?;
                Ok(Self::Const(Felt::new_unchecked(value)))
            },
            3 => {
                let bytes = source.read_array::<2>()?;
                Ok(Self::Local(i16::from_le_bytes(bytes)))
            },
            4 => Ok(Self::Unavailable),
            5 => {
                let base = match source.read_u8()? {
                    0 => {
                        let bytes = source.read_array::<2>()?;
                        DebugFrameBase::Local(i16::from_le_bytes(bytes))
                    },
                    1 => DebugFrameBase::Memory(source.read_u32()?),
                    tag => {
                        return Err(DeserializationError::InvalidValue(format!(
                            "invalid resolved debug frame-base tag: {tag}"
                        )));
                    },
                };
                let bytes = source.read_array::<8>()?;
                let byte_offset = i64::from_le_bytes(bytes);
                Ok(Self::ResolvedFrameBase { base, byte_offset })
            },
            _ => Err(DeserializationError::InvalidValue(format!(
                "invalid DebugVarLocation tag: {tag}"
            ))),
        }
    }

    fn min_serialized_size() -> usize {
        // `Unavailable` is encoded as a one-byte tag with no payload.
        u8::min_serialized_size()
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use miden_core::serde::{Deserializable, Serializable, SliceReader};
    use miden_debug_types::{ByteIndex, Uri};

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
        var.set_location(Location::new(
            Uri::new("test.rs"),
            ByteIndex::from(0u32),
            ByteIndex::from(5u32),
        ));
        assert_eq!(var.to_string(), "var.y = mem[100] [test.rs@0..5]");
    }

    #[test]
    fn debug_var_location_display() {
        assert_eq!(DebugVarLocation::Stack(0).to_string(), "stack[0]");
        assert_eq!(DebugVarLocation::Memory(256).to_string(), "mem[256]");
        assert_eq!(DebugVarLocation::Const(Felt::new_unchecked(42)).to_string(), "const(42)");
        assert_eq!(DebugVarLocation::Local(-3).to_string(), "FMP-3");
        assert_eq!(
            DebugVarLocation::ResolvedFrameBase {
                base: DebugFrameBase::Local(-3),
                byte_offset: 12,
            }
            .to_string(),
            "frame-base(FMP-3)+12"
        );
        assert_eq!(DebugVarLocation::Unavailable.to_string(), "unavailable");
    }

    #[test]
    fn debug_var_location_serialization_round_trip() {
        let locations = [
            DebugVarLocation::Stack(7),
            DebugVarLocation::Memory(0xdead_beef),
            DebugVarLocation::Const(Felt::new_unchecked(999)),
            DebugVarLocation::Local(-3),
            DebugVarLocation::Unavailable,
            DebugVarLocation::ResolvedFrameBase {
                base: DebugFrameBase::Local(-3),
                byte_offset: 28,
            },
            DebugVarLocation::ResolvedFrameBase {
                base: DebugFrameBase::Memory(100),
                byte_offset: -16,
            },
        ];

        for loc in &locations {
            let mut bytes = Vec::new();
            loc.write_into(&mut bytes);
            let mut reader = SliceReader::new(&bytes);
            let deser = DebugVarLocation::read_from(&mut reader).unwrap();
            assert_eq!(&deser, loc);
        }
    }

    #[test]
    fn debug_var_location_min_serialized_size_matches_shortest_variant() {
        let location = DebugVarLocation::Unavailable;
        let min_serialized_size = DebugVarLocation::min_serialized_size();
        let mut bytes = Vec::new();
        location.write_into(&mut bytes);

        assert_eq!(min_serialized_size, 1);
        assert_eq!(bytes.len(), min_serialized_size);
    }

    #[test]
    fn debug_var_info_set_value_location() {
        let mut var = DebugVarInfo::new("x", DebugVarLocation::Stack(0));
        var.set_value_location(DebugVarLocation::ResolvedFrameBase {
            base: DebugFrameBase::Local(-2),
            byte_offset: 12,
        });
        assert_eq!(
            var.value_location(),
            &DebugVarLocation::ResolvedFrameBase {
                base: DebugFrameBase::Local(-2),
                byte_offset: 12,
            }
        );
    }
}
