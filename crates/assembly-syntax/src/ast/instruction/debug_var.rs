use alloc::{format, string::ToString, sync::Arc, vec::Vec};
use core::{fmt, num::NonZeroU32};

use miden_core::serde::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, read_bounded_len,
};
use miden_debug_types::Location;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

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

/// A location expression in Miden runtime coordinates.
///
/// This is the package-level escape hatch for locations which cannot be represented by one of the
/// simple [`DebugVarLocation`] variants. Producers must resolve source-specific coordinates, such
/// as Wasm local/global indices, before constructing this expression.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct DebugLocationExpression {
    operations: Vec<DebugLocationExpressionOp>,
}

/// Error returned when a structured debug location expression exceeds the wire-format limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error(
    "debug location expression has {operation_count} operations, but at most {MAX_DEBUG_LOCATION_EXPRESSION_OPS} are supported"
)]
pub struct DebugLocationExpressionError {
    operation_count: usize,
}

impl DebugLocationExpressionError {
    /// Returns the rejected operation count.
    pub fn operation_count(&self) -> usize {
        self.operation_count
    }
}

#[cfg(feature = "serde")]
#[derive(Deserialize)]
struct DebugLocationExpressionSerde {
    #[serde(deserialize_with = "deserialize_debug_location_expression_operations")]
    operations: Vec<DebugLocationExpressionOp>,
}

#[cfg(feature = "serde")]
fn deserialize_debug_location_expression_operations<'de, D>(
    deserializer: D,
) -> Result<Vec<DebugLocationExpressionOp>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct OperationsVisitor;

    impl<'de> serde::de::Visitor<'de> for OperationsVisitor {
        type Value = Vec<DebugLocationExpressionOp>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_DEBUG_LOCATION_EXPRESSION_OPS} debug location operations"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            if let Some(operation_count) = sequence.size_hint()
                && operation_count > MAX_DEBUG_LOCATION_EXPRESSION_OPS
            {
                return Err(serde::de::Error::custom(DebugLocationExpressionError {
                    operation_count,
                }));
            }

            let mut operations = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(8));
            while let Some(operation) = sequence.next_element()? {
                if operations.len() == MAX_DEBUG_LOCATION_EXPRESSION_OPS {
                    return Err(serde::de::Error::custom(DebugLocationExpressionError {
                        operation_count: operations.len() + 1,
                    }));
                }
                operations.push(operation);
            }
            Ok(operations)
        }
    }

    deserializer.deserialize_seq(OperationsVisitor)
}

const MAX_DEBUG_LOCATION_EXPRESSION_OPS: usize = 256;

impl DebugLocationExpression {
    /// Creates a location expression from runtime-resolved operations.
    ///
    /// # Errors
    ///
    /// Returns an error when the expression exceeds the maximum operation count accepted by the
    /// package wire format.
    pub fn new(
        operations: Vec<DebugLocationExpressionOp>,
    ) -> Result<Self, DebugLocationExpressionError> {
        validate_debug_location_expression_len(operations.len())?;
        Ok(Self { operations })
    }

    /// Returns the operations in evaluation order.
    pub fn operations(&self) -> &[DebugLocationExpressionOp] {
        &self.operations
    }

    /// Returns true if this expression contains no operations.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for DebugLocationExpression {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let expression = DebugLocationExpressionSerde::deserialize(deserializer)?;
        Self::new(expression.operations).map_err(serde::de::Error::custom)
    }
}

/// An operation in a [`DebugLocationExpression`].
///
/// Operations evaluate on a signed integer stack. Read operations push canonical field element
/// values as integers, arithmetic operations transform those values, and the final integer is
/// converted back to a field element. Invalid arithmetic or field conversions make the location
/// unavailable rather than wrapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DebugLocationExpressionOp {
    /// Push the value at this Miden operand-stack position (0 is the top).
    ReadStack(u8),
    /// Push the value stored at this Miden memory element address.
    ReadMemory(u32),
    /// Push the value stored at this signed FMP-relative local offset.
    ReadLocal(i16),
    /// Push an unsigned integer constant.
    ConstU64(u64),
    /// Push a signed integer constant.
    ConstI64(i64),
    /// Add an unsigned integer constant to the top value.
    AddUnsigned(u64),
    /// Pop two values and push `lhs + rhs`.
    Add,
    /// Pop two values and push `lhs - rhs`.
    Sub,
    /// Interpret the top value as a Wasm byte address, convert it to a Miden element address, and
    /// push the value stored at that address.
    DerefBytes,
    /// Resolve and push a byte address relative to a runtime frame base.
    FrameBaseAddress {
        /// Resolved location containing the frame-base byte address.
        base: DebugFrameBase,
        /// Byte offset from the base.
        byte_offset: i64,
    },
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
    /// A compound location expressed entirely in Miden runtime coordinates.
    Expression(DebugLocationExpression),
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
            Self::Expression(expression) => {
                f.write_str("expr(")?;
                f.debug_list().entries(expression.operations()).finish()?;
                f.write_str(")")
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
                write_debug_frame_base(*base, target);
                target.write_bytes(&byte_offset.to_le_bytes());
            },
            Self::Expression(expression) => {
                target.write_u8(6);
                expression.write_into(target);
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
                let base = read_debug_frame_base(source)?;
                let bytes = source.read_array::<8>()?;
                let byte_offset = i64::from_le_bytes(bytes);
                Ok(Self::ResolvedFrameBase { base, byte_offset })
            },
            6 => Ok(Self::Expression(DebugLocationExpression::read_from(source)?)),
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

impl Serializable for DebugLocationExpression {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.operations.len());
        for operation in &self.operations {
            operation.write_into(target);
        }
    }
}

impl Deserializable for DebugLocationExpression {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let count = read_bounded_len(source, "debug location expression operations", 1)?;
        validate_debug_location_expression_len(count)
            .map_err(|error| DeserializationError::InvalidValue(error.to_string()))?;
        let mut operations = Vec::with_capacity(count.min(8));
        for _ in 0..count {
            operations.push(DebugLocationExpressionOp::read_from(source)?);
        }
        Ok(Self { operations })
    }

    fn min_serialized_size() -> usize {
        usize::min_serialized_size()
    }
}

fn validate_debug_location_expression_len(
    operation_count: usize,
) -> Result<(), DebugLocationExpressionError> {
    if operation_count > MAX_DEBUG_LOCATION_EXPRESSION_OPS {
        return Err(DebugLocationExpressionError { operation_count });
    }
    Ok(())
}

impl Serializable for DebugLocationExpressionOp {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::ReadStack(position) => {
                target.write_u8(0);
                target.write_u8(*position);
            },
            Self::ReadMemory(address) => {
                target.write_u8(1);
                target.write_u32(*address);
            },
            Self::ReadLocal(offset) => {
                target.write_u8(2);
                target.write_bytes(&offset.to_le_bytes());
            },
            Self::ConstU64(value) => {
                target.write_u8(3);
                target.write_u64(*value);
            },
            Self::ConstI64(value) => {
                target.write_u8(4);
                target.write_bytes(&value.to_le_bytes());
            },
            Self::AddUnsigned(value) => {
                target.write_u8(5);
                target.write_u64(*value);
            },
            Self::Add => target.write_u8(6),
            Self::Sub => target.write_u8(7),
            Self::DerefBytes => target.write_u8(8),
            Self::FrameBaseAddress { base, byte_offset } => {
                target.write_u8(9);
                write_debug_frame_base(*base, target);
                target.write_bytes(&byte_offset.to_le_bytes());
            },
        }
    }
}

impl Deserializable for DebugLocationExpressionOp {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            0 => Ok(Self::ReadStack(source.read_u8()?)),
            1 => Ok(Self::ReadMemory(source.read_u32()?)),
            2 => Ok(Self::ReadLocal(i16::from_le_bytes(source.read_array::<2>()?))),
            3 => Ok(Self::ConstU64(source.read_u64()?)),
            4 => Ok(Self::ConstI64(i64::from_le_bytes(source.read_array::<8>()?))),
            5 => Ok(Self::AddUnsigned(source.read_u64()?)),
            6 => Ok(Self::Add),
            7 => Ok(Self::Sub),
            8 => Ok(Self::DerefBytes),
            9 => {
                let base = read_debug_frame_base(source)?;
                let byte_offset = i64::from_le_bytes(source.read_array::<8>()?);
                Ok(Self::FrameBaseAddress { base, byte_offset })
            },
            tag => Err(DeserializationError::InvalidValue(format!(
                "invalid DebugLocationExpressionOp tag: {tag}"
            ))),
        }
    }

    fn min_serialized_size() -> usize {
        u8::min_serialized_size()
    }
}

fn write_debug_frame_base<W: ByteWriter>(base: DebugFrameBase, target: &mut W) {
    match base {
        DebugFrameBase::Local(offset) => {
            target.write_u8(0);
            target.write_bytes(&offset.to_le_bytes());
        },
        DebugFrameBase::Memory(address) => {
            target.write_u8(1);
            target.write_u32(address);
        },
    }
}

fn read_debug_frame_base<R: ByteReader>(
    source: &mut R,
) -> Result<DebugFrameBase, DeserializationError> {
    match source.read_u8()? {
        0 => Ok(DebugFrameBase::Local(i16::from_le_bytes(source.read_array::<2>()?))),
        1 => Ok(DebugFrameBase::Memory(source.read_u32()?)),
        tag => Err(DeserializationError::InvalidValue(format!(
            "invalid resolved debug frame-base tag: {tag}"
        ))),
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
        assert_eq!(
            DebugVarLocation::Expression(
                DebugLocationExpression::new(vec![
                    DebugLocationExpressionOp::FrameBaseAddress {
                        base: DebugFrameBase::Local(-2),
                        byte_offset: 4,
                    },
                    DebugLocationExpressionOp::AddUnsigned(8),
                    DebugLocationExpressionOp::DerefBytes,
                ])
                .unwrap(),
            )
            .to_string(),
            "expr([FrameBaseAddress { base: Local(-2), byte_offset: 4 }, AddUnsigned(8), DerefBytes])"
        );
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
            DebugVarLocation::Expression(
                DebugLocationExpression::new(vec![
                    DebugLocationExpressionOp::ReadStack(2),
                    DebugLocationExpressionOp::ConstI64(-4),
                    DebugLocationExpressionOp::Add,
                    DebugLocationExpressionOp::DerefBytes,
                ])
                .unwrap(),
            ),
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
    fn debug_location_expression_wire_encoding_is_stable() {
        let expression = DebugLocationExpression::new(vec![
            DebugLocationExpressionOp::ReadStack(0x2a),
            DebugLocationExpressionOp::ReadMemory(0x1234_5678),
            DebugLocationExpressionOp::ReadLocal(-2),
            DebugLocationExpressionOp::ConstU64(0x0102_0304_0506_0708),
            DebugLocationExpressionOp::ConstI64(-2),
            DebugLocationExpressionOp::AddUnsigned(0x1112_1314_1516_1718),
            DebugLocationExpressionOp::Add,
            DebugLocationExpressionOp::Sub,
            DebugLocationExpressionOp::DerefBytes,
            DebugLocationExpressionOp::FrameBaseAddress {
                base: DebugFrameBase::Local(-4),
                byte_offset: 0x0102_0304_0506_0708,
            },
            DebugLocationExpressionOp::FrameBaseAddress {
                base: DebugFrameBase::Memory(0xa1b2_c3d4),
                byte_offset: -3,
            },
        ])
        .unwrap();
        let expected = vec![
            0x17, 0x00, 0x2a, 0x01, 0x78, 0x56, 0x34, 0x12, 0x02, 0xfe, 0xff, 0x03, 0x08, 0x07,
            0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x04, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x05, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x06, 0x07, 0x08, 0x09,
            0x00, 0xfc, 0xff, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x09, 0x01, 0xd4,
            0xc3, 0xb2, 0xa1, 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        let mut bytes = Vec::new();
        expression.write_into(&mut bytes);
        assert_eq!(bytes, expected);

        let mut reader = SliceReader::new(&expected);
        assert_eq!(DebugLocationExpression::read_from(&mut reader).unwrap(), expression);
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
    fn debug_location_expression_rejects_unknown_operation() {
        let mut bytes = Vec::new();
        bytes.write_usize(1);
        bytes.write_u8(u8::MAX);

        let mut reader = SliceReader::new(&bytes);
        let err = DebugLocationExpression::read_from(&mut reader).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("invalid DebugLocationExpressionOp tag"));
    }

    #[test]
    fn debug_location_expression_caps_operation_count_before_allocation() {
        let count = MAX_DEBUG_LOCATION_EXPRESSION_OPS + 1;
        let mut bytes = Vec::new();
        bytes.write_usize(count);
        bytes.resize(bytes.len() + count, 0);

        let mut reader = SliceReader::new(&bytes);
        let err = DebugLocationExpression::read_from(&mut reader).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("at most 256"));
    }

    #[test]
    fn debug_location_expression_constructor_rejects_oversized_input() {
        let operations =
            vec![DebugLocationExpressionOp::Add; MAX_DEBUG_LOCATION_EXPRESSION_OPS + 1];
        let error = DebugLocationExpression::new(operations).unwrap_err();

        assert_eq!(error.operation_count(), MAX_DEBUG_LOCATION_EXPRESSION_OPS + 1);
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

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trips_location_expressions() {
        let expression = DebugLocationExpression::new(vec![
            DebugLocationExpressionOp::ReadLocal(-2),
            DebugLocationExpressionOp::DerefBytes,
        ])
        .unwrap();
        let json = serde_json::to_string(&expression).unwrap();

        assert_eq!(serde_json::from_str::<DebugLocationExpression>(&json).unwrap(), expression);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_oversized_location_expressions() {
        let expression = DebugLocationExpression {
            operations: vec![DebugLocationExpressionOp::Add; MAX_DEBUG_LOCATION_EXPRESSION_OPS + 1],
        };
        let json = serde_json::to_string(&expression).unwrap();
        let error = serde_json::from_str::<DebugLocationExpression>(&json).unwrap_err();

        assert!(error.to_string().contains("at most 256"));
    }
}
