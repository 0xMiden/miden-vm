//! AssemblyOp serialization support.
//!
//! This module provides serialization/deserialization for [`AssemblyOp`] data that is stored
//! separately in [`DebugInfo`](crate::mast::debuginfo::DebugInfo). The format uses:
//!
//! - A variable-length data blob for AssemblyOp payloads (num_cycles, should_break, location, etc.)
//! - A string table for deduplicating context names, op strings, and URIs
//! - Fixed-width info records that index into the data blob
//!
//! This mirrors the pattern used for decorator serialization in [`super::decorator`].

use alloc::vec::Vec;

use miden_debug_types::{ByteIndex, Location, Uri};

use super::string_table::{StringTable, StringTableBuilder};
use crate::{
    operations::AssemblyOp,
    utils::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
    },
};

/// Offset into the asm_op_data blob.
pub type AsmOpDataOffset = u32;

// ASM OP INFO
// ================================================================================================

/// Fixed-width serialized representation of an [`AssemblyOp`].
///
/// Each `AsmOpInfo` stores an offset into the variable-length data blob where the AssemblyOp's
/// payload is stored. The payload format is:
///
/// ```text
/// num_cycles: u8
/// should_break: u8 (0 or 1)
/// has_location: u8 (0 or 1)
/// [if has_location]:
///     uri_idx: usize (index into string table)
///     start: u32
///     end: u32
/// context_name_idx: usize (index into string table)
/// op_idx: usize (index into string table)
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct AsmOpInfo {
    data_offset: AsmOpDataOffset,
}

impl AsmOpInfo {
    /// Creates a new `AsmOpInfo` with the given data offset.
    pub fn new(data_offset: AsmOpDataOffset) -> Self {
        Self { data_offset }
    }

    /// Reconstructs an [`AssemblyOp`] from the serialized data.
    pub fn try_into_asm_op(
        &self,
        string_table: &StringTable,
        asm_op_data: &[u8],
    ) -> Result<AssemblyOp, DeserializationError> {
        if self.data_offset as usize >= asm_op_data.len() {
            return Err(DeserializationError::InvalidValue(
                "AsmOpInfo data_offset out of bounds".into(),
            ));
        }

        let mut reader = SliceReader::new(&asm_op_data[self.data_offset as usize..]);

        let num_cycles = reader.read_u8()?;
        let should_break = reader.read_bool()?;

        let location = if reader.read_bool()? {
            let uri_idx = reader.read_usize()?;
            let uri = string_table.read_arc_str(uri_idx).map(Uri::from)?;
            let start = reader.read_u32()?;
            let end = reader.read_u32()?;
            Some(Location::new(uri, ByteIndex::new(start), ByteIndex::new(end)))
        } else {
            None
        };

        let context_name_idx = reader.read_usize()?;
        let context_name = string_table.read_string(context_name_idx)?;

        let op_idx = reader.read_usize()?;
        let op = string_table.read_string(op_idx)?;

        Ok(AssemblyOp::new(location, context_name, num_cycles, op, should_break))
    }
}

impl Serializable for AsmOpInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.data_offset.write_into(target);
    }
}

impl Deserializable for AsmOpInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let data_offset = source.read()?;
        Ok(Self { data_offset })
    }
}

// ASM OP DATA BUILDER
// ================================================================================================

/// Builder for serializing [`AssemblyOp`] data.
///
/// This builder collects AssemblyOps and produces:
/// - A variable-length data blob with all AssemblyOp payloads
/// - A string table for deduplicating strings
/// - A list of [`AsmOpInfo`] records for deserialization
#[derive(Debug, Default)]
pub struct AsmOpDataBuilder {
    /// Raw data blob for AssemblyOp payloads.
    asm_op_data: Vec<u8>,
    /// Info records for each AssemblyOp.
    asm_op_infos: Vec<AsmOpInfo>,
    /// String table builder for deduplicating strings.
    string_table_builder: StringTableBuilder,
}

impl AsmOpDataBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an AssemblyOp to the builder.
    ///
    /// Returns the index of the AssemblyOp in the infos list.
    pub fn add_asm_op(&mut self, asm_op: &AssemblyOp) -> usize {
        use crate::utils::{ByteWriter, Serializable};

        let data_offset = self.asm_op_data.len() as AsmOpDataOffset;

        // Serialize num_cycles (u8)
        self.asm_op_data.write_u8(asm_op.num_cycles());

        // Serialize should_break (bool)
        self.asm_op_data.write_bool(asm_op.should_break());

        // Serialize location
        if let Some(location) = asm_op.location() {
            self.asm_op_data.write_bool(true); // has_location = true
            let uri_idx = self.string_table_builder.add_string(location.uri.as_str());
            uri_idx.write_into(&mut self.asm_op_data);
            self.asm_op_data.write_u32(location.start.to_u32());
            self.asm_op_data.write_u32(location.end.to_u32());
        } else {
            self.asm_op_data.write_bool(false); // has_location = false
        }

        // Serialize context_name
        let context_name_idx = self.string_table_builder.add_string(asm_op.context_name());
        context_name_idx.write_into(&mut self.asm_op_data);

        // Serialize op
        let op_idx = self.string_table_builder.add_string(asm_op.op());
        op_idx.write_into(&mut self.asm_op_data);

        let idx = self.asm_op_infos.len();
        self.asm_op_infos.push(AsmOpInfo::new(data_offset));
        idx
    }

    /// Finalizes the builder and returns the serialized components.
    ///
    /// Returns a tuple of:
    /// - The raw data blob
    /// - The list of AsmOpInfo records
    /// - The string table
    pub fn finalize(self) -> (Vec<u8>, Vec<AsmOpInfo>, StringTable) {
        (self.asm_op_data, self.asm_op_infos, self.string_table_builder.into_table())
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn test_asm_op_roundtrip_no_location() {
        let asm_op = AssemblyOp::new(None, "test_context".to_string(), 5, "add".to_string(), false);

        let mut builder = AsmOpDataBuilder::new();
        builder.add_asm_op(&asm_op);

        let (data, infos, string_table) = builder.finalize();

        assert_eq!(infos.len(), 1);
        let restored = infos[0].try_into_asm_op(&string_table, &data).unwrap();

        assert_eq!(restored.location(), None);
        assert_eq!(restored.context_name(), "test_context");
        assert_eq!(restored.op(), "add");
        assert_eq!(restored.num_cycles(), 5);
        assert!(!restored.should_break());
    }

    #[test]
    fn test_asm_op_roundtrip_with_location() {
        let location =
            Location::new(Uri::new("test://file.masm"), ByteIndex::new(10), ByteIndex::new(20));
        let asm_op = AssemblyOp::new(
            Some(location.clone()),
            "my_proc".to_string(),
            3,
            "mul".to_string(),
            true,
        );

        let mut builder = AsmOpDataBuilder::new();
        builder.add_asm_op(&asm_op);

        let (data, infos, string_table) = builder.finalize();

        let restored = infos[0].try_into_asm_op(&string_table, &data).unwrap();

        let restored_loc = restored.location().expect("should have location");
        assert_eq!(restored_loc.uri.as_str(), "test://file.masm");
        assert_eq!(restored_loc.start.to_u32(), 10);
        assert_eq!(restored_loc.end.to_u32(), 20);
        assert_eq!(restored.context_name(), "my_proc");
        assert_eq!(restored.op(), "mul");
        assert_eq!(restored.num_cycles(), 3);
        assert!(restored.should_break());
    }

    #[test]
    fn test_asm_op_string_deduplication() {
        // Add multiple asm_ops with the same context name to verify string deduplication
        let asm_op1 =
            AssemblyOp::new(None, "shared_context".to_string(), 1, "op1".to_string(), false);
        let asm_op2 =
            AssemblyOp::new(None, "shared_context".to_string(), 2, "op2".to_string(), false);
        let asm_op3 =
            AssemblyOp::new(None, "shared_context".to_string(), 3, "op1".to_string(), false);

        let mut builder = AsmOpDataBuilder::new();
        builder.add_asm_op(&asm_op1);
        builder.add_asm_op(&asm_op2);
        builder.add_asm_op(&asm_op3);

        let (data, infos, string_table) = builder.finalize();

        assert_eq!(infos.len(), 3);

        // Verify all restore correctly
        for (i, (info, original)) in infos.iter().zip([&asm_op1, &asm_op2, &asm_op3]).enumerate() {
            let restored = info.try_into_asm_op(&string_table, &data).unwrap();
            assert_eq!(restored.context_name(), original.context_name(), "asm_op {}", i);
            assert_eq!(restored.op(), original.op(), "asm_op {}", i);
            assert_eq!(restored.num_cycles(), original.num_cycles(), "asm_op {}", i);
        }
    }

    #[test]
    fn test_asm_op_info_serialization() {
        let info = AsmOpInfo::new(42);

        let mut bytes = Vec::new();
        info.write_into(&mut bytes);

        let mut reader = SliceReader::new(&bytes);
        let restored = AsmOpInfo::read_from(&mut reader).unwrap();

        assert_eq!(info, restored);
    }

    #[test]
    fn test_empty_builder() {
        let builder = AsmOpDataBuilder::new();
        let (data, infos, _string_table) = builder.finalize();

        assert!(data.is_empty());
        assert!(infos.is_empty());
    }
}
