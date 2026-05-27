//! Debug information management for MAST forests.
//!
//! This module provides the [`DebugInfo`] struct which consolidates all debug-related metadata for
//! a MAST forest in a single location. This includes:
//!
//! - Assembly operation source mappings
//! - Debug variable locations
//! - Error code mappings for descriptive error messages
//! - Procedure names
//!
//! Executable decorators have been removed. Assembly operation metadata remains available for
//! debugging and error reporting.
//!
//! # Production Builds
//!
//! The `DebugInfo` can be stripped for production builds using the [`clear()`](Self::clear) method,
//! which removes debug metadata while preserving executable structure.

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_debug_types::{FileLineCol, Location};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{AsmOpId, MastForestError, MastNodeId};
use crate::{
    Word,
    mast::serialization::{
        StringTable,
        asm_op::{AsmOpDataBuilder, AsmOpInfo},
        decorator::DecoratorInfo,
    },
    operations::{AssemblyOp, DebugVarInfo},
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
    utils::IndexVec,
};

mod asm_op_storage;
pub use asm_op_storage::{AsmOpIndexError, OpToAsmOpId};

mod debug_var_storage;
pub use debug_var_storage::{DebugInfoIndexError, DebugVarId, OpToDebugVarIds};

// DEBUG INFO
// ================================================================================================

/// Debug information for a MAST forest, containing source metadata and error messages.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugInfo {
    /// All AssemblyOps in the MAST forest.
    asm_ops: IndexVec<AsmOpId, AssemblyOp>,

    /// Efficient access to AssemblyOps per operation per node.
    asm_op_storage: OpToAsmOpId,

    /// All debug variable information in the MAST forest.
    debug_vars: IndexVec<DebugVarId, DebugVarInfo>,

    /// Efficient access to debug variables per operation per node.
    op_debug_var_storage: OpToDebugVarIds,

    /// Maps error codes to error messages.
    error_codes: BTreeMap<u64, Arc<str>>,

    /// Maps MAST root digests to procedure names for debugging purposes.
    #[cfg_attr(feature = "serde", serde(skip))]
    procedure_names: BTreeMap<Word, Arc<str>>,
}

impl DebugInfo {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new empty [DebugInfo].
    pub fn new() -> Self {
        Self {
            asm_ops: IndexVec::new(),
            asm_op_storage: OpToAsmOpId::new(),
            debug_vars: IndexVec::new(),
            op_debug_var_storage: OpToDebugVarIds::new(),
            error_codes: BTreeMap::new(),
            procedure_names: BTreeMap::new(),
        }
    }

    /// Creates an empty [DebugInfo] with specified capacities.
    pub fn with_capacity(
        nodes_capacity: usize,
        operations_capacity: usize,
        asm_ops_capacity: usize,
        debug_vars_capacity: usize,
    ) -> Self {
        Self {
            asm_ops: IndexVec::with_capacity(asm_ops_capacity),
            asm_op_storage: OpToAsmOpId::with_capacity(nodes_capacity, operations_capacity),
            debug_vars: IndexVec::with_capacity(debug_vars_capacity),
            op_debug_var_storage: OpToDebugVarIds::with_capacity(
                nodes_capacity,
                operations_capacity,
                debug_vars_capacity,
            ),
            error_codes: BTreeMap::new(),
            procedure_names: BTreeMap::new(),
        }
    }

    /// Creates an empty [DebugInfo] with valid CSR structures for N nodes.
    pub fn empty_for_nodes(_num_nodes: usize) -> Self {
        Self::new()
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns true if this [DebugInfo] has no asm_ops, debug vars, error codes, or procedure
    /// names.
    pub fn is_empty(&self) -> bool {
        self.asm_ops.is_empty()
            && self.debug_vars.is_empty()
            && self.error_codes.is_empty()
            && self.procedure_names.is_empty()
    }

    /// Strips all debug information, removing asm_ops, debug vars, error codes, and procedure
    /// names.
    ///
    /// This is used for release builds where debug info is not needed.
    pub fn clear(&mut self) {
        self.asm_ops = IndexVec::new();
        self.asm_op_storage = OpToAsmOpId::new();
        self.debug_vars = IndexVec::new();
        self.op_debug_var_storage.clear();
        self.error_codes.clear();
        self.procedure_names.clear();
    }

    // DEBUG VARIABLE ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of debug variables.
    pub fn num_debug_vars(&self) -> usize {
        self.debug_vars.len()
    }

    /// Returns all debug variables as a slice.
    pub fn debug_vars(&self) -> &[DebugVarInfo] {
        self.debug_vars.as_slice()
    }

    /// Returns the debug variable with the given ID, if it exists.
    pub fn debug_var(&self, debug_var_id: DebugVarId) -> Option<&DebugVarInfo> {
        self.debug_vars.get(debug_var_id)
    }

    /// Returns all `(op_idx, DebugVarId)` pairs for the given node, or an empty vec if the
    /// node has no debug vars.
    pub fn debug_vars_for_node(&self, node_id: MastNodeId) -> Vec<(usize, DebugVarId)> {
        self.op_debug_var_storage.debug_vars_for_node(node_id)
    }

    /// Returns debug variable IDs for a specific operation within a node.
    pub fn debug_vars_for_operation(
        &self,
        node_id: MastNodeId,
        local_op_idx: usize,
    ) -> &[DebugVarId] {
        self.op_debug_var_storage
            .debug_var_ids_for_operation(node_id, local_op_idx)
            .unwrap_or(&[])
    }

    // ASSEMBLY OP ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of AssemblyOps.
    pub fn num_asm_ops(&self) -> usize {
        self.asm_ops.len()
    }

    /// Returns all AssemblyOps as a slice.
    pub fn asm_ops(&self) -> &[AssemblyOp] {
        self.asm_ops.as_slice()
    }

    /// Returns the AssemblyOp with the given ID, if it exists.
    pub fn asm_op(&self, asm_op_id: AsmOpId) -> Option<&AssemblyOp> {
        self.asm_ops.get(asm_op_id)
    }

    /// Returns the AssemblyOp for a specific operation within a node, if any.
    pub fn asm_op_for_operation(&self, node_id: MastNodeId, op_idx: usize) -> Option<&AssemblyOp> {
        let asm_op_id = self.asm_op_storage.asm_op_id_for_operation(node_id, op_idx)?;
        self.asm_ops.get(asm_op_id)
    }

    /// Returns the first AssemblyOp for a node, if any.
    pub fn first_asm_op_for_node(&self, node_id: MastNodeId) -> Option<&AssemblyOp> {
        let asm_op_id = self.asm_op_storage.first_asm_op_for_node(node_id)?;
        self.asm_ops.get(asm_op_id)
    }

    /// Returns all `(op_idx, AsmOpId)` pairs for the given node.
    pub fn asm_ops_for_node(&self, node_id: MastNodeId) -> Vec<(usize, AsmOpId)> {
        self.asm_op_storage.asm_ops_for_node(node_id)
    }

    // ASSEMBLY OP MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds an AssemblyOp and returns its ID.
    pub fn add_asm_op(&mut self, asm_op: AssemblyOp) -> Result<AsmOpId, MastForestError> {
        self.asm_ops.push(asm_op).map_err(|_| MastForestError::TooManyDebugInfoEntries)
    }

    /// Rewrites the source-backed locations stored in this debug info.
    pub fn rewrite_source_locations(
        &mut self,
        mut rewrite_location: impl FnMut(Location) -> Location,
        mut rewrite_file_line_col: impl FnMut(FileLineCol) -> FileLineCol,
    ) {
        for asm_op in self.asm_ops.iter_mut() {
            if let Some(location) = asm_op.location().cloned() {
                asm_op.set_location(rewrite_location(location));
            }
        }

        for debug_var in self.debug_vars.iter_mut() {
            if let Some(location) = debug_var.location().cloned() {
                debug_var.set_location(rewrite_file_line_col(location));
            }
        }
    }

    /// Registers operation-indexed AssemblyOps for a node.
    ///
    /// The `num_operations` parameter must be the total number of operations in the node. This is
    /// needed to allocate enough space for all operations, even those without AssemblyOps, so that
    /// lookups at any valid operation index will work correctly.
    pub fn register_asm_ops(
        &mut self,
        node_id: MastNodeId,
        num_operations: usize,
        asm_ops: Vec<(usize, AsmOpId)>,
    ) -> Result<(), AsmOpIndexError> {
        self.asm_op_storage.add_asm_ops_for_node(node_id, num_operations, asm_ops)
    }

    /// Remaps the asm_op_storage to use new node IDs after nodes have been removed/reordered.
    ///
    /// This should be called after nodes are removed from the MastForest to ensure the asm_op
    /// storage still references valid node IDs.
    pub(super) fn remap_asm_op_storage(&mut self, remapping: &BTreeMap<MastNodeId, MastNodeId>) {
        self.asm_op_storage = self.asm_op_storage.remap_nodes(remapping);
    }

    // DEBUG VARIABLE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds a debug variable and returns its ID.
    pub fn add_debug_var(
        &mut self,
        debug_var: DebugVarInfo,
    ) -> Result<DebugVarId, MastForestError> {
        self.debug_vars
            .push(debug_var)
            .map_err(|_| MastForestError::TooManyDebugInfoEntries)
    }

    /// Registers operation-indexed debug variables for a node.
    ///
    /// This associates already-added debug variables with specific operations within a node.
    pub fn register_op_indexed_debug_vars(
        &mut self,
        node_id: MastNodeId,
        debug_vars_info: Vec<(usize, DebugVarId)>,
    ) -> Result<(), DebugInfoIndexError> {
        self.op_debug_var_storage.add_debug_var_info_for_node(node_id, debug_vars_info)
    }

    // ERROR CODE METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns an error message by code.
    pub fn error_message(&self, code: u64) -> Option<Arc<str>> {
        self.error_codes.get(&code).cloned()
    }

    /// Returns an iterator over error codes.
    pub fn error_codes(&self) -> impl Iterator<Item = (&u64, &Arc<str>)> {
        self.error_codes.iter()
    }

    /// Inserts an error code with its message.
    pub fn insert_error_code(&mut self, code: u64, msg: Arc<str>) {
        self.error_codes.insert(code, msg);
    }

    /// Inserts multiple error codes at once.
    ///
    /// This is used when bulk error code insertion is needed.
    pub fn extend_error_codes<I>(&mut self, error_codes: I)
    where
        I: IntoIterator<Item = (u64, Arc<str>)>,
    {
        self.error_codes.extend(error_codes);
    }

    /// Clears all error codes.
    ///
    /// This is used when error code information needs to be reset.
    pub fn clear_error_codes(&mut self) {
        self.error_codes.clear();
    }

    // PROCEDURE NAME METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the procedure name for the given MAST root digest, if present.
    pub fn procedure_name(&self, digest: &Word) -> Option<&str> {
        self.procedure_names.get(digest).map(AsRef::as_ref)
    }

    /// Returns an iterator over all (digest, name) pairs.
    pub fn procedure_names(&self) -> impl Iterator<Item = (Word, &Arc<str>)> {
        self.procedure_names.iter().map(|(key, name)| (*key, name))
    }

    /// Returns the number of procedure names.
    pub fn num_procedure_names(&self) -> usize {
        self.procedure_names.len()
    }

    /// Inserts a procedure name for the given MAST root digest.
    pub fn insert_procedure_name(&mut self, digest: Word, name: Arc<str>) {
        self.procedure_names.insert(digest, name);
    }

    /// Inserts multiple procedure names at once.
    pub fn extend_procedure_names<I>(&mut self, names: I)
    where
        I: IntoIterator<Item = (Word, Arc<str>)>,
    {
        self.procedure_names.extend(names);
    }

    /// Clears all procedure names.
    pub fn clear_procedure_names(&mut self) {
        self.procedure_names.clear();
    }

    // VALIDATION
    // --------------------------------------------------------------------------------------------

    /// Validate the integrity of the DebugInfo structure.
    ///
    /// This validates:
    /// - All CSR structures in asm_op_storage
    /// - All CSR structures in op_debug_var_storage
    /// - All AsmOpIds reference valid AssemblyOps
    /// - All debug var IDs reference valid debug vars
    pub(super) fn validate(&self) -> Result<(), String> {
        let asm_op_count = self.asm_ops.len();

        // Validate OpToAsmOpId CSR
        self.asm_op_storage.validate_csr(asm_op_count)?;

        // Validate OpToDebugVarIds CSR
        let debug_var_count = self.debug_vars.len();
        self.op_debug_var_storage.validate_csr(debug_var_count)?;

        Ok(())
    }
}

impl Serializable for DebugInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // 1. Serialize empty legacy decorator sections.
        Vec::<u8>::new().write_into(target);
        StringTable::new(Vec::new(), Vec::new()).write_into(target);
        Vec::<DecoratorInfo>::new().write_into(target);

        // 2. Serialize error codes
        let error_codes: BTreeMap<u64, String> =
            self.error_codes.iter().map(|(k, v)| (*k, v.to_string())).collect();
        error_codes.write_into(target);

        // 3. Serialize empty legacy OpToDecoratorIds CSR.
        write_empty_legacy_op_decorator_storage(target);

        // 4. Serialize empty legacy NodeToDecoratorIds CSR.
        write_empty_legacy_node_decorator_storage(target);

        // 5. Serialize procedure names
        let procedure_names: BTreeMap<Word, String> =
            self.procedure_names().map(|(k, v)| (k, v.to_string())).collect();
        procedure_names.write_into(target);

        // 6. Serialize AssemblyOps (data, string table, infos)
        let mut asm_op_data_builder = AsmOpDataBuilder::new();
        for asm_op in self.asm_ops.iter() {
            asm_op_data_builder.add_asm_op(asm_op);
        }
        let (asm_op_data, asm_op_infos, asm_op_string_table) = asm_op_data_builder.finalize();

        asm_op_data.write_into(target);
        asm_op_string_table.write_into(target);
        asm_op_infos.write_into(target);

        // 7. Serialize OpToAsmOpId CSR (dense representation)
        self.asm_op_storage.write_into(target);

        // 8. Serialize debug variables
        self.debug_vars.write_into(target);

        // 9. Serialize OpToDebugVarIds CSR
        self.op_debug_var_storage.write_into(target);
    }
}

impl Deserializable for DebugInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // 1. Read and reject legacy decorator data.
        let decorator_data: Vec<u8> = Deserializable::read_from(source)?;
        let string_table: StringTable = Deserializable::read_from(source)?;
        let decorator_infos: Vec<DecoratorInfo> = Deserializable::read_from(source)?;
        if !decorator_data.is_empty() || !decorator_infos.is_empty() {
            return Err(DeserializationError::InvalidValue(
                "decorators are no longer supported".into(),
            ));
        }
        let _ = string_table;

        // 3. Read error codes
        let error_codes_raw: BTreeMap<u64, String> = Deserializable::read_from(source)?;
        let error_codes: BTreeMap<u64, Arc<str>> =
            error_codes_raw.into_iter().map(|(k, v)| (k, Arc::from(v.as_str()))).collect();

        // 4. Read OpToDecoratorIds CSR (dense representation)
        if !read_empty_legacy_op_decorator_storage(source)? {
            return Err(DeserializationError::InvalidValue(
                "operation-indexed decorators are no longer supported".into(),
            ));
        }

        // 5. Read NodeToDecoratorIds CSR (dense representation)
        if !read_empty_legacy_node_decorator_storage(source)? {
            return Err(DeserializationError::InvalidValue(
                "node decorators are no longer supported".into(),
            ));
        }

        // 6. Read procedure names
        // Note: Procedure name digests are validated at the MastForest level (in
        // MastForest::validate) to ensure they reference actual procedures in the forest.
        let procedure_names_raw: BTreeMap<Word, String> = Deserializable::read_from(source)?;
        let procedure_names: BTreeMap<Word, Arc<str>> = procedure_names_raw
            .into_iter()
            .map(|(k, v)| (k, Arc::from(v.as_str())))
            .collect();

        // 7. Read AssemblyOps (data, string table, infos)
        let asm_op_data: Vec<u8> = Deserializable::read_from(source)?;
        let asm_op_string_table: StringTable = Deserializable::read_from(source)?;
        let asm_op_infos: Vec<AsmOpInfo> = Deserializable::read_from(source)?;

        // 8. Reconstruct AssemblyOps
        let mut asm_ops = IndexVec::new();
        for asm_op_info in asm_op_infos {
            let asm_op = asm_op_info.try_into_asm_op(&asm_op_string_table, &asm_op_data)?;
            asm_ops.push(asm_op).map_err(|_| {
                DeserializationError::InvalidValue(
                    "Failed to add AssemblyOp to IndexVec".to_string(),
                )
            })?;
        }

        // 9. Read OpToAsmOpId CSR (dense representation)
        let asm_op_storage = OpToAsmOpId::read_from(source, asm_ops.len())?;

        // 10. Read debug variables
        let debug_vars: IndexVec<DebugVarId, DebugVarInfo> = Deserializable::read_from(source)?;

        // 11. Read OpToDebugVarIds CSR
        let op_debug_var_storage = OpToDebugVarIds::read_from(source, debug_vars.len())?;

        // 12. Construct and validate DebugInfo
        let debug_info = DebugInfo {
            asm_ops,
            asm_op_storage,
            debug_vars,
            op_debug_var_storage,
            error_codes,
            procedure_names,
        };

        debug_info.validate().map_err(|e| {
            DeserializationError::InvalidValue(format!("DebugInfo validation failed: {e}"))
        })?;

        Ok(debug_info)
    }
}

impl Default for DebugInfo {
    fn default() -> Self {
        Self::new()
    }
}

fn write_empty_legacy_op_decorator_storage<W: ByteWriter>(target: &mut W) {
    Vec::<u32>::new().write_into(target);
    Vec::<usize>::new().write_into(target);
    Vec::<usize>::new().write_into(target);
}

fn read_empty_legacy_op_decorator_storage<R: ByteReader>(
    source: &mut R,
) -> Result<bool, DeserializationError> {
    let decorator_ids: Vec<u32> = Deserializable::read_from(source)?;
    let op_indptr_for_decorator_ids: Vec<usize> = Deserializable::read_from(source)?;
    let node_indptr_for_op_idx: Vec<usize> = Deserializable::read_from(source)?;

    Ok(decorator_ids.is_empty()
        && is_all_zero(&op_indptr_for_decorator_ids)
        && is_all_zero(&node_indptr_for_op_idx))
}

fn write_empty_legacy_node_decorator_storage<W: ByteWriter>(target: &mut W) {
    write_empty_legacy_csr_u32(target);
    write_empty_legacy_csr_u32(target);
}

fn read_empty_legacy_node_decorator_storage<R: ByteReader>(
    source: &mut R,
) -> Result<bool, DeserializationError> {
    Ok(read_empty_legacy_csr_u32(source)? && read_empty_legacy_csr_u32(source)?)
}

fn write_empty_legacy_csr_u32<W: ByteWriter>(target: &mut W) {
    Vec::<u32>::new().write_into(target);
    Vec::<usize>::new().write_into(target);
}

fn read_empty_legacy_csr_u32<R: ByteReader>(source: &mut R) -> Result<bool, DeserializationError> {
    let data: Vec<u32> = Deserializable::read_from(source)?;
    let indptr: Vec<usize> = Deserializable::read_from(source)?;

    Ok(data.is_empty() && is_all_zero(&indptr))
}

fn is_all_zero(values: &[usize]) -> bool {
    values.iter().all(|value| *value == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serde::SliceReader;

    #[test]
    fn legacy_empty_decorator_storage_accepts_all_zero_pointer_rows() {
        let mut op_storage = Vec::new();
        Vec::<u32>::new().write_into(&mut op_storage);
        vec![0usize, 0, 0].write_into(&mut op_storage);
        vec![0usize, 0].write_into(&mut op_storage);

        let mut reader = SliceReader::new(&op_storage);
        assert!(read_empty_legacy_op_decorator_storage(&mut reader).unwrap());

        let mut node_storage = Vec::new();
        Vec::<u32>::new().write_into(&mut node_storage);
        vec![0usize, 0].write_into(&mut node_storage);
        Vec::<u32>::new().write_into(&mut node_storage);
        vec![0usize, 0, 0].write_into(&mut node_storage);

        let mut reader = SliceReader::new(&node_storage);
        assert!(read_empty_legacy_node_decorator_storage(&mut reader).unwrap());
    }

    #[test]
    fn legacy_empty_decorator_storage_rejects_nonzero_pointers() {
        let mut op_storage = Vec::new();
        Vec::<u32>::new().write_into(&mut op_storage);
        vec![0usize, 1].write_into(&mut op_storage);
        vec![0usize].write_into(&mut op_storage);

        let mut reader = SliceReader::new(&op_storage);
        assert!(!read_empty_legacy_op_decorator_storage(&mut reader).unwrap());
    }
}
