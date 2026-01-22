//! Debug information management for MAST forests.
//!
//! This module provides the [`DebugInfo`] struct which consolidates all debug-related
//! information for a MAST forest in a single location. This includes:
//!
//! - All decorators (debug, trace, and assembly operation metadata)
//! - Operation-indexed decorator mappings for efficient lookup
//! - Node-level decorator storage (before_enter/after_exit)
//! - Error code mappings for descriptive error messages
//!
//! The debug info is always available at the `MastForest` level (as per issue #1821),
//! but may be conditionally included during assembly to maintain backward compatibility.
//! Decorators are only executed when the processor is running in debug mode, allowing
//! debug information to be available for debugging and error reporting without
//! impacting performance in production execution.
//!
//! # Debug Mode Semantics
//!
//! Debug mode is controlled via [`ExecutionOptions`](air::options::ExecutionOptions):
//! - `with_debugging(true)` enables debug mode explicitly
//! - `with_tracing()` automatically enables debug mode (tracing requires debug info)
//! - By default, debug mode is disabled for maximum performance
//!
//! When debug mode is disabled:
//! - Debug decorators are not executed
//! - Trace decorators are not executed
//! - Assembly operation decorators are not recorded
//! - before_enter/after_exit decorators are not executed
//!
//! When debug mode is enabled:
//! - All decorator types are executed according to their semantics
//! - Debug decorators trigger host callbacks for breakpoints
//! - Trace decorators trigger host callbacks for tracing
//! - Assembly operation decorators provide source mapping information
//! - before_enter/after_exit decorators execute around node execution
//!
//! # Production Builds
//!
//! The `DebugInfo` can be stripped for production builds using the [`clear()`](Self::clear)
//! method, which removes decorators while preserving critical information. This allows
//! backward compatibility while enabling size optimization for deployment.

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_utils_indexing::{Idx, IndexVec};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{AsmOpId, Decorator, DecoratorId, MastForestError, MastNodeId};
use crate::{
    AssemblyOp, LexicographicWord, Word,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

mod asm_op_storage;
pub use asm_op_storage::{AsmOpIndexError, OpToAsmOpId};

mod decorator_storage;
pub use decorator_storage::{
    DecoratedLinks, DecoratedLinksIter, DecoratorIndexError, OpToDecoratorIds,
};

mod node_decorator_storage;
pub use node_decorator_storage::NodeToDecoratorIds;

// DEBUG INFO
// ================================================================================================

/// Debug information for a MAST forest, containing decorators and error messages.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugInfo {
    /// All decorators in the MAST forest (Debug and Trace only, no AsmOp).
    decorators: IndexVec<DecoratorId, Decorator>,

    /// Efficient access to decorators per operation per node.
    op_decorator_storage: OpToDecoratorIds,

    /// Efficient storage for node-level decorators (before_enter and after_exit).
    node_decorator_storage: NodeToDecoratorIds,

    /// All AssemblyOps in the MAST forest.
    asm_ops: IndexVec<AsmOpId, AssemblyOp>,

    /// Efficient access to AssemblyOps per operation per node.
    asm_op_storage: OpToAsmOpId,

    /// Maps error codes to error messages.
    error_codes: BTreeMap<u64, Arc<str>>,

    /// Maps MAST root digests to procedure names for debugging purposes.
    #[cfg_attr(feature = "serde", serde(skip))]
    procedure_names: BTreeMap<LexicographicWord, Arc<str>>,
}

impl DebugInfo {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new empty [DebugInfo].
    pub fn new() -> Self {
        Self {
            decorators: IndexVec::new(),
            op_decorator_storage: OpToDecoratorIds::new(),
            node_decorator_storage: NodeToDecoratorIds::new(),
            asm_ops: IndexVec::new(),
            asm_op_storage: OpToAsmOpId::new(),
            error_codes: BTreeMap::new(),
            procedure_names: BTreeMap::new(),
        }
    }

    /// Creates an empty [DebugInfo] with specified capacities.
    pub fn with_capacity(
        decorators_capacity: usize,
        nodes_capacity: usize,
        operations_capacity: usize,
        decorator_ids_capacity: usize,
    ) -> Self {
        Self {
            decorators: IndexVec::with_capacity(decorators_capacity),
            op_decorator_storage: OpToDecoratorIds::with_capacity(
                nodes_capacity,
                operations_capacity,
                decorator_ids_capacity,
            ),
            node_decorator_storage: NodeToDecoratorIds::with_capacity(nodes_capacity, 0, 0),
            asm_ops: IndexVec::new(),
            asm_op_storage: OpToAsmOpId::new(),
            error_codes: BTreeMap::new(),
            procedure_names: BTreeMap::new(),
        }
    }

    /// Creates an empty [DebugInfo] with valid CSR structures for N nodes.
    pub fn empty_for_nodes(num_nodes: usize) -> Self {
        let node_indptr_for_op_idx = IndexVec::try_from(vec![0; num_nodes + 1])
            .expect("num_nodes should not exceed u32::MAX");

        let op_decorator_storage =
            OpToDecoratorIds::from_components(Vec::new(), Vec::new(), node_indptr_for_op_idx)
                .expect("Empty CSR structure should be valid");

        Self {
            decorators: IndexVec::new(),
            op_decorator_storage,
            node_decorator_storage: NodeToDecoratorIds::new(),
            asm_ops: IndexVec::new(),
            asm_op_storage: OpToAsmOpId::new(),
            error_codes: BTreeMap::new(),
            procedure_names: BTreeMap::new(),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns true if this [DebugInfo] has no decorators, asm_ops, error codes, or procedure
    /// names.
    pub fn is_empty(&self) -> bool {
        self.decorators.is_empty()
            && self.asm_ops.is_empty()
            && self.error_codes.is_empty()
            && self.procedure_names.is_empty()
    }

    /// Strips all debug information, removing decorators, asm_ops, error codes, and procedure
    /// names.
    ///
    /// This is used for release builds where debug info is not needed.
    pub fn clear(&mut self) {
        self.clear_mappings();
        self.decorators = IndexVec::new();
        self.asm_ops = IndexVec::new();
        self.asm_op_storage = OpToAsmOpId::new();
        self.error_codes.clear();
        self.procedure_names.clear();
    }

    // DECORATOR ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of decorators.
    pub fn num_decorators(&self) -> usize {
        self.decorators.len()
    }

    /// Returns all decorators as a slice.
    pub fn decorators(&self) -> &[Decorator] {
        self.decorators.as_slice()
    }

    /// Returns the decorator with the given ID, if it exists.
    pub fn decorator(&self, decorator_id: DecoratorId) -> Option<&Decorator> {
        self.decorators.get(decorator_id)
    }

    /// Returns the before-enter decorators for the given node.
    pub fn before_enter_decorators(&self, node_id: MastNodeId) -> &[DecoratorId] {
        self.node_decorator_storage.get_before_decorators(node_id)
    }

    /// Returns the after-exit decorators for the given node.
    pub fn after_exit_decorators(&self, node_id: MastNodeId) -> &[DecoratorId] {
        self.node_decorator_storage.get_after_decorators(node_id)
    }

    /// Returns decorators for a specific operation within a node.
    pub fn decorators_for_operation(
        &self,
        node_id: MastNodeId,
        local_op_idx: usize,
    ) -> &[DecoratorId] {
        self.op_decorator_storage
            .decorator_ids_for_operation(node_id, local_op_idx)
            .unwrap_or(&[])
    }

    /// Returns decorator links for a node, including operation indices.
    pub(super) fn decorator_links_for_node(
        &self,
        node_id: MastNodeId,
    ) -> Result<DecoratedLinks<'_>, DecoratorIndexError> {
        self.op_decorator_storage.decorator_links_for_node(node_id)
    }

    // DECORATOR MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds a decorator and returns its ID.
    pub fn add_decorator(&mut self, decorator: Decorator) -> Result<DecoratorId, MastForestError> {
        self.decorators.push(decorator).map_err(|_| MastForestError::TooManyDecorators)
    }

    /// Returns a mutable reference the decorator with the given ID, if it exists.
    pub(super) fn decorator_mut(&mut self, decorator_id: DecoratorId) -> Option<&mut Decorator> {
        if decorator_id.to_usize() < self.decorators.len() {
            Some(&mut self.decorators[decorator_id])
        } else {
            None
        }
    }

    /// Adds node-level decorators (before_enter and after_exit) for the given node.
    ///
    /// # Note
    /// This method does not validate decorator IDs immediately. Validation occurs during
    /// operations that need to access the actual decorator data (e.g., merging, serialization).
    pub(super) fn register_node_decorators(
        &mut self,
        node_id: MastNodeId,
        before_enter: &[DecoratorId],
        after_exit: &[DecoratorId],
    ) {
        self.node_decorator_storage
            .add_node_decorators(node_id, before_enter, after_exit);
    }

    /// Registers operation-indexed decorators for a node.
    ///
    /// This associates already-added decorators with specific operations within a node.
    pub(crate) fn register_op_indexed_decorators(
        &mut self,
        node_id: MastNodeId,
        decorators_info: Vec<(usize, DecoratorId)>,
    ) -> Result<(), crate::mast::debuginfo::decorator_storage::DecoratorIndexError> {
        self.op_decorator_storage.add_decorator_info_for_node(node_id, decorators_info)
    }

    /// Clears all decorator information while preserving error codes.
    ///
    /// This is used when rebuilding decorator information from nodes.
    pub fn clear_mappings(&mut self) {
        self.op_decorator_storage = OpToDecoratorIds::new();
        self.node_decorator_storage.clear();
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

    // ASSEMBLY OP MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds an AssemblyOp and returns its ID.
    pub fn add_asm_op(&mut self, asm_op: AssemblyOp) -> Result<AsmOpId, MastForestError> {
        self.asm_ops.push(asm_op).map_err(|_| MastForestError::TooManyDecorators)
    }

    /// Registers operation-indexed AssemblyOps for a node.
    ///
    /// The `num_operations` parameter must be the total number of operations in the node.
    /// This is needed to allocate enough space for all operations, even those without
    /// AssemblyOps, so that lookups at any valid operation index will work correctly.
    pub fn register_asm_ops(
        &mut self,
        node_id: MastNodeId,
        num_operations: usize,
        asm_ops: Vec<(usize, AsmOpId)>,
    ) -> Result<(), AsmOpIndexError> {
        self.asm_op_storage.add_asm_op_for_node(node_id, num_operations, asm_ops)
    }

    /// Remaps the asm_op_storage to use new node IDs after nodes have been removed/reordered.
    ///
    /// This should be called after nodes are removed from the MastForest to ensure
    /// the asm_op storage still references valid node IDs.
    pub(super) fn remap_asm_op_storage(
        &mut self,
        remapping: &alloc::collections::BTreeMap<MastNodeId, MastNodeId>,
    ) {
        self.asm_op_storage = self.asm_op_storage.remap_nodes(remapping);
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
        self.procedure_names.get(&LexicographicWord::from(*digest)).map(|s| s.as_ref())
    }

    /// Returns an iterator over all (digest, name) pairs.
    pub fn procedure_names(&self) -> impl Iterator<Item = (Word, &Arc<str>)> {
        self.procedure_names.iter().map(|(key, name)| (key.into_inner(), name))
    }

    /// Returns the number of procedure names.
    pub fn num_procedure_names(&self) -> usize {
        self.procedure_names.len()
    }

    /// Inserts a procedure name for the given MAST root digest.
    pub fn insert_procedure_name(&mut self, digest: Word, name: Arc<str>) {
        self.procedure_names.insert(LexicographicWord::from(digest), name);
    }

    /// Inserts multiple procedure names at once.
    pub fn extend_procedure_names<I>(&mut self, names: I)
    where
        I: IntoIterator<Item = (Word, Arc<str>)>,
    {
        self.procedure_names
            .extend(names.into_iter().map(|(d, n)| (LexicographicWord::from(d), n)));
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
    /// - All CSR structures in op_decorator_storage
    /// - All CSR structures in node_decorator_storage
    /// - All CSR structures in asm_op_storage
    /// - All decorator IDs reference valid decorators
    /// - All AsmOpIds reference valid AssemblyOps
    pub(super) fn validate(&self) -> Result<(), String> {
        let decorator_count = self.decorators.len();
        let asm_op_count = self.asm_ops.len();

        // Validate OpToDecoratorIds CSR
        self.op_decorator_storage.validate_csr(decorator_count)?;

        // Validate NodeToDecoratorIds CSR
        self.node_decorator_storage.validate_csr(decorator_count)?;

        // Validate OpToAsmOpId CSR
        self.asm_op_storage.validate_csr(asm_op_count)?;

        Ok(())
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the operation decorator storage.
    #[cfg(test)]
    pub(crate) fn op_decorator_storage(&self) -> &OpToDecoratorIds {
        &self.op_decorator_storage
    }
}

impl Serializable for DebugInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        use crate::mast::serialization::{
            asm_op::AsmOpDataBuilder, decorator::DecoratorDataBuilder,
        };

        // 1. Serialize decorators (data, string table, infos)
        let mut decorator_data_builder = DecoratorDataBuilder::new();
        for decorator in self.decorators.iter() {
            decorator_data_builder.add_decorator(decorator);
        }
        let (decorator_data, decorator_infos, string_table) = decorator_data_builder.finalize();

        decorator_data.write_into(target);
        string_table.write_into(target);
        decorator_infos.write_into(target);

        // 2. Serialize error codes
        let error_codes: alloc::collections::BTreeMap<u64, alloc::string::String> =
            self.error_codes.iter().map(|(k, v)| (*k, v.to_string())).collect();
        error_codes.write_into(target);

        // 3. Serialize OpToDecoratorIds CSR (dense representation)
        // Dense representation: serialize indptr arrays as-is (no sparse encoding).
        // Analysis shows sparse saves <1KB even with 90% empty nodes, not worth complexity.
        // See measurement: https://gist.github.com/huitseeker/7379e2eecffd7020ae577e986057a400
        self.op_decorator_storage.write_into(target);

        // 4. Serialize NodeToDecoratorIds CSR (dense representation)
        self.node_decorator_storage.write_into(target);

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
    }
}

impl Deserializable for DebugInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        use crate::mast::serialization::{asm_op::AsmOpInfo, decorator::DecoratorInfo};

        // 1. Read decorator data and string table
        let decorator_data: Vec<u8> = Deserializable::read_from(source)?;
        let string_table: crate::mast::serialization::StringTable =
            Deserializable::read_from(source)?;
        let decorator_infos: Vec<DecoratorInfo> = Deserializable::read_from(source)?;

        // 2. Reconstruct decorators
        let mut decorators = IndexVec::new();
        for decorator_info in decorator_infos {
            let decorator = decorator_info.try_into_decorator(&string_table, &decorator_data)?;
            decorators.push(decorator).map_err(|_| {
                DeserializationError::InvalidValue(
                    "Failed to add decorator to IndexVec".to_string(),
                )
            })?;
        }

        // 3. Read error codes
        let error_codes_raw: alloc::collections::BTreeMap<u64, alloc::string::String> =
            Deserializable::read_from(source)?;
        let error_codes: alloc::collections::BTreeMap<u64, alloc::sync::Arc<str>> = error_codes_raw
            .into_iter()
            .map(|(k, v)| (k, alloc::sync::Arc::from(v.as_str())))
            .collect();

        // 4. Read OpToDecoratorIds CSR (dense representation)
        let op_decorator_storage = OpToDecoratorIds::read_from(source, decorators.len())?;

        // 5. Read NodeToDecoratorIds CSR (dense representation)
        let node_decorator_storage = NodeToDecoratorIds::read_from(source, decorators.len())?;

        // 6. Read procedure names
        // Note: Procedure name digests are validated at the MastForest level (in
        // MastForest::validate) to ensure they reference actual procedures in the forest.
        let procedure_names_raw: BTreeMap<Word, String> = Deserializable::read_from(source)?;
        let procedure_names: BTreeMap<LexicographicWord, Arc<str>> = procedure_names_raw
            .into_iter()
            .map(|(k, v)| (LexicographicWord::from(k), Arc::from(v.as_str())))
            .collect();

        // 7. Read AssemblyOps (data, string table, infos)
        let asm_op_data: Vec<u8> = Deserializable::read_from(source)?;
        let asm_op_string_table: crate::mast::serialization::StringTable =
            Deserializable::read_from(source)?;
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

        // 10. Construct and validate DebugInfo
        let debug_info = DebugInfo {
            decorators,
            op_decorator_storage,
            node_decorator_storage,
            asm_ops,
            asm_op_storage,
            error_codes,
            procedure_names,
        };

        debug_info.validate().map_err(|e| {
            DeserializationError::InvalidValue(format!("DebugInfo validation failed: {}", e))
        })?;

        Ok(debug_info)
    }
}

impl Default for DebugInfo {
    fn default() -> Self {
        Self::new()
    }
}
