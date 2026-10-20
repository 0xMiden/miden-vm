use alloc::{collections::BTreeMap, vec};

use miden_air::trace::chiplets::KERNEL_ROM_TRACE_WIDTH;
use miden_core::{
    crypto::merkle::{MerkleTree, NodeIndex},
    field::PrimeCharacteristicRing,
};

use super::{ChipletTraceFragment, Felt, Hasher, KernelDescriptor, Word as Digest, ZERO};
use crate::{ExecutionError, errors::OperationError};

#[cfg(test)]
mod tests;

// TYPE ALIASES
// ================================================================================================

type ProcHashBytes = [u8; 32];

// KERNEL ROM
// ================================================================================================

/// Kernel ROM chiplet for the VM.
///
/// Validates each SYSCALL target against the private kernel descriptor and emits one trace row
/// per distinct accessed procedure. Each row authenticates its digest against the public kernel
/// Merkle root through the hasher controller, independently of its call multiplicity.
///
/// Row: `m | digest[4] | hasher_start | leaf_index | direction_bit | depth | leaf[4]`.
#[derive(Debug)]
pub struct KernelRom {
    access_map: BTreeMap<ProcHashBytes, ProcAccessInfo>,
    kernel: KernelDescriptor,
    depth: Felt,
    num_accessed: usize,
}

impl KernelRom {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [KernelRom] instantiated from the specified KernelDescriptor.
    ///
    /// The kernel ROM is populated with all procedures from the provided kernel. For each
    /// procedure the access count is set to 0.
    pub fn new(kernel: KernelDescriptor) -> Self {
        let mut access_map = BTreeMap::new();
        for (index, &proc_hash) in kernel.proc_hashes().iter().enumerate() {
            access_map.insert(proc_hash.into(), ProcAccessInfo::new(proc_hash, index));
        }

        Self {
            access_map,
            kernel,
            depth: ZERO,
            num_accessed: 0,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns length of execution trace required to describe kernel ROM.
    ///
    /// This is the number of distinct accessed kernel procedures.
    pub fn trace_len(&self) -> usize {
        self.num_accessed
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Marks the specified procedure as accessed from the program.
    ///
    /// # Errors
    /// If the specified procedure does not exist in this kernel ROM, an error is returned.
    pub fn access_proc(&mut self, proc_root: Digest) -> Result<(), OperationError> {
        let proc_hash_bytes: ProcHashBytes = proc_root.into();
        let access_info = self
            .access_map
            .get_mut(&proc_hash_bytes)
            .ok_or(OperationError::SyscallTargetNotInKernel { proc_root })?;

        if access_info.num_accesses == 0 {
            self.num_accessed += 1;
        }
        access_info.num_accesses += 1;
        Ok(())
    }

    /// Append one membership verification per accessed procedure, preserving earlier addresses.
    pub fn authenticate(
        &mut self,
        hasher: &mut Hasher,
        tree: &MerkleTree,
        max_controller_len: usize,
        max_compression_len: usize,
    ) -> Result<(), ExecutionError> {
        self.depth = Felt::from(tree.depth());
        for info in self.access_map.values_mut().filter(|info| info.num_accesses != 0) {
            let index = NodeIndex::new(tree.depth(), info.leaf_index as u64)
                .expect("kernel index is within its canonical tree");
            let path = tree.get_path(index).expect("kernel leaf is in the tree");
            info.leaf = hasher.hash_kernel_leaf(info.proc_hash);
            let (start, root) =
                hasher.build_merkle_root(info.leaf, &path, Felt::from_usize(info.leaf_index));
            debug_assert_eq!(root, tree.root());
            info.hasher_start = Some(start);
            if hasher.trace_len() > max_controller_len
                || hasher.eidos_compression_trace_len() > max_compression_len
            {
                return Err(ExecutionError::TraceLenExceeded(max_controller_len));
            }
        }
        Ok(())
    }

    // EXECUTION TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Populates the provided execution trace fragment with execution trace of this kernel ROM.
    ///
    /// Emits multiplicity, digest, and the authenticated path's address, index, direction, and
    /// depth.
    pub fn fill_trace(self, trace: &mut ChipletTraceFragment) {
        debug_assert_eq!(
            KERNEL_ROM_TRACE_WIDTH,
            trace.width(),
            "inconsistent trace fragment width"
        );

        let mut values = vec![ZERO; self.trace_len() * KERNEL_ROM_TRACE_WIDTH];
        let (rows, _) = values.as_chunks_mut::<KERNEL_ROM_TRACE_WIDTH>();
        for (row, access_info) in rows
            .iter_mut()
            .zip(self.access_map.values().filter(|info| info.num_accesses != 0))
        {
            row[0] = Felt::from_u64(access_info.num_accesses as u64);
            row[1] = access_info.proc_hash[0];
            row[2] = access_info.proc_hash[1];
            row[3] = access_info.proc_hash[2];
            row[4] = access_info.proc_hash[3];
            row[5] = access_info
                .hasher_start
                .expect("kernel membership must be initialized before trace filling");
            row[6] = Felt::from_usize(access_info.leaf_index);
            row[7] = Felt::from_usize(access_info.leaf_index & 1);
            row[8] = self.depth;
            row[9..13].copy_from_slice(access_info.leaf.as_elements());
        }
        trace.copy_rows_from(&values);
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the underlying kernel for this ROM.
    pub const fn kernel(&self) -> &KernelDescriptor {
        &self.kernel
    }
}

// PROCEDURE ACCESS INFO
// ================================================================================================

/// Procedure access information for a given kernel procedure.
#[derive(Debug)]
struct ProcAccessInfo {
    proc_hash: Digest,
    num_accesses: usize,
    leaf_index: usize,
    hasher_start: Option<Felt>,
    leaf: Digest,
}

impl ProcAccessInfo {
    /// Returns a new [ProcAccessInfo] for the specified procedure with `num_accesses` set to 0.
    pub fn new(proc_hash: Digest, leaf_index: usize) -> Self {
        Self {
            proc_hash,
            num_accesses: 0,
            leaf_index,
            hasher_start: None,
            leaf: Digest::default(),
        }
    }
}
