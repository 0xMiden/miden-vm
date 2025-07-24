use alloc::{sync::Arc, vec::Vec};

use midenc_hir_type::FunctionType;

use super::LibraryPath;
use crate::{
    Word,
    ast::{ProcedureIndex, ProcedureName},
};

// MODULE INFO
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    path: LibraryPath,
    procedures: Vec<ProcedureInfo>,
}

impl ModuleInfo {
    /// Returns a new [`ModuleInfo`] instantiated library path.
    pub fn new(path: LibraryPath) -> Self {
        Self { path, procedures: Vec::new() }
    }

    /// Adds a procedure to the module.
    pub fn add_procedure(
        &mut self,
        name: ProcedureName,
        digest: Word,
        signature: Option<Arc<FunctionType>>,
    ) {
        self.procedures.push(ProcedureInfo { name, digest, signature });
    }

    /// Returns the module's library path.
    pub fn path(&self) -> &LibraryPath {
        &self.path
    }

    /// Returns the number of procedures in the module.
    pub fn num_procedures(&self) -> usize {
        self.procedures.len()
    }

    /// Returns the [`ProcedureInfo`] of the procedure at the provided index, if any.
    pub fn get_procedure_by_index(&self, index: ProcedureIndex) -> Option<&ProcedureInfo> {
        self.procedures.get(index.as_usize())
    }

    /// Returns the digest of the procedure with the provided name, if any.
    pub fn get_procedure_digest_by_name(&self, name: &ProcedureName) -> Option<Word> {
        self.procedures.iter().find_map(|proc_info| {
            if &proc_info.name == name {
                Some(proc_info.digest)
            } else {
                None
            }
        })
    }

    /// Returns an iterator over the procedure infos in the module with their corresponding
    /// procedure index in the module.
    pub fn procedures(&self) -> impl Iterator<Item = (ProcedureIndex, &ProcedureInfo)> {
        self.procedures
            .iter()
            .enumerate()
            .map(|(idx, proc)| (ProcedureIndex::new(idx), proc))
    }

    /// Returns an iterator over the MAST roots of procedures defined in this module.
    pub fn procedure_digests(&self) -> impl Iterator<Item = Word> + '_ {
        self.procedures.iter().map(|p| p.digest)
    }
}

/// Stores the name and digest of a procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureInfo {
    pub name: ProcedureName,
    pub digest: Word,
    pub signature: Option<Arc<FunctionType>>,
}
