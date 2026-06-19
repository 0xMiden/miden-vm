use alloc::{collections::BTreeMap, sync::Arc};

use miden_core::{Word, mast::MastForest};
use miden_mast_package::{PackageDebugInfoError, debug_info::PackageDebugInfo};

/// Executable MAST loaded by the host, together with the package debug info that belongs to the
/// same forest.
#[derive(Debug, Clone)]
pub struct LoadedMastForest {
    mast_forest: Arc<MastForest>,
    debug_info: Result<Option<Arc<PackageDebugInfo>>, Arc<PackageDebugInfoError>>,
}

impl LoadedMastForest {
    /// Creates a loaded MAST forest without package-owned debug info.
    pub fn new(mast_forest: Arc<MastForest>) -> Self {
        Self { mast_forest, debug_info: Ok(None) }
    }

    /// Creates a loaded MAST forest with package debug info already decoded from the owning
    /// package.
    pub fn with_package_debug_info(
        mast_forest: Arc<MastForest>,
        debug_info: Result<Option<PackageDebugInfo>, PackageDebugInfoError>,
    ) -> Self {
        Self {
            mast_forest,
            debug_info: debug_info.map(|debug_info| debug_info.map(Arc::new)).map_err(Arc::new),
        }
    }

    /// Returns the executable MAST forest.
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        &self.mast_forest
    }

    /// Returns the package debug info associated with this forest, if any.
    pub fn package_debug_info(
        &self,
    ) -> Result<Option<Arc<PackageDebugInfo>>, Arc<PackageDebugInfoError>> {
        self.debug_info.clone()
    }
}

/// A set of [`MastForest`]s available to the prover that programs may refer to (by means of an
/// [`miden_core::mast::ExternalNode`]).
///
/// For example, a program's kernel and core library would most likely not be compiled directly
/// with the program, and instead be provided separately to the prover. This has the benefit of
/// reducing program binary size. The store could also be much more complex, such as accessing a
/// centralized registry of [`MastForest`]s when it doesn't find one locally.
pub trait MastForestStore {
    /// Returns a [`MastForest`] which is guaranteed to contain a procedure with the provided
    /// procedure hash as one of its procedure, if any.
    fn get(&self, procedure_hash: &Word) -> Option<LoadedMastForest>;
}

/// A simple [`MastForestStore`] where all known [`MastForest`]s are held in memory.
#[derive(Debug, Default, Clone)]
pub struct MemMastForestStore {
    mast_forests: BTreeMap<Word, LoadedMastForest>,
}

impl MemMastForestStore {
    /// Inserts all the procedures of the provided MAST forest in the store.
    pub fn insert(&mut self, mast_forest: Arc<MastForest>) {
        self.insert_loaded(LoadedMastForest::new(mast_forest));
    }

    /// Inserts all the procedures of the provided loaded MAST forest in the store.
    pub fn insert_loaded(&mut self, loaded_mast_forest: LoadedMastForest) {
        // only register the procedures which are local to this forest
        for proc_digest in loaded_mast_forest.mast_forest.local_procedure_digests() {
            self.mast_forests.insert(proc_digest, loaded_mast_forest.clone());
        }
    }
}

impl MastForestStore for MemMastForestStore {
    fn get(&self, procedure_hash: &Word) -> Option<LoadedMastForest> {
        self.mast_forests.get(procedure_hash).cloned()
    }
}
