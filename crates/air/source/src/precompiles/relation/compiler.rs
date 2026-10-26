use alloc::vec::Vec;

use miden_ace::{AceError, CapturedAir, CompiledRelation};

use super::AIRS;

/// One symbolic capture of each AIR, shared by the compiler backends.
pub struct CapturedPvmRelation {
    airs: Vec<CapturedAir>,
}

impl CapturedPvmRelation {
    pub fn airs(&self) -> &[CapturedAir] {
        &self.airs
    }

    pub fn new() -> Result<Self, AceError> {
        Ok(Self {
            airs: AIRS.iter().map(CapturedAir::new).collect::<Result<_, _>>()?,
        })
    }

    pub fn compile(&self) -> Result<CompiledRelation<'_>, AceError> {
        let airs: Vec<_> = self.airs.iter().collect();
        CompiledRelation::from_captured(&airs, crate::precompiles::ace::LMCS_ALIGNMENT)
    }
}
