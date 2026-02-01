//! VM profile types (mirrors miden-base profile format)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmProfile {
    pub profile_version: String,
    pub source: String,
    pub timestamp: String,
    pub miden_vm_version: String,
    pub transaction_kernel: TransactionKernelProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionKernelProfile {
    pub total_cycles: u64,
    pub phases: HashMap<String, PhaseProfile>,
    pub instruction_mix: InstructionMix,
    pub key_procedures: Vec<ProcedureProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseProfile {
    pub cycles: u64,
    pub operations: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionMix {
    pub arithmetic: f64,
    pub hashing: f64,
    pub memory: f64,
    pub control_flow: f64,
    pub signature_verify: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcedureProfile {
    pub name: String,
    pub cycles: u64,
    pub invocations: u64,
}

impl InstructionMix {
    /// Validate that mix percentages sum to approximately 1.0
    pub fn validate(&self) -> anyhow::Result<()> {
        let total = self.arithmetic + self.hashing + self.memory + self.control_flow + self.signature_verify;
        if (total - 1.0).abs() > 0.01 {
            anyhow::bail!("Instruction mix percentages sum to {}, expected ~1.0", total);
        }
        Ok(())
    }
}
