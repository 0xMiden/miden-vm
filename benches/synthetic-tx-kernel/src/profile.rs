//! VM profile types (mirrors miden-base profile format)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmProfile {
    /// Profile format version (expected format: "major.minor.patch", e.g., "1.0.0")
    pub profile_version: String,
    pub source: String,
    /// ISO 8601 formatted timestamp (e.g., "2024-01-15T10:30:00Z")
    pub timestamp: String,
    /// Miden VM version (expected format: "major.minor.patch", e.g., "0.20.0")
    pub miden_vm_version: String,
    pub transaction_kernel: TransactionKernelProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionKernelProfile {
    pub total_cycles: u64,
    /// Phase names are expected to be from a fixed set:
    /// "prologue", "notes_processing", "tx_script_processing", "epilogue"
    pub phases: BTreeMap<String, PhaseProfile>,
    pub instruction_mix: InstructionMix,
    pub key_procedures: Vec<ProcedureProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseProfile {
    pub cycles: u64,
    /// Operation types are expected to be from a fixed set:
    /// "hperm", "hmerge", "mtree_get", "sig_verify_falcon512"
    pub operations: BTreeMap<String, u64>,
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
    /// Validates that:
    /// - All individual values are between 0.0 and 1.0 (inclusive)
    /// - Values sum to approximately 1.0 (within 1% tolerance)
    pub fn validate(&self) -> anyhow::Result<()> {
        // Check each field is in valid range [0.0, 1.0]
        let fields = [
            ("arithmetic", self.arithmetic),
            ("hashing", self.hashing),
            ("memory", self.memory),
            ("control_flow", self.control_flow),
            ("signature_verify", self.signature_verify),
        ];

        for (name, value) in fields {
            if !(0.0..=1.0).contains(&value) {
                anyhow::bail!(
                    "Instruction mix field '{}' must be between 0.0 and 1.0, got {}",
                    name,
                    value
                );
            }
        }

        // Check sum is approximately 1.0
        let total = self.arithmetic
            + self.hashing
            + self.memory
            + self.control_flow
            + self.signature_verify;
        if (total - 1.0).abs() > 0.01 {
            anyhow::bail!("Instruction mix percentages sum to {}, expected ~1.0", total);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_valid_instruction_mix() -> InstructionMix {
        InstructionMix {
            arithmetic: 0.05,
            hashing: 0.45,
            memory: 0.08,
            control_flow: 0.05,
            signature_verify: 0.37,
        }
    }

    fn create_valid_vm_profile() -> VmProfile {
        let mut phases = BTreeMap::new();
        phases.insert(
            "prologue".to_string(),
            PhaseProfile {
                cycles: 3173,
                operations: BTreeMap::new(),
            },
        );
        phases.insert(
            "epilogue".to_string(),
            PhaseProfile {
                cycles: 63977,
                operations: BTreeMap::new(),
            },
        );

        VmProfile {
            profile_version: "1.0.0".to_string(),
            source: "test".to_string(),
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            miden_vm_version: "0.20.0".to_string(),
            transaction_kernel: TransactionKernelProfile {
                total_cycles: 73123,
                phases,
                instruction_mix: create_valid_instruction_mix(),
                key_procedures: vec![ProcedureProfile {
                    name: "auth_procedure".to_string(),
                    cycles: 62667,
                    invocations: 1,
                }],
            },
        }
    }

    #[test]
    fn instruction_mix_valid_passes() {
        let mix = create_valid_instruction_mix();
        assert!(mix.validate().is_ok());
    }

    #[test]
    fn instruction_mix_negative_value_fails() {
        let mix = InstructionMix {
            arithmetic: -0.1,
            hashing: 0.5,
            memory: 0.2,
            control_flow: 0.2,
            signature_verify: 0.2,
        };
        assert!(mix.validate().is_err());
    }

    #[test]
    fn instruction_mix_value_over_one_fails() {
        let mix = InstructionMix {
            arithmetic: 1.5,
            hashing: 0.5,
            memory: 0.2,
            control_flow: 0.2,
            signature_verify: 0.2,
        };
        assert!(mix.validate().is_err());
    }

    #[test]
    fn instruction_mix_sum_not_one_fails() {
        let mix = InstructionMix {
            arithmetic: 0.3,
            hashing: 0.3,
            memory: 0.2,
            control_flow: 0.2,
            signature_verify: 0.2,
        };
        let result = mix.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("sum to"));
    }

    #[test]
    fn instruction_mix_sum_within_tolerance_passes() {
        let mix = InstructionMix {
            arithmetic: 0.2001,
            hashing: 0.1999,
            memory: 0.2,
            control_flow: 0.2,
            signature_verify: 0.2,
        };
        assert!(mix.validate().is_ok());
    }

    #[test]
    fn serde_roundtrip_vm_profile() {
        let original = create_valid_vm_profile();
        let json = serde_json::to_string(&original).expect("serialize failed");
        let deserialized: VmProfile = serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(original.profile_version, deserialized.profile_version);
        assert_eq!(original.source, deserialized.source);
        assert_eq!(original.timestamp, deserialized.timestamp);
        assert_eq!(original.miden_vm_version, deserialized.miden_vm_version);
        assert_eq!(
            original.transaction_kernel.total_cycles,
            deserialized.transaction_kernel.total_cycles
        );
        assert_eq!(
            original.transaction_kernel.phases.len(),
            deserialized.transaction_kernel.phases.len()
        );
        assert_eq!(
            original.transaction_kernel.key_procedures.len(),
            deserialized.transaction_kernel.key_procedures.len()
        );
    }

    #[test]
    fn serde_empty_hashmaps() {
        let profile = VmProfile {
            profile_version: "1.0.0".to_string(),
            source: "test".to_string(),
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            miden_vm_version: "0.20.0".to_string(),
            transaction_kernel: TransactionKernelProfile {
                total_cycles: 0,
                phases: BTreeMap::new(),
                instruction_mix: InstructionMix {
                    arithmetic: 0.2,
                    hashing: 0.2,
                    memory: 0.2,
                    control_flow: 0.2,
                    signature_verify: 0.2,
                },
                key_procedures: vec![],
            },
        };

        let json = serde_json::to_string(&profile).expect("serialize failed");
        let deserialized: VmProfile = serde_json::from_str(&json).expect("deserialize failed");

        assert!(deserialized.transaction_kernel.phases.is_empty());
        assert!(deserialized.transaction_kernel.key_procedures.is_empty());
    }

    #[test]
    fn serde_zero_cycles() {
        let mut phases = BTreeMap::new();
        phases.insert(
            "prologue".to_string(),
            PhaseProfile { cycles: 0, operations: BTreeMap::new() },
        );

        let profile = VmProfile {
            profile_version: "1.0.0".to_string(),
            source: "test".to_string(),
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            miden_vm_version: "0.20.0".to_string(),
            transaction_kernel: TransactionKernelProfile {
                total_cycles: 0,
                phases,
                instruction_mix: InstructionMix {
                    arithmetic: 0.2,
                    hashing: 0.2,
                    memory: 0.2,
                    control_flow: 0.2,
                    signature_verify: 0.2,
                },
                key_procedures: vec![],
            },
        };

        let json = serde_json::to_string(&profile).expect("serialize failed");
        let deserialized: VmProfile = serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(deserialized.transaction_kernel.total_cycles, 0);
        let prologue = deserialized
            .transaction_kernel
            .phases
            .get("prologue")
            .expect("prologue phase missing");
        assert_eq!(prologue.cycles, 0);
    }
}
