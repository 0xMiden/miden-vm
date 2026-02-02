//! Generates Miden assembly from VM profiles

use anyhow::Result;

use crate::profile::VmProfile;

/// Generates masm code for a synthetic transaction kernel
pub struct MasmGenerator {
    profile: VmProfile,
}

impl MasmGenerator {
    pub fn new(profile: VmProfile) -> Self {
        Self { profile }
    }

    /// Generate the complete synthetic kernel program
    pub fn generate_kernel(&self) -> Result<String> {
        let mut code = String::new();

        // Header
        code.push_str("# Synthetic Transaction Kernel\n");
        code.push_str(&format!("# Generated from: {}\n", self.profile.source));
        code.push_str(&format!("# Version: {}\n\n", self.profile.miden_vm_version));

        // Main program
        code.push_str("begin\n");
        code.push_str("    # Synthetic transaction kernel\n");
        code.push_str("    # Total cycles: ");
        code.push_str(&self.profile.transaction_kernel.total_cycles.to_string());
        code.push_str("\n\n");

        // Generate each phase
        for (phase_name, phase) in &self.profile.transaction_kernel.phases {
            code.push_str(&self.generate_phase(phase_name, phase)?);
        }

        code.push_str("end\n");

        Ok(code)
    }

    fn generate_phase(&self, name: &str, phase: &crate::profile::PhaseProfile) -> Result<String> {
        let mut code = String::new();
        code.push_str(&format!("    # Phase: {} ({} cycles)\n", name, phase.cycles));

        // Generate operations based on the phase's operation counts
        for (op_name, count) in &phase.operations {
            code.push_str(&self.generate_operation(op_name, *count)?);
        }

        code.push('\n');
        Ok(code)
    }

    fn generate_operation(&self, op_name: &str, count: u64) -> Result<String> {
        // Map operation names to masm code
        match op_name {
            "hperm" => Ok(format!("    # {} hperm operations\n", count)),
            "hmerge" => Ok(format!("    # {} hmerge operations\n", count)),
            "mtree_get" => Ok(format!("    # {} mtree_get operations\n", count)),
            "sig_verify_falcon512" => self.generate_falcon_verify(count),
            _ => Ok(format!("    # {} {} operations (unimplemented)\n", count, op_name)),
        }
    }

    fn generate_falcon_verify(&self, count: u64) -> Result<String> {
        let mut code = String::new();
        code.push_str(&format!("    # {} Falcon512 signature verifications\n", count));
        // Placeholder - actual implementation would call falcon512 verify
        code.push_str("    # exec.falcon512::verify\n");
        Ok(code)
    }

    /// Generate a component benchmark for a specific operation type
    pub fn generate_component_benchmark(
        &self,
        operation: &str,
        iterations: usize,
    ) -> Result<String> {
        let mut code = String::new();

        code.push_str(&format!("# Component Benchmark: {}\n", operation));
        if operation == "falcon512_verify" {
            code.push_str("use miden::core::crypto::dsa::falcon512poseidon2\n\n");
        }
        code.push_str("begin\n");
        code.push_str(&format!("    repeat.{}\n", iterations));

        // Generate actual operations based on the operation type
        match operation {
            "falcon512_verify" => {
                code.push_str("        exec.falcon512poseidon2::verify\n");
            }
            "hperm" => {
                code.push_str("        hperm\n");
            }
            "hmerge" => {
                code.push_str("        hmerge\n");
            }
            "load_store" => {
                code.push_str("        push.0 mem_storew_be\n");
                code.push_str("        push.0 mem_loadw_be\n");
                code.push_str("        dropw\n");
            }
            _ => {
                code.push_str(&format!("        # {} operation (unimplemented)\n", operation));
                code.push_str("        nop\n");
            }
        }

        code.push_str("    end\n");
        code.push_str("end\n");

        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{
        InstructionMix, PhaseProfile, ProcedureProfile, TransactionKernelProfile, VmProfile,
    };
    use miden_core_lib::CoreLibrary;
    use miden_vm::Assembler;
    use std::collections::BTreeMap;

    fn test_generator() -> MasmGenerator {
        let profile = VmProfile {
            profile_version: "1.0.0".to_string(),
            source: "test".to_string(),
            timestamp: "2026-02-02T00:00:00Z".to_string(),
            miden_vm_version: "0.1.0".to_string(),
            transaction_kernel: TransactionKernelProfile {
                total_cycles: 0,
                phases: BTreeMap::from([(
                    "prologue".to_string(),
                    PhaseProfile {
                        cycles: 0,
                        operations: BTreeMap::new(),
                    },
                )]),
                instruction_mix: InstructionMix {
                    arithmetic: 0.2,
                    hashing: 0.2,
                    memory: 0.2,
                    control_flow: 0.2,
                    signature_verify: 0.2,
                },
                key_procedures: vec![ProcedureProfile {
                    name: "auth_procedure".to_string(),
                    cycles: 0,
                    invocations: 0,
                }],
            },
        };

        MasmGenerator::new(profile)
    }

    #[test]
    fn component_benchmarks_assemble() {
        let generator = test_generator();
        let operations = ["falcon512_verify", "hperm", "hmerge", "load_store"];

        for operation in operations {
            let source = generator
                .generate_component_benchmark(operation, 1)
                .expect("failed to generate benchmark");

            let assembler = if operation == "falcon512_verify" {
                Assembler::default()
                    .with_dynamic_library(CoreLibrary::default())
                    .expect("failed to load core library")
            } else {
                Assembler::default()
            };

            assembler
                .assemble_program(&source)
                .expect("failed to assemble benchmark");
        }
    }

    #[test]
    fn falcon512_component_benchmark_emits_verify() {
        let generator = test_generator();
        let source = generator
            .generate_component_benchmark("falcon512_verify", 1)
            .expect("failed to generate benchmark");

        assert!(source.contains("exec.falcon512poseidon2::verify"));
    }
}
