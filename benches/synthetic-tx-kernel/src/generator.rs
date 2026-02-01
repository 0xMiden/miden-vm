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

        // Imports
        code.push_str("use.miden::core::sys\n");
        code.push_str("use.miden::core::mem\n");
        code.push_str("use.miden::std::crypto::falcon::falcon512\n\n");

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

        code.push_str("\n    # Clean up stack\n");
        code.push_str("    exec.sys::truncate_stack\n");
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
        code.push_str("use.miden::core::sys\n\n");
        code.push_str("begin\n");
        code.push_str(&format!("    repeat.{}\n", iterations));
        code.push_str("        # Perform operation\n");
        code.push_str(&format!("        # {} operation here\n", operation));
        code.push_str("    end\n");
        code.push_str("    exec.sys::truncate_stack\n");
        code.push_str("end\n");

        Ok(code)
    }
}
