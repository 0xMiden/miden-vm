//! Generates Miden assembly from VM profiles

use std::fmt::Write;

use anyhow::Result;

use crate::profile::VmProfile;

/// Cycle costs for individual operations (measured from actual execution)
pub const CYCLES_PER_HPERM: u64 = 1;
pub const CYCLES_PER_HMERGE: u64 = 16;
pub const CYCLES_PER_FALCON512_VERIFY: u64 = 59859;
pub const CYCLES_PER_LOAD_STORE: u64 = 10; // Approximate for push+store+load+drop
const MAX_REPEAT: u64 = 1000;

/// Generates masm code for a synthetic transaction kernel
pub struct MasmGenerator {
    profile: VmProfile,
    trace_scale: f64,
}

impl MasmGenerator {
    pub fn new(profile: VmProfile) -> Self {
        Self { profile, trace_scale: 1.0 }
    }

    pub fn with_trace_scale(mut self, trace_scale: f64) -> Self {
        self.trace_scale = if trace_scale.is_finite() && trace_scale > 0.0 {
            trace_scale
        } else {
            1.0
        };
        self
    }

    /// Generate the complete synthetic kernel program
    pub fn generate_kernel(&self) -> Result<String> {
        let mut code = String::new();
        let kernel = &self.profile.transaction_kernel;

        // Header
        writeln!(code, "# Synthetic Transaction Kernel")?;
        writeln!(code, "# Generated from: {}", self.profile.source)?;
        writeln!(code, "# Version: {}\n", self.profile.miden_vm_version)?;

        // Use core library for crypto operations
        writeln!(code, "use miden::core::crypto::dsa::falcon512poseidon2")?;
        writeln!(code, "use miden::core::crypto::hashes::poseidon2\n")?;

        // Main program
        writeln!(code, "begin")?;
        writeln!(code, "    # Synthetic transaction kernel")?;
        writeln!(code, "    # Total cycles: {}", kernel.total_cycles)?;
        writeln!(code, "    # Instruction mix: {:?}\n", kernel.instruction_mix)?;

        // Generate each phase
        for (phase_name, phase) in &kernel.phases {
            code.push_str(&self.generate_phase(phase_name, phase)?);
        }

        writeln!(code, "end")?;
        Ok(code)
    }

    fn generate_phase(&self, name: &str, phase: &crate::profile::PhaseProfile) -> Result<String> {
        let mut code = String::new();
        code.push_str(&format!("    # Phase: {} ({} cycles)\n", name, phase.cycles));

        // If phase has specific operations defined, use those
        if !phase.operations.is_empty() {
            for (op_name, count) in &phase.operations {
                let scaled = self.scale_count(*count);
                code.push_str(&self.generate_operation(op_name, scaled)?);
            }
        } else {
            // Otherwise, generate operations based on instruction mix
            code.push_str(&self.generate_phase_from_mix(name, phase.cycles)?);
        }

        code.push('\n');
        Ok(code)
    }

    /// Generate operations for a phase based on the global instruction mix
    ///
    /// This generates a representative mix of operations that approximates the
    /// instruction mix without trying to exactly match every cycle (which would
    /// create an impractical number of operations).
    fn generate_phase_from_mix(&self, _phase_name: &str, phase_cycles: u64) -> Result<String> {
        let mix = &self.profile.transaction_kernel.instruction_mix;
        let mut code = String::new();

        // Scale down the operations to reasonable numbers while maintaining proportions
        // We target ~1000-10000 cycles per phase for the synthetic benchmark
        let scale_factor = if phase_cycles > 10000 {
            phase_cycles as f64 / 5000.0 // Scale to ~5000 cycles
        } else {
            1.0
        } * self.trace_scale;

        // Calculate how many of each operation to generate based on instruction mix
        let sig_verify_count = ((phase_cycles as f64 * mix.signature_verify)
            / CYCLES_PER_FALCON512_VERIFY as f64
            / scale_factor)
            .max(1.0) as u64;
        let hperm_count = ((phase_cycles as f64 * mix.hashing)
            / CYCLES_PER_HPERM as f64
            / scale_factor)
            .max(10.0) as u64;
        let load_store_count =
            ((phase_cycles as f64 * mix.memory) / CYCLES_PER_LOAD_STORE as f64 / scale_factor)
                .max(5.0) as u64;
        let arithmetic_count =
            ((phase_cycles as f64 * mix.arithmetic) / scale_factor).max(10.0) as u64;
        let control_count =
            ((phase_cycles as f64 * mix.control_flow) / 5.0 / scale_factor).max(5.0) as u64;

        // Generate signature verifications (most expensive operation)
        if mix.signature_verify > 0.0 {
            code.push_str(&self.generate_falcon_verify_block(sig_verify_count)?);
        }

        // Generate hashing operations
        if mix.hashing > 0.0 {
            code.push_str(&self.generate_hperm_block(hperm_count)?);
        }

        // Generate memory operations
        if mix.memory > 0.0 {
            code.push_str(&self.generate_load_store_block(load_store_count)?);
        }

        // Generate arithmetic operations (simple math)
        if mix.arithmetic > 0.0 {
            code.push_str(&self.generate_arithmetic_block(arithmetic_count)?);
        }

        // Generate control flow (loops, conditionals)
        if mix.control_flow > 0.0 {
            code.push_str(&self.generate_control_flow_block(control_count)?);
        }

        Ok(code)
    }

    fn scale_count(&self, count: u64) -> u64 {
        ((count as f64) / self.trace_scale).max(1.0) as u64
    }

    fn generate_operation(&self, op_name: &str, count: u64) -> Result<String> {
        match op_name {
            "hperm" => self.generate_hperm_block(count),
            "hmerge" => self.generate_hmerge_block(count),
            "mtree_get" => self.generate_mtree_get_block(count),
            "sig_verify_falcon512" => self.generate_falcon_verify_block(count),
            _ => Ok(format!("    # {} {} operations (unimplemented)\n", count, op_name)),
        }
    }

    fn generate_hperm_block(&self, count: u64) -> Result<String> {
        let mut code = String::new();
        code.push_str(&format!("    # {} hperm operations\n", count));

        // Set up initial hash state (12 elements)
        code.push_str("    # Initialize hash state\n");
        code.push_str("    padw padw padw\n");

        // Generate hperm operations in a loop
        if count > 100 {
            push_repeat_block(&mut code, count, "    ", &["hperm"]);
        } else {
            for _ in 0..count {
                code.push_str("    hperm\n");
            }
        }

        // Clean up stack
        code.push_str("    dropw dropw dropw\n");
        Ok(code)
    }

    fn generate_hmerge_block(&self, count: u64) -> Result<String> {
        let mut code = String::new();
        code.push_str(&format!("    # {} hmerge operations\n", count));

        // Generate hmerge operations with balanced stack per iteration
        let hmerge_body =
            ["push.1 push.2 push.3 push.4", "push.5 push.6 push.7 push.8", "hmerge", "dropw"];
        if count > 100 {
            push_repeat_block(&mut code, count, "    ", &hmerge_body);
        } else {
            for _ in 0..count {
                code.push_str("    push.1 push.2 push.3 push.4\n");
                code.push_str("    push.5 push.6 push.7 push.8\n");
                code.push_str("    hmerge\n");
                code.push_str("    dropw\n");
            }
        }
        Ok(code)
    }

    fn generate_mtree_get_block(&self, count: u64) -> Result<String> {
        let mut code = String::new();
        code.push_str(&format!("    # {} mtree_get operations\n", count));
        code.push_str("    # Note: mtree_get requires Merkle store setup\n");

        // Placeholder - mtree_get requires proper Merkle store initialization
        for _ in 0..count.min(10) {
            code.push_str("    # mtree_get (requires store setup)\n");
        }

        Ok(code)
    }

    fn generate_falcon_verify_block(&self, count: u64) -> Result<String> {
        let mut code = String::new();
        code.push_str(&format!("    # {} Falcon512 signature verifications\n", count));
        code.push_str(&format!(
            "    # Each verification is ~{} cycles\n",
            CYCLES_PER_FALCON512_VERIFY
        ));

        // For synthetic benchmarks, we simulate the cycle cost without actually
        // executing the verification (which requires advice inputs).
        // We use a loop of nop operations that approximates the cycle count.
        // Each loop iteration costs ~1 cycle (the nop itself + loop overhead).

        let scaled_cycles =
            ((CYCLES_PER_FALCON512_VERIFY as f64) / self.trace_scale).max(1.0) as u64;

        for _ in 0..count {
            code.push_str(&format!(
                "    # Simulating falcon512_verify cycle count (~{} cycles)\n",
                scaled_cycles
            ));
            push_repeat_block(&mut code, scaled_cycles, "    ", &["nop"]);
        }

        Ok(code)
    }

    fn generate_load_store_block(&self, count: u64) -> Result<String> {
        let mut code = String::new();
        code.push_str(&format!("    # {} load/store operations\n", count));

        if count > 100 {
            let body = [
                "push.1 push.2 push.3 push.4",
                "push.0 mem_storew_be",
                "push.0 mem_loadw_be",
                "dropw",
            ];
            push_repeat_block(&mut code, count, "    ", &body);
        } else {
            for _ in 0..count {
                code.push_str("    push.1 push.2 push.3 push.4\n");
                code.push_str("    push.0 mem_storew_be\n");
                code.push_str("    push.0 mem_loadw_be\n");
                code.push_str("    dropw\n");
            }
        }

        Ok(code)
    }

    fn generate_arithmetic_block(&self, count: u64) -> Result<String> {
        let mut code = String::new();
        code.push_str(&format!("    # {} arithmetic operations\n", count));

        // Use balanced operations that don't accumulate on the stack
        // Each iteration: push two values, add them, drop the result
        if count > 100 {
            push_repeat_block(&mut code, count, "    ", &["push.1 push.2 add drop"]);
        } else {
            for _ in 0..count {
                code.push_str("    push.1 push.2 add drop\n");
            }
        }

        Ok(code)
    }

    fn generate_control_flow_block(&self, count: u64) -> Result<String> {
        let mut code = String::new();
        code.push_str(&format!("    # {} control flow operations\n", count));

        // Simple control flow with if/else
        let iterations = count / 5; // Each iteration ~5 cycles
        if iterations > 10 {
            let body = ["push.1", "if.true", "    push.2", "else", "    push.3", "end", "drop"];
            push_repeat_block(&mut code, iterations.min(100), "    ", &body);
        } else {
            for _ in 0..iterations {
                code.push_str("    push.1\n");
                code.push_str("    if.true\n");
                code.push_str("        push.2\n");
                code.push_str("    else\n");
                code.push_str("        push.3\n");
                code.push_str("    end\n");
                code.push_str("    drop\n");
            }
        }

        Ok(code)
    }

    /// Generate a component benchmark for a specific operation type
    pub fn generate_component_benchmark(
        &self,
        operation: &str,
        iterations: usize,
    ) -> Result<String> {
        let mut code = String::new();

        writeln!(code, "# Component Benchmark: {}", operation)?;

        match operation {
            "falcon512_verify" => {
                writeln!(code, "use miden::core::crypto::dsa::falcon512poseidon2\n")?;
                writeln!(code, "begin")?;
                writeln!(code, "    # Stack must contain PK commitment and message inputs")?;
                writeln!(code, "    # Stack: [PK_COMMITMENT (4 elements), MSG (4 elements)]")?;
                let body = ["# Execute verification", "exec.falcon512poseidon2::verify", "drop"];
                push_repeat_block(&mut code, iterations as u64, "    ", &body);
                writeln!(code, "end")?;
            },
            "hperm" => {
                writeln!(code, "begin")?;
                writeln!(code, "    # Initialize hash state (12 elements)")?;
                writeln!(code, "    padw padw padw")?;
                push_repeat_block(&mut code, iterations as u64, "    ", &["hperm"]);
                writeln!(code, "    # Clean up")?;
                writeln!(code, "    dropw dropw dropw")?;
                writeln!(code, "end")?;
            },
            "hmerge" => {
                writeln!(code, "begin")?;
                let body = [
                    "push.1 push.2 push.3 push.4",
                    "push.5 push.6 push.7 push.8",
                    "hmerge",
                    "dropw",
                ];
                push_repeat_block(&mut code, iterations as u64, "    ", &body);
                writeln!(code, "end")?;
            },
            "load_store" => {
                writeln!(code, "begin")?;
                let body = [
                    "push.1 push.2 push.3 push.4",
                    "push.0 mem_storew_be",
                    "push.0 mem_loadw_be",
                    "dropw",
                ];
                push_repeat_block(&mut code, iterations as u64, "    ", &body);
                writeln!(code, "end")?;
            },
            "arithmetic" => {
                writeln!(code, "begin")?;
                push_repeat_block(
                    &mut code,
                    iterations as u64,
                    "    ",
                    &["push.1 push.2 add drop"],
                );
                writeln!(code, "end")?;
            },
            "control_flow" => {
                writeln!(code, "begin")?;
                let body = ["push.1", "if.true", "    push.2", "else", "    push.3", "end", "drop"];
                push_repeat_block(&mut code, iterations as u64, "    ", &body);
                writeln!(code, "end")?;
            },
            _ => {
                writeln!(code, "# {} operation (unimplemented)", operation)?;
                writeln!(code, "begin")?;
                push_repeat_block(&mut code, iterations as u64, "    ", &["nop"]);
                writeln!(code, "end")?;
            },
        }

        Ok(code)
    }
}

fn push_repeat_block(code: &mut String, count: u64, indent: &str, body_lines: &[&str]) {
    if count == 0 {
        return;
    }
    if count <= MAX_REPEAT {
        push_single_repeat_block(code, count, indent, body_lines);
        return;
    }

    let block_size = MAX_REPEAT * MAX_REPEAT;
    let mut remaining = count;

    while remaining >= block_size {
        push_nested_repeat_block(code, MAX_REPEAT, MAX_REPEAT, indent, body_lines);
        remaining -= block_size;
    }

    if remaining >= MAX_REPEAT {
        let outer = remaining / MAX_REPEAT;
        push_nested_repeat_block(code, outer, MAX_REPEAT, indent, body_lines);
        remaining %= MAX_REPEAT;
    }

    if remaining > 0 {
        push_single_repeat_block(code, remaining, indent, body_lines);
    }
}

fn push_single_repeat_block(code: &mut String, count: u64, indent: &str, body_lines: &[&str]) {
    writeln!(code, "{indent}repeat.{count}").unwrap();
    for line in body_lines {
        writeln!(code, "{indent}    {line}").unwrap();
    }
    writeln!(code, "{indent}end").unwrap();
}

fn push_nested_repeat_block(
    code: &mut String,
    outer: u64,
    inner: u64,
    indent: &str,
    body_lines: &[&str],
) {
    writeln!(code, "{indent}repeat.{outer}").unwrap();
    writeln!(code, "{indent}    repeat.{inner}").unwrap();
    for line in body_lines {
        writeln!(code, "{indent}        {line}").unwrap();
    }
    writeln!(code, "{indent}    end").unwrap();
    writeln!(code, "{indent}end").unwrap();
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use miden_core_lib::CoreLibrary;
    use miden_processor::{advice::AdviceInputs, fast::FastProcessor, ExecutionOptions};
    use miden_vm::{Assembler, DefaultHost, StackInputs};

    use super::*;
    use crate::{
        data_generator::Falcon512Generator,
        profile::{
            InstructionMix, PhaseProfile, ProcedureProfile, TransactionKernelProfile, VmProfile,
        },
    };

    fn test_generator() -> MasmGenerator {
        let profile = VmProfile {
            profile_version: "1.0.0".to_string(),
            source: "test".to_string(),
            timestamp: "2026-02-02T00:00:00Z".to_string(),
            miden_vm_version: "0.1.0".to_string(),
            transaction_kernel: TransactionKernelProfile {
                total_cycles: 0,
                trace_main_len: None,
                trace_padded_len: None,
                phases: BTreeMap::from([(
                    "prologue".to_string(),
                    PhaseProfile { cycles: 0, operations: BTreeMap::new() },
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
                operation_details: Vec::new(),
            },
        };

        MasmGenerator::new(profile)
    }

    #[test]
    fn component_benchmarks_assemble() {
        let generator = test_generator();
        let operations = [
            "falcon512_verify",
            "hperm",
            "hmerge",
            "load_store",
            "arithmetic",
            "control_flow",
        ];

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

            assembler.assemble_program(&source).expect("failed to assemble benchmark");
        }
    }

    #[test]
    fn component_benchmarks_execute() {
        let generator = test_generator();
        let operations = ["hperm", "hmerge", "load_store", "arithmetic", "control_flow"];

        for operation in operations {
            let source = generator
                .generate_component_benchmark(operation, 3)
                .expect("failed to generate benchmark");

            let program = Assembler::default()
                .assemble_program(&source)
                .expect("failed to assemble benchmark");

            let mut host = DefaultHost::default();
            let processor = FastProcessor::new_with_options(
                StackInputs::default(),
                AdviceInputs::default(),
                ExecutionOptions::default(),
            );
            let runtime = tokio::runtime::Runtime::new().expect("failed to create runtime");

            runtime
                .block_on(async { processor.execute(&program, &mut host).await })
                .expect("failed to execute benchmark");
        }
    }

    #[test]
    fn falcon512_component_benchmark_execute() {
        let generator = test_generator();
        let source = generator
            .generate_component_benchmark("falcon512_verify", 1)
            .expect("failed to generate benchmark");
        let program = Assembler::default()
            .with_dynamic_library(CoreLibrary::default())
            .expect("failed to load core library")
            .assemble_program(&source)
            .expect("failed to assemble benchmark");

        let verify_data =
            Falcon512Generator::generate_verify_data().expect("failed to generate verify data");
        let stack_inputs = verify_data.to_stack_inputs().expect("failed to build stack inputs");
        let advice_inputs = AdviceInputs::default().with_stack(verify_data.signature);

        let mut host = DefaultHost::default();
        host.load_library(&CoreLibrary::default()).expect("failed to load core library");
        let processor = FastProcessor::new_with_options(
            stack_inputs,
            advice_inputs,
            ExecutionOptions::default(),
        );
        let runtime = tokio::runtime::Runtime::new().expect("failed to create runtime");

        runtime
            .block_on(async { processor.execute(&program, &mut host).await })
            .expect("failed to execute benchmark");
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
