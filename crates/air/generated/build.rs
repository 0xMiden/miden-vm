use std::{env, fs, path::PathBuf};

use miden_air_definitions::compiler::vm::{CompiledRelation, LayoutKind, capture_vm_airs};
use miden_constraint_compiler::backend::{
    rust_descriptor::{self, AirDescriptorEmitter},
    rust_eval::{AirEvaluator, emit_native_optimized_module},
};

#[path = "build/precompiles.rs"]
mod precompiles;
#[path = "build/preparation_pilot.rs"]
mod preparation_pilot;
#[path = "build/symbolic_fixture.rs"]
mod symbolic_fixture;

fn main() {
    precompiles::generate();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build/preparation_pilot.rs");
    println!("cargo:rerun-if-changed=build/preparation_fixture.rs");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"));
    preparation_pilot::generate(&out);
    println!("cargo:rerun-if-changed=build/symbolic_fixture.rs");
    fs::write(out.join("symbolic_operations_fixture.rs"), symbolic_fixture::generate())
        .expect("write rich-operation execution fixture");
    let write = |name: &str, contents: String| {
        let path = out.join(name);
        fs::write(&path, contents)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
    };
    let captured = capture_vm_airs().expect("capture canonical VM sources");
    let labels: Vec<_> =
        captured.iter().map(|(air, _)| format!("MidenAir::{}", air.name())).collect();
    let evals: Vec<_> = captured
        .iter()
        .zip(&labels)
        .map(|((air, captured), label)| AirEvaluator {
            name: air.file_token(),
            air_label: label,
            program: captured.program(),
            descriptor: captured.descriptor(),
        })
        .collect();
    let descriptors: Vec<_> = captured
        .iter()
        .zip(&labels)
        .map(|((air, captured), label)| AirDescriptorEmitter {
            name: air.file_token(),
            air_label: label,
            descriptor: captured.descriptor(),
        })
        .collect();
    write("native_evaluators.rs", emit_native_optimized_module("", &evals));
    write("native_descriptors.rs", rust_descriptor::emit_module("", &descriptors));
    let airs: Vec<_> = captured.iter().map(|(_, air)| air).collect();
    let relation = CompiledRelation::from_captured(&airs, miden_crypto::hash::eidos::BLOCK_LEN)
        .expect("compile VM relation");
    write(
        "air_shape.rs",
        format!("{:?}", miden_air_definitions::compiler::vm::air_shape(&relation)),
    );
    write("raw_widths.rs", format!("{:?}", relation.geometry().raw_widths()));
    let circuit: miden_air_definitions::vm::ace::RecursiveAceCircuit = relation
        .build_circuit(LayoutKind::Masm)
        .expect("canonical VM ACE circuit")
        .to_ace()
        .expect("encode VM ACE")
        .try_into()
        .expect("VM recursive circuit");
    write(
        "ace_circuit_shape.rs",
        format!("{:?}", (circuit.num_inputs, circuit.num_eval_gates, circuit.stream_len)),
    );
    write(
        "ace_instructions.rs",
        format!(
            "{:?}",
            circuit
                .instructions
                .iter()
                .map(miden_air_definitions::vm::Felt::as_canonical_u64)
                .collect::<Vec<_>>()
        ),
    );
}
