use std::{env, fs, path::PathBuf};

use miden_air_definitions::compiler::vm::{CompiledRelation, LayoutKind, capture_vm_airs};
use miden_constraint_compiler::backend::{
    rust_descriptor::{self, AirDescriptorEmitter},
    rust_eval::{
        AirEvaluator, NativeAirEvaluator, emit_native_optimized_module, emit_optimized_module,
    },
};

#[path = "build/precompiles.rs"]
mod precompiles;
#[path = "build/preparation_pilot.rs"]
mod preparation_pilot;

fn main() {
    precompiles::generate();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build/preparation_pilot.rs");
    println!("cargo:rerun-if-changed=build/preparation_fixture.rs");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"));
    preparation_pilot::generate(&out);
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
            graph: captured.graph(),
            constraints: captured.constraints(),
        })
        .collect();
    write("evaluators.rs", emit_optimized_module("", &evals));
    let native: Vec<_> = captured
        .iter()
        .zip(&labels)
        .filter_map(|((air, captured), label)| {
            captured.descriptor().map(|descriptor| (air, captured, label, descriptor))
        })
        .collect();
    let native_evals: Vec<_> = native
        .iter()
        .map(|(air, captured, label, descriptor)| NativeAirEvaluator {
            eval: AirEvaluator {
                name: air.file_token(),
                air_label: label,
                graph: captured.graph(),
                constraints: captured.constraints(),
            },
            descriptor,
        })
        .collect();
    let native_descriptors: Vec<_> = native
        .iter()
        .map(|(air, _, label, descriptor)| AirDescriptorEmitter {
            name: air.file_token(),
            air_label: label,
            descriptor,
        })
        .collect();
    write("native_evaluators.rs", emit_native_optimized_module("", &native_evals));
    write("native_descriptors.rs", rust_descriptor::emit_module("", &native_descriptors));
    let degree_arms = captured
        .iter()
        .map(|(air, captured)| {
            format!("source::MidenAir::{} => {:?},", air.name(), captured.degrees())
        })
        .collect::<String>();
    write(
        "degrees.rs",
        format!(
            "fn generated_degrees(air: MidenAir) -> ConstraintDegrees {{ match air.0 {{ \
             {degree_arms} }} }}"
        ),
    );
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
