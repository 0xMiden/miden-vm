use std::{env, fs, path::PathBuf};

use miden_air_definitions::{
    AIRS,
    ace::{CapturedAir, CompiledRelation, LayoutKind},
    config,
};
use miden_constraint_compiler::backend::rust_eval::{AirEvaluator, emit_module};

#[path = "build/precompiles.rs"]
mod precompiles;

fn main() {
    precompiles::generate();
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"));
    let write = |name: &str, contents: String| {
        let path = out.join(name);
        fs::write(&path, contents)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
    };
    let captured: Vec<_> = AIRS
        .iter()
        .copied()
        .map(|air| (air, CapturedAir::new(&air).expect("capture VM AIR")))
        .collect();
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
    write("evaluators.rs", emit_module("", &evals));
    let degree_arms = captured
        .iter()
        .map(|(air, captured)| format!("MidenAir::{} => {:?},", air.name(), captured.degrees()))
        .collect::<String>();
    write(
        "degrees.rs",
        format!(
            "pub(super) fn generated_degrees(air: MidenAir) -> ConstraintDegrees {{ match air {{ \
             {degree_arms} }} }}"
        ),
    );
    let airs: Vec<_> = captured.iter().map(|(_, air)| air).collect();
    let relation =
        CompiledRelation::from_captured(&airs, config::SPONGE_RATE).expect("compile VM relation");
    write(
        "air_shape.rs",
        format!("{:?}", miden_air_definitions::geometry::air_shape(&relation)),
    );
    write("raw_widths.rs", format!("{:?}", relation.geometry().raw_widths()));
    let circuit: miden_air_definitions::ace::RecursiveAceCircuit = relation
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
                .map(miden_air_definitions::Felt::as_canonical_u64)
                .collect::<Vec<_>>()
        ),
    );
}
