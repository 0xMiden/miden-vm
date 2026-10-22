use std::{env, fs, path::PathBuf};

use miden_ace_codegen::{LayoutKind, RecursiveAceCircuit};
use miden_air_definitions::precompiles::{
    geometry,
    relation::{AIRS, CapturedPvmRelation},
};
use miden_constraint_compiler::backend::rust_eval::{AirEvaluator, emit_module};

pub fn generate() {
    println!("cargo:rerun-if-changed=build/precompiles.rs");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"));
    let write = |name: &str, contents: String| {
        let path = out.join(format!("pvm_{name}"));
        fs::write(&path, contents)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
    };
    let captured = CapturedPvmRelation::new().expect("capture PVM AIRs");
    let evals: Vec<_> = captured
        .airs()
        .iter()
        .zip(&AIRS)
        .map(|(air, declaration)| AirEvaluator {
            name: declaration.file_token(),
            air_label: declaration.file_token(),
            graph: air.graph(),
            constraints: air.constraints(),
        })
        .collect();
    write("evaluators.rs", emit_module("", &evals));
    let degree_arms = AIRS
        .iter()
        .zip(captured.airs())
        .map(|(air, capture)| format!("ChipletAir::{air:?} => {:?},", capture.degrees()))
        .collect::<String>();
    write(
        "degrees.rs",
        format!(
            "pub(super) fn generated_degrees(air: &ChipletAir) -> ConstraintDegrees {{ match air {{ {degree_arms} }} }}"
        ),
    );
    let compiled = captured.compile().expect("compile PVM relation");
    let circuit: RecursiveAceCircuit = compiled
        .build_circuit(LayoutKind::Masm)
        .expect("PVM ACE circuit")
        .to_ace()
        .expect("encode PVM ACE")
        .try_into()
        .expect("PVM recursive circuit");
    write(
        "ace_instructions.rs",
        format!(
            "{:?}",
            circuit
                .instructions
                .iter()
                .map(miden_core::Felt::as_canonical_u64)
                .collect::<Vec<_>>()
        ),
    );
    write(
        "protocol.rs",
        format!(
            "pub const PROTOCOL: ProtocolMetadata = ProtocolMetadata {{ circuit_shape: {:?}, air_shape: {:?}, raw_widths: &{:?}, num_quotient_chunks: {} }};",
            (circuit.num_inputs, circuit.num_eval_gates, circuit.stream_len),
            geometry::air_shape(&compiled),
            compiled.geometry().raw_widths(),
            compiled.geometry().num_quotient_chunks
        ),
    );
}
