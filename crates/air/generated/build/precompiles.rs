use std::{env, fs, path::PathBuf};

use miden_ace::{RecursiveAceCircuit, compiler::LayoutKind};
use miden_air_definitions::{
    compiler::precompiles::{self as compiler, CapturedPvmRelation},
    precompiles::{fixed, relation::AIRS},
};
use miden_constraint_compiler::backend::{
    rust_descriptor::{self, AirDescriptorEmitter},
    rust_eval::{AirEvaluator, emit_native_optimized_module},
};

pub fn generate() {
    println!("cargo:rerun-if-changed=build/precompiles.rs");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"));
    let write = |name: &str, contents: String| {
        let path = out.join(format!("pvm_{name}"));
        fs::write(&path, contents)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
    };
    let captured = CapturedPvmRelation::new().expect("capture PVM AIRs");
    assert_eq!(captured.airs().len(), AIRS.len(), "canonical PVM capture count");
    let evals: Vec<_> = captured
        .airs()
        .iter()
        .zip(&AIRS)
        .map(|(air, declaration)| AirEvaluator {
            name: declaration.file_token(),
            air_label: declaration.file_token(),
            program: air.program(),
            descriptor: air.descriptor(),
        })
        .collect();
    let descriptors: Vec<_> = captured
        .airs()
        .iter()
        .zip(&AIRS)
        .map(|(air, declaration)| AirDescriptorEmitter {
            name: declaration.file_token(),
            air_label: declaration.file_token(),
            descriptor: air.descriptor(),
        })
        .collect();
    write("native_evaluators.rs", emit_native_optimized_module("", &evals));
    write("native_descriptors.rs", rust_descriptor::emit_module("", &descriptors));
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
    let fixed_boundary_lookup_terms =
        fixed::fixed_uintval_msgs().count() + fixed::fixed_ecgroup_msgs().count();
    write(
        "protocol.rs",
        format!(
            "pub const PROTOCOL: ProtocolMetadata = ProtocolMetadata {{ circuit_shape: {:?}, air_shape: {:?}, raw_widths: &{:?}, num_quotient_chunks: {}, fixed_boundary_lookup_terms: {} }};",
            (circuit.num_inputs, circuit.num_eval_gates, circuit.stream_len),
            compiler::air_shape(&compiled),
            compiled.geometry().raw_widths(),
            compiled.geometry().num_quotient_chunks,
            fixed_boundary_lookup_terms
        ),
    );
}
