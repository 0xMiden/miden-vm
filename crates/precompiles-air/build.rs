use std::{env, fmt::Write as _, fs, path::PathBuf};

use miden_ace_codegen::{LayoutKind, RecursiveAceCircuit};
use miden_constraint_compiler::backend::rust_eval::{AirEvaluator, emit_module};
use miden_precompiles_air_definitions::{
    geometry,
    relation::{AIR_DECLARATIONS, CapturedPvmRelation, RelationSelection},
};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"));
    let write = |name: &str, contents: String| {
        let path = out.join(name);
        fs::write(&path, contents)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
    };
    let captured = CapturedPvmRelation::new().expect("capture declared PVM AIRs");
    let labels: Vec<_> = AIR_DECLARATIONS
        .iter()
        .map(|declaration| declaration.air.file_token())
        .collect();
    let evals: Vec<_> = captured
        .airs()
        .iter()
        .zip(&labels)
        .map(|(air, label)| AirEvaluator {
            name: label,
            air_label: label,
            graph: air.graph(),
            constraints: air.constraints(),
        })
        .collect();
    write("evaluators.rs", emit_module("", &evals));
    let degree_arms = AIR_DECLARATIONS
        .iter()
        .zip(captured.airs())
        .map(|(declaration, air)| {
            format!("ChipletAir::{:?} => {:?},", declaration.air, air.degrees())
        })
        .collect::<String>();
    write(
        "degrees.rs",
        format!(
            "fn generated_degrees(air: &ChipletAir) -> ConstraintDegrees {{ match air {{ \
             {degree_arms} }} }}"
        ),
    );

    let mut source = String::new();
    let mut entries = String::new();
    let mut instruction_arms = String::new();
    for selection in RelationSelection::all() {
        let compiled = captured.compile(selection).expect("compile declared PVM member");
        let circuit: RecursiveAceCircuit = compiled
            .build_circuit(LayoutKind::Masm)
            .expect("PVM ACE circuit")
            .to_ace()
            .expect("encode PVM ACE")
            .try_into()
            .expect("PVM recursive circuit");
        let mask = selection.mask();
        writeln!(
            source,
            "const METADATA_{mask}: ProtocolMetadata = ProtocolMetadata {{ selection_mask: {mask}, \
             circuit_shape: {:?}, air_shape: {:?}, raw_widths: &{:?}, num_quotient_chunks: {} }};",
            (circuit.num_inputs, circuit.num_eval_gates, circuit.stream_len),
            geometry::air_shape(&compiled, selection),
            compiled.geometry().raw_widths(),
            compiled.geometry().num_quotient_chunks
        )
        .unwrap();
        write!(entries, "METADATA_{mask},").unwrap();
        write(
            &format!("ace_instructions_{mask}.rs"),
            format!(
                "{:?}",
                circuit
                    .instructions
                    .iter()
                    .map(miden_core::Felt::as_canonical_u64)
                    .collect::<Vec<_>>()
            ),
        );
        writeln!(
            source,
            "static ACE_INSTRUCTIONS_{mask}: &[u64] = \
             &include!(concat!(env!(\"OUT_DIR\"), \"/ace_instructions_{mask}.rs\"));"
        )
        .unwrap();
        write!(instruction_arms, "{mask} => ACE_INSTRUCTIONS_{mask},").unwrap();
    }
    writeln!(
        source,
        "/// Build-compiled metadata of every declared relation member.\n\
         pub const PROTOCOLS: &[ProtocolMetadata] = &[{entries}];\n\
         const FULL_METADATA: ProtocolMetadata = METADATA_{full};\n\
         fn generated_instructions(mask: u32) -> &'static [u64] {{ match mask {{ \
         {instruction_arms} _ => unreachable!(\"validated relation selection\") }} }}",
        full = RelationSelection::FULL.mask()
    )
    .unwrap();
    write("protocol.rs", source);
}
