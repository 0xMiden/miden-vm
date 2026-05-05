use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use std::{fs, io, println};

use miden_ace_codegen::{AceCircuit, AceConfig, LayoutKind, build_ace_circuit_for_air};
use miden_air::ProcessorAir;
use miden_core::{Felt, crypto::hash::Poseidon2, field::QuadFelt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Check,
    Write,
}

const MASM_CONFIG: AceConfig = AceConfig {
    num_quotient_chunks: 8,
    layout: LayoutKind::Masm,
};
pub const RELATION_DIGEST_PATHS: (&str, &str) =
    ("asm/sys/vm/mod.masm", "asm/sys/vm/constraints_eval.masm");

const PROTOCOL_ID: u64 = 0;
const AIR_CONFIG_PATH: &str = "../../../air/src/config.rs";
const CONSTRAINTS_EVAL_PATH: &str = "asm/sys/vm/constraints_eval.masm";
const RELATION_DIGEST_PATH: &str = RELATION_DIGEST_PATHS.0;

/// Builds the ACE circuit used by the Miden VM recursive verifier.
pub fn build_circuit(config: AceConfig) -> AceCircuit<QuadFelt> {
    let air = ProcessorAir;
    build_ace_circuit_for_air::<_, Felt, QuadFelt>(&air, config).unwrap()
}

/// Computes the relation digest used by recursive verification.
pub fn compute_relation_digest(circuit_commitment: &[Felt; 4]) -> [Felt; 4] {
    let input: Vec<Felt> = core::iter::once(Felt::new_unchecked(PROTOCOL_ID))
        .chain(circuit_commitment.iter().copied())
        .collect();
    let digest = Poseidon2::hash_elements(&input);
    let elems = digest.as_elements();
    [elems[0], elems[1], elems[2], elems[3]]
}

/// Runs write (`--write`) or staleness-check (`--check`) mode.
pub fn run(mode: Mode) -> Result<(), String> {
    match mode {
        Mode::Check => check(),
        Mode::Write => write().map_err(|e| format!("{e}")),
    }
}

/// Runs the full regeneration flow.
fn write() -> io::Result<()> {
    let artifact = compute_artifacts()?;
    write_artifacts(&artifact)
}

/// Checks generated artifacts against current AIR-derived values.
fn check() -> Result<(), String> {
    constraints_eval_masm_matches_air()?;
    relation_digest_matches_air()?;
    Ok(())
}

/// Generate a full computed snapshot from the current AIR.
fn compute_artifacts() -> io::Result<ComputedArtifacts> {
    let circuit = build_circuit(MASM_CONFIG);
    let encoded = circuit.to_ace().unwrap();

    let num_inputs = encoded.num_vars();
    let num_eval_gates = encoded.num_eval_rows();
    let instructions = encoded.instructions();
    let size_in_felt = encoded.size_in_felt();
    if !size_in_felt.is_multiple_of(8) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "circuit size_in_felt ({size_in_felt}) is not 8-aligned; adv_pipe requires 8-element chunks"
            ),
        ));
    }
    let adv_pipe_rows = size_in_felt / 8;

    let circuit_commitment: [Felt; 4] = encoded.circuit_hash().into();
    let relation_digest = compute_relation_digest(&circuit_commitment);

    let mut constraints_eval = read_file(CONSTRAINTS_EVAL_PATH);
    {
        replace_masm_const(&mut constraints_eval, "NUM_INPUTS_CIRCUIT", &num_inputs.to_string());
        replace_masm_const(
            &mut constraints_eval,
            "NUM_EVAL_GATES_CIRCUIT",
            &num_eval_gates.to_string(),
        );

        let proc_start =
            constraints_eval.find("proc load_ace_circuit_description").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "proc load_ace_circuit_description not found",
                )
            })?;
        if let Some(repeat_offset) = constraints_eval[proc_start..].find("repeat.") {
            let abs = proc_start + repeat_offset;
            let end = constraints_eval[abs..]
                .find('\n')
                .map(|i| abs + i)
                .unwrap_or(constraints_eval.len());
            constraints_eval.replace_range(abs..end, &format!("repeat.{adv_pipe_rows}"));
        }

        let section_marker = "# CONSTRAINT EVALUATION CIRCUIT DESCRIPTION";
        let section_start = constraints_eval.find(section_marker).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "constraints section marker not found")
        })?;
        constraints_eval.truncate(section_start);
        let trimmed = constraints_eval.trim_end().len();
        constraints_eval.truncate(trimmed);
        constraints_eval.push_str("\n\n# CONSTRAINT EVALUATION CIRCUIT DESCRIPTION\n");
        constraints_eval
            .push_str("# =================================================================================================\n\n");
        constraints_eval.push_str("adv_map CIRCUIT_COMMITMENT = [\n");

        for (i, chunk) in instructions.chunks(8).enumerate() {
            let vals: Vec<String> =
                chunk.iter().map(|f| f.as_canonical_u64().to_string()).collect();
            let line = vals.join(",");
            if i < adv_pipe_rows - 1 {
                constraints_eval.push_str(&format!("    {line},\n"));
            } else {
                constraints_eval.push_str(&format!("    {line}\n"));
            }
        }
        constraints_eval.push_str("]\n");
    }

    let mut relation_mod = read_file(RELATION_DIGEST_PATH);
    for (i, elem) in relation_digest.iter().enumerate() {
        replace_masm_const(
            &mut relation_mod,
            &format!("RELATION_DIGEST_{i}"),
            &elem.as_canonical_u64().to_string(),
        );
    }

    let mut air_config = read_file(AIR_CONFIG_PATH);
    let marker = "pub const RELATION_DIGEST: [Felt; 4] = [";
    let start = air_config.find(marker).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "RELATION_DIGEST not found in config.rs")
    })?;
    let block_start = start + marker.len();
    let block_end =
        air_config[block_start..]
            .find("];")
            .map(|idx| idx + block_start)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "RELATION_DIGEST terminator not found")
            })?;
    let mut new_block: String = relation_digest
        .iter()
        .map(|f| format!("\n    Felt::new_unchecked({}),", f.as_canonical_u64()))
        .collect();
    new_block.push('\n');
    air_config.replace_range(block_start..block_end, &new_block);

    Ok(ComputedArtifacts {
        num_inputs,
        num_eval_gates,
        adv_pipe_rows,
        circuit_commitment,
        relation_digest,
        constraints_eval,
        relation_mod,
        air_config,
    })
}

fn write_artifacts(artifact: &ComputedArtifacts) -> io::Result<()> {
    write_file(CONSTRAINTS_EVAL_PATH, &artifact.constraints_eval)?;
    write_file(RELATION_DIGEST_PATH, &artifact.relation_mod)?;
    write_file(AIR_CONFIG_PATH, &artifact.air_config)?;
    println!(
        "wrote asm/sys/vm/constraints_eval.masm ({} inputs, {} eval gates, repeat.{})",
        artifact.num_inputs, artifact.num_eval_gates, artifact.adv_pipe_rows
    );
    println!("wrote asm/sys/vm/mod.masm (RELATION_DIGEST)");
    println!("wrote air/src/config.rs (RELATION_DIGEST)");
    println!("done — run `cargo test -p miden-air --lib` to update the insta snapshot");
    Ok(())
}

/// Verify that the ACE circuit constants in `constraints_eval.masm` match the current AIR.
pub fn constraints_eval_masm_matches_air() -> Result<(), String> {
    let artifact = compute_artifacts().map_err(|e| e.to_string())?;
    let masm = read_file(RELATION_DIGEST_PATHS.1);
    let actual_num_inputs: usize =
        parse_masm_const(&masm, "NUM_INPUTS_CIRCUIT", "constraints_eval.masm")?;
    let actual_num_eval: usize =
        parse_masm_const(&masm, "NUM_EVAL_GATES_CIRCUIT", "constraints_eval.masm")?;

    let proc_start = masm
        .find("proc load_ace_circuit_description")
        .ok_or_else(|| "load_ace_circuit_description proc not found".to_string())?;
    let actual_adv_pipe: usize = masm[proc_start..]
        .lines()
        .find_map(|line| line.trim().strip_prefix("repeat.").and_then(|v| v.parse::<usize>().ok()))
        .ok_or_else(|| "repeat.N not found in load_ace_circuit_description".to_string())?;

    let adv_start = masm
        .find("adv_map CIRCUIT_COMMITMENT = [")
        .ok_or_else(|| "adv_map CIRCUIT_COMMITMENT not found".to_string())?;
    let adv_end = masm[adv_start..]
        .find(']')
        .map(|idx| idx + adv_start)
        .ok_or_else(|| "adv_map data block terminator not found".to_string())?;
    let data_str = &masm[masm[..adv_start].len() + "adv_map CIRCUIT_COMMITMENT = [".len()..adv_end];
    let actual_data: Vec<Felt> = data_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<u64>()
                .map(Felt::new_unchecked)
                .map_err(|_| "invalid u64 in adv_map".to_string())
        })
        .collect::<Result<_, _>>()?;
    let actual_hash = Poseidon2::hash_elements(&actual_data);

    let actual_hash_u64: Vec<u64> =
        actual_hash.as_elements().iter().map(Felt::as_canonical_u64).collect();
    let expected_hash_u64: Vec<u64> =
        artifact.circuit_commitment.iter().map(Felt::as_canonical_u64).collect();

    if actual_num_inputs != artifact.num_inputs {
        return Err(format!(
            "NUM_INPUTS_CIRCUIT is stale ({actual_num_inputs} != {})",
            artifact.num_inputs,
        ));
    }
    if actual_num_eval != artifact.num_eval_gates {
        return Err(format!(
            "NUM_EVAL_GATES_CIRCUIT is stale ({actual_num_eval} != {})",
            artifact.num_eval_gates,
        ));
    }
    if actual_adv_pipe != artifact.adv_pipe_rows {
        return Err(format!(
            "repeat.N in load_ace_circuit_description is stale ({actual_adv_pipe} != {})",
            artifact.adv_pipe_rows,
        ));
    }
    if actual_hash_u64 != expected_hash_u64 {
        return Err("Circuit data in adv_map is stale (hash mismatch)".into());
    }
    Ok(())
}

/// Verify that RELATION_DIGEST in `air/src/config.rs` and `sys/vm/mod.masm` matches current AIR.
pub fn relation_digest_matches_air() -> Result<(), String> {
    let artifact = compute_artifacts().map_err(|e| e.to_string())?;
    let expected = artifact.relation_digest;

    if miden_air::config::RELATION_DIGEST != expected {
        return Err("RELATION_DIGEST in air/src/config.rs is stale".into());
    }

    let masm = read_file(RELATION_DIGEST_PATH);
    let mut masm_digest: [Felt; 4] = [Felt::ZERO; 4];
    for (i, slot) in masm_digest.iter_mut().enumerate() {
        let name = format!("RELATION_DIGEST_{i}");
        *slot =
            parse_masm_const::<u64>(&masm, &name, "sys/vm/mod.masm").map(Felt::new_unchecked)?;
    }

    if masm_digest != expected {
        return Err("RELATION_DIGEST in sys/vm/mod.masm is stale".into());
    }

    Ok(())
}

fn parse_masm_const<T: core::str::FromStr>(
    masm: &str,
    name: &str,
    file_label: &str,
) -> Result<T, String>
where
    T::Err: core::fmt::Debug,
{
    let prefix = format!("const {name} = ");
    masm.lines()
        .find_map(|line| line.trim().strip_prefix(&prefix).and_then(|v| v.parse::<T>().ok()))
        .ok_or_else(|| format!("constant {name} not found in {file_label}"))
}

fn replace_masm_const(content: &mut String, name: &str, new_value: &str) {
    let prefix = format!("const {name} = ");
    let line_start = content.find(&prefix).unwrap_or_else(|| panic!("const {name} not found"));
    let line_end = content[line_start..]
        .find('\n')
        .map(|i| line_start + i)
        .unwrap_or(content.len());
    content.replace_range(line_start..line_end, &format!("{prefix}{new_value}"));
}

fn read_file(rel_path: &str) -> String {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel_path);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

fn write_file(rel_path: &str, contents: &str) -> io::Result<()> {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel_path);
    fs::write(&path, contents)
        .map_err(|e| io::Error::new(e.kind(), format!("failed to write {path}: {e}")))
}

struct ComputedArtifacts {
    num_inputs: usize,
    num_eval_gates: usize,
    adv_pipe_rows: usize,
    circuit_commitment: [Felt; 4],
    relation_digest: [Felt; 4],
    constraints_eval: String,
    relation_mod: String,
    air_config: String,
}
