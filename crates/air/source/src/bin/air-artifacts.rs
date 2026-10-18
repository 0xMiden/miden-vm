//! Explicit Rust and canonical ACE artifact delivery/checking from authored VM and PVM AIRs.
//!
//! Accepted values are mandatory explicit inputs. This command compares candidates and never
//! accepts a new pin, derives setup commitments, or imports production evaluator types.

use std::{env, fs, path::PathBuf, process::ExitCode};

use miden_air_source::{
    codegen::{degrees, evaluator, metadata},
    precompile, vm,
};
use miden_core::Felt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const USAGE: &str = "usage: air-artifacts [--check|--write] --accepted-pins /explicit/accepted.json /explicit/artifact/directory (default: --check)";

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| format!("accepted pins require a nonempty string {key:?}"))
}

fn required_digest(value: &Value, key: &str) -> Result<Vec<u64>, String> {
    let entries = value
        .get(key)
        .and_then(Value::as_array)
        .filter(|entries| entries.len() == 4)
        .ok_or_else(|| format!("accepted pins require {key:?} as four canonical field integers"))?;
    entries
        .iter()
        .map(|entry| {
            let integer =
                entry.as_u64().ok_or_else(|| format!("{key:?} must contain u64 integers"))?;
            Felt::new(integer)
                .map_err(|_| format!("{key:?} contains a noncanonical field integer"))?;
            Ok(integer)
        })
        .collect()
}

fn run() -> Result<(), String> {
    let mut write = false;
    let mut mode_seen = false;
    let mut destination = None;
    let mut accepted_path = None;
    let mut arguments = env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--write" || argument == "--check" {
            if mode_seen {
                return Err("select at most one of --check or --write".into());
            }
            mode_seen = true;
            write = argument == "--write";
        } else if argument == "--accepted-pins" {
            if accepted_path.is_some() {
                return Err("provide --accepted-pins exactly once".into());
            }
            accepted_path = Some(PathBuf::from(arguments.next().ok_or_else(|| {
                format!("--accepted-pins requires an explicit file path; {USAGE}")
            })?));
        } else if argument.to_string_lossy().starts_with('-') {
            return Err(format!("unknown argument: {}", argument.to_string_lossy()));
        } else if destination.replace(PathBuf::from(argument)).is_some() {
            return Err("provide exactly one explicit artifact destination directory".into());
        }
    }
    let destination = destination.ok_or_else(|| USAGE.to_string())?;
    let accepted_path =
        accepted_path.ok_or_else(|| format!("--accepted-pins is required; {USAGE}"))?;
    let accepted_bytes = fs::read(&accepted_path)
        .map_err(|error| format!("{}: {error}", accepted_path.display()))?;
    let accepted: Value = serde_json::from_slice(&accepted_bytes)
        .map_err(|error| format!("{}: {error}", accepted_path.display()))?;
    if accepted.get("accepted_schema").and_then(Value::as_u64) != Some(1) {
        return Err(
            "unsupported or missing accepted pins schema; expected accepted_schema 1".into()
        );
    }
    let baseline = required_string(&accepted, "baseline")?;
    let statement_context = required_string(&accepted, "statement_context")?;

    // These are authored source types. Compiled production evaluators are never capture inputs.
    let vm_circuit = miden_ace::CompiledCircuit::from_circuit(
        vm::ace::build_canonical_multi_air_ace_circuit(vm::ace::recursive_verifier_ace_config()),
    );
    let precompile_circuit = miden_ace::CompiledCircuit::from_circuit(
        precompile::ace::build_canonical_precompile_ace_circuit(),
    );
    let circuits = [
        ("vm", "vm.ace", vm_circuit),
        ("precompile", "precompile.ace", precompile_circuit),
    ];
    let mut artifacts = Vec::new();
    let mut members = Vec::new();
    for (relation, name, compiled) in circuits {
        let encoded = compiled.encoded();
        let pins = accepted
            .get("relations")
            .and_then(|relations| relations.get(relation))
            .ok_or_else(|| format!("accepted pins missing relation {relation:?}"))?;
        let protocol_id = pins
            .get("protocol_id")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("accepted pins require protocol_id for {relation}"))?;
        Felt::new(protocol_id).map_err(|_| format!("{relation} protocol_id is noncanonical"))?;
        let configuration = required_string(pins, "configuration")?;
        let accepted_circuit = required_digest(pins, "accepted_circuit_digest")?;
        let accepted_relation = required_digest(pins, "accepted_relation_digest")?;
        let candidate_digest = compiled.commitment();
        let candidate: Vec<u64> =
            candidate_digest.as_elements().iter().map(Felt::as_canonical_u64).collect();
        if candidate != accepted_circuit {
            return Err(format!(
                "{relation} candidate circuit digest {candidate:?} does not match explicitly accepted digest {accepted_circuit:?}; no artifacts written and no pins accepted"
            ));
        }
        let candidate_relation: Vec<u64> =
            miden_stark::config::relation_digest(protocol_id, &candidate_digest)
                .iter()
                .map(Felt::as_canonical_u64)
                .collect();
        if candidate_relation != accepted_relation {
            return Err(format!(
                "{relation} candidate relation digest {candidate_relation:?} does not match explicitly accepted digest {accepted_relation:?}; no artifacts written and no pins accepted"
            ));
        }
        let bytes = encoded.to_canonical_bytes();
        // Validate the transport independently before delivering a compiler-produced artifact.
        let decoded = miden_ace::EncodedCircuit::from_canonical_bytes(&bytes)
            .map_err(|error| format!("{name} canonical transport: {error}"))?;
        if &decoded != encoded {
            return Err(format!("{name}: canonical artifact round trip changed the stream"));
        }
        let sha256: String =
            Sha256::digest(&bytes).iter().map(|byte| format!("{byte:02x}")).collect();
        members.push(json!({
            "relation": relation, "file": name, "codec": "MIDACE-v1",
            "num_vars": encoded.num_vars(), "num_ops": encoded.num_eval_rows(),
            "instruction_elements": encoded.size_in_felt(), "bytes": bytes.len(), "sha256": sha256,
            "accepted_pin_policy": "compare; never accept implicitly", "protocol_id": protocol_id,
            "configuration": configuration, "accepted_circuit_digest": accepted_circuit,
            "accepted_relation_digest": accepted_relation, "candidate_circuit_digest": candidate,
            "candidate_relation_digest": candidate_relation,
            "statement_context": statement_context,
        }));
        artifacts.push((name, bytes));
    }
    let evaluator_source = evaluator::generate();
    let evaluator_bytes = evaluator::encode(&evaluator_source);
    let evaluator_sha256: String = Sha256::digest(&evaluator_bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let evaluator_source_sha256: String = Sha256::digest(evaluator_source.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut degree_tables = Vec::new();
    for (file, source) in degrees::generate() {
        let sha256: String = Sha256::digest(source.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        degree_tables.push(json!({ "file": file, "bytes": source.len(), "sha256": sha256 }));
        artifacts.push((file, source.into_bytes()));
    }
    let mut metadata_tables = Vec::new();
    for (file, source) in metadata::generate() {
        let sha256: String = Sha256::digest(source.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        metadata_tables.push(json!({ "file": file, "bytes": source.len(), "sha256": sha256 }));
        artifacts.push((file, source.into_bytes()));
    }
    let manifest = json!({
        "artifact_schema": 1, "baseline": baseline,
        "field": "canonical Miden Felt, little-endian u64", "members": members,
        "rust_evaluator": evaluator::ARTIFACT_FILE,
        "rust_evaluator_codec": "zlib",
        "rust_evaluator_bytes": evaluator_bytes.len(),
        "rust_evaluator_sha256": evaluator_sha256,
        "rust_evaluator_source_bytes": evaluator_source.len(),
        "rust_evaluator_source_sha256": evaluator_source_sha256,
        "constraint_degree_tables": degree_tables,
        "air_metadata_tables": metadata_tables,
        "pvm_evaluation": "authored dispatch delegated through independent production type",
    });
    artifacts.push((evaluator::ARTIFACT_FILE, evaluator_bytes));
    // Both relation pins and ACE transport round trips have passed before any output mutation.
    if write {
        fs::create_dir_all(&destination)
            .map_err(|error| format!("{}: {error}", destination.display()))?;
    }
    for (name, bytes) in artifacts {
        let path = destination.join(name);
        if write {
            if !fs::read(&path).is_ok_and(|existing| existing == bytes) {
                fs::write(&path, &bytes).map_err(|error| format!("{}: {error}", path.display()))?;
            }
        } else {
            let staged = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            if staged != bytes {
                return Err(format!(
                    "{} differs from authored generated output; inspect before explicit --write",
                    path.display()
                ));
            }
        }
        println!(
            "{} {} ({} bytes)",
            if write { "wrote/verified" } else { "checked" },
            path.display(),
            bytes.len()
        );
    }
    let manifest_path = destination.join("manifest.json");
    if write {
        let mut bytes = serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        fs::write(&manifest_path, bytes)
            .map_err(|error| format!("{}: {error}", manifest_path.display()))?;
    } else {
        let bytes = fs::read(&manifest_path)
            .map_err(|error| format!("{}: {error}", manifest_path.display()))?;
        let staged: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("{}: {error}", manifest_path.display()))?;
        if staged != manifest {
            return Err(format!(
                "{} metadata differs from authored candidates and explicit accepted pins",
                manifest_path.display()
            ));
        }
    }
    println!(
        "{} {} (shape, transport fingerprints, evaluator metadata and preserved accepted values)",
        if write { "wrote" } else { "checked" },
        manifest_path.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        },
    }
}
