use miden_ace_codegen::{AceCircuit, AceConfig, LayoutKind};
use miden_air::ProcessorAir;
use miden_core::{Felt, field::QuadFelt};

/// The ACE circuit configuration used by the Miden VM recursive verifier.
const MASM_CONFIG: AceConfig = AceConfig {
    num_quotient_chunks: 8,
    num_vlpi_groups: 1,
    layout: LayoutKind::Masm,
};

const REGEN_CMD: &str =
    "cargo test --release -p miden-core-lib regenerate_ace_circuit_data -- --ignored";

/// Build the batched ACE circuit for the Miden VM ProcessorAir.
pub fn build_batched_circuit(config: AceConfig) -> AceCircuit<QuadFelt> {
    let air = ProcessorAir;
    let batch_config = miden_air::ace::reduced_aux_batch_config();
    miden_air::ace::build_batched_ace_circuit::<_, QuadFelt>(&air, config, &batch_config).unwrap()
}

/// Protocol version constant used in the computation of RELATION_DIGEST.
const PROTOCOL_ID: u64 = 0;

/// Compute RELATION_DIGEST = Poseidon2::hash_elements([PROTOCOL_ID, circuit_commitment...]).
fn compute_relation_digest(circuit_commitment: &[Felt; 4]) -> [Felt; 4] {
    let input: Vec<Felt> = core::iter::once(Felt::new(PROTOCOL_ID))
        .chain(circuit_commitment.iter().copied())
        .collect();
    let digest = miden_utils_testing::crypto::Poseidon2::hash_elements(&input);
    let elems = digest.as_elements();
    [elems[0], elems[1], elems[2], elems[3]]
}

/// Parse a MASM constant declaration (`const NAME = VALUE`) from file contents.
fn parse_masm_const<T: core::str::FromStr>(masm: &str, name: &str, file_label: &str) -> T
where
    T::Err: core::fmt::Debug,
{
    let prefix = format!("const {name} = ");
    masm.lines()
        .find_map(|line| line.trim().strip_prefix(&prefix).map(|v| v.parse::<T>().unwrap()))
        .unwrap_or_else(|| panic!("constant {name} not found in {file_label}"))
}

/// Replace a MASM constant declaration in-place: `const NAME = OLD` → `const NAME = NEW`.
fn replace_masm_const(content: &mut String, name: &str, new_value: &str) {
    let prefix = format!("const {name} = ");
    let line_start = content.find(&prefix).unwrap_or_else(|| panic!("const {name} not found"));
    let line_end = content[line_start..]
        .find('\n')
        .map(|i| line_start + i)
        .unwrap_or(content.len());
    content.replace_range(line_start..line_end, &format!("{prefix}{new_value}"));
}

/// Read a file relative to the crate manifest directory.
fn read_file(rel_path: &str) -> String {
    let path = format!("{}/{rel_path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// Write a file relative to the crate manifest directory.
fn write_file(rel_path: &str, contents: &str) {
    let path = format!("{}/{rel_path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::write(&path, contents).unwrap_or_else(|e| panic!("failed to write {path}: {e}"));
}

// GENERATOR
// ================================================================================================

/// Regenerate all ACE circuit-derived files from the current AIR.
///
/// Writes:
///   1. `asm/sys/vm/constraints_eval.masm` — circuit constants + adv_map data
///   2. `asm/sys/vm/mod.masm` — RELATION_DIGEST_0..3
///   3. `../../../air/src/config.rs` — RELATION_DIGEST constant
///
/// Run with: cargo test --release -p miden-core-lib regenerate_ace_circuit_data -- --ignored
#[test]
#[ignore = "run manually to regenerate ACE circuit data in MASM and Rust files"]
#[allow(clippy::print_stdout)]
fn regenerate_ace_circuit_data() {
    let circuit = build_batched_circuit(MASM_CONFIG);
    let encoded = circuit.to_ace().unwrap();

    let num_vars = encoded.num_vars();
    let num_eval = encoded.num_eval_rows();
    let instructions = encoded.instructions();
    let size_in_felt = encoded.size_in_felt();

    assert_eq!(
        size_in_felt % 8,
        0,
        "circuit size_in_felt ({size_in_felt}) is not 8-aligned; adv_pipe requires 8-element chunks"
    );
    let num_adv_pipe = size_in_felt / 8;

    let circuit_commitment: [Felt; 4] = encoded.circuit_hash().into();
    let relation_digest = compute_relation_digest(&circuit_commitment);

    // --- 1. Write constraints_eval.masm ---
    {
        let mut masm = read_file("asm/sys/vm/constraints_eval.masm");

        // Update constants.
        replace_masm_const(&mut masm, "NUM_INPUTS_CIRCUIT", &num_vars.to_string());
        replace_masm_const(&mut masm, "NUM_EVAL_GATES_CIRCUIT", &num_eval.to_string());

        // Update repeat.N inside load_ace_circuit_description.
        let proc_start = masm.find("proc load_ace_circuit_description").unwrap();
        if let Some(repeat_offset) = masm[proc_start..].find("repeat.") {
            let abs = proc_start + repeat_offset;
            let end = masm[abs..].find('\n').map(|i| abs + i).unwrap_or(masm.len());
            masm.replace_range(abs..end, &format!("repeat.{num_adv_pipe}"));
        }

        // Replace adv_map data block and its section header (everything from
        // `# CONSTRAINT EVALUATION` to EOF).
        let section_marker = "# CONSTRAINT EVALUATION CIRCUIT DESCRIPTION";
        let section_start = masm.find(section_marker).unwrap();
        masm.truncate(section_start);
        let trimmed = masm.trim_end().len();
        masm.truncate(trimmed);

        // Write section header and data block.
        let adv_marker = "adv_map CIRCUIT_COMMITMENT = [";
        masm.push_str("\n\n# CONSTRAINT EVALUATION CIRCUIT DESCRIPTION\n");
        masm.push_str("# =================================================================================================\n\n");
        masm.push_str(adv_marker);
        masm.push('\n');

        // Write instruction data in rows of 8.
        for (i, chunk) in instructions.chunks(8).enumerate() {
            let vals: Vec<String> =
                chunk.iter().map(|f| f.as_canonical_u64().to_string()).collect();
            let line = vals.join(",");
            if i < num_adv_pipe - 1 {
                masm.push_str(&format!("    {line},\n"));
            } else {
                masm.push_str(&format!("    {line}\n"));
            }
        }
        masm.push_str("]\n");

        write_file("asm/sys/vm/constraints_eval.masm", &masm);
        println!(
            "wrote asm/sys/vm/constraints_eval.masm ({num_vars} inputs, {num_eval} eval gates, repeat.{num_adv_pipe})"
        );
    }

    // --- 2. Write RELATION_DIGEST in mod.masm ---
    {
        let mut masm = read_file("asm/sys/vm/mod.masm");
        for (i, elem) in relation_digest.iter().enumerate() {
            replace_masm_const(
                &mut masm,
                &format!("RELATION_DIGEST_{i}"),
                &elem.as_canonical_u64().to_string(),
            );
        }
        write_file("asm/sys/vm/mod.masm", &masm);
        println!("wrote asm/sys/vm/mod.masm (RELATION_DIGEST)");
    }

    // --- 3. Write RELATION_DIGEST in air/src/config.rs ---
    {
        let config_path = "../../../air/src/config.rs";
        let mut config = read_file(config_path);
        let marker = "pub const RELATION_DIGEST: [Felt; 4] = [";
        let start = config.find(marker).expect("RELATION_DIGEST not found in config.rs");
        let block_start = start + marker.len();
        let block_end = config[block_start..].find("];").unwrap() + block_start;
        let new_block = relation_digest
            .iter()
            .map(|f| format!("\n    Felt::new({}),", f.as_canonical_u64()))
            .collect::<String>()
            + "\n";
        config.replace_range(block_start..block_end, &new_block);
        write_file(config_path, &config);
        println!("wrote air/src/config.rs (RELATION_DIGEST)");
    }

    println!("done — run `cargo test -p miden-air --lib` to update the insta snapshot");
}

// STALENESS CHECKS
// ================================================================================================

/// Verify that the ACE circuit constants in `constraints_eval.masm` match the current AIR.
///
/// If this test fails after changing AIR constraints, regenerate with:
///   cargo test --release -p miden-core-lib regenerate_ace_circuit_data -- --ignored
#[test]
fn constraints_eval_masm_matches_air() {
    let circuit = build_batched_circuit(MASM_CONFIG);
    let encoded = circuit.to_ace().unwrap();

    let expected_num_inputs = encoded.num_vars();
    let expected_num_eval = encoded.num_eval_rows();
    let size_in_felt = encoded.size_in_felt();
    assert_eq!(
        size_in_felt % 8,
        0,
        "circuit size_in_felt ({size_in_felt}) is not 8-aligned; adv_pipe requires 8-element chunks"
    );
    let expected_adv_pipe = size_in_felt / 8;
    let expected_hash = encoded.circuit_hash();

    let masm = read_file("asm/sys/vm/constraints_eval.masm");

    let actual_num_inputs: usize =
        parse_masm_const(&masm, "NUM_INPUTS_CIRCUIT", "constraints_eval.masm");
    let actual_num_eval: usize =
        parse_masm_const(&masm, "NUM_EVAL_GATES_CIRCUIT", "constraints_eval.masm");

    // Parse `repeat.N` inside load_ace_circuit_description.
    let proc_start = masm.find("proc load_ace_circuit_description").unwrap();
    let actual_adv_pipe: usize = masm[proc_start..]
        .lines()
        .find_map(|line| line.trim().strip_prefix("repeat.").map(|v| v.parse().unwrap()))
        .expect("repeat.N not found in load_ace_circuit_description");

    // Parse the adv_map data to compute its hash.
    let adv_start = masm.find("adv_map CIRCUIT_COMMITMENT = [").unwrap();
    let adv_end = masm[adv_start..].find(']').unwrap() + adv_start;
    let data_str = &masm[masm[..adv_start].len() + "adv_map CIRCUIT_COMMITMENT = [".len()..adv_end];
    let actual_data: Vec<Felt> = data_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| Felt::new(s.parse::<u64>().unwrap()))
        .collect();
    let actual_hash = miden_utils_testing::crypto::Poseidon2::hash_elements(&actual_data);

    assert_eq!(
        actual_num_inputs, expected_num_inputs,
        "NUM_INPUTS_CIRCUIT is stale ({actual_num_inputs} != {expected_num_inputs}). Regenerate with: {REGEN_CMD}"
    );
    assert_eq!(
        actual_num_eval, expected_num_eval,
        "NUM_EVAL_GATES_CIRCUIT is stale ({actual_num_eval} != {expected_num_eval}). Regenerate with: {REGEN_CMD}"
    );
    assert_eq!(
        actual_adv_pipe, expected_adv_pipe,
        "repeat.N in load_ace_circuit_description is stale ({actual_adv_pipe} != {expected_adv_pipe}). Regenerate with: {REGEN_CMD}"
    );

    let actual_hash_u64: Vec<u64> =
        actual_hash.as_elements().iter().map(|f| f.as_canonical_u64()).collect();
    let expected_hash_u64: Vec<u64> = expected_hash.iter().map(|f| f.as_canonical_u64()).collect();
    assert_eq!(
        actual_hash_u64, expected_hash_u64,
        "Circuit data in adv_map is stale (hash mismatch). Regenerate with: {REGEN_CMD}"
    );
}

/// Verify that RELATION_DIGEST in `air/src/config.rs` (Rust) and `sys/vm/mod.masm` (MASM)
/// both match the value recomputed from the current AIR.
#[test]
fn relation_digest_matches_air() {
    let circuit = build_batched_circuit(MASM_CONFIG);
    let encoded = circuit.to_ace().unwrap();
    let circuit_commitment: [Felt; 4] = encoded.circuit_hash().into();
    let expected = compute_relation_digest(&circuit_commitment);

    // 1. Verify the Rust constant in air/src/config.rs.
    assert_eq!(
        miden_air::config::RELATION_DIGEST,
        expected,
        "RELATION_DIGEST in air/src/config.rs is stale. Regenerate with: {REGEN_CMD}",
    );

    // 2. Verify the MASM constants in sys/vm/mod.masm.
    let masm = read_file("asm/sys/vm/mod.masm");
    let masm_digest: [Felt; 4] = core::array::from_fn(|i| {
        let name = format!("RELATION_DIGEST_{i}");
        Felt::new(parse_masm_const::<u64>(&masm, &name, "sys/vm/mod.masm"))
    });

    assert_eq!(
        masm_digest, expected,
        "RELATION_DIGEST in sys/vm/mod.masm is stale. Regenerate with: {REGEN_CMD}",
    );
}
