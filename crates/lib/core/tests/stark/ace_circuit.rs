use miden_ace_codegen::{AceCircuit, AceConfig, LayoutKind};
use miden_air::ProcessorAir;
use miden_core::{Felt, field::QuadFelt};

/// The ACE circuit configuration used by the Miden VM recursive verifier.
const MASM_CONFIG: AceConfig = AceConfig {
    num_quotient_chunks: 8,
    num_vlpi_groups: 1,
    layout: LayoutKind::Masm,
    quotient_extension: false,
    quotient_segment_len: 0,
};

const REGEN_CMD: &str = "cargo test --release -p miden-core-lib generate_constraints_eval_masm_data -- --ignored --nocapture";

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

/// Read MASM source from a path relative to the crate manifest directory.
fn read_masm(rel_path: &str) -> String {
    let path = format!("{}/{rel_path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

// GENERATOR
// ================================================================================================

#[test]
#[ignore = "run manually to regenerate constraints_eval.masm data"]
#[allow(clippy::print_stdout)]
fn generate_constraints_eval_masm_data() {
    let circuit = build_batched_circuit(MASM_CONFIG);
    let encoded = circuit.to_ace().unwrap();

    let num_vars = encoded.num_vars();
    let num_eval = encoded.num_eval_rows();
    let num_inputs = encoded.num_inputs();
    let num_constants = encoded.num_constants();
    let instructions = encoded.instructions();
    let size_in_felt = encoded.size_in_felt();
    let hash = encoded.circuit_hash();

    assert_eq!(
        size_in_felt % 8,
        0,
        "circuit size_in_felt ({size_in_felt}) is not 8-aligned; adv_pipe requires 8-element chunks"
    );
    let num_adv_pipe = size_in_felt / 8;

    println!("=== ACE Circuit Data for constraints_eval.masm ===");
    println!("NUM_INPUTS_CIRCUIT = {num_vars}");
    println!("NUM_EVAL_GATES_CIRCUIT = {num_eval}");
    println!("num_inputs (READ slots) = {num_inputs}");
    println!("num_constants = {num_constants}");
    println!("size_in_felt = {size_in_felt}");
    println!("num_adv_pipe (repeat.N) = {num_adv_pipe}");
    println!();

    println!(
        "CIRCUIT_COMMITMENT hash = [{}, {}, {}, {}]",
        hash[0].as_canonical_u64(),
        hash[1].as_canonical_u64(),
        hash[2].as_canonical_u64(),
        hash[3].as_canonical_u64()
    );

    let circuit_commitment: [Felt; 4] = hash.into();
    let rd = compute_relation_digest(&circuit_commitment);
    println!();
    println!("# RELATION_DIGEST constants for sys/vm/mod.masm:");
    for (i, elem) in rd.iter().enumerate() {
        println!("const RELATION_DIGEST_{i} = {}", elem.as_canonical_u64());
    }
    println!();

    println!("adv_map CIRCUIT_COMMITMENT = [");
    for (i, chunk) in instructions.chunks(8).enumerate() {
        let vals: Vec<String> = chunk.iter().map(|f| f.as_canonical_u64().to_string()).collect();
        let line = vals.join(",");
        if i < num_adv_pipe - 1 {
            println!("    {line},");
        } else {
            println!("    {line}");
        }
    }
    println!("]");

    let layout = circuit.layout();
    println!();
    println!("Layout total_inputs = {}", layout.total_inputs);
    println!("Layout counts = {:?}", layout.counts);
}

// STALENESS CHECKS
// ================================================================================================

/// Verify that the ACE circuit constants in `constraints_eval.masm` match the current AIR.
///
/// If this test fails after changing AIR constraints, regenerate with:
///   cargo test --release -p miden-core-lib generate_constraints_eval_masm_data -- --ignored
/// --nocapture
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

    let masm = read_masm("asm/sys/vm/constraints_eval.masm");

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
    let masm = read_masm("asm/sys/vm/mod.masm");
    let masm_digest: [Felt; 4] = core::array::from_fn(|i| {
        let name = format!("RELATION_DIGEST_{i}");
        Felt::new(parse_masm_const::<u64>(&masm, &name, "sys/vm/mod.masm"))
    });

    assert_eq!(
        masm_digest, expected,
        "RELATION_DIGEST in sys/vm/mod.masm is stale. Regenerate with: {REGEN_CMD}",
    );
}
