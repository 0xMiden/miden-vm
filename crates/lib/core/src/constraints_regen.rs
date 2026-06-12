use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use std::{fs, io, println};

use miden_ace_codegen::{AceCircuit, AceConfig, LayoutKind};
use miden_air::{
    MidenMultiAir, NUM_PUBLIC_VALUES, ProofOrder, Statement, config,
    trace::and8_lookup::LOG_AND8_TABLE_HEIGHT,
};
use miden_core::{Felt, crypto::hash::Poseidon2, field::QuadFelt};
use miden_crypto::stark::Preprocessed;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Check,
    Write,
}

const MASM_CONFIG: AceConfig = AceConfig {
    num_quotient_chunks: 8,
    num_vlpi_groups: 1,
    layout: LayoutKind::Masm,
    is_multi_air: true,
};

const PROTOCOL_ID: u64 = 0;
const AIR_CONFIG_PATH: &str = "../../../air/src/config.rs";
const CONSTRAINTS_EVAL_DISPATCHER_PATH: &str = "asm/sys/vm/constraints_eval.masm";
const RELATION_DIGEST_PATH: &str = "asm/sys/vm/mod.masm";

/// Builds one recursive-verifier ACE circuit for a specific proof order.
pub fn build_batched_circuit_for_order(
    order: &ProofOrder,
    config: AceConfig,
) -> AceCircuit<QuadFelt> {
    assert!(
        config.is_multi_air,
        "production circuit is multi-AIR; pass AceConfig with is_multi_air = true"
    );
    miden_air::ace::build_multi_air_ace_circuit_for_order::<QuadFelt>(config, order).unwrap()
}

/// Builds the default instance-order circuit.
pub fn build_batched_circuit(config: AceConfig) -> AceCircuit<QuadFelt> {
    build_batched_circuit_for_order(&ProofOrder::instance_order(), config)
}

/// Computes the tagged meta relation digest used by recursive verification.
pub fn compute_relation_digest(commitments: &[(ProofOrder, [Felt; 4])]) -> [Felt; 4] {
    let mut input = Vec::with_capacity(1 + commitments.len() * 5);
    input.push(Felt::new_unchecked(PROTOCOL_ID));
    for (order, commitment) in commitments {
        input.push(Felt::new_unchecked(order.tag() as u64));
        input.extend_from_slice(commitment);
    }

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

fn write() -> io::Result<()> {
    let artifact = compute_artifacts()?;
    write_artifacts(&artifact)
}

fn check() -> Result<(), String> {
    constraints_eval_masm_matches_air()?;
    relation_digest_matches_air()?;
    Ok(())
}

fn compute_artifacts() -> io::Result<ComputedArtifacts> {
    let mut order_artifacts = Vec::new();
    let mut commitments = Vec::new();

    for order in ProofOrder::variants() {
        let circuit = build_batched_circuit_for_order(&order, MASM_CONFIG);
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

        let masm = render_constraints_eval_file(
            &order,
            num_inputs,
            num_eval_gates,
            adv_pipe_rows,
            instructions,
        );

        commitments.push((order.clone(), circuit_commitment));
        order_artifacts.push(OrderArtifact {
            order,
            num_inputs,
            num_eval_gates,
            adv_pipe_rows,
            circuit_commitment,
            constraints_eval: masm,
        });
    }

    let relation_digest = compute_relation_digest(&commitments);
    let and8_preprocessed_commitment = compute_and8_preprocessed_commitment();
    let dispatcher = render_constraints_eval_dispatcher(&order_artifacts);

    let mut relation_mod = read_file(RELATION_DIGEST_PATH);
    for (i, elem) in relation_digest.iter().enumerate() {
        replace_masm_const(
            &mut relation_mod,
            &format!("RELATION_DIGEST_{i}"),
            &elem.as_canonical_u64().to_string(),
        );
    }
    for (i, elem) in and8_preprocessed_commitment.iter().enumerate() {
        replace_masm_const(
            &mut relation_mod,
            &format!("AND8_PREPROCESSED_TRACE_COM_{i}"),
            &elem.as_canonical_u64().to_string(),
        );
    }
    replace_masm_const(
        &mut relation_mod,
        "AND8_LOOKUP_LOG_HEIGHT",
        &LOG_AND8_TABLE_HEIGHT.to_string(),
    );

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
        order_artifacts,
        relation_digest,
        and8_preprocessed_commitment,
        dispatcher,
        relation_mod,
        air_config,
    })
}

fn compute_and8_preprocessed_commitment() -> [Felt; 4] {
    let config = config::poseidon2_config(config::pcs_params());
    let statement: Statement<Felt, QuadFelt, MidenMultiAir> =
        Statement::new(MidenMultiAir::new(), vec![Felt::ZERO; NUM_PUBLIC_VALUES], Vec::new())
            .expect("zero public inputs satisfy Miden statement shape");
    let preprocessed = Preprocessed::build(&statement, &config)
        .expect("Miden relation must declare the AND8 preprocessed table");

    preprocessed.commitment().into()
}

fn render_constraints_eval_file(
    order: &ProofOrder,
    num_inputs: usize,
    num_eval_gates: usize,
    adv_pipe_rows: usize,
    instructions: &[Felt],
) -> String {
    let order_label = order.label();

    let mut masm = format!(
        concat!(
            "use miden::core::crypto::hashes::poseidon2\n",
            "use miden::core::stark::constants\n",
            "use miden::core::sys::vm::constraints_eval_inputs\n\n",
            "# CONSTANTS\n",
            "# =================================================================================================\n\n",
            "# Number of READ variables (inputs + constants) for the constraint evaluation circuit.\n",
            "const NUM_INPUTS_CIRCUIT = {num_inputs}\n\n",
            "# Number of evaluation gates in the constraint evaluation circuit.\n",
            "const NUM_EVAL_GATES_CIRCUIT = {num_eval_gates}\n\n",
            "# Max cycle length for periodic columns.\n",
            "const MAX_CYCLE_LEN_LOG = 4\n\n",
            "# ERRORS\n",
            "# =================================================================================================\n\n",
            "const ERR_FAILED_TO_LOAD_CIRCUIT_DESCRIPTION = \"failed to load the circuit description for the constraints evaluation check\"\n\n",
            "# CONSTRAINT EVALUATION CHECKER\n",
            "# =================================================================================================\n\n",
            "#! Executes the constraints evaluation check for proof order: {order_label}.\n",
            "#!\n",
            "#! Inputs:  []\n",
            "#! Outputs: []\n",
            "pub proc execute_constraint_evaluation_check()\n",
            "    push.MAX_CYCLE_LEN_LOG\n",
            "    exec.constraints_eval_inputs::set_up_auxiliary_inputs_ace\n\n",
            "    exec.load_ace_circuit_description\n\n",
            "    push.NUM_EVAL_GATES_CIRCUIT\n",
            "    push.NUM_INPUTS_CIRCUIT\n",
            "    exec.constants::public_inputs_address_ptr mem_load\n",
            "    eval_circuit\n",
            "    drop drop drop\n",
            "end\n\n",
            "#! Loads the description of this order-specific ACE circuit.\n",
            "proc load_ace_circuit_description\n",
            "    push.CIRCUIT_COMMITMENT\n",
            "    adv.push_mapval\n",
            "    exec.constants::ace_circuit_stream_ptr\n",
            "    padw padw padw\n",
            "    repeat.{adv_pipe_rows}\n",
            "        adv_pipe\n",
            "        exec.poseidon2::permute\n",
            "    end\n",
            "    exec.poseidon2::squeeze_digest\n",
            "    movup.4 drop\n",
            "    assert_eqw.err=ERR_FAILED_TO_LOAD_CIRCUIT_DESCRIPTION\n",
            "end\n\n",
            "# CONSTRAINT EVALUATION CIRCUIT DESCRIPTION\n",
            "# =================================================================================================\n\n",
            "adv_map CIRCUIT_COMMITMENT = [\n",
        ),
        num_inputs = num_inputs,
        num_eval_gates = num_eval_gates,
        order_label = order_label,
        adv_pipe_rows = adv_pipe_rows,
    );

    for (i, chunk) in instructions.chunks(8).enumerate() {
        let vals: Vec<String> = chunk.iter().map(|f| f.as_canonical_u64().to_string()).collect();
        let line = vals.join(",");
        if i < adv_pipe_rows - 1 {
            masm.push_str(&format!("    {line},\n"));
        } else {
            masm.push_str(&format!("    {line}\n"));
        }
    }
    masm.push_str("]\n");
    masm
}

fn render_constraints_eval_dispatcher(orders: &[OrderArtifact]) -> String {
    assert!(!orders.is_empty(), "at least one proof order is required");

    let mut masm = String::new();
    for order in orders {
        masm.push_str(&format!("use miden::core::sys::vm::{}\n", order.order.file_stem()));
    }
    masm.push_str("use miden::core::stark::constants\n\n");
    masm.push_str("# CONSTRAINT EVALUATION CHECK DISPATCHER\n");
    masm.push_str(
        "# =================================================================================================\n\n",
    );
    masm.push_str("#! Runs the order-specific recursive-verifier ACE circuit.\n");
    masm.push_str("#!\n");
    masm.push_str(
        "#! `ORDER_TAG_PTR` is derived from the per-AIR trace heights during transcript\n",
    );
    masm.push_str("#! initialization and compared against each generated proof-order tag.\n");
    masm.push_str("#!\n");
    masm.push_str("#! Inputs:  []\n");
    masm.push_str("#! Outputs: []\n");
    masm.push_str("pub proc execute_constraint_evaluation_check\n");
    masm.push_str("    exec.constants::assert_valid_order_tag\n");

    render_dispatch_branch(&mut masm, orders, 0);
    masm.push_str("end\n");
    masm
}

fn render_dispatch_branch(masm: &mut String, orders: &[OrderArtifact], index: usize) {
    let order = &orders[index].order;
    let indent = "    ".repeat(index + 1);
    if index == orders.len() - 1 {
        masm.push_str(&format!(
            "{indent}exec.{}::execute_constraint_evaluation_check\n",
            order.file_stem(),
        ));
        return;
    }

    masm.push_str(&format!("{indent}exec.constants::get_order_tag\n"));
    masm.push_str(&format!("{indent}{} eq\n", order_tag_expr(order)));
    masm.push_str(&format!("{indent}if.true\n"));
    masm.push_str(&format!(
        "{indent}    exec.{}::execute_constraint_evaluation_check\n",
        order.file_stem(),
    ));
    masm.push_str(&format!("{indent}else\n"));
    render_dispatch_branch(masm, orders, index + 1);
    masm.push_str(&format!("{indent}end\n"));
}

fn write_artifacts(artifact: &ComputedArtifacts) -> io::Result<()> {
    for order_artifact in &artifact.order_artifacts {
        write_file(
            &constraints_eval_path(&order_artifact.order),
            &order_artifact.constraints_eval,
        )?;
        println!(
            "wrote asm/sys/vm/{}.masm ({} inputs, {} eval gates, repeat.{})",
            order_artifact.order.file_stem(),
            order_artifact.num_inputs,
            order_artifact.num_eval_gates,
            order_artifact.adv_pipe_rows,
        );
    }
    write_file(CONSTRAINTS_EVAL_DISPATCHER_PATH, &artifact.dispatcher)?;
    write_file(RELATION_DIGEST_PATH, &artifact.relation_mod)?;
    write_file(AIR_CONFIG_PATH, &artifact.air_config)?;
    println!("wrote asm/sys/vm/constraints_eval.masm (dispatcher)");
    println!("wrote asm/sys/vm/mod.masm (RELATION_DIGEST)");
    println!("wrote air/src/config.rs (RELATION_DIGEST)");
    println!("done - run `cargo test -p miden-air --lib` to update the insta snapshot");
    Ok(())
}

/// Verify that the order-specific ACE circuit constants match the current AIR.
pub fn constraints_eval_masm_matches_air() -> Result<(), String> {
    let artifact = compute_artifacts().map_err(|e| e.to_string())?;
    for order_artifact in &artifact.order_artifacts {
        check_constraints_eval_file(order_artifact)?;
    }
    let dispatcher = read_file(CONSTRAINTS_EVAL_DISPATCHER_PATH);
    if dispatcher != artifact.dispatcher {
        return Err(format!("{CONSTRAINTS_EVAL_DISPATCHER_PATH} is stale"));
    }
    Ok(())
}

fn check_constraints_eval_file(artifact: &OrderArtifact) -> Result<(), String> {
    let path = constraints_eval_path(&artifact.order);
    let masm = read_file(&path);
    let actual_num_inputs: usize = parse_masm_const(&masm, "NUM_INPUTS_CIRCUIT", &path)?;
    let actual_num_eval: usize = parse_masm_const(&masm, "NUM_EVAL_GATES_CIRCUIT", &path)?;

    let proc_start = masm
        .find("proc load_ace_circuit_description")
        .ok_or_else(|| format!("load_ace_circuit_description proc not found in {path}"))?;
    let actual_adv_pipe: usize = masm[proc_start..]
        .lines()
        .find_map(|line| line.trim().strip_prefix("repeat.").and_then(|v| v.parse::<usize>().ok()))
        .ok_or_else(|| format!("repeat.N not found in load_ace_circuit_description of {path}"))?;

    let adv_start = masm
        .find("adv_map CIRCUIT_COMMITMENT = [")
        .ok_or_else(|| format!("adv_map CIRCUIT_COMMITMENT not found in {path}"))?;
    let adv_end = masm[adv_start..]
        .find(']')
        .map(|idx| idx + adv_start)
        .ok_or_else(|| format!("adv_map data block terminator not found in {path}"))?;
    let data_str = &masm[masm[..adv_start].len() + "adv_map CIRCUIT_COMMITMENT = [".len()..adv_end];
    let actual_data: Vec<Felt> = data_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<u64>()
                .map(Felt::new_unchecked)
                .map_err(|_| format!("invalid u64 in adv_map of {path}"))
        })
        .collect::<Result<_, _>>()?;
    let actual_hash = Poseidon2::hash_elements(&actual_data);

    let actual_hash_u64: Vec<u64> =
        actual_hash.as_elements().iter().map(Felt::as_canonical_u64).collect();
    let expected_hash_u64: Vec<u64> =
        artifact.circuit_commitment.iter().map(Felt::as_canonical_u64).collect();

    if actual_num_inputs != artifact.num_inputs {
        return Err(format!(
            "NUM_INPUTS_CIRCUIT is stale in {path} ({actual_num_inputs} != {})",
            artifact.num_inputs,
        ));
    }
    if actual_num_eval != artifact.num_eval_gates {
        return Err(format!(
            "NUM_EVAL_GATES_CIRCUIT is stale in {path} ({actual_num_eval} != {})",
            artifact.num_eval_gates,
        ));
    }
    if actual_adv_pipe != artifact.adv_pipe_rows {
        return Err(format!(
            "repeat.N in {path} is stale ({actual_adv_pipe} != {})",
            artifact.adv_pipe_rows,
        ));
    }
    if actual_hash_u64 != expected_hash_u64 {
        return Err(format!("Circuit data in adv_map of {path} is stale (hash mismatch)"));
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

    let mut masm_preprocessed: [Felt; 4] = [Felt::ZERO; 4];
    for (i, slot) in masm_preprocessed.iter_mut().enumerate() {
        let name = format!("AND8_PREPROCESSED_TRACE_COM_{i}");
        *slot =
            parse_masm_const::<u64>(&masm, &name, "sys/vm/mod.masm").map(Felt::new_unchecked)?;
    }
    if masm_preprocessed != artifact.and8_preprocessed_commitment {
        return Err("AND8 preprocessed commitment in sys/vm/mod.masm is stale".into());
    }

    Ok(())
}

fn constraints_eval_path(order: &ProofOrder) -> String {
    format!("asm/sys/vm/{}.masm", order.file_stem())
}

fn order_tag_expr(order: &ProofOrder) -> String {
    format!("push.{}", order.tag())
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

struct OrderArtifact {
    order: ProofOrder,
    num_inputs: usize,
    num_eval_gates: usize,
    adv_pipe_rows: usize,
    circuit_commitment: [Felt; 4],
    constraints_eval: String,
}

struct ComputedArtifacts {
    order_artifacts: Vec<OrderArtifact>,
    relation_digest: [Felt; 4],
    and8_preprocessed_commitment: [Felt; 4],
    dispatcher: String,
    relation_mod: String,
    air_config: String,
}
