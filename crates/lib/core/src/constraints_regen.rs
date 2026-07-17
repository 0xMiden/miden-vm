use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use std::{fs, io, println};

use miden_air::{
    AIRS, MIDEN_AIR_COUNT, MidenAir, PROOF_ORDER_COUNT, ProofOrder,
    ace::build_recursive_verifier_ace_circuit, config::ACE_CIRCUIT_REGISTRY_DEPTH,
};
use miden_core::{Felt, Word, crypto::hash::Poseidon2};
use miden_crypto::{merkle::MerkleTree, stark::air::BaseAir};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Check,
    Write,
}

const PROTOCOL_ID: u64 = 0;
const ACE_REGISTRY_LEAF_COUNT: usize = 1 << ACE_CIRCUIT_REGISTRY_DEPTH;
const ACE_REGISTRY_PADDING_DOMAIN: u64 = 0xace;
const AIR_CONFIG_PATH: &str = "../../../air/src/config.rs";
const CONSTRAINTS_EVAL_PATH: &str = "asm/sys/vm/constraints_eval.masm";
const RELATION_DIGEST_PATH: &str = "asm/sys/vm/mod.masm";
const STARK_CONSTANTS_PATH: &str = "asm/stark/constants.masm";
const VM_PUBLIC_INPUTS_PATH: &str = "asm/sys/vm/public_inputs.masm";

/// Computes the relation digest used by recursive verification.
pub fn compute_relation_digest(registry_root: &[Felt; 4]) -> [Felt; 4] {
    let input: Vec<Felt> = core::iter::once(Felt::new_unchecked(PROTOCOL_ID))
        .chain(registry_root.iter().copied())
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
    public_inputs_masm_matches_air()?;
    Ok(())
}

/// Generate a full computed snapshot from the current AIR.
fn compute_artifacts() -> io::Result<ComputedArtifacts> {
    let mut order_artifacts = Vec::new();
    for order in ProofOrder::variants() {
        let circuit = build_recursive_verifier_ace_circuit(&order)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        order_artifacts.push(OrderArtifact {
            order,
            num_inputs: circuit.num_inputs,
            num_eval_gates: circuit.num_eval_gates,
            stream_len: circuit.stream_len,
            circuit_commitment: word_to_array(circuit.commitment),
        });
    }
    if order_artifacts.len() != PROOF_ORDER_COUNT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proof-order variant count does not match PROOF_ORDER_COUNT",
        ));
    }

    ensure_uniform_circuit_metadata(&order_artifacts)?;
    let registry = AceCircuitRegistry::from_order_artifacts(&order_artifacts)?;
    let registry_root = registry.root;
    let registry_leaves = registry.leaves.iter().copied().map(word_to_array).collect::<Vec<_>>();
    let relation_digest = compute_relation_digest(&registry_root);
    let constraints_eval = render_constraints_eval_file(&order_artifacts)?;
    let order_tag_count = PROOF_ORDER_COUNT;

    let mut relation_mod = read_file(RELATION_DIGEST_PATH)?;
    for (i, elem) in relation_digest.iter().enumerate() {
        replace_masm_const(
            &mut relation_mod,
            &format!("RELATION_DIGEST_{i}"),
            &elem.as_canonical_u64().to_string(),
        )?;
    }
    for (i, elem) in registry_root.iter().enumerate() {
        replace_masm_const(
            &mut relation_mod,
            &format!("ACE_REGISTRY_ROOT_{i}"),
            &elem.as_canonical_u64().to_string(),
        )?;
    }

    let mut air_config = read_file(AIR_CONFIG_PATH)?;
    replace_felt_array_const(&mut air_config, "RELATION_DIGEST", &relation_digest)?;
    replace_felt_array_const(&mut air_config, "ACE_CIRCUIT_REGISTRY_ROOT", &registry_root)?;
    replace_registry_leaves(&mut air_config, &registry_leaves)?;

    let mut stark_constants = read_file(STARK_CONSTANTS_PATH)?;
    replace_masm_const(&mut stark_constants, "ORDER_TAG_COUNT", &order_tag_count.to_string())?;

    let first = order_artifacts.first().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "at least one ACE circuit is required")
    })?;

    Ok(ComputedArtifacts {
        num_inputs: first.num_inputs,
        num_eval_gates: first.num_eval_gates,
        adv_pipe_rows: first.stream_len / 8,
        order_tag_count,
        registry_root,
        registry_leaves,
        relation_digest,
        constraints_eval,
        relation_mod,
        air_config,
        stark_constants,
    })
}

fn write_artifacts(artifact: &ComputedArtifacts) -> io::Result<()> {
    write_file(CONSTRAINTS_EVAL_PATH, &artifact.constraints_eval)?;
    write_file(RELATION_DIGEST_PATH, &artifact.relation_mod)?;
    write_file(AIR_CONFIG_PATH, &artifact.air_config)?;
    write_file(STARK_CONSTANTS_PATH, &artifact.stark_constants)?;
    println!(
        "wrote asm/sys/vm/constraints_eval.masm ({} inputs, {} eval gates, repeat.{})",
        artifact.num_inputs, artifact.num_eval_gates, artifact.adv_pipe_rows
    );
    println!("wrote asm/sys/vm/mod.masm (relation digest and ACE registry root)");
    println!("wrote asm/stark/constants.masm ({} proof-order tags)", artifact.order_tag_count);
    println!("wrote air/src/config.rs (relation digest and ACE registry)");
    println!("done - run `cargo test -p miden-air --lib` to update the insta snapshot");
    Ok(())
}

fn ensure_uniform_circuit_metadata(order_artifacts: &[OrderArtifact]) -> io::Result<()> {
    let Some(first) = order_artifacts.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "at least one ACE circuit is required",
        ));
    };

    for artifact in &order_artifacts[1..] {
        if artifact.num_inputs != first.num_inputs
            || artifact.num_eval_gates != first.num_eval_gates
            || artifact.stream_len != first.stream_len
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ACE circuit metadata differs for {}", artifact.order.file_stem()),
            ));
        }
    }

    Ok(())
}

fn padding_leaf(index: usize) -> Word {
    Poseidon2::hash_elements(&[
        Felt::new_unchecked(ACE_REGISTRY_PADDING_DOMAIN),
        Felt::new_unchecked(index as u64),
    ])
}

fn word_from_array(elements: [Felt; 4]) -> Word {
    Word::new(elements)
}

fn word_to_array(word: Word) -> [Felt; 4] {
    [word[0], word[1], word[2], word[3]]
}

struct AceCircuitRegistry {
    leaves: Vec<Word>,
    root: [Felt; 4],
}

impl AceCircuitRegistry {
    fn from_order_artifacts(order_artifacts: &[OrderArtifact]) -> io::Result<Self> {
        let active_leaf_count = PROOF_ORDER_COUNT;
        if active_leaf_count > ACE_REGISTRY_LEAF_COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACE circuit registry is too small for the supported proof orders",
            ));
        }

        let mut leaves = (0..ACE_REGISTRY_LEAF_COUNT).map(padding_leaf).collect::<Vec<_>>();
        let mut seen = vec![false; active_leaf_count];

        for artifact in order_artifacts {
            let tag = artifact.order.tag() as usize;
            if tag >= active_leaf_count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("proof-order tag {tag} is outside the active registry range"),
                ));
            }
            if seen[tag] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("duplicate proof-order tag {tag}"),
                ));
            }

            seen[tag] = true;
            leaves[tag] = word_from_array(artifact.circuit_commitment);
        }

        if let Some(missing_tag) = seen.iter().position(|&is_seen| !is_seen) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing ACE circuit commitment for proof-order tag {missing_tag}"),
            ));
        }

        let tree = MerkleTree::new(&leaves).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to build ACE circuit registry: {err}"),
            )
        })?;

        Ok(Self { leaves, root: word_to_array(tree.root()) })
    }
}

fn render_constraints_eval_file(order_artifacts: &[OrderArtifact]) -> io::Result<String> {
    let Some(first) = order_artifacts.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "at least one ACE circuit is required",
        ));
    };
    if !first.stream_len.is_multiple_of(8) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ACE stream must be 8-felt aligned",
        ));
    }

    let adv_pipe_rows = first.stream_len / 8;
    let max_cycle_len_log = max_periodic_cycle_len_log();

    Ok(format!(
        concat!(
            "use miden::core::crypto::hashes::poseidon2\n",
            "use miden::core::stark::constants\n",
            "use miden::core::sys::vm::constraints_eval_inputs\n\n",
            "# CONSTANTS\n",
            "# =================================================================================================\n\n",
            "# Number of READ variables (inputs + constants) for the constraint evaluation circuit.\n",
            "const NUM_INPUTS_CIRCUIT = {num_inputs}\n\n",
            "# Number of evaluation gates in the constraint evaluation circuit\n",
            "const NUM_EVAL_GATES_CIRCUIT = {num_eval_gates}\n\n",
            "# Max cycle length for periodic columns\n",
            "const MAX_CYCLE_LEN_LOG = {max_cycle_len_log}\n\n",
            "# Depth of the ACE circuit registry tree.\n",
            "const ACE_REGISTRY_DEPTH = {ace_registry_depth}\n\n",
            "# ERRORS\n",
            "# =================================================================================================\n\n",
            "const ERR_CIRCUIT_COMMITMENT_MISMATCH = \"hashed ACE circuit stream does not match registry commitment\"\n\n",
            "# CONSTRAINT EVALUATION CHECKER\n",
            "# =================================================================================================\n\n",
            "#! Executes the constraints evaluation check for the proof order selected by ORDER_TAG.\n",
            "#!\n",
            "#! Inputs:  []\n",
            "#! Outputs: []\n",
            "pub proc execute_constraint_evaluation_check()\n",
            "    exec.constants::assert_valid_order_tag\n\n",
            "    push.MAX_CYCLE_LEN_LOG\n",
            "    exec.constraints_eval_inputs::set_up_auxiliary_inputs_ace\n\n",
            "    exec.load_and_authenticate_ace_circuit\n\n",
            "    push.NUM_EVAL_GATES_CIRCUIT\n",
            "    push.NUM_INPUTS_CIRCUIT\n",
            "    exec.constants::public_inputs_address_ptr mem_load\n",
            "    eval_circuit\n",
            "    drop drop drop\n",
            "end\n\n",
            "#! Loads and authenticates the ACE circuit selected by ORDER_TAG.\n",
            "proc load_and_authenticate_ace_circuit\n",
            "    exec.load_ace_registry_commitment\n",
            "    adv.push_mapval\n",
            "    exec.constants::ace_circuit_stream_ptr\n",
            "    padw padw padw\n",
            "    repeat.{adv_pipe_rows}\n",
            "        adv_pipe\n",
            "        exec.poseidon2::permute\n",
            "    end\n",
            "    exec.poseidon2::squeeze_digest\n",
            "    movup.4 drop\n",
            "    assert_eqw.err=ERR_CIRCUIT_COMMITMENT_MISMATCH\n",
            "end\n\n",
            "#! Loads the ACE circuit commitment selected by ORDER_TAG from the registry tree.\n",
            "proc load_ace_registry_commitment\n",
            "    padw exec.constants::ace_registry_root_ptr mem_loadw_le\n",
            "    exec.constants::get_order_tag\n",
            "    push.ACE_REGISTRY_DEPTH\n",
            "    mtree_get\n",
            "    swapw dropw\n",
            "end\n",
        ),
        num_inputs = first.num_inputs,
        num_eval_gates = first.num_eval_gates,
        max_cycle_len_log = max_cycle_len_log,
        ace_registry_depth = ACE_CIRCUIT_REGISTRY_DEPTH,
        adv_pipe_rows = adv_pipe_rows,
    ))
}

fn max_periodic_cycle_len_log() -> u32 {
    let max_len = AIRS
        .iter()
        .flat_map(<MidenAir as BaseAir<Felt>>::periodic_columns)
        .map(|column| column.len())
        .max()
        .unwrap_or(1);

    assert!(
        max_len.is_power_of_two(),
        "maximum AIR periodic cycle length must be a power of two"
    );
    max_len.ilog2()
}

/// Verify that the ACE circuit constants in `constraints_eval.masm` match the current AIR.
pub fn constraints_eval_masm_matches_air() -> Result<(), String> {
    let artifact = compute_artifacts().map_err(|e| e.to_string())?;
    let masm = read_file(CONSTRAINTS_EVAL_PATH).map_err(|e| e.to_string())?;
    if masm != artifact.constraints_eval {
        return Err(format!("{CONSTRAINTS_EVAL_PATH} is stale"));
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
    if miden_air::config::ACE_CIRCUIT_REGISTRY_ROOT != artifact.registry_root {
        return Err("ACE_CIRCUIT_REGISTRY_ROOT in air/src/config.rs is stale".into());
    }
    if miden_air::config::ACE_CIRCUIT_REGISTRY_LEAVES != artifact.registry_leaves.as_slice() {
        return Err("ACE_CIRCUIT_REGISTRY_LEAVES in air/src/config.rs is stale".into());
    }

    let masm = read_file(RELATION_DIGEST_PATH).map_err(|e| e.to_string())?;
    let mut masm_digest: [Felt; 4] = [Felt::ZERO; 4];
    for (i, slot) in masm_digest.iter_mut().enumerate() {
        let name = format!("RELATION_DIGEST_{i}");
        *slot =
            parse_masm_const::<u64>(&masm, &name, "sys/vm/mod.masm").map(Felt::new_unchecked)?;
    }

    if masm_digest != expected {
        return Err("RELATION_DIGEST in sys/vm/mod.masm is stale".into());
    }

    let mut masm_registry_root: [Felt; 4] = [Felt::ZERO; 4];
    for (i, slot) in masm_registry_root.iter_mut().enumerate() {
        let name = format!("ACE_REGISTRY_ROOT_{i}");
        *slot =
            parse_masm_const::<u64>(&masm, &name, "sys/vm/mod.masm").map(Felt::new_unchecked)?;
    }

    if masm_registry_root != artifact.registry_root {
        return Err("ACE registry root in sys/vm/mod.masm is stale".into());
    }

    let constants = read_file(STARK_CONSTANTS_PATH).map_err(|e| e.to_string())?;
    let order_tag_count =
        parse_masm_const::<usize>(&constants, "ORDER_TAG_COUNT", "stark/constants.masm")?;
    if order_tag_count != artifact.order_tag_count {
        return Err("ORDER_TAG_COUNT in stark/constants.masm is stale".into());
    }

    Ok(())
}

/// Verify that Miden VM public-input constants match the current AIR set.
pub fn public_inputs_masm_matches_air() -> Result<(), String> {
    let public_inputs = read_file(VM_PUBLIC_INPUTS_PATH).map_err(|e| e.to_string())?;
    let num_miden_airs =
        parse_masm_const::<usize>(&public_inputs, "NUM_MIDEN_AIRS", VM_PUBLIC_INPUTS_PATH)?;
    if num_miden_airs != MIDEN_AIR_COUNT {
        return Err("NUM_MIDEN_AIRS in sys/vm/public_inputs.masm is stale".into());
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

fn replace_masm_const(content: &mut String, name: &str, new_value: &str) -> io::Result<()> {
    let prefix = format!("const {name} = ");
    let line_start = content
        .find(&prefix)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} not found")))?;
    let line_end = content[line_start..]
        .find('\n')
        .map(|i| line_start + i)
        .unwrap_or(content.len());
    content.replace_range(line_start..line_end, &format!("{prefix}{new_value}"));
    Ok(())
}

fn replace_felt_array_const(
    content: &mut String,
    name: &str,
    values: &[Felt; 4],
) -> io::Result<()> {
    let marker = format!("pub const {name}: [Felt; 4] = [");
    let start = content
        .find(&marker)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} not found")))?;
    let block_start = start + marker.len();
    let block_end =
        content[block_start..].find("];").map(|idx| idx + block_start).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} terminator not found"))
        })?;
    let mut new_block: String = values
        .iter()
        .map(|f| format!("\n    Felt::new_unchecked({}),", f.as_canonical_u64()))
        .collect();
    new_block.push('\n');
    content.replace_range(block_start..block_end, &new_block);
    Ok(())
}

fn replace_registry_leaves(content: &mut String, leaves: &[[Felt; 4]]) -> io::Result<()> {
    let marker = "pub const ACE_CIRCUIT_REGISTRY_LEAVES: &[[Felt; 4]] = &[";
    let start = content.find(marker).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "ACE_CIRCUIT_REGISTRY_LEAVES not found in config.rs",
        )
    })?;
    let block_start = start + marker.len();
    let block_end =
        content[block_start..].find("];").map(|idx| idx + block_start).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "ACE_CIRCUIT_REGISTRY_LEAVES terminator not found",
            )
        })?;
    content.replace_range(block_start..block_end, &render_registry_leaves(leaves));
    Ok(())
}

fn render_registry_leaves(leaves: &[[Felt; 4]]) -> String {
    let mut block = String::new();
    for leaf in leaves {
        block.push_str("\n    [\n");
        for elem in leaf {
            block.push_str(&format!("        Felt::new_unchecked({}),\n", elem.as_canonical_u64()));
        }
        block.push_str("    ],");
    }
    block.push('\n');
    block
}

fn read_file(rel_path: &str) -> io::Result<String> {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel_path);
    fs::read_to_string(&path)
        .map_err(|e| io::Error::new(e.kind(), format!("failed to read {path}: {e}")))
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
    order_tag_count: usize,
    registry_root: [Felt; 4],
    registry_leaves: Vec<[Felt; 4]>,
    relation_digest: [Felt; 4],
    constraints_eval: String,
    relation_mod: String,
    air_config: String,
    stark_constants: String,
}

struct OrderArtifact {
    order: ProofOrder,
    num_inputs: usize,
    num_eval_gates: usize,
    stream_len: usize,
    circuit_commitment: [Felt; 4],
}
