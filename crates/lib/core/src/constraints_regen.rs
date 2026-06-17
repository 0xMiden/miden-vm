use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use std::{fs, io, println};

use miden_ace_codegen::{AceCircuit, AceConfig, LayoutKind};
use miden_air::{
    AIRS, MidenAir, MidenMultiAir, NUM_PUBLIC_VALUES, ProofOrder, Statement, config,
    trace::and8_lookup::LOG_AND8_LOOKUP_TRACE_HEIGHT,
};
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    Word,
    hash::eidos::Eidos,
    merkle::MerkleTree,
    stark::{Preprocessed, air::LiftedAir},
};

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

const ACE_REGISTRY_DEPTH: usize = 5;
const ACE_REGISTRY_LEAF_COUNT: usize = 1 << ACE_REGISTRY_DEPTH;
const ACE_REGISTRY_PADDING_DOMAIN: u64 = 0xace;
const AIR_CONFIG_PATH: &str = "../../../air/src/config.rs";
const CONSTRAINTS_EVAL_PATH: &str = "asm/sys/vm/constraints_eval.masm";
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

/// Computes the ACE circuit registry root used by recursive verification.
pub fn compute_relation_digest(commitments: &[(ProofOrder, [Felt; 4])]) -> [Felt; 4] {
    AceCircuitRegistry::from_commitments(commitments)
        .expect("ACE circuit commitments must cover all proof-order tags")
        .root
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

    for order in ProofOrder::variants() {
        let circuit = build_batched_circuit_for_order(&order, MASM_CONFIG);
        let encoded = circuit.to_ace().unwrap();

        let num_inputs = encoded.num_vars();
        let num_eval_gates = encoded.num_eval_rows();
        let instructions = encoded.instructions();
        let stream_len = encoded.size_in_felt();
        if stream_len != instructions.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "circuit size_in_felt ({stream_len}) does not match instruction count ({})",
                    instructions.len()
                ),
            ));
        }
        if !stream_len.is_multiple_of(8) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "circuit stream length ({stream_len}) is not 8-aligned; adv_pipe requires 8-element chunks"
                ),
            ));
        }
        let adv_pipe_rows = stream_len / 8;
        let circuit_digest = Eidos::hash_elements(instructions);
        let circuit_elements = circuit_digest.as_elements();
        let circuit_commitment = [
            circuit_elements[0],
            circuit_elements[1],
            circuit_elements[2],
            circuit_elements[3],
        ];

        order_artifacts.push(OrderArtifact {
            order,
            num_inputs,
            num_eval_gates,
            stream_len,
            adv_pipe_rows,
            circuit_commitment,
            instructions: instructions.to_vec(),
        });
    }

    ensure_uniform_circuit_metadata(&order_artifacts)?;
    let registry = AceCircuitRegistry::from_order_artifacts(&order_artifacts)?;
    let relation_digest = registry.root;
    let registry_leaves = registry.leaves.iter().copied().map(word_to_array).collect::<Vec<_>>();
    let and8_preprocessed_commitment = compute_and8_preprocessed_commitment();
    let constraints_eval = render_constraints_eval_file(&order_artifacts)?;

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
        &LOG_AND8_LOOKUP_TRACE_HEIGHT.to_string(),
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

    let marker =
        "pub const ACE_CIRCUIT_REGISTRY_LEAVES: [[Felt; 4]; 1 << ACE_CIRCUIT_REGISTRY_DEPTH] = [";
    let start = air_config.find(marker).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "ACE_CIRCUIT_REGISTRY_LEAVES not found in config.rs",
        )
    })?;
    let block_start = start + marker.len();
    let block_end =
        air_config[block_start..]
            .find("];")
            .map(|idx| idx + block_start)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "ACE_CIRCUIT_REGISTRY_LEAVES terminator not found",
                )
            })?;
    air_config.replace_range(block_start..block_end, &render_registry_leaves(&registry_leaves));

    Ok(ComputedArtifacts {
        relation_digest,
        registry_leaves,
        and8_preprocessed_commitment,
        constraints_eval,
        relation_mod,
        air_config,
    })
}

fn compute_and8_preprocessed_commitment() -> [Felt; 4] {
    let config = config::eidos_config(config::pcs_params());
    let statement: Statement<Felt, QuadFelt, MidenMultiAir> =
        Statement::new(MidenMultiAir::new(), vec![Felt::ZERO; NUM_PUBLIC_VALUES], Vec::new())
            .expect("zero public inputs satisfy Miden statement shape");
    let preprocessed = Preprocessed::build(&statement, &config)
        .expect("Miden relation must declare the AND8 preprocessed table");

    let commitment: [u64; 4] = preprocessed.commitment().into();
    commitment.map(Felt::new_unchecked)
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
    Eidos::hash_elements(&[
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
        let commitments = order_artifacts
            .iter()
            .map(|artifact| (artifact.order.clone(), artifact.circuit_commitment))
            .collect::<Vec<_>>();

        Self::from_commitments(&commitments)
    }

    fn from_commitments(commitments: &[(ProofOrder, [Felt; 4])]) -> io::Result<Self> {
        let active_leaf_count = ProofOrder::variants().len();
        if active_leaf_count > ACE_REGISTRY_LEAF_COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACE circuit registry is too small for the supported proof orders",
            ));
        }

        let mut leaves = (0..ACE_REGISTRY_LEAF_COUNT).map(padding_leaf).collect::<Vec<_>>();
        let mut seen = vec![false; active_leaf_count];

        for (order, commitment) in commitments {
            let tag = order.tag() as usize;
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
            leaves[tag] = word_from_array(*commitment);
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

fn render_constraints_eval_file(order_artifacts: &[OrderArtifact]) -> io::Result<String> {
    let Some(first) = order_artifacts.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "at least one ACE circuit is required",
        ));
    };
    assert!(
        first.stream_len.is_multiple_of(8),
        "ACE circuit stream must be 8-felt aligned for adv_pipe"
    );
    let circuit_len =
        u32::try_from(first.stream_len).expect("ACE circuit stream length must fit in u32");
    let circuit_stream_init_cv = Eidos::init_chaining_word(0, circuit_len);
    let max_cycle_len_log = max_periodic_cycle_len_log();

    let mut masm = format!(
        concat!(
            "use miden::core::stark::constants\n",
            "use miden::core::stark::utils\n\n",
            "# CONSTANTS\n",
            "# =================================================================================================\n\n",
            "# Number of READ variables (inputs + constants) for the constraint evaluation circuit.\n",
            "const NUM_INPUTS_CIRCUIT = {num_inputs}\n\n",
            "# Number of evaluation gates in the constraint evaluation circuit.\n",
            "const NUM_EVAL_GATES_CIRCUIT = {num_eval_gates}\n\n",
            "# Max cycle length for periodic columns.\n",
            "const MAX_CYCLE_LEN_LOG = {max_cycle_len_log}\n\n",
            "# Depth of the ACE circuit registry tree.\n",
            "const ACE_REGISTRY_DEPTH = {ace_registry_depth}\n\n",
            "# Initial chaining value for hashing the ACE circuit stream.\n",
            "const CIRCUIT_STREAM_INIT_CV_0 = {init_cv_0}\n",
            "const CIRCUIT_STREAM_INIT_CV_1 = {init_cv_1}\n",
            "const CIRCUIT_STREAM_INIT_CV_2 = {init_cv_2}\n",
            "const CIRCUIT_STREAM_INIT_CV_3 = {init_cv_3}\n\n",
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
            "    exec.utils::set_up_auxiliary_inputs_ace\n\n",
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
            "    # => [C]\n",
            "    adv.push_mapval\n",
            "    # => [C]\n",
            "    exec.constants::ace_circuit_stream_ptr\n",
            "    # => [ptr, C]\n",
            "    push.CIRCUIT_STREAM_INIT_CV_3.CIRCUIT_STREAM_INIT_CV_2.CIRCUIT_STREAM_INIT_CV_1.CIRCUIT_STREAM_INIT_CV_0\n",
            "    # => [CV, ptr, C]\n",
            "    padw padw\n",
            "    # => [BLOCK_SLOTS, CV, ptr, C]\n",
            "    repeat.{adv_pipe_rows}\n",
            "        adv_pipe\n",
            "        # => [BLOCK, CV, ptr_next, C]\n",
            "        bcompress\n",
            "        # => [BLOCK, CV_NEXT, ptr_next, C]\n",
            "    end\n",
            "    dropw dropw\n",
            "    # => [DIGEST, ptr_final, C]\n",
            "    movup.4 drop\n",
            "    # => [DIGEST, C]\n",
            "    assert_eqw.err=ERR_CIRCUIT_COMMITMENT_MISMATCH\n",
            "    # => []\n",
            "end\n\n",
            "#! Loads the ACE circuit commitment selected by ORDER_TAG from the registry tree.\n",
            "proc load_ace_registry_commitment\n",
            "    exec.constants::relation_digest_ptr mem_loadw_le\n",
            "    # => [REGISTRY_ROOT]\n",
            "    exec.constants::get_order_tag\n",
            "    # => [order_tag, REGISTRY_ROOT]\n",
            "    push.ACE_REGISTRY_DEPTH\n",
            "    # => [depth, order_tag, REGISTRY_ROOT]\n",
            "    mtree_get\n",
            "    # => [C, REGISTRY_ROOT]\n",
            "    swapw dropw\n",
            "    # => [C]\n",
            "end\n\n",
            "# COMMITTED ACE CIRCUIT STREAMS\n",
            "# =================================================================================================\n\n",
        ),
        num_inputs = first.num_inputs,
        num_eval_gates = first.num_eval_gates,
        max_cycle_len_log = max_cycle_len_log,
        ace_registry_depth = ACE_REGISTRY_DEPTH,
        adv_pipe_rows = first.adv_pipe_rows,
        init_cv_0 = circuit_stream_init_cv[0].as_canonical_u64(),
        init_cv_1 = circuit_stream_init_cv[1].as_canonical_u64(),
        init_cv_2 = circuit_stream_init_cv[2].as_canonical_u64(),
        init_cv_3 = circuit_stream_init_cv[3].as_canonical_u64(),
    );

    for (index, artifact) in order_artifacts.iter().enumerate() {
        render_circuit_adv_map(&mut masm, artifact);
        if index + 1 != order_artifacts.len() {
            masm.push('\n');
        }
    }
    Ok(masm)
}

fn render_circuit_adv_map(masm: &mut String, artifact: &OrderArtifact) {
    masm.push_str(&format!("# Proof order: {}\n", artifact.order.label()));
    masm.push_str(&format!(
        "adv_map ACE_CIRCUIT_{}([{}, {}, {}, {}]) = [\n",
        artifact.order.tag(),
        artifact.circuit_commitment[0].as_canonical_u64(),
        artifact.circuit_commitment[1].as_canonical_u64(),
        artifact.circuit_commitment[2].as_canonical_u64(),
        artifact.circuit_commitment[3].as_canonical_u64(),
    ));
    for (i, chunk) in artifact.instructions.chunks(8).enumerate() {
        let vals: Vec<String> = chunk.iter().map(|f| f.as_canonical_u64().to_string()).collect();
        let line = vals.join(",");
        if i < artifact.adv_pipe_rows - 1 {
            masm.push_str(&format!("    {line},\n"));
        } else {
            masm.push_str(&format!("    {line}\n"));
        }
    }
    masm.push_str("]\n");
}

fn max_periodic_cycle_len_log() -> u32 {
    let max_len = AIRS
        .iter()
        .flat_map(|spec| <MidenAir as LiftedAir<Felt, QuadFelt>>::periodic_columns(&spec.air))
        .map(|column| column.len())
        .max()
        .unwrap_or(1);

    assert!(
        max_len.is_power_of_two(),
        "maximum AIR periodic cycle length must be a power of two"
    );
    max_len.ilog2()
}

fn write_artifacts(artifact: &ComputedArtifacts) -> io::Result<()> {
    remove_legacy_constraints_eval_files()?;
    write_file(CONSTRAINTS_EVAL_PATH, &artifact.constraints_eval)?;
    write_file(RELATION_DIGEST_PATH, &artifact.relation_mod)?;
    write_file(AIR_CONFIG_PATH, &artifact.air_config)?;
    println!("wrote asm/sys/vm/constraints_eval.masm (generic evaluator)");
    println!("wrote asm/sys/vm/mod.masm (RELATION_DIGEST)");
    println!("wrote air/src/config.rs (ACE registry)");
    println!("done - run `cargo test -p miden-air --lib` to update the insta snapshot");
    Ok(())
}

fn remove_legacy_constraints_eval_files() -> io::Result<()> {
    for order in ProofOrder::variants() {
        remove_file_if_exists(&format!("asm/sys/vm/{}.masm", order.file_stem()))?;
        remove_file_if_exists(&format!("docs/sys/vm/{}.md", order.file_stem()))?;
    }
    Ok(())
}

fn remove_file_if_exists(rel_path: &str) -> io::Result<()> {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel_path);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(io::Error::new(err.kind(), format!("failed to remove {path}: {err}"))),
    }
}

/// Verify that the generated ACE evaluator matches the current AIR.
pub fn constraints_eval_masm_matches_air() -> Result<(), String> {
    let artifact = compute_artifacts().map_err(|e| e.to_string())?;
    check_legacy_constraints_eval_files_absent()?;
    let constraints_eval = read_file(CONSTRAINTS_EVAL_PATH);
    if constraints_eval != artifact.constraints_eval {
        return Err(format!("{CONSTRAINTS_EVAL_PATH} is stale"));
    }
    Ok(())
}

fn check_legacy_constraints_eval_files_absent() -> Result<(), String> {
    for order in ProofOrder::variants() {
        let path = format!("asm/sys/vm/{}.masm", order.file_stem());
        if file_exists(&path) {
            return Err(format!("{path} is a legacy order-specific evaluator"));
        }
        let doc_path = format!("docs/sys/vm/{}.md", order.file_stem());
        if file_exists(&doc_path) {
            return Err(format!("{doc_path} is a legacy order-specific evaluator doc"));
        }
    }
    Ok(())
}

/// Verify that the ACE registry constants match the current AIR.
pub fn relation_digest_matches_air() -> Result<(), String> {
    let artifact = compute_artifacts().map_err(|e| e.to_string())?;
    let expected = artifact.relation_digest;

    if miden_air::config::RELATION_DIGEST != expected {
        return Err("RELATION_DIGEST in air/src/config.rs is stale".into());
    }
    if miden_air::config::ACE_CIRCUIT_REGISTRY_LEAVES.as_slice()
        != artifact.registry_leaves.as_slice()
    {
        return Err("ACE_CIRCUIT_REGISTRY_LEAVES in air/src/config.rs is stale".into());
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

fn file_exists(rel_path: &str) -> bool {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel_path);
    fs::metadata(path).is_ok()
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
    stream_len: usize,
    adv_pipe_rows: usize,
    circuit_commitment: [Felt; 4],
    instructions: Vec<Felt>,
}

struct ComputedArtifacts {
    relation_digest: [Felt; 4],
    registry_leaves: Vec<[Felt; 4]>,
    and8_preprocessed_commitment: [Felt; 4],
    constraints_eval: String,
    relation_mod: String,
    air_config: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ace_registry_places_commitments_by_order_tag() {
        let commitments = dummy_commitments();
        let registry = AceCircuitRegistry::from_commitments(&commitments).unwrap();

        for (order, commitment) in commitments {
            assert_eq!(registry.leaves[order.tag() as usize], word_from_array(commitment));
        }
    }

    #[test]
    fn ace_registry_uses_padding_leaves_outside_supported_orders() {
        let registry = AceCircuitRegistry::from_commitments(&dummy_commitments()).unwrap();

        for index in ProofOrder::variants().len()..ACE_REGISTRY_LEAF_COUNT {
            assert_eq!(registry.leaves[index], padding_leaf(index));
        }
    }

    #[test]
    fn ace_registry_rejects_missing_and_duplicate_tags() {
        let mut missing = dummy_commitments();
        missing.pop();
        assert!(AceCircuitRegistry::from_commitments(&missing).is_err());

        let mut duplicate = dummy_commitments();
        duplicate[1].0 = duplicate[0].0.clone();
        assert!(AceCircuitRegistry::from_commitments(&duplicate).is_err());
    }

    fn dummy_commitments() -> Vec<(ProofOrder, [Felt; 4])> {
        ProofOrder::variants()
            .into_iter()
            .map(|order| {
                let tag = order.tag() as u64;
                (
                    order,
                    [
                        Felt::new_unchecked(tag + 1),
                        Felt::new_unchecked(tag + 2),
                        Felt::new_unchecked(tag + 3),
                        Felt::new_unchecked(tag + 4),
                    ],
                )
            })
            .collect()
    }
}
