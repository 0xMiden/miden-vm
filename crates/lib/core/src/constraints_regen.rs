use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use std::{fs, io, println};

use miden_ace_codegen::padding_leaf;
use miden_air::{
    AIRS, MIDEN_AIR_COUNT, MidenAir, PROOF_ORDER_COUNT, ProofOrder,
    ace::RecursiveAceCircuitFactory,
    config::{ACE_CIRCUIT_REGISTRY_DEPTH, relation_digest},
};
use miden_core::{Felt, Word, crypto::hash::Poseidon2};
use miden_crypto::{
    merkle::MerkleTree,
    stark::{QuotientRecompositionInputs, air::BaseAir, quotient_recomposition_inputs},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Check,
    Write,
}

const PROTOCOL_ID: u64 = 1;
const ACE_REGISTRY_LEAF_COUNT: usize = 1 << ACE_CIRCUIT_REGISTRY_DEPTH;
const AIR_CONFIG_PATH: &str = "../../../air/src/config.rs";
const CONSTRAINTS_EVAL_PATH: &str = "asm/sys/vm/constraints_eval.masm";
const RELATION_DIGEST_PATH: &str = "asm/sys/vm/mod.masm";
const VM_AUX_TRACE_PATH: &str = "asm/sys/vm/aux_trace.masm";
const VM_LAYOUT_PATH: &str = "asm/sys/vm/layout.masm";
const VM_PUBLIC_INPUTS_PATH: &str = "asm/sys/vm/public_inputs.masm";
const PVM_LAYOUT_PATH: &str = "asm/sys/pvm/layout.masm";

/// Computes the relation digest used by recursive verification.
pub fn compute_relation_digest(registry_root: &[Felt; 4]) -> [Felt; 4] {
    relation_digest(PROTOCOL_ID, &Word::new(*registry_root))
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
    // One factored build serves every proof order. Each order still assembles and encodes the
    // full stream, but the factory avoids rebuilding the composition and rehashing the common
    // section.
    let factory = RecursiveAceCircuitFactory::new()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    let num_quotient_chunks = factory.num_quotient_chunks();
    if !num_quotient_chunks.is_power_of_two() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("quotient chunk count {num_quotient_chunks} is not a power of two"),
        ));
    }
    let quotient_inputs = quotient_recomposition_inputs::<Felt>(
        num_quotient_chunks.ilog2() as u8,
        miden_air::config::pcs_params().log_blowup(),
    )
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    // Retain the first order's common-section bytes and require exact equality for later orders.
    // Comparing cached digests alone would not establish that the emitted sections are equal.
    let mut common_section: Option<Vec<Felt>> = None;
    let mut leaf_buffer = miden_ace_codegen::ShuffleEncodeBuffer::new();
    for order in ProofOrder::variants() {
        let circuit = factory
            .circuit_for_order(&order)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;

        // Compare the encode-only leaf with the assembled stream for every order before
        // deriving the root. This catches encoding divergence between the two construction
        // paths. It is not a hash oracle: both paths share the factory's cached sponge states.
        // Hash behavior is covered separately by the one-shot builder sweep in
        // air/tests/ace_codegen.rs and miden-crypto's packed-vs-scalar differential test.
        let fast_leaf = factory
            .leaf_for_order(&order, &mut leaf_buffer)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        if fast_leaf != circuit.commitment {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "encode-only registry leaf diverges from the assembled circuit for {}",
                    order.file_stem()
                ),
            ));
        }

        let common = &circuit.instructions[circuit.shuffle_prefix_len..];
        match &common_section {
            None => {
                if Poseidon2::hash_elements(common) != circuit.common_commitment {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ACE common-section digest does not match the emitted common section",
                    ));
                }
                common_section = Some(common.to_vec());
            },
            Some(reference) => {
                if common != reference.as_slice() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "ACE common section is not order-invariant: differs for {}",
                            order.file_stem()
                        ),
                    ));
                }
            },
        }

        order_artifacts.push(OrderArtifact {
            order,
            num_inputs: circuit.num_inputs,
            num_eval_gates: circuit.num_eval_gates,
            stream_len: circuit.stream_len,
            shuffle_prefix_len: circuit.shuffle_prefix_len,
            common_commitment: word_to_array(circuit.common_commitment),
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
    let relation_digest = compute_relation_digest(&registry_root);
    let constraints_eval = render_constraints_eval_file(&order_artifacts, quotient_inputs)?;

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

    let first = order_artifacts.first().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "at least one ACE circuit is required")
    })?;
    ensure_vm_ace_stream_fits(first.stream_len)?;

    Ok(ComputedArtifacts {
        num_inputs: first.num_inputs,
        num_eval_gates: first.num_eval_gates,
        prefix_rows: first.shuffle_prefix_len / 8,
        common_rows: (first.stream_len - first.shuffle_prefix_len) / 8,
        registry_root,
        relation_digest,
        constraints_eval,
        relation_mod,
        air_config,
    })
}

fn ensure_vm_ace_stream_fits(stream_len: usize) -> io::Result<()> {
    let vm_layout = read_file(VM_LAYOUT_PATH)?;
    let pvm_layout = read_file(PVM_LAYOUT_PATH)?;
    let stream_start =
        parse_masm_const::<usize>(&vm_layout, "ACE_CIRCUIT_STREAM_PTR", VM_LAYOUT_PATH)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let pvm_start = parse_masm_const::<usize>(&pvm_layout, "PUBLIC_INPUTS_PTR", PVM_LAYOUT_PATH)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    check_vm_ace_stream_capacity(stream_start, pvm_start, stream_len)
}

fn check_vm_ace_stream_capacity(
    stream_start: usize,
    pvm_start: usize,
    stream_len: usize,
) -> io::Result<()> {
    let capacity = pvm_start.checked_sub(stream_start).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "PVM allocation starts before the VM ACE stream")
    })?;
    if stream_len > capacity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "VM ACE stream requires {stream_len} felts but its fixed reservation holds \
                 {capacity}"
            ),
        ));
    }
    Ok(())
}

fn write_artifacts(artifact: &ComputedArtifacts) -> io::Result<()> {
    write_file(CONSTRAINTS_EVAL_PATH, &artifact.constraints_eval)?;
    write_file(RELATION_DIGEST_PATH, &artifact.relation_mod)?;
    write_file(AIR_CONFIG_PATH, &artifact.air_config)?;
    println!(
        "wrote asm/sys/vm/constraints_eval.masm ({} inputs, {} eval gates, repeat.{}+{})",
        artifact.num_inputs, artifact.num_eval_gates, artifact.prefix_rows, artifact.common_rows
    );
    println!("wrote asm/sys/vm/mod.masm (relation digest and ACE registry root)");
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
            || artifact.shuffle_prefix_len != first.shuffle_prefix_len
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ACE circuit metadata differs for {}", artifact.order.file_stem()),
            ));
        }
        if artifact.common_commitment != first.common_commitment {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ACE common-section digest differs for {}", artifact.order.file_stem()),
            ));
        }
    }

    Ok(())
}

fn word_from_array(elements: [Felt; 4]) -> Word {
    Word::new(elements)
}

fn word_to_array(word: Word) -> [Felt; 4] {
    [word[0], word[1], word[2], word[3]]
}

struct AceCircuitRegistry {
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

        let mut leaves = alloc::vec![padding_leaf(); ACE_REGISTRY_LEAF_COUNT];
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

        Ok(Self { root: word_to_array(tree.root()) })
    }
}

fn render_constraints_eval_file(
    order_artifacts: &[OrderArtifact],
    quotient_inputs: QuotientRecompositionInputs<Felt>,
) -> io::Result<String> {
    let Some(first) = order_artifacts.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "at least one ACE circuit is required",
        ));
    };
    let max_cycle_len_log = max_periodic_cycle_len_log();
    let h_common = first.common_commitment;

    miden_ace_codegen::render_masm_constraints_eval(&miden_ace_codegen::MasmConstraintsEvalConfig {
        generated_by: "cargo run -p miden-core-lib --features constraints-tools --bin \
                           regenerate-constraints -- --write",
        layout_module: "miden::core::sys::vm::layout",
        num_inputs: first.num_inputs,
        num_eval_gates: first.num_eval_gates,
        stream_len: first.stream_len,
        shuffle_prefix_len: first.shuffle_prefix_len,
        max_cycle_len_log,
        registry_depth: ACE_CIRCUIT_REGISTRY_DEPTH,
        order_tag_count: PROOF_ORDER_COUNT,
        num_airs: MIDEN_AIR_COUNT,
        quotient_inputs,
        common_commitment: Word::new(h_common),
    })
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
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
        return Err(
            "ACE_CIRCUIT_REGISTRY_ROOT in air/src/config.rs is stale (the root binds every \
             registry leaf; leaves are recomputed at runtime and are not checked in)"
                .into(),
        );
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

    // `derive_order_tag` sweeps this many AIRs and weights each inversion by
    // `(NUM_MIDEN_AIRS - 1 - pos)!`, so a stale value silently mis-ranks proof orders.
    let num_miden_airs = parse_masm_const::<usize>(&masm, "NUM_MIDEN_AIRS", "sys/vm/mod.masm")?;
    if num_miden_airs != MIDEN_AIR_COUNT {
        return Err("NUM_MIDEN_AIRS in sys/vm/mod.masm is stale".into());
    }

    // The VM aux hook dispatches the three weighted boundary sums by proof-order tag. Keep its
    // active-tag bound tied to the same AIR-derived order count as the generated evaluator.
    let aux_trace = read_file(VM_AUX_TRACE_PATH).map_err(|e| e.to_string())?;
    let order_tag_count =
        parse_masm_const::<usize>(&aux_trace, "ORDER_TAG_COUNT", VM_AUX_TRACE_PATH)?;
    if order_tag_count != PROOF_ORDER_COUNT {
        return Err("ORDER_TAG_COUNT in sys/vm/aux_trace.masm is stale".into());
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
    let marker = format!("pub const {name}:");
    let start = content
        .find(&marker)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} not found")))?;
    let init_marker = " = [";
    let init_start =
        content[start..].find(init_marker).map(|idx| start + idx).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} initializer not found"))
        })?;
    let block_start = init_start + init_marker.len();
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
    prefix_rows: usize,
    common_rows: usize,
    registry_root: [Felt; 4],
    relation_digest: [Felt; 4],
    constraints_eval: String,
    relation_mod: String,
    air_config: String,
}

struct OrderArtifact {
    order: ProofOrder,
    num_inputs: usize,
    num_eval_gates: usize,
    stream_len: usize,
    shuffle_prefix_len: usize,
    common_commitment: [Felt; 4],
    circuit_commitment: [Felt; 4],
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::check_vm_ace_stream_capacity;

    #[test]
    fn vm_ace_stream_capacity_accepts_exact_fit_and_rejects_overflow() {
        let stream_start = 1_000;
        let pvm_start = 1_100;

        check_vm_ace_stream_capacity(stream_start, pvm_start, 100).expect("exact fit");
        let error = check_vm_ace_stream_capacity(stream_start, pvm_start, 101)
            .expect_err("one felt beyond the reservation must fail");
        assert!(error.to_string().contains("requires 101 felts"));
    }

    #[test]
    fn vm_ace_stream_capacity_rejects_reversed_anchors() {
        let error = check_vm_ace_stream_capacity(1_100, 1_000, 0)
            .expect_err("the PVM allocation must follow the VM stream");
        assert!(error.to_string().contains("PVM allocation starts before"));
    }
}
