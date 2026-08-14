//! Regeneration tool for the PVM ACE registry constants (`ace_registry/data.rs`).
//!
//! `--write` compares packed encode-only and scalar assembled commitments for every
//! ordering before minting constants. `--check` recomputes every packed leaf and compares
//! the exact encode-only and assembled shuffle streams for every ordering. A from-scratch
//! `hash_elements` cross-check over a structured order sample separately covers the
//! resumed-sponge arithmetic.
//!
//! Both modes cover all proof orders; sampling is confined to the independent hash oracle.

use std::{
    format, io, println,
    string::{String, ToString},
    vec::Vec,
};

use miden_ace_codegen::{
    FactoredCircuitFactory, PackedLeafScratch, ShuffleEncodeBuffer, fold_row_to_root,
    order_from_tag, order_tag, subtree_leaves,
};
use miden_core::{Felt, Word, crypto::hash::Poseidon2};
use miden_crypto::merkle::MerkleTree;
use rayon::prelude::*;

use crate::{
    ace::{PVM_REGISTRY_LAYOUT, build_precompile_factored_ace_circuit, structured_orders},
    ace_registry::{
        PVM_ACE_REGISTRY_LEVEL12_ROW, PVM_ACE_REGISTRY_ROOT, PVM_RELATION_DIGEST,
        relation_digest_for_root,
    },
};

const DATA_PATH: &str = "src/ace_registry/data.rs";

/// Whether [`run`] re-mints the committed artifacts (`Write`) or byte-compares a freshly
/// built set against them (`Check`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Check,
    Write,
}

/// Runs write (`--write`) or staleness-check (`--check`) mode.
pub fn run(mode: Mode) -> Result<(), String> {
    if cfg!(debug_assertions) {
        println!(
            "warning: debug builds are much slower; use `make check-pvm-registry` or \
             `make regenerate-pvm-registry` for the release-mode registry tools"
        );
    }
    let computed = compute(mode)?;
    match mode {
        Mode::Check => check(&computed),
        Mode::Write => write(&computed).map_err(|e| format!("{e}")),
    }
}

struct Computed {
    row: Vec<Word>,
    root: Word,
    digest: [Felt; 4],
}

/// Enumerate every ordering and compute the registry row, root, and relation digest.
fn compute(mode: Mode) -> Result<Computed, String> {
    let factored = build_precompile_factored_ace_circuit().map_err(|e| format!("{e}"))?;
    let factory = FactoredCircuitFactory::new(factored).map_err(|e| format!("{e}"))?;

    // From-scratch hash cross-check on the structured sample: the resumed sponge must
    // reproduce full-stream `hash_elements` digests. This is the hash-fault oracle the
    // per-order dual path below cannot be (both its sides share the resumed states).
    let mut scalar_buffer = ShuffleEncodeBuffer::new();
    for order in structured_orders() {
        let circuit = factory.circuit_for_order(&order).map_err(|e| format!("{e}"))?;
        let instructions = circuit.encoded.instructions();
        let scalar_leaf =
            factory.leaf_for_order(&order, &mut scalar_buffer).map_err(|e| format!("{e}"))?;
        if Poseidon2::hash_elements(&instructions[..circuit.shuffle_prefix_len])
            != circuit.shuffle_commitment
            || Poseidon2::hash_elements(&instructions[circuit.shuffle_prefix_len..])
                != circuit.common_commitment
            || scalar_leaf != circuit.commitment
        {
            return Err(format!(
                "resumed-sponge commitments diverge from from-scratch hashing for {order:?}"
            ));
        }
    }

    // One subtree per checked-in row node. Never materialises the full tree; the fan-out
    // is here because the generic subtree unit is deliberately serial.
    let completed = std::sync::atomic::AtomicUsize::new(0);
    let total = PVM_REGISTRY_LAYOUT.row_len();
    println!(
        "computing {} leaves over {total} subtrees, checking every assembled order ({mode:?})",
        PVM_REGISTRY_LAYOUT.order_count(),
    );
    let row: Vec<Word> = (0..PVM_REGISTRY_LAYOUT.row_len())
        .into_par_iter()
        .map_init(
            || (PackedLeafScratch::new(), ShuffleEncodeBuffer::new()),
            |(packed_scratch, scalar_buffer), subtree_index| -> Result<Word, String> {
                let leaves =
                    subtree_leaves(&factory, &PVM_REGISTRY_LAYOUT, subtree_index, packed_scratch)
                        .map_err(|e| format!("{e}"))?;

                let start = subtree_index * PVM_REGISTRY_LAYOUT.leaves_per_subtree();
                for (offset, leaf) in leaves.iter().enumerate() {
                    let tag = (start + offset) as u32;
                    let Some(order) = order_from_tag(tag, PVM_REGISTRY_LAYOUT.num_airs()) else {
                        continue;
                    };
                    if order_tag(&order) != tag {
                        return Err(format!(
                            "proof-order encoder does not invert the decoder at tag {tag}; \
                             refusing to mint"
                        ));
                    }

                    match mode {
                        Mode::Write => {
                            // Minting keeps the strongest hash differential: packed encode-only
                            // against the scalar commitment of the fully assembled stream.
                            let assembled =
                                factory.circuit_for_order(&order).map_err(|e| format!("{e}"))?;
                            if *leaf != assembled.commitment {
                                return Err(format!(
                                    "batched encode-only registry leaf diverges from the scalar \
                                     assembled circuit at tag {tag}; refusing to mint"
                                ));
                            }
                        },
                        Mode::Check => {
                            // Drift checks still cover every assembled order, but compare exact
                            // preimages instead of repeating 3.6 million scalar sponge runs.
                            let assembled = factory
                                .factored()
                                .circuit_for_order(&order)
                                .and_then(|circuit| circuit.to_ace())
                                .map_err(|e| format!("{e}"))?;
                            let fast = factory
                                .factored()
                                .encode_shuffle_section_for_order(&order, scalar_buffer)
                                .map_err(|e| format!("{e}"))?;
                            let shuffle_start = factory.const_felts();
                            let shuffle_end = shuffle_start + factory.factored().num_shuffle_ops();
                            if fast != &assembled.instructions()[shuffle_start..shuffle_end] {
                                return Err(format!(
                                    "encode-only shuffle stream diverges from the assembled \
                                     circuit at tag {tag}"
                                ));
                            }
                        },
                    }
                }

                let finished = completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if finished.is_multiple_of(512) || finished == total {
                    println!("  {finished}/{total} subtrees");
                }

                MerkleTree::new(&leaves)
                    .map(|subtree| subtree.root())
                    .map_err(|e| format!("subtree {subtree_index}: {e}"))
            },
        )
        .collect::<Result<Vec<_>, _>>()?;

    let root = fold_row_to_root(&row);
    let digest = relation_digest_for_root(&root);

    Ok(Computed { row, root, digest })
}

fn check(computed: &Computed) -> Result<(), String> {
    if computed.root != Word::new(PVM_ACE_REGISTRY_ROOT.map(Felt::new_unchecked)) {
        return Err("PVM_ACE_REGISTRY_ROOT in ace_registry/data.rs is stale (the root binds \
                    every registry leaf; leaves are recomputed and are not checked in)"
            .into());
    }
    if computed.digest != PVM_RELATION_DIGEST.map(Felt::new_unchecked) {
        return Err("PVM_RELATION_DIGEST in ace_registry/data.rs is stale".into());
    }
    let checked_in = PVM_ACE_REGISTRY_LEVEL12_ROW
        .iter()
        .map(|node| Word::new(node.map(Felt::new_unchecked)));
    if !computed.row.iter().copied().eq(checked_in) {
        return Err("PVM_ACE_REGISTRY_LEVEL12_ROW in ace_registry/data.rs is stale".into());
    }

    let path = data_path();
    let checked_in = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read generated registry data at {path}: {e}"))?;
    if checked_in != render(computed) {
        return Err(format!(
            "{DATA_PATH} was not produced by the current generator; run \
             `make regenerate-pvm-registry`"
        ));
    }

    println!("PVM ACE registry constants are up to date");
    Ok(())
}

fn format_word(word: &Word) -> String {
    word.iter().fold(String::new(), |mut output, felt| {
        output.push_str(&format!("    {},\n", felt.as_canonical_u64()));
        output
    })
}

fn render(computed: &Computed) -> String {
    let mut rows = String::new();
    for node in &computed.row {
        let limbs: Vec<String> =
            node.iter().map(|felt| felt.as_canonical_u64().to_string()).collect();
        rows.push_str(&format!("    [{}],\n", limbs.join(", ")));
    }
    let root = format_word(&computed.root);
    let digest = format_word(&Word::new(computed.digest));

    format!(
        "//! GENERATED by `make regenerate-pvm-registry` — do not edit by hand.\n//!\n//! \
         Protocol constants of the PVM ACE circuit registry. The row is authenticated\n//! \
         against the root at first use (`verified_pyramid`), so it carries no trust; \
         the\n//! root and relation digest are the protocol-visible values.\n\n/// Root of \
         the PVM ACE circuit registry (raw canonical u64 limbs).\npub const \
         PVM_ACE_REGISTRY_ROOT: [u64; 4] = [\n{root}];\n\n/// Relation digest binding the \
         registry root into the Fiat-Shamir transcript\n/// (raw canonical u64 limbs): \
         `Poseidon2(PVM_PROTOCOL_ID || PVM_ACE_REGISTRY_ROOT)`.\npub const \
         PVM_RELATION_DIGEST: [u64; 4] = [\n{digest}];\n\n/// The registry tree's 4096 nodes \
         at depth 12 (raw canonical u64 limbs).\n#[rustfmt::skip]\npub static \
         PVM_ACE_REGISTRY_LEVEL12_ROW: [[u64; 4]; 4096] = [\n{rows}];\n"
    )
}

fn data_path() -> String {
    format!("{}/{}", env!("CARGO_MANIFEST_DIR"), DATA_PATH)
}

fn write(computed: &Computed) -> io::Result<()> {
    let path = data_path();
    std::fs::write(&path, render(computed))
        .map_err(|e| io::Error::new(e.kind(), format!("failed to write {path}: {e}")))?;
    println!("wrote {path}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use miden_core::{Felt, Word};

    use super::format_word;

    #[test]
    fn generated_words_put_one_limb_on_each_line() {
        let word =
            Word::new([Felt::from(1u32), Felt::from(2u32), Felt::from(3u32), Felt::from(4u32)]);
        assert_eq!(format_word(&word), "    1,\n    2,\n    3,\n    4,\n");
    }
}
