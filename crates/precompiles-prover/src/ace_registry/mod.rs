//! The PVM ACE circuit registry: root-committed and served one path per proof.
//!
//! The precompile relation commits to one factored ACE circuit per proof ordering of its
//! ten chiplets — `10!` active leaves in a depth-22 tree, indexed by order tag. The
//! generic machinery lives in [`miden_ace_codegen::registry`]; this module is its PVM
//! instantiation: the checked-in constants (`data.rs`, written by `pvm-registry-regen`),
//! the process-wide caches, and the relation-digest domain.
//!
//! The full `2^22`-leaf tree is never materialised. The checked-in row is authenticated
//! against the root, and each lookup rebuilds one 1024-leaf subtree and splices its path
//! with the nodes above that row.

use alloc::vec::Vec;
#[cfg(any(test, feature = "std"))]
use std::sync::OnceLock;

#[cfg(any(test, feature = "std"))]
use miden_ace_codegen::{
    FactoredCircuitFactory, PackedLeafScratch, order_from_tag, padding_leaf, path_in_verified_tree,
    subtree_leaves, verify_row,
};
#[cfg(any(test, feature = "std"))]
use miden_core::field::QuadFelt;
use miden_core::{Felt, Word};
#[cfg(any(test, feature = "std"))]
use miden_crypto::merkle::{MerklePath, MerkleTree};

#[cfg(any(test, feature = "std"))]
use crate::{
    ace::{PVM_ORDER_COUNT, PVM_REGISTRY_LAYOUT, build_precompile_factored_ace_circuit},
    session::NUM_CHIPLETS,
};

mod data;
pub(crate) use data::PVM_ACE_REGISTRY_LEVEL12_ROW;
pub use data::{PVM_ACE_REGISTRY_ROOT, PVM_RELATION_DIGEST};

/// Depth of the checked-in node row (see `data.rs`).
///
/// The row stores 4096 nodes (128 KiB as raw limbs); each lookup recomputes 1024 leaves.
pub const PVM_REGISTRY_ROW_DEPTH: usize = 12;

/// Protocol version included in the PVM relation digest.
///
/// The ACE registry binds the generated circuit, but not external multi-AIR assertions such as
/// `ChipletMultiAir::eval_external`. Changes to those semantics require a protocol-version bump.
/// The Miden VM currently uses the same version; distinct registry roots separate the relations.
pub(crate) const PVM_PROTOCOL_ID: u64 = 1;

/// Compute the relation digest binding a registry root into the Fiat-Shamir transcript.
pub(crate) fn relation_digest_for_root(root: &Word) -> [Felt; 4] {
    miden_air::config::relation_digest(PVM_PROTOCOL_ID, root)
}

#[cfg(any(test, feature = "std"))]
/// How to react to a registry-constant mismatch, appended to the panic messages raised
/// by the generic authentication checks.
const MISMATCH_HINT: &str = "If this protocol change is intentional, run \
     `make regenerate-pvm-registry` and record the break; otherwise inspect the unexpected \
     registry drift before updating constants";

#[cfg(any(test, feature = "std"))]
/// Authentication data for one PVM registry slot: its leaf and Merkle path.
///
/// Returns `None` when `tag` does not address a slot of the registry tree. Padding slots
/// (tags at or above `PVM_ORDER_COUNT`) resolve like any other slot. A verifier must reject
/// those tags before treating the leaf as a circuit commitment.
pub fn pvm_ace_registry_path(tag: u32) -> Option<(Word, MerklePath)> {
    if (tag as usize) >= PVM_REGISTRY_LAYOUT.leaf_count() {
        return None;
    }
    let subtree_index = tag as usize / PVM_REGISTRY_LAYOUT.subtree_leaves();
    let leaves = leaves_for_subtree(subtree_index);
    let subtree = MerkleTree::new(&leaves).expect("subtree has power-of-two leaves");
    Some(
        path_in_verified_tree(
            &PVM_REGISTRY_LAYOUT,
            verified_pyramid(),
            &subtree,
            tag,
            MISMATCH_HINT,
        )
        .expect("bounded tag and verified pyramid must produce a registry path"),
    )
}

#[cfg(any(test, feature = "std"))]
/// The row-and-above node pyramid, authenticated against [`PVM_ACE_REGISTRY_ROOT`]
/// before anything can read it.
fn verified_pyramid() -> &'static Vec<Vec<Word>> {
    static PYRAMID: OnceLock<Vec<Vec<Word>>> = OnceLock::new();
    PYRAMID.get_or_init(|| {
        let row: Vec<Word> = PVM_ACE_REGISTRY_LEVEL12_ROW
            .iter()
            .map(|node| Word::new(node.map(Felt::new_unchecked)))
            .collect();
        verify_row(&PVM_REGISTRY_LAYOUT, &row, registry_root(), MISMATCH_HINT)
    })
}

/// The checked-in registry root.
pub fn registry_root() -> Word {
    Word::new(PVM_ACE_REGISTRY_ROOT.map(Felt::new_unchecked))
}

#[cfg(any(test, feature = "std"))]
/// The factored composition and factory, built once per process.
pub(crate) fn factory() -> &'static FactoredCircuitFactory<QuadFelt> {
    static FACTORY: OnceLock<FactoredCircuitFactory<QuadFelt>> = OnceLock::new();
    FACTORY.get_or_init(|| {
        let factored =
            build_precompile_factored_ace_circuit().expect("precompile composition must build");
        FactoredCircuitFactory::new(factored).expect("factory construction cross-checks must pass")
    })
}

/// Batch size per worker when a subtree's leaves are computed in parallel.
#[cfg(all(feature = "concurrent", any(test, feature = "std")))]
const LEAF_CHUNK: usize = 64;

#[cfg(any(test, feature = "std"))]
/// Recompute one subtree's leaves.
///
/// Under the `concurrent` feature the subtree is split across the rayon pool: a lookup's
/// whole cost is this recompute, and it is otherwise a single-core loop.
fn leaves_for_subtree(subtree_index: usize) -> Vec<Word> {
    let factory = factory();
    #[cfg(feature = "concurrent")]
    {
        use rayon::prelude::*;

        let leaves = PVM_REGISTRY_LAYOUT.subtree_leaves();
        let start = subtree_index * leaves;
        (0..leaves)
            .into_par_iter()
            .chunks(LEAF_CHUNK)
            .map_init(PackedLeafScratch::new, |scratch, offsets| {
                subtree_leaf_range(factory, start, &offsets, scratch)
            })
            .flatten()
            .collect()
    }
    #[cfg(not(feature = "concurrent"))]
    {
        let mut scratch = PackedLeafScratch::new();
        subtree_leaves(factory, &PVM_REGISTRY_LAYOUT, subtree_index, &mut scratch)
            .expect("registry leaves must encode for every proof order")
    }
}

#[cfg(all(feature = "concurrent", any(test, feature = "std")))]
/// Leaves for a set of slot offsets within the subtree starting at `start`.
fn subtree_leaf_range(
    factory: &FactoredCircuitFactory<QuadFelt>,
    start: usize,
    offsets: &[usize],
    scratch: &mut PackedLeafScratch,
) -> Vec<Word> {
    let orders: Vec<Vec<usize>> = offsets
        .iter()
        .filter_map(|&offset| order_from_tag((start + offset) as u32, NUM_CHIPLETS))
        .collect();
    let order_refs: Vec<&[usize]> = orders.iter().map(Vec::as_slice).collect();
    let mut leaves = Vec::with_capacity(offsets.len());
    if !order_refs.is_empty() {
        factory
            .leaves_for_orders(&order_refs, scratch, &mut leaves)
            .expect("registry leaves must encode for every proof order");
    }
    // Slots past the realizable prefix are padding.
    leaves.resize(offsets.len(), padding_leaf());
    leaves
}

#[cfg(test)]
mod tests;
