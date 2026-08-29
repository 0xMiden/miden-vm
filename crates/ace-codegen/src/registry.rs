//! Registry construction over the proof orderings of a factored ACE composition.
//!
//! A multi-AIR relation whose committed trace order varies per workload needs one ACE
//! circuit per ordering. The accepted set is committed as a Merkle tree — the *registry*
//! — whose leaf at index `t` is the circuit commitment of the ordering with
//! [`order_tag`] `t`, and whose root is a protocol constant bound into the Fiat-Shamir
//! transcript. Orderings that no workload can produce are covered by a constant
//! [`padding_leaf`].
//!
//! At `n` AIRs there are `n!` orderings, so for anything past a handful the leaves can
//! be neither checked in nor materialised per process. This module implements the
//! scheme that avoids both: check in the tree's node row at some
//! [`RegistryLayout::row_depth`], authenticate that row against the root once
//! ([`verify_row`]), and per lookup recompute only the addressed leaf's subtree
//! ([`subtree_leaves`]) before splicing the two halves of its authentication path
//! ([`path_in_verified_tree`]).
//!
//! Everything here is parameterised by [`RegistryLayout`]; `row_depth = 0` degenerates
//! to "recompute every leaf, check the root", which is the right shape for a registry
//! small enough to rebuild wholesale.

use miden_core::{Felt, Word, crypto::hash::Poseidon2};
use miden_crypto::{
    field::ExtensionField,
    merkle::{MerklePath, MerkleTree, NodeIndex},
};

use crate::{
    AceError,
    factory::{FactoredCircuitFactory, PackedLeafScratch},
};

/// Domain tag distinguishing registry padding leaves from circuit commitments.
const PADDING_DOMAIN: u64 = 0xace;

/// Largest AIR count whose complete permutation set fits in the `u32` registry-tag space.
///
/// `12!` fits; `13!` does not. Registry construction must reject larger compositions before
/// any tag is narrowed to `u32`.
pub const MAX_REGISTRY_AIRS: usize = 12;

/// Leaf value for registry slots that no proof ordering maps to.
///
/// Constant, not index-derived: identical padding leaves let every all-padding subtree
/// share one root per depth. The domain tag — not the index — is what stops a padding
/// leaf being read as a circuit commitment, and a tag bound below the active leaf count
/// stops padding slots being opened at all.
pub fn padding_leaf() -> Word {
    Poseidon2::hash_elements(&[Felt::new_unchecked(PADDING_DOMAIN)])
}

/// Compute `n!`.
pub const fn factorial(n: usize) -> usize {
    let mut result: usize = 1;
    let mut factor: usize = 2;
    while factor <= n {
        result = match result.checked_mul(factor) {
            Some(value) => value,
            None => panic!("factorial overflows usize"),
        };
        factor += 1;
    }
    result
}

/// Return the smallest `d` such that `2^d >= value`.
pub const fn ceil_log2(value: usize) -> usize {
    assert!(value > 0, "ceil_log2 is undefined for zero");
    let mut value = value - 1;
    let mut result = 0;
    while value > 0 {
        value >>= 1;
        result += 1;
    }
    result
}

/// Registry tag of a proof ordering: its Lehmer rank relative to the canonical
/// (identity) instance order.
///
/// Digit `i` counts the smaller instance indices to the right of position `i`, weighted
/// by `(n - 1 - i)!`. Panics unless `proof_order` is a nonempty permutation of
/// `0..proof_order.len()` within [`MAX_REGISTRY_AIRS`].
pub fn order_tag(proof_order: &[usize]) -> u32 {
    let num_airs = proof_order.len();
    assert!(
        (1..=MAX_REGISTRY_AIRS).contains(&num_airs),
        "registry order must contain 1..={MAX_REGISTRY_AIRS} AIRs"
    );
    assert!(is_permutation(proof_order), "proof order must be a permutation");
    let mut rank: u64 = 0;
    for i in 0..num_airs {
        let smaller_after =
            proof_order[i + 1..].iter().filter(|&&index| index < proof_order[i]).count();
        rank += smaller_after as u64 * factorial(num_airs - 1 - i) as u64;
    }
    u32::try_from(rank).expect("tags of a supported AIR count fit in u32")
}

/// Decode a registry tag into its proof ordering over `num_airs` AIRs.
///
/// Returns `None` for tags at or above `num_airs!`, i.e. registry padding slots.
pub fn order_from_tag(tag: u32, num_airs: usize) -> Option<Vec<usize>> {
    if !(1..=MAX_REGISTRY_AIRS).contains(&num_airs) {
        return None;
    }
    if tag as usize >= factorial(num_airs) {
        return None;
    }
    let mut rank = tag as usize;
    let mut remaining: Vec<usize> = (0..num_airs).collect();
    let mut order = Vec::with_capacity(num_airs);
    for i in 0..num_airs {
        let factor = factorial(num_airs - 1 - i);
        // The next Lehmer digit selects an instance index from the remaining ordered list.
        order.push(remaining.remove(rank / factor));
        rank %= factor;
    }
    Some(order)
}

fn is_permutation(proof_order: &[usize]) -> bool {
    let mut seen = vec![false; proof_order.len()];
    proof_order
        .iter()
        .all(|&index| index < seen.len() && !core::mem::replace(&mut seen[index], true))
}

/// Shape of a registry: how many orderings it covers and where its checked-in node row
/// sits.
///
/// `row_depth` trades checked-in artifact size against per-lookup work: the row holds
/// `2^row_depth` nodes and each covers `2^(tree_depth - row_depth)` leaves, which is
/// what a lookup recomputes. `row_depth = 0` means the row is the root itself, i.e.
/// every lookup rebuilds the whole tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryLayout {
    num_airs: usize,
    row_depth: usize,
}

impl RegistryLayout {
    /// Build a layout, or `None` if the AIR count cannot be represented by `u32` tags or
    /// the checked-in row does not sit strictly above the leaves.
    ///
    /// A registry needs at least two AIRs. A single AIR has one ordering, while the Merkle
    /// implementation used by the serving path requires at least two leaves.
    pub const fn new(num_airs: usize, row_depth: usize) -> Option<Self> {
        if num_airs < 2 || num_airs > MAX_REGISTRY_AIRS {
            return None;
        }
        if row_depth >= ceil_log2(factorial(num_airs)) {
            return None;
        }
        Some(Self { num_airs, row_depth })
    }

    /// Number of AIRs in the composition.
    pub const fn num_airs(&self) -> usize {
        self.num_airs
    }

    /// Number of proof orderings, i.e. active leaves (`num_airs!`).
    pub const fn order_count(&self) -> usize {
        factorial(self.num_airs)
    }

    /// Smallest tree depth covering every tag.
    pub const fn tree_depth(&self) -> usize {
        ceil_log2(self.order_count())
    }

    /// Total leaf slots, active plus padding.
    pub const fn leaf_count(&self) -> usize {
        1 << self.tree_depth()
    }

    /// Depth of the checked-in node row.
    pub const fn row_depth(&self) -> usize {
        self.row_depth
    }

    /// Number of nodes in the checked-in row.
    pub const fn row_len(&self) -> usize {
        1 << self.row_depth
    }

    /// Leaves under one row node, i.e. the work one lookup recomputes.
    pub const fn leaves_per_subtree(&self) -> usize {
        1 << (self.tree_depth() - self.row_depth)
    }
}

/// Compute the leaves of one row node's subtree, in slot order.
///
/// Slots below `layout.order_count()` get their ordering's circuit leaf through the
/// factory's encode-only path; the rest keep [`padding_leaf`]. Realizable tags form a
/// prefix of the slot range, so at most one subtree is part active and part padding.
///
/// This is the unit of work a caller parallelises over (`0..layout.row_len()` when
/// minting, one index when serving); it is deliberately free of any parallelism itself.
pub fn subtree_leaves<EF>(
    factory: &FactoredCircuitFactory<EF>,
    layout: &RegistryLayout,
    subtree_index: usize,
    scratch: &mut PackedLeafScratch,
) -> Result<Vec<Word>, AceError>
where
    EF: ExtensionField<Felt>,
{
    let start = subtree_start(layout, subtree_index)?;
    let realizable = layout.order_count().saturating_sub(start).min(layout.leaves_per_subtree());
    let orders: Vec<Vec<usize>> = (0..realizable)
        .map(|offset| {
            order_from_tag((start + offset) as u32, layout.num_airs())
                .expect("tag below the order count is realizable")
        })
        .collect();
    let order_refs: Vec<&[usize]> = orders.iter().map(Vec::as_slice).collect();

    let mut leaves = Vec::with_capacity(layout.leaves_per_subtree());
    if !order_refs.is_empty() {
        factory.leaves_for_orders(&order_refs, scratch, &mut leaves)?;
    }
    leaves.resize(layout.leaves_per_subtree(), padding_leaf());
    Ok(leaves)
}

fn subtree_start(layout: &RegistryLayout, subtree_index: usize) -> Result<usize, AceError> {
    if subtree_index >= layout.row_len() {
        return Err(AceError::InvalidInputLayout {
            message: format!(
                "registry subtree index {subtree_index} is outside 0..{}",
                layout.row_len()
            ),
        });
    }
    subtree_index.checked_mul(layout.leaves_per_subtree()).ok_or_else(|| {
        AceError::InvalidInputLayout {
            message: "registry subtree offset overflowed".into(),
        }
    })
}

/// Fold a node row up to the tree root.
pub fn fold_row_to_root(row: &[Word]) -> Word {
    assert!(row.len().is_power_of_two(), "a node row has a power-of-two length");
    fold_levels(row).last().expect("root level")[0]
}

/// Node levels from `row` upward: element 0 is the row itself, the last the one-node root.
fn fold_levels(row: &[Word]) -> Vec<Vec<Word>> {
    let mut levels: Vec<Vec<Word>> = Vec::new();
    levels.push(row.to_vec());
    while levels.last().expect("at least the row").len() > 1 {
        let below = levels.last().expect("level exists");
        #[allow(clippy::chunks_exact_to_as_chunks)]
        let above: Vec<Word> = below
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| Poseidon2::merge(&[pair[0], pair[1]]))
            .collect();
        levels.push(above);
    }
    levels
}

/// Hash a checked-in node row upward and authenticate it against the registry root.
///
/// Returns the node pyramid, `pyramid[d]` holding the `2^d` nodes at depth `d` for `d`
/// in `0..=row_depth`. The row itself is therefore not trust-bearing: a wrong or stale
/// row fails here rather than producing paths that fail opaquely later. `mismatch_hint`
/// is appended to the panic message so a caller can say how to regenerate its own
/// constants.
pub fn verify_row(
    layout: &RegistryLayout,
    row: &[Word],
    expected_root: Word,
    mismatch_hint: &str,
) -> Vec<Vec<Word>> {
    assert_eq!(
        row.len(),
        layout.row_len(),
        "checked-in node row length does not match the registry layout"
    );
    let mut levels = fold_levels(row);
    levels.reverse();
    assert_eq!(
        levels[0][0], expected_root,
        "checked-in ACE registry node row does not hash to the registry root. {mismatch_hint}",
    );
    levels
}

/// Splice the authentication path for `tag` from its recomputed subtree and the verified
/// pyramid above the row.
///
/// The lower `tree_depth - row_depth` siblings come from `subtree`; the upper
/// `row_depth` siblings are read off the pyramid, whose entries were authenticated
/// against the root by [`verify_row`]. The subtree's own root is checked against its row
/// entry first, which re-derives per lookup the binding the mint established.
pub fn path_in_verified_tree(
    layout: &RegistryLayout,
    pyramid: &[Vec<Word>],
    subtree: &MerkleTree,
    tag: u32,
    mismatch_hint: &str,
) -> Result<(Word, MerklePath), AceError> {
    if tag as usize >= layout.leaf_count() {
        return Err(AceError::InvalidInputLayout {
            message: format!("registry tag {tag} is outside the tree"),
        });
    }
    if pyramid.len() != layout.row_depth() + 1
        || pyramid.iter().enumerate().any(|(depth, level)| level.len() != 1 << depth)
    {
        return Err(AceError::InvalidInputLayout {
            message: "registry pyramid does not match the layout".into(),
        });
    }

    let subtree_index = tag as usize / layout.leaves_per_subtree();
    assert_eq!(
        subtree.root(),
        pyramid[layout.row_depth()][subtree_index],
        "recomputed ACE registry subtree {subtree_index} does not match the checked-in \
         node row. {mismatch_hint}",
    );

    let index = NodeIndex::new(
        (layout.tree_depth() - layout.row_depth()) as u8,
        (tag as usize % layout.leaves_per_subtree()) as u64,
    )
    .map_err(|_| AceError::InvalidInputLayout {
        message: "registry tag does not fit the subtree".into(),
    })?;
    let leaf = subtree.get_node(index).map_err(|_| AceError::InvalidInputLayout {
        message: "registry subtree does not contain the selected leaf".into(),
    })?;
    let mut nodes = subtree
        .get_path(index)
        .map_err(|_| AceError::InvalidInputLayout {
            message: "registry subtree cannot authenticate the selected leaf".into(),
        })?
        .nodes()
        .to_vec();

    // Upper siblings: at depth `d` the ancestor of the tag's subtree is
    // `subtree_index >> (row_depth - d)`, and its sibling flips bit 0.
    for depth in (1..=layout.row_depth()).rev() {
        let ancestor = subtree_index >> (layout.row_depth() - depth);
        nodes.push(pyramid[depth][ancestor ^ 1]);
    }
    Ok((leaf, MerklePath::new(nodes)))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn registry_path_case() -> impl Strategy<Value = (RegistryLayout, u32, u32)> {
        (2usize..=6).prop_flat_map(|num_airs| {
            let tree_depth = ceil_log2(factorial(num_airs));
            (0..tree_depth).prop_flat_map(move |row_depth| {
                let layout = RegistryLayout::new(num_airs, row_depth).expect("valid layout");
                let mut boundary_tags = vec![0, layout.order_count() as u32 - 1];
                if layout.order_count() < layout.leaf_count() {
                    boundary_tags.push(layout.order_count() as u32);
                }
                boundary_tags.push(layout.leaf_count() as u32 - 1);
                (
                    Just(layout),
                    prop_oneof![
                        3 => proptest::sample::select(boundary_tags),
                        5 => 0..layout.leaf_count() as u32,
                    ],
                    any::<u32>(),
                )
            })
        })
    }

    #[test]
    fn order_tags_round_trip_over_the_whole_range() {
        for num_airs in 1..=6 {
            for tag in 0..factorial(num_airs) as u32 {
                let order = order_from_tag(tag, num_airs).expect("tag in range");
                assert_eq!(order_tag(&order), tag, "round trip fails at {num_airs} AIRs, {tag}");
            }
            assert_eq!(order_from_tag(factorial(num_airs) as u32, num_airs), None);
            let identity: Vec<usize> = (0..num_airs).collect();
            assert_eq!(order_tag(&identity), 0, "the identity ordering must be tag 0");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn larger_order_tags_round_trip(raw_tags in any::<[u32; 6]>()) {
            for (num_airs, raw_tag) in (7..=MAX_REGISTRY_AIRS).zip(raw_tags) {
                let tag = raw_tag % factorial(num_airs) as u32;
                let order = order_from_tag(tag, num_airs).expect("tag in range");
                prop_assert_eq!(order_tag(&order), tag);
            }
        }

        #[test]
        fn spliced_paths_match_varied_registry_layouts(
            (layout, tag, salt) in registry_path_case(),
        ) {
            let mut leaves: Vec<Word> = (0..layout.order_count())
                .map(|index| {
                    Poseidon2::hash_elements(&[
                        Felt::new_unchecked(u64::from(salt)),
                        Felt::new_unchecked(index as u64),
                    ])
                })
                .collect();
            leaves.resize(layout.leaf_count(), padding_leaf());

            let tree = MerkleTree::new(&leaves).expect("complete tree");
            let row: Vec<Word> = if layout.row_depth() == 0 {
                vec![tree.root()]
            } else {
                (0..layout.row_len())
                    .map(|index| {
                        tree.get_node(
                            NodeIndex::new(layout.row_depth() as u8, index as u64)
                                .expect("row index"),
                        )
                        .expect("row node")
                    })
                    .collect()
            };
            let pyramid = verify_row(&layout, &row, tree.root(), "toy row must authenticate");
            let subtree_index = tag as usize / layout.leaves_per_subtree();
            let start = subtree_index * layout.leaves_per_subtree();
            let subtree = MerkleTree::new(&leaves[start..start + layout.leaves_per_subtree()])
                .expect("complete subtree");

            let (leaf, path) =
                path_in_verified_tree(&layout, &pyramid, &subtree, tag, "toy path")
                    .expect("valid path");
            prop_assert_eq!(leaf, leaves[tag as usize]);
            prop_assert_eq!(
                path.compute_root(u64::from(tag), leaf).expect("path root"),
                tree.root(),
            );
        }
    }

    #[test]
    fn layout_derives_its_shape_from_the_air_count() {
        let layout = RegistryLayout::new(10, 12).expect("valid layout");
        assert_eq!(layout.order_count(), 3_628_800);
        assert_eq!(layout.tree_depth(), 22);
        assert_eq!(layout.leaf_count(), 1 << 22);
        assert_eq!(layout.row_len(), 4096);
        assert_eq!(layout.leaves_per_subtree(), 1024);

        // row_depth = 0 degenerates to a single whole-tree rebuild per lookup.
        let whole = RegistryLayout::new(3, 0).expect("valid layout");
        assert_eq!(whole.row_len(), 1);
        assert_eq!(whole.leaves_per_subtree(), whole.leaf_count());

        assert!(RegistryLayout::new(3, 3).is_none(), "row must sit above the leaves");
        assert!(RegistryLayout::new(3, 4).is_none(), "row cannot sit below the leaves");
        assert!(RegistryLayout::new(0, 0).is_none(), "a registry needs at least two AIRs");
        assert!(RegistryLayout::new(1, 0).is_none(), "a registry needs at least two leaves");
        assert!(
            RegistryLayout::new(MAX_REGISTRY_AIRS + 1, 0).is_none(),
            "the full permutation set must fit in u32 tags"
        );
        assert_eq!(order_from_tag(0, MAX_REGISTRY_AIRS + 1), None);
    }

    #[test]
    fn subtree_offsets_reject_indices_outside_the_row() {
        let layout = RegistryLayout::new(3, 1).expect("valid layout");
        assert!(subtree_start(&layout, layout.row_len()).is_err());
        assert!(subtree_start(&layout, usize::MAX).is_err());
    }

    #[test]
    #[should_panic(expected = "proof order must be a permutation")]
    fn order_tag_rejects_invalid_permutations_in_all_builds() {
        let _ = order_tag(&[0, 0, 2]);
    }

    #[test]
    #[should_panic(expected = "node row length does not match the registry layout")]
    fn verified_rows_are_bound_to_the_layout() {
        let layout = RegistryLayout::new(3, 1).expect("valid layout");
        let row = vec![padding_leaf()];
        let _ = verify_row(&layout, &row, row[0], "test row must be complete");
    }

    #[test]
    fn spliced_paths_match_a_materialised_tree_for_every_slot() {
        // A row depth above 1 makes the pyramid's upper-sibling shift
        // (`subtree_index >> (row_depth - depth)`) act on more than the trivial
        // zero-shift level, matching the production depth-12 geometry in miniature.
        for (num_airs, row_depth) in [(3, 1), (4, 2)] {
            assert_spliced_paths_match_a_materialised_tree(num_airs, row_depth);
        }
    }

    fn assert_spliced_paths_match_a_materialised_tree(num_airs: usize, row_depth: usize) {
        let layout = RegistryLayout::new(num_airs, row_depth).expect("valid layout");
        let mut leaves: Vec<Word> = (0..layout.order_count())
            .map(|tag| Poseidon2::hash_elements(&[Felt::new_unchecked(0x1000 + tag as u64)]))
            .collect();
        leaves.resize(layout.leaf_count(), padding_leaf());

        let tree = MerkleTree::new(&leaves).expect("complete tree");
        let row: Vec<Word> = (0..layout.row_len())
            .map(|index| {
                tree.get_node(
                    NodeIndex::new(layout.row_depth() as u8, index as u64).expect("row index"),
                )
                .expect("row node")
            })
            .collect();
        let pyramid = verify_row(&layout, &row, tree.root(), "toy row must authenticate");

        for tag in 0..layout.leaf_count() {
            let subtree_index = tag / layout.leaves_per_subtree();
            let start = subtree_index * layout.leaves_per_subtree();
            let subtree = MerkleTree::new(&leaves[start..start + layout.leaves_per_subtree()])
                .expect("complete subtree");
            let (leaf, path) =
                path_in_verified_tree(&layout, &pyramid, &subtree, tag as u32, "toy path")
                    .expect("valid path");
            assert_eq!(leaf, leaves[tag]);
            assert_eq!(
                path.compute_root(tag as u64, leaf).expect("path root"),
                tree.root(),
                "path does not verify at tag {tag}"
            );
        }

        let subtree =
            MerkleTree::new(&leaves[..layout.leaves_per_subtree()]).expect("complete subtree");
        assert!(
            path_in_verified_tree(
                &layout,
                &pyramid,
                &subtree,
                layout.leaf_count() as u32,
                "toy path",
            )
            .is_err(),
            "a tag outside the tree must be rejected"
        );
        assert!(
            path_in_verified_tree(&layout, &pyramid[..1], &subtree, 0, "toy path").is_err(),
            "a pyramid that does not match the layout must be rejected"
        );
    }
}
