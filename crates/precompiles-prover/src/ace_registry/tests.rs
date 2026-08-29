use miden_ace_codegen::{ShuffleEncodeBuffer, order_tag, padding_leaf};
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_lifted_air::MultiAir;

use super::*;
use crate::{
    ace::{PVM_REGISTRY_LAYOUT, structured_orders},
    session::{ChipletMultiAir, NUM_CHIPLETS},
};

/// The registry does not include statement-level assertions, so each protocol version pins their
/// result on a fixed, non-zero fixture independently of the implementation helpers.
#[test]
fn external_assertion_matches_the_protocol_version() {
    let challenges = [
        QuadFelt::new([Felt::from(3u32), Felt::from(5u32)]),
        QuadFelt::new([Felt::from(7u32), Felt::from(11u32)]),
    ];
    let aux_values: [[QuadFelt; 1]; NUM_CHIPLETS] = core::array::from_fn(|i| {
        [QuadFelt::new([Felt::from((i + 1) as u32), Felt::from((2 * i + 1) as u32)])]
    });
    let aux_refs: Vec<&[QuadFelt]> = aux_values.iter().map(<[QuadFelt; 1]>::as_slice).collect();

    let actual = ChipletMultiAir::new()
        .eval_external(&challenges, &[], &[], &aux_refs, &[])
        .expect("fixture denominators are non-zero");
    let expected = match PVM_PROTOCOL_ID {
        1 => QuadFelt::new([
            Felt::new_unchecked(17_120_654_257_594_545_925),
            Felt::new_unchecked(12_713_559_468_620_802_518),
        ]),
        version => panic!("add an external-assertion vector for protocol version {version}"),
    };

    assert_eq!(actual.as_slice(), &[expected]);
}

/// Exercise the deployed serving path in distinct active subtrees, including a
/// non-involutive order. The generic registry tests cover every path in a materialised
/// toy tree; the release drift gate checks all `10!` PVM leaves.
#[test]
fn registry_serves_verified_paths_from_distinct_active_subtrees() {
    let factory = factory();
    let expected_root = registry_root();
    let mut buffer = ShuffleEncodeBuffer::new();
    let orders = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]];
    let tags = orders.map(|order| order_tag(&order));
    assert_ne!(
        tags[0] as usize / PVM_REGISTRY_LAYOUT.leaves_per_subtree(),
        tags[1] as usize / PVM_REGISTRY_LAYOUT.leaves_per_subtree(),
        "fixtures must exercise distinct active subtrees"
    );

    for (order, tag) in orders.into_iter().zip(tags) {
        let (leaf, path) = pvm_ace_registry_path(tag).expect("tag addresses a slot");
        let assembled = factory.circuit_for_order(&order).expect("assembled circuit");
        assert_eq!(leaf, assembled.commitment, "served leaf diverges at tag {tag}");
        let fast = factory.leaf_for_order(&order, &mut buffer).expect("encode-only leaf");
        assert_eq!(fast, leaf, "encode-only leaf diverges at tag {tag}");

        let computed = path.compute_root(u64::from(tag), leaf).expect("path root computes");
        assert_eq!(computed, expected_root, "path at tag {tag} does not verify");
    }
}

/// Padding slots resolve to the constant padding leaf and verify against the root;
/// out-of-range tags do not resolve.
#[test]
fn registry_serves_padding_slots_and_rejects_out_of_range_tags() {
    let padding_tag = PVM_ORDER_COUNT as u32; // first slot no proof order maps to
    let (leaf, path) = pvm_ace_registry_path(padding_tag).expect("padding slot resolves");
    assert_eq!(leaf, padding_leaf(), "padding slot must hold the padding leaf");
    let computed = path.compute_root(u64::from(padding_tag), leaf).expect("path root computes");
    assert_eq!(computed, registry_root(), "padding path does not verify");

    let last_tag = (PVM_REGISTRY_LAYOUT.leaf_count() - 1) as u32;
    assert!(pvm_ace_registry_path(last_tag).is_some(), "last slot resolves");
    assert!(
        pvm_ace_registry_path(PVM_REGISTRY_LAYOUT.leaf_count() as u32).is_none(),
        "out-of-range tags must not resolve"
    );
}

/// The checked-in relation digest must equal the digest formula over the checked-in
/// root — a hand-checkable binding, independent of the registry build.
#[test]
fn relation_digest_matches_the_checked_in_root() {
    let expected = relation_digest_for_root(&registry_root());
    assert_eq!(
        PVM_RELATION_DIGEST.map(Felt::new_unchecked),
        expected,
        "PVM_RELATION_DIGEST does not bind PVM_ACE_REGISTRY_ROOT; run \
         `make regenerate-pvm-registry` for an intentional protocol change"
    );
    assert_eq!(
        crate::stark_config::PRECOMPILE_RELATION_DIGEST,
        expected,
        "production configs must use the generated PVM registry digest"
    );
}

/// Pointer identity confirms that repeated lookups return the same cached allocation.
#[test]
fn active_subtree_lookups_reuse_cached_allocation() {
    let first = cached_leaves_for_subtree(399);
    let second = cached_leaves_for_subtree(399);
    assert!(
        core::ptr::eq(first, second),
        "repeat active-subtree lookups must return the cached slice"
    );
    assert_eq!(first.len(), PVM_REGISTRY_LAYOUT.leaves_per_subtree());
}

/// All fully padded subtrees share one vector; padding indices are structurally outside
/// the active cache's range, so they can neither recompute leaves nor occupy entries.
#[test]
fn padding_subtrees_share_one_vector() {
    let boundary = PVM_REGISTRY_LAYOUT
        .order_count()
        .div_ceil(PVM_REGISTRY_LAYOUT.leaves_per_subtree());
    assert_eq!(boundary, 3_544, "10! spans 3,543 full subtrees plus the 768-leaf boundary");

    let first_padding = cached_leaves_for_subtree(boundary);
    let last_slot = cached_leaves_for_subtree(PVM_REGISTRY_LAYOUT.row_len() - 1);
    assert!(
        core::ptr::eq(first_padding, last_slot),
        "every fully padded subtree must resolve to the shared vector"
    );
    assert_eq!(first_padding[0], padding_leaf(), "the shared vector holds padding leaves");
}

/// From-scratch segment oracle over the structured sample: hash the ASSEMBLED stream's
/// two segments with plain `hash_elements` (no resumed sponge state) and pin them
/// against the factory's commitments, plus common-section byte-identity against the
/// canonical order. The factory serves ONE cached common digest to every order, so the
/// encode-vs-assembled dual paths are definitionally blind to order-dependent bytes
/// escaping into the common section; this is the oracle that sees them — the PVM
/// counterpart of the Miden VM's segment test in air/tests/ace_codegen.rs.
#[test]
fn assembled_segments_match_from_scratch_hashing_for_structured_orders() {
    use miden_core::crypto::hash::Poseidon2;

    let factory = factory();
    let canonical: Vec<usize> = (0..NUM_CHIPLETS).collect();
    let canonical_circuit = factory.circuit_for_order(&canonical).expect("canonical circuit");
    let canonical_common =
        canonical_circuit.encoded.instructions()[canonical_circuit.shuffle_prefix_len..].to_vec();

    for order in structured_orders() {
        let circuit = factory.circuit_for_order(&order).expect("assembled circuit");
        let instructions = circuit.encoded.instructions();
        let (prefix, common) = instructions.split_at(circuit.shuffle_prefix_len);
        assert_eq!(
            Poseidon2::hash_elements(prefix),
            circuit.shuffle_commitment,
            "resumed prefix digest diverges from from-scratch hashing for {order:?}"
        );
        assert_eq!(
            Poseidon2::hash_elements(common),
            circuit.common_commitment,
            "cached common digest diverges from from-scratch hashing for {order:?}"
        );
        assert_eq!(
            common,
            canonical_common.as_slice(),
            "common section is not order-invariant for {order:?}"
        );
    }
}

/// The concurrent serve path splits a subtree into LEAF_CHUNK ranges; a range that
/// straddles the realizable/padding boundary must fill its suffix with padding leaves.
/// For the deployed geometry the boundary (768 = 12 * 64) lands exactly on a chunk
/// edge, so this exercises the straddling logic no production chunking reaches.
#[cfg(feature = "concurrent")]
#[test]
fn concurrent_leaf_range_handles_a_straddling_boundary() {
    use miden_ace_codegen::{PackedLeafScratch, order_from_tag, padding_leaf};

    let factory = factory();
    let boundary_subtree = PVM_ORDER_COUNT / PVM_REGISTRY_LAYOUT.leaves_per_subtree();
    let start = boundary_subtree * PVM_REGISTRY_LAYOUT.leaves_per_subtree();
    let realizable = PVM_ORDER_COUNT - start;

    // A window straddling the boundary: some realizable offsets, some padding.
    let offsets: Vec<usize> = (realizable - 4..realizable + 4).collect();
    let mut scratch = PackedLeafScratch::new();
    let leaves = subtree_leaf_range(factory, start, &offsets, &mut scratch);

    assert_eq!(leaves.len(), offsets.len());
    let mut buffer = ShuffleEncodeBuffer::new();
    for (leaf, &offset) in leaves.iter().zip(&offsets) {
        match order_from_tag((start + offset) as u32, NUM_CHIPLETS) {
            Some(order) => assert_eq!(
                *leaf,
                factory.leaf_for_order(&order, &mut buffer).expect("scalar leaf"),
                "realizable offset {offset} diverges"
            ),
            None => assert_eq!(*leaf, padding_leaf(), "padding offset {offset} diverges"),
        }
    }
}
