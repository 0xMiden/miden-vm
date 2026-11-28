//! Fuzz target for MastForestWireView trusted wire-backed access.
//!
//! This target focuses on the trusted inspection path exposed by
//! `MastForestWireView::new()`. It exercises layout scanning and cheap random-access helpers
//! without going through full trusted or untrusted materialization.
//!
//! Run with: cargo +nightly fuzz run mast_forest_wire_view_new --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::mast::MastForestWireView;
use miden_core_fuzz::select_roots;

fuzz_target!(|data: &[u8]| {
    // GENERATOR-DRIVEN KNOWN-ROOTS ORACLE — runs FIRST, before the arbitrary-input guard
    // (a constructor regression rejecting EVERY input must fail the oracle here, not
    // silently skip it via the early return below). For each iteration a
    // forest is built through the public builder with a root SUBSET and ORDER derived from
    // the fuzz data (varying counts, subsets, and orders over the 5-node set, including a
    // non-root node), the expected roots are captured IN MEMORY BEFORE serialization, and
    // every accessor result must equal the captured sequence — closing
    // the single-static-sequence limitation.
    {
        let mut forest = miden_core::mast::MastForest::new();
        let mut node_ids = Vec::new();
        for op in [
            miden_core::operations::Operation::Add,
            miden_core::operations::Operation::Mul,
            miden_core::operations::Operation::Eq,
            miden_core::operations::Operation::Clk,
        ] {
            node_ids.push(
                miden_core::mast::BasicBlockNodeBuilder::new(vec![op])
                    .add_to_forest(&mut forest)
                    .expect("block should add"),
            );
        }
        let join = miden_core::mast::JoinNodeBuilder::new([node_ids[0], node_ids[1]])
            .add_to_forest(&mut forest)
            .expect("join should add");
        node_ids.push(join);

        // Root selection from fuzz data: k in 0..=5 (k == 0 exercises ROOTLESS forests —
        // a constructor rejecting them must fail here), then distinct
        // node ids in first-occurrence order. The count check PRECEDES each push so k == 0
        // yields NO roots even with trailing bytes (a former push-then-check
        // ordering produced one root for supposedly rootless forests).
        let k = usize::from(data.first().copied().unwrap_or(0) % 6);
        let roots = select_roots(data, &node_ids, k);
        assert_eq!(roots.len(), k, "selection must produce exactly k roots");
        for id in &roots {
            forest.make_root(*id);
        }
        // LARGE-ID FIXTURE : a ONCE-built forest with 300 nodes and
        // roots at ids spanning the u8 boundary ([255, 256, 0] — non-sorted, id 256 only
        // expressible beyond one byte). An accessor truncating ids to u8 (256 -> 0) or a
        // constructor mishandling large node counts fails the comparison below.
        static LARGE_FOREST: std::sync::OnceLock<(Vec<u8>, Vec<miden_core::mast::MastNodeId>)> =
            std::sync::OnceLock::new();
        let (large_bytes, large_expected) = LARGE_FOREST.get_or_init(|| {
            let mut forest = miden_core::mast::MastForest::new();
            let mut ids = Vec::new();
            for i in 0..300u32 {
                let op = if i % 2 == 0 {
                    miden_core::operations::Operation::Add
                } else {
                    miden_core::operations::Operation::Mul
                };
                ids.push(
                    miden_core::mast::BasicBlockNodeBuilder::new(vec![op])
                        .add_to_forest(&mut forest)
                        .expect("block should add"),
                );
            }
            for id in [ids[255], ids[256], ids[0]] {
                forest.make_root(id);
            }
            let expected: Vec<miden_core::mast::MastNodeId> =
                forest.procedure_roots().to_vec();
            use miden_core::serde::Serializable;
            (forest.to_bytes(), expected)
        });
        let large_view = MastForestWireView::new(large_bytes)
            .expect("the large known-valid forest must construct a wire view");
        assert_eq!(
            large_view.procedure_root_count(),
            large_expected.len(),
            "large forest root count must match the in-memory construction"
        );
        for (i, expected_root) in large_expected.iter().enumerate() {
            let got = large_view
                .procedure_root_at(i)
                .expect("a valid large-forest root must materialize");
            assert_eq!(
                got, *expected_root,
                "large-forest root {i} truncated, swapped, or mispaired"
            );
        }
        // Expected roots captured BEFORE serialization: decoding the writer's own
        // output would cancel consistent disagreement.
        let expected_roots: Vec<miden_core::mast::MastNodeId> =
            forest.procedure_roots().to_vec();
        use miden_core::serde::Serializable;
        let bytes = forest.to_bytes();

        let known_view = MastForestWireView::new(&bytes)
            .expect("a builder-constructed forest must construct a wire view");
        assert_eq!(
            known_view.procedure_root_count(),
            expected_roots.len(),
            "generated forest root count must match the in-memory construction"
        );
        for (i, expected_root) in expected_roots.iter().enumerate() {
            let got = known_view
                .procedure_root_at(i)
                .expect("a valid generated root must materialize");
            assert_eq!(
                got, *expected_root,
                "root {i} swapped, sorted, or mispaired against writer ground truth"
            );
        }
    }

    let Ok(view) = MastForestWireView::new(data) else {
        return;
    };

    let root_count = view.procedure_root_count();
    let node_count = view.node_count();

    if root_count > 0 {
        let last_root = root_count - 1;
        let _ = view.procedure_root_at(0);
        let _ = view.procedure_root_at(last_root);
    }

    // ROOTS CONSISTENCY ORACLE (the caveat-driven follow-up): procedure_root_at
    // is exercised by NO other target, so its contract is pinned here. In-range roots must
    // materialize EXCEPT for the lazily-validated root-id signature ("Invalid deserialized
    // MAST node ID" — the reported class on the roots side: root values are checked at
    // ACCESS time, not construction, so writer-unproducible ids can pass construction and
    // fail in-range access); any OTHER in-range error is a regression. Out-of-range
    // indices must ALWAYS fail (documented trait contract).
    for i in 0..root_count {
        match view.procedure_root_at(i) {
            Ok(root) => {
                // Independent bound check: the returned id must be within node_count
                // (verified here against the view's OWN node_count, not the accessor's
                // internal validation — an Ok-only oracle accepts
                // wrong roots; this at least rejects any out-of-bounds id the accessor
                // might return if its internal from_u32 check were mutated away).
                assert!(
                    u32::from(root) < node_count as u32,
                    "in-range root {i} returned id {} >= node_count {node_count}",
                    u32::from(root)
                );
                // Determinism: re-reading the same index must return the same id.
                let again = view
                    .procedure_root_at(i)
                    .expect("in-range root must materialize consistently");
                assert_eq!(again, root, "root {i} must be stable across accesses");
            },
            Err(miden_core::serde::DeserializationError::InvalidValue(msg))
                if msg.starts_with("Invalid deserialized MAST node ID") =>
            {
                // reported-class lazily-validated root value; tolerated, signature-scoped.
                // LIMITATION : the serialized root id itself cannot be
                // independently decoded from the target — the layout is pub(super) and
                // duplicating the wire parser here would be the fragile-parallel-
                // implementation class — so a WITHIN-BOUNDS wrong-root swap is not
                // externally detectable; the bound + determinism checks are the reachable
                // subset.
            },
            Err(e) => panic!(
                "in-range root {i}/{root_count} failed with an UNEXPECTED error: {e:?}"
            ),
        }
    }
    // Bounds contract for EVERY view, including empty root lists (the
    // former root_count > 0 guard left index 0 unchecked for empty lists, where it is
    // already out of range).
    assert!(
        view.procedure_root_at(root_count).is_err(),
        "out-of-range root index {root_count} must fail (documented contract)"
    );
    if node_count > 0 {
        let last_node = node_count - 1;
        let _ = view.node_entry_at(0);
        let _ = view.node_entry_at(last_node);
    }
});
