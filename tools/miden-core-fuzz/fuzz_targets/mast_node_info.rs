//! Fuzz target for MastNodeInfo deserialization.
//!
//! MastNodeInfo is a fixed-width structure (8 bytes node entry + 32 bytes digest = 40 bytes).
//! This target exercises `MastNodeEntry` decoding plus `MastNodeInfo` materialization through the
//! trusted wire-view API.
//!
//! Run with: cargo +nightly fuzz run mast_node_info --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{
    mast::MastForestWireView,
    serde::{Deserializable, Serializable},
};

fuzz_target!(|data: &[u8]| {
    let Ok(view) = MastForestWireView::new(data) else {
        return;
    };

    if view.node_count() == 0 {
        return;
    }

    let last = view.node_count() - 1;

    let _ = view.node_entry_at(0);
    let _ = view.node_info_at(0);
    let _ = view.node_digest_at(0);

    let _ = view.node_entry_at(last);
    let _ = view.node_info_at(last);
    let _ = view.node_digest_at(last);

    // Check consistency through the ungated view accessors and digest serialization.
    for i in 0..view.node_count() {
        let entry = view.node_entry_at(i).expect("in-range entry must decode");
        // Non-external digest limbs are intentionally decoded lazily. Permit only the field-range
        // error, and require both digest-bearing accessors to agree exactly.
        let info = match view.node_info_at(i) {
            Ok(info) => info,
            Err(miden_core::serde::DeserializationError::InvalidValue(msg))
                if msg == "value not in the appropriate range" =>
            {
                assert_eq!(
                    view.node_digest_at(i),
                    Err(miden_core::serde::DeserializationError::InvalidValue(msg)),
                    "in-range digest accessors must return the same error"
                );
                continue;
            },
            Err(e) => panic!("in-range node {i} failed with an unexpected error: {e:?}"),
        };
        // With info materialized, both independent accessors must succeed.
        assert_eq!(
            info.node_entry(),
            entry,
            "info's entry must match the view's entry accessor"
        );
        let digest = info.digest();
        let view_digest = view
            .node_digest_at(i)
            .expect("in-range digest must materialize once info did");
        assert_eq!(
            digest, view_digest,
            "info's digest must match the view's digest accessor"
        );
        // Word digest roundtrip through ungated serde: encode -> decode -> equal.
        let bytes = digest.to_bytes();
        let redecoded = miden_core::Word::read_from_bytes(&bytes).expect("digest must re-decode");
        assert_eq!(redecoded, digest, "digest roundtrip must be stable");
    }
});
