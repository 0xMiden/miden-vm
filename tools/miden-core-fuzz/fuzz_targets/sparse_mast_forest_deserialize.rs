//! Fuzz sparse replay parsing, hash validation, and canonical round trips.

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{
    mast::SparseMastForest,
    serde::{Deserializable, Serializable},
};

fuzz_target!(|data: &[u8]| {
    if let Ok(forest) = SparseMastForest::read_from_bytes(data) {
        forest.validate().expect("the checked reader must validate hashes");
        let canonical = forest.to_bytes();
        let restored = SparseMastForest::read_from_bytes(&canonical)
            .expect("a checked forest must decode from its own encoding");
        assert_eq!(forest.nodes(), restored.nodes());
        assert_eq!(forest.procedure_roots(), restored.procedure_roots());
        assert_eq!(canonical, restored.to_bytes());
        assert!(SparseMastForest::read_from_bytes_trusted(data).is_ok());
    }
    let _ = SparseMastForest::read_from_bytes_with_budget(data, 64);
    let _ = SparseMastForest::read_from_bytes_trusted(data);
});
