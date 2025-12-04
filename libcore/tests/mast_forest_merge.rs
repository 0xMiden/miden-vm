use miden_processor::MastForest;

/// Tests that the libcore merged with itself produces a forest that has the same procedure
/// roots.
///
/// This test is added here since we do not have the StdLib in miden-core where merging is
/// implemented and the StdLib serves as a convenient example of a large MastForest.
#[test]
fn mast_forest_merge_libcore() {
    let std_lib = miden_libcore::CoreLibrary::default();
    let std_forest = std_lib.mast_forest().as_ref();

    let (merged, _) = MastForest::merge([std_forest, std_forest]).unwrap();

    let merged_digests = merged.procedure_digests().collect::<Vec<_>>();
    for digest in std_forest.procedure_digests() {
        assert!(merged_digests.contains(&digest));
    }
}
