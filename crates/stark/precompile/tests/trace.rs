//! External coverage for trace-only import and lowering without a prover API.
#![cfg(feature = "trace")]

use miden_core::{
    deferred::{
        DEFERRED_AND_FRAME, Node, PrecompileWitness, PrecompileWitnessEntry, TRUE_DIGEST,
        fold_deferred_root,
    },
    utils::Matrix,
};
use miden_precompile_stark::trace::import_witnesses;

#[test]
fn imported_witnesses_expose_roots_and_lower_to_relation_traces() {
    let witness = PrecompileWitness::from_entries(vec![PrecompileWitnessEntry::Join {
        frame: DEFERRED_AND_FRAME,
        lhs: 0,
        rhs: 0,
    }])
    .expect("a nonempty true assertion has a canonical singleton graph");
    let root = Node::and(TRUE_DIGEST, TRUE_DIGEST).digest();
    let imported =
        import_witnesses(vec![witness.clone(), witness]).expect("import repeated assertions");
    assert_eq!(imported.roots(), &[root, root]);

    let traces = imported.finish();
    let expected = fold_deferred_root(root, root);
    assert_eq!(traces.public_root().as_array(), expected.into_elements());
    assert_eq!(traces.air_inputs(), expected.as_elements().to_vec());
    assert_eq!(traces.mains().len(), miden_air_source::precompile::NUM_CHIPLETS);
    assert!(traces.mains().iter().all(|trace| trace.height().is_power_of_two()));
    assert_eq!(traces.into_mains().len(), miden_air_source::precompile::NUM_CHIPLETS);
}
