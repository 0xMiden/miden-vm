#[test]
fn mast_forest_public_api_is_immutable_after_creation() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/mast_forest_immutable/index_node_mut.rs");
}

#[test]
fn execution_proof_is_the_versioned_transport() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/execution_proof_transport/direct_serialize.rs");
}
