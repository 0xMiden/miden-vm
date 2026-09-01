#[test]
fn mast_forest_public_api_is_immutable_after_creation() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/mast_forest_immutable/index_node_mut.rs");
}

#[test]
fn execution_proof_transport_is_versioned() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/execution_proof_transport/direct_serialize.rs");
}
