#[test]
fn public_api_contracts() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/mast_forest_immutable/index_node_mut.rs");
    tests.pass("tests/ui/execution_proof_transport/direct_serialize.rs");
}
