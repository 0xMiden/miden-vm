#[test]
fn public_api_contracts() {
    // Keep the fixtures in one case so nextest cannot run separate processes that overwrite
    // trybuild's shared Cargo manifest when its best-effort file lock expires under load.
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/mast_forest_immutable/index_node_mut.rs");
    tests.pass("tests/ui/execution_proof_transport/direct_serialize.rs");
}
