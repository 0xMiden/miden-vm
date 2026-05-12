#[test]
fn mast_forest_public_api_is_immutable_after_creation() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/mast_forest_immutable/add_debug_var.rs");
    tests.compile_fail("tests/ui/mast_forest_immutable/debug_info_mut.rs");
    tests.compile_fail("tests/ui/mast_forest_immutable/index_node_mut.rs");

    #[cfg(any(feature = "arbitrary", feature = "testing"))]
    tests.compile_fail("tests/ui/mast_forest_immutable/add_decorator.rs");
}
