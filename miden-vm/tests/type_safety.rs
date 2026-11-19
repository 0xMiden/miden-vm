#[test]
fn typed_execution_contracts() {
    // One harness avoids races on trybuild's generated manifest under nextest.
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/fail/*.rs");
}
