extern crate alloc;

/// Instantiates a test with Miden standard library included.
#[macro_export]
macro_rules! build_test {
    ($($params:tt)+) => {{
        let mut test = miden_utils_testing::build_test_by_mode!(false, $($params)+);
        test.libraries = vec![miden_stdlib::StdLibrary::default().into()];
        test
    }}
}

/// Instantiates a test in debug mode with Miden standard library included.
#[macro_export]
macro_rules! build_debug_test {
    ($($params:tt)+) => {{
        let mut test = miden_utils_testing::build_test_by_mode!(true, $($params)+);
        test.libraries = vec![miden_stdlib::StdLibrary::default().into()];
        test
    }}
}

mod collections;
mod crypto;
mod mast_forest_merge;
mod math;
mod mem;
mod sys;
mod word;
