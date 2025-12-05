extern crate alloc;

/// Instantiates a test with Miden core library included.
#[macro_export]
macro_rules! build_test {
    ($($params:tt)+) => {{
        let libcore = miden_libcore::CoreLibrary::default();
        let mut test = miden_utils_testing::build_test_by_mode!(false, $($params)+);
        test.libraries.push(libcore.library().clone());
        test.add_event_handlers(libcore.handlers());

        test
    }}
}

/// Instantiates a test in debug mode with Miden core library included.
#[macro_export]
macro_rules! build_debug_test {
    ($($params:tt)+) => {{
        let libcore = miden_libcore::CoreLibrary::default();
        let mut test = miden_utils_testing::build_test_by_mode!(true, $($params)+);
        test.libraries.push(libcore.library().clone());
        test.add_event_handlers(libcore.handlers());

        test
    }}
}

mod collections;
mod crypto;
mod helpers;
mod mast_forest_merge;
mod math;
mod mem;
mod pcs;
mod stark;
mod sys;
mod word;
