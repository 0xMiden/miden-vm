extern crate alloc;

/// Instantiates a test with Miden core library included.
#[macro_export]
macro_rules! build_test {
    ($($params:tt)+) => {{
        let core_lib = miden_core_lib::CoreLibrary::default();
        let mut test = miden_utils_testing::build_test_by_mode!(false, $($params)+);
        test.libraries.push(core_lib.library().clone());
        test.add_event_handlers(core_lib.handlers());

        test
    }}
}

/// Instantiates a test in debug mode with Miden core library included.
#[macro_export]
macro_rules! build_debug_test {
    ($($params:tt)+) => {{
        let core_lib = miden_core_lib::CoreLibrary::default();
        let mut test = miden_utils_testing::build_test_by_mode!(true, $($params)+);
        test.libraries.push(core_lib.library().clone());
        test.add_event_handlers(core_lib.handlers());

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
