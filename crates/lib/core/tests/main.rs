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

#[cfg(feature = "core-lib-extra-tests")]
mod collections;
#[cfg(feature = "core-lib-extra-tests")]
mod crypto;
mod helpers;
#[cfg(feature = "core-lib-extra-tests")]
mod mast_forest_merge;
#[cfg(feature = "core-lib-extra-tests")]
mod math;
#[cfg(feature = "core-lib-extra-tests")]
mod mem;
#[cfg(feature = "legacy-stark-tests")]
mod pcs;
#[cfg(feature = "legacy-stark-tests")]
mod stark;
mod sys;
#[cfg(feature = "core-lib-extra-tests")]
mod word;
