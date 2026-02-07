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

/// Asserts that executing the test fails with a FailedAssertion containing the expected message.
#[macro_export]
macro_rules! expect_assert_error_message {
    ($test:expr $(,)?) => {
        ::miden_utils_testing::expect_exec_error_matches!(
            $test,
            ::miden_processor::ExecutionError::OperationError {
                err: ::miden_processor::operation::OperationError::FailedAssertion {
                    err_msg,
                    ..
                },
                ..
            }
            if err_msg.as_deref().map(|msg| msg.len() > 5).unwrap_or(false)
        );
    };
    ($test:expr, $min_len:expr $(,)?) => {
        ::miden_utils_testing::expect_exec_error_matches!(
            $test,
            ::miden_processor::ExecutionError::OperationError {
                err: ::miden_processor::operation::OperationError::FailedAssertion {
                    err_msg,
                    ..
                },
                ..
            }
            if err_msg.as_deref().map(|msg| msg.len() > $min_len).unwrap_or(false)
        );
    };
    ($test:expr, contains $needle:expr $(,)?) => {
        ::miden_utils_testing::expect_exec_error_matches!(
            $test,
            ::miden_processor::ExecutionError::OperationError {
                err: ::miden_processor::operation::OperationError::FailedAssertion {
                    err_msg,
                    ..
                },
                ..
            }
            if err_msg
                .as_deref()
                .map(|msg| msg.len() > 5 && msg.contains($needle))
                .unwrap_or(false)
        );
    };
}

mod collections;
mod crypto;
mod helpers;
mod mast_forest_merge;
mod math;
mod mem;
mod stark_asserts;
mod sys;
mod word;

// These tests are disabled until the recursive verifier is updated to work with Plonky3 proofs
// mod pcs;
// mod stark;
