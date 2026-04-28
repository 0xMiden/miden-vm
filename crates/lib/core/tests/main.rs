extern crate alloc;

/// Instantiates a test with Miden core library included.
#[macro_export]
macro_rules! build_test {
    ($($params:tt)+) => {{
        let core_lib = miden_core_lib::CoreLibrary::default();
        miden_utils_testing::build_test_by_mode!(false, $($params)+)
            .with_library(core_lib.library().clone())
            .with_event_handlers(core_lib.handlers())
    }}
}

/// Instantiates a test in debug mode with Miden core library included.
#[macro_export]
macro_rules! build_debug_test {
    ($($params:tt)+) => {{
        let core_lib = miden_core_lib::CoreLibrary::default();
        miden_utils_testing::build_test_by_mode!(true, $($params)+)
            .with_library(core_lib.library().clone())
            .with_event_handlers(core_lib.handlers())
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

#[test]
fn core_library_does_not_export_precompile_impl_helpers() {
    use miden_assembly::Path;
    use miden_core_lib::CoreLibrary;

    let core_lib = CoreLibrary::default();
    let library = core_lib.library();

    let public_paths = [
        "::miden::core::crypto::hashes::keccak256::hash_bytes",
        "::miden::core::crypto::hashes::sha512::hash_bytes",
        "::miden::core::crypto::dsa::ecdsa_k256_keccak::verify_prehash",
        "::miden::core::crypto::dsa::eddsa_ed25519::verify_prehash",
    ];
    for path in public_paths {
        assert!(
            library.get_procedure_root_by_path(Path::new(path)).is_some(),
            "expected public wrapper to be exported: {path}",
        );
    }

    let internal_paths = [
        "::miden::core::crypto::hashes::keccak256::hash_bytes_impl",
        "::miden::core::crypto::hashes::sha512::hash_bytes_impl",
        "::miden::core::crypto::dsa::ecdsa_k256_keccak::verify_prehash_impl",
        "::miden::core::crypto::dsa::eddsa_ed25519::verify_prehash_impl",
    ];
    for path in internal_paths {
        assert!(
            library.get_procedure_root_by_path(Path::new(path)).is_none(),
            "internal precompile helper must not be exported: {path}",
        );
    }
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

mod stark;
