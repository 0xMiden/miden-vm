extern crate alloc;

/// Instantiates a test with Miden core library included.
#[macro_export]
macro_rules! build_test {
    ($source:expr $(, $tail:expr)* $(,)?) => {{
        let core_lib = miden_core_lib::CoreLibrary::default();
        let source = $source;
        miden_utils_testing::build_test_by_mode!(false, source $(, $tail)*)
            .with_library(core_lib.package())
            .with_event_handlers(core_lib.handlers())
    }}
}

/// Instantiates a test in debug mode with Miden core library included.
#[macro_export]
macro_rules! build_debug_test {
    ($source:expr $(, $tail:expr)* $(,)?) => {{
        let core_lib = miden_core_lib::CoreLibrary::default();
        let source = $source;
        miden_utils_testing::build_test_by_mode!(true, source $(, $tail)*)
            .with_library(core_lib.package())
            .with_event_handlers(core_lib.handlers())
    }}
}

/// Asserts that executing the test fails with a FailedAssertion.
#[macro_export]
macro_rules! expect_assert_error_message {
    ($test:expr $(,)?) => {
        ::miden_utils_testing::expect_exec_error_matches!(
            $test,
            ::miden_processor::ExecutionError::OperationError {
                err: ::miden_processor::operation::OperationError::FailedAssertion {
                    ..
                },
                ..
            }
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

#[macro_export]
macro_rules! expect_assert_error_code_from_msg {
    ($test:expr, $msg:expr $(,)?) => {
        ::miden_utils_testing::expect_exec_error_matches!(
            $test,
            ::miden_processor::ExecutionError::OperationError {
                err: ::miden_processor::operation::OperationError::FailedAssertion {
                    err_code,
                    err_msg,
                },
                ..
            }
            if err_code == ::miden_core::mast::error_code_from_msg($msg) && err_msg.is_none()
        );
    };
}

#[test]
fn core_library_does_not_export_fri_preprocess_test_helper() {
    use miden_core_lib::CoreLibrary;

    let core_lib = CoreLibrary::default();
    let package = core_lib.package();

    assert!(
        package
            .get_procedure_root_by_path("::miden::core::pcs::fri::frie2f4::preprocess")
            .is_none(),
        "FRI preprocess helper must not be exported by corelib",
    );
}

#[test]
fn core_library_exports_official_precompile_wrappers() {
    use miden_core_lib::CoreLibrary;

    let core_lib = CoreLibrary::default();
    let package = core_lib.package();

    for path in [
        "::miden::precompiles::crypto::hashes::keccak256::hash_bytes_mem",
        "::miden::precompiles::crypto::hashes::keccak256::hash_1_chunk_mem",
        "::miden::precompiles::crypto::hashes::keccak256::hash_2_chunks_mem",
        "::miden::precompiles::crypto::hashes::sha512::hash_bytes_mem",
        "::miden::precompiles::crypto::hashes::sha512::hash_1_chunk_mem",
        "::miden::precompiles::crypto::hashes::sha512::hash_2_chunks_mem",
        "::miden::precompiles::crypto::hashes::sha512::hash_3_chunks_mem",
        "::miden::precompiles::crypto::dsa::ecdsa_secp256k1::assert_verify_prehash",
        "::miden::precompiles::crypto::dsa::eddsa_ed25519::assert_verify",
    ] {
        assert!(
            package.get_procedure_root_by_path(path).is_some(),
            "{path} must be exported by aggregate corelib",
        );
    }
}

#[test]
fn core_library_package_exports_core_and_precompiles() {
    use miden_core_lib::CoreLibrary;

    let core_lib = CoreLibrary::default();
    let package = core_lib.package();

    for path in [
        "::miden::core::math::u64::overflowing_add",
        "::miden::core::crypto::hashes::sha256::hash",
        "::miden::precompiles::math::u256::push_zero_digest",
        "::miden::precompiles::crypto::hashes::keccak256::hash_bytes_mem",
    ] {
        assert!(
            package.get_procedure_root_by_path(path).is_some(),
            "{path} must be exported by aggregate corelib",
        );
    }
}

#[test]
fn core_lib_reexports_precompile_api() {
    let _ = miden_core_lib::precompiles::registry();
    let _ = miden_core_lib::precompiles::PrecompilesLibrary::default();
}

#[test]
fn core_library_links_precompile_wrappers_without_precompiles_library() {
    use miden_assembly::{Assembler, Linkage};
    use miden_core_lib::CoreLibrary;

    let source = "begin exec.::miden::precompiles::math::u256::push_zero_digest dropw end";
    Assembler::default()
        .with_package(CoreLibrary::default().package(), Linkage::Dynamic)
        .expect("failed to link core library")
        .assemble_program("core_links_precompiles", source)
        .expect("failed to assemble program against core-provided precompiles");
}

#[test]
fn core_library_load_registers_precompile_handlers() {
    use miden_core_lib::CoreLibrary;
    use miden_processor::{BaseHost, DefaultHost};

    let core_lib = CoreLibrary::default();
    let mut host = DefaultHost::default();
    host.load_library(&core_lib).expect("failed to load core library");

    for (event, _) in miden_core_lib::precompiles::event_handlers::default_event_handlers() {
        assert_eq!(host.resolve_event(event.to_event_id()), Some(&event));
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
