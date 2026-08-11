extern crate alloc;

/// Instantiates a test with Miden core library included.
#[macro_export]
macro_rules! build_test {
    ($source:expr $(, $tail:expr)* $(,)?) => {{
        let core_lib = miden_core_lib::CoreLibrary::default();
        let source = $source;
        miden_utils_testing::build_test_by_mode!(false, source $(, $tail)*)
            .with_library(core_lib.package())
            .with_library(core_lib.precompiles_package())
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
            .with_library(core_lib.precompiles_package())
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
fn core_library_exports_crypto_wrappers() {
    use miden_core_lib::CoreLibrary;

    let core_lib = CoreLibrary::default();
    let package = core_lib.package();

    for path in [
        "::miden::core::crypto::hashes::keccak256::hash_bytes",
        "::miden::core::crypto::hashes::keccak256::hash",
        "::miden::core::crypto::hashes::keccak256::merge",
        "::miden::core::crypto::dsa::ecdsa_k256_keccak::verify",
    ] {
        assert!(
            package.get_procedure_root_by_path(path).is_some(),
            "{path} must be exported by corelib",
        );
    }
}

#[test]
fn core_and_precompiles_are_separate_packages() {
    use miden_assembly::Path;
    use miden_core_lib::CoreLibrary;

    let core_lib = CoreLibrary::default();
    let core_package = core_lib.package();
    let precompiles_package = core_lib.precompiles_package();

    for path in [
        "::miden::core::math::u64::overflowing_add",
        "::miden::core::crypto::hashes::sha256::hash",
    ] {
        assert!(
            core_package.get_procedure_root_by_path(path).is_some(),
            "{path} must be exported by miden-core",
        );
    }

    for path in [
        "::miden::precompiles::u256::push_zero_digest",
        "::miden::precompiles::hashes::keccak256::hash_bytes_mem",
    ] {
        assert!(
            core_package.get_procedure_root_by_path(path).is_none(),
            "{path} must not be exported by miden-core",
        );
        assert!(
            precompiles_package.get_procedure_root_by_path(path).is_some(),
            "{path} must be exported by miden-precompiles",
        );
    }

    for package in [&core_package, &precompiles_package] {
        assert!(
            package.manifest.get_module(Path::new("::miden")).is_none(),
            "package {} must not declare the bare miden namespace",
            package.name,
        );
    }

    let dependencies = core_package.manifest.dependencies().collect::<Vec<_>>();
    assert_eq!(dependencies.len(), 1, "miden-core must have one MASM package dependency");
    assert_eq!(dependencies[0].name, precompiles_package.name);
    assert_eq!(dependencies[0].version, precompiles_package.version);
    assert_eq!(dependencies[0].digest, precompiles_package.digest());
}

#[test]
fn core_packages_do_not_block_sibling_miden_namespaces() {
    use std::sync::Arc;

    use miden_assembly::{
        Assembler, DefaultSourceManager, Linkage,
        ast::{Module, ModuleKind},
    };
    use miden_core_lib::CoreLibrary;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let protocol_utils = Module::parser(Some(ModuleKind::Library))
        .parse_str(
            None,
            "namespace miden::protocol_utils\npub proc identity push.0 drop end",
            source_manager.clone(),
        )
        .expect("protocol utility module should parse");

    let mut assembler = Assembler::new(source_manager);
    for package in CoreLibrary::default().packages() {
        assembler
            .link_package(package, Linkage::Dynamic)
            .expect("official Miden packages should link");
    }

    assembler
        .assemble_library("miden-protocol-utils", protocol_utils, None::<Box<Module>>)
        .expect("official packages must not claim the parent of miden::protocol_utils");
}

#[test]
fn precompile_semantic_api_is_available_from_precompiles_crate() {
    let _ = miden_precompiles::registry();
    let _ = miden_precompiles::UintPrecompile::id();
}

#[test]
fn core_library_links_precompile_wrappers_with_separate_precompiles_package() {
    use miden_assembly::{Assembler, Linkage};
    use miden_core_lib::CoreLibrary;

    let source = concat!(
        "begin ",
        "push.0 push.0 ",
        "exec.::miden::core::crypto::hashes::keccak256::hash_bytes ",
        "dropw dropw ",
        "end",
    );
    let core_lib = CoreLibrary::default();
    let mut assembler = Assembler::default();
    for package in core_lib.packages() {
        assembler
            .link_package(package, Linkage::Dynamic)
            .expect("failed to link core library package");
    }
    assembler
        .assemble_program("core_links_precompile_wrappers", source)
        .expect("failed to assemble program against core precompile wrappers");
}

#[test]
fn core_library_load_registers_precompile_handlers() {
    use miden_core_lib::{
        CoreLibrary,
        handlers::precompiles::{
            keccak256::KECCAK256_DIGEST_EVENT_NAME, uint_field_inv::UINT_FIELD_INV_EVENT_NAME,
        },
    };
    use miden_processor::{BaseHost, DefaultHost};

    let core_lib = CoreLibrary::default();
    let mut host = DefaultHost::default();
    host.load_library(&core_lib).expect("failed to load core library");

    for event in [KECCAK256_DIGEST_EVENT_NAME, UINT_FIELD_INV_EVENT_NAME] {
        assert_eq!(host.resolve_event(event.to_event_id()), Some(&event));
    }
}

mod collections;
mod crypto;
mod helpers;
mod mast_forest_merge;
mod math;
mod mem;
mod precompiles;
mod stark_asserts;
mod sys;
mod word;

mod stark;
