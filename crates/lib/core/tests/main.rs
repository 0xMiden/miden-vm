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
fn core_library_exports_crypto_wrappers() {
    use miden_core_lib::CoreLibrary;

    let core_lib = CoreLibrary::default();
    let package = core_lib.package();

    for path in [
        "::miden::core::crypto::hashes::keccak256::hash_bytes",
        "::miden::core::crypto::hashes::keccak256::hash",
        "::miden::core::crypto::hashes::keccak256::merge",
        "::miden::core::crypto::dsa::ecdsa_k256_keccak::verify",
        "::miden::core::crypto::dsa::ecdsa_k256_keccak::verify_bytes",
        "::miden::core::crypto::dsa::ecdsa_k256_keccak::recover",
        "::miden::core::crypto::dsa::ecdsa_k256_keccak::recover_bytes",
    ] {
        assert!(
            package.get_procedure_root_by_path(path).is_some(),
            "{path} must be exported by corelib",
        );
    }
}

#[test]
fn core_library_exports_eidos_streaming_api() {
    use miden_core_lib::CoreLibrary;

    let core_lib = CoreLibrary::default();
    let package = core_lib.package();
    let module = "::miden::core::crypto::hashes::eidos";

    for procedure in [
        "init_chaining_word",
        "init_chaining_word_in_domain",
        "init_with_chaining_word",
        "init",
        "init_in_domain",
        "compress",
        "digest",
        "copy_digest",
        "absorb_double_words_from_memory",
        "prepare_hasher_state",
        "hash_elements_with_state",
        "hash_elements",
        "hash_elements_in_domain",
        "pad_and_hash_elements",
    ] {
        let path = format!("{module}::{procedure}");
        assert!(
            package.get_procedure_root_by_path(path.as_str()).is_some(),
            "{path} must be exported by corelib",
        );
    }

    for procedure in ["init_no_padding", "hash_elements_with_domain"] {
        let path = format!("{module}::{procedure}");
        assert!(
            package.get_procedure_root_by_path(path.as_str()).is_none(),
            "{path} must not be exported by corelib",
        );
    }
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
    assembler
        .link_package(CoreLibrary::default().package(), Linkage::Dynamic)
        .expect("official Miden packages should link");

    assembler
        .assemble_library("miden-protocol-utils", protocol_utils, None::<Box<Module>>)
        .expect("official packages must not claim the parent of miden::protocol_utils");
}

#[test]
fn precompile_semantic_api_is_available_from_precompiles_crate() {
    let _ = miden_precompiles::registry();
    let _ = miden_precompiles::UintPrecompile::domain();
}

#[test]
fn core_library_load_registers_required_handlers() {
    use miden_core_lib::{
        CoreLibrary,
        handlers::{
            aead_eidos::AEAD_EIDOS_DECRYPT_EMPTY_AD_EVENT_NAME,
            ecdsa_k256_keccak::ECDSA_K256_KECCAK_RECOVER_EVENT_NAME,
            precompiles::{
                keccak256::KECCAK256_DIGEST_EVENT_NAME, uint_field_inv::UINT_FIELD_INV_EVENT_NAME,
            },
        },
    };
    use miden_processor::{BaseHost, DefaultHost};

    let core_lib = CoreLibrary::default();
    let mut host = DefaultHost::default();
    host.load_library(&core_lib).expect("failed to load core library");

    for event in [
        AEAD_EIDOS_DECRYPT_EMPTY_AD_EVENT_NAME,
        KECCAK256_DIGEST_EVENT_NAME,
        UINT_FIELD_INV_EVENT_NAME,
        ECDSA_K256_KECCAK_RECOVER_EVENT_NAME,
    ] {
        assert_eq!(host.resolve_event(event.to_event_id()), Some(&event));
    }
}

mod collections;
mod crypto;
mod helpers;
mod mast_forest_merge;
mod math;
mod mem;
mod pcs;
mod precompiles;
mod stark_asserts;
mod support;
mod sys;
mod word;

mod stark;

// These procedures consume/produce independent felts even though their semantic fields are
// narrower. Check the exported Fast ABI, which uses physical layout instead of canonical
// flattening.
#[test]
fn verifier_signatures_match_operand_stack_layout() {
    use miden_assembly::ast::types::Type;
    use miden_core_lib::CoreLibrary;
    use miden_mast_package::PackageExport;

    let core_lib = CoreLibrary::default();
    let package = core_lib.package();
    for (path, inputs, outputs) in [
        ("::miden::core::stark::verifier::verify", 20, 4),
        ("::miden::core::stark::security::compute_conjectured_security_level", 12, 1),
        ("::miden::core::sys::vm::verify_proof", 4, 16),
        ("::miden::core::sys::pvm::verify_proof", 4, 12),
    ] {
        let Some(PackageExport::Procedure(export)) = package.manifest.get_export(path) else {
            panic!("missing procedure: {path}");
        };
        let signature = export.signature.as_ref().expect("typed procedure");
        assert_eq!(
            signature.params.iter().map(Type::size_in_felts).sum::<usize>(),
            inputs,
            "{path} inputs"
        );
        assert_eq!(
            signature.results.iter().map(Type::size_in_felts).sum::<usize>(),
            outputs,
            "{path} outputs"
        );
    }

    // Total arity alone would miss padding moved to the end of a record.
    for (name, field_count) in [("StackProofParameters", 4), ("StackSecurityDescriptor", 9)] {
        let path = format!("::miden::core::stark::types::{name}");
        let Some(PackageExport::Type(export)) = package.manifest.get_export(path.as_str()) else {
            panic!("missing type: {path}");
        };
        let Type::Struct(record) = &export.ty else {
            panic!("expected struct: {path}");
        };
        let offsets: Vec<_> = record
            .get()
            .fields()
            .iter()
            .filter(|field| !field.name.as_deref().unwrap().ends_with("_padding"))
            .map(|field| field.offset)
            .collect();
        assert_eq!(offsets, (0..field_count).map(|index| index * 4).collect::<Vec<_>>(), "{path}");
    }

    let Some(PackageExport::Type(export)) = package
        .manifest
        .get_export("::miden::core::crypto::dsa::falcon512_eidos::StoredCoefficient")
    else {
        panic!("missing coefficient memory type");
    };
    assert_eq!(
        export.ty.size_in_bytes(),
        4,
        "coefficient buffers advance one felt per coefficient"
    );
    assert_eq!(export.ty.min_alignment(), 4);
}
