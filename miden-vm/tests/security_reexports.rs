use {
    miden_vm::ProofSecurityParameters,
    miden_vm::ProvenSecurityReport,
    miden_vm::SecurityReport,
};

#[test]
fn security_types_are_available_through_the_vm_crate() {
    let _: Option<ProofSecurityParameters> = None;
    let _: Option<ProvenSecurityReport> = None;
    let _: Option<SecurityReport> = None;
}

#[test]
fn core_facade_paths_preserve_type_identity() {
    let _: Option<miden_vm::crypto::merkle::MerklePath> =
        None::<miden_core::crypto::merkle::MerklePath>;
    let _: Option<miden_vm::field::QuadFelt> = None::<miden_core::field::QuadFelt>;
    let _: Option<miden_vm::serde::DeserializationError> =
        None::<miden_core::serde::DeserializationError>;
    let _: Option<miden_vm::utils::RowMajorMatrix<miden_core::Felt>> =
        None::<miden_core::utils::RowMajorMatrix<miden_core::Felt>>;
}

#[cfg(feature = "std")]
#[test]
fn std_utility_paths_preserve_type_identity() {
    let _: Option<miden_vm::utils::ReadAdapter<'static>> =
        None::<miden_core::utils::ReadAdapter<'static>>;
}

#[test]
fn proven_security_estimator_root_is_available_through_the_vm_crate() {
    assert_eq!(
        miden_vm::proven_security_estimator_root(),
        miden_core_lib::CoreLibrary::default().proven_security_estimator_root(),
    );
}
