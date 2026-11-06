use miden_vm::{ProofSecurityParameters, ProvenSecurityReport, SecurityReport};

#[test]
fn security_types_are_available_through_the_vm_crate() {
    let _: Option<ProofSecurityParameters> = None;
    let _: Option<ProvenSecurityReport> = None;
    let _: Option<SecurityReport> = None;
}

#[test]
fn proven_security_estimator_root_is_available_through_the_vm_crate() {
    assert_eq!(
        miden_vm::proven_security_estimator_root(),
        miden_core_lib::CoreLibrary::default().proven_security_estimator_root(),
    );
}
