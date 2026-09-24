use miden_vm::{
    AirShape, InstanceShape, LookupShape, ProofSecurityParameters, ProtocolParams, SecurityReport,
    SecurityTerm,
};

#[test]
fn security_types_are_available_through_the_vm_crate() {
    let _: Option<AirShape> = None;
    let _: Option<InstanceShape> = None;
    let _: Option<LookupShape> = None;
    let _: Option<ProofSecurityParameters> = None;
    let _: Option<ProtocolParams> = None;
    let _: Option<SecurityReport> = None;
    let _: Option<SecurityTerm> = None;
}
