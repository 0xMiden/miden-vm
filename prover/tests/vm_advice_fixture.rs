#![cfg(feature = "std")]

use miden_core::{
    program::{KernelDescriptor, StackInputs, StackOutputs},
    proof::HashFunction,
};
use miden_processor::{DefaultHost, ExecutionRequest, WitnessOutput, trace::build_trace};

/// Explicit fixture maintenance; standard tests consume the checked-in proof instead.
#[test]
#[ignore = "set MIDEN_VM_FIXTURE_OUTPUT_DIR to regenerate fixtures outside the source tree"]
fn regenerate_vm_advice_fixture() {
    use miden_core::serde::Serializable;

    let directory = std::path::PathBuf::from(
        std::env::var_os("MIDEN_VM_FIXTURE_OUTPUT_DIR")
            .expect("set MIDEN_VM_FIXTURE_OUTPUT_DIR to an output directory"),
    );
    std::fs::create_dir_all(&directory).unwrap();
    rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap().install(|| {
        let program = miden_assembly::Assembler::default()
            .assemble_program("advice_fixture", "begin push.5 push.8 add drop end")
            .unwrap()
            .unwrap_program();
        let WitnessOutput { claim, witness, .. } = ExecutionRequest::new(&program)
            .record_witness()
            .run_sync(&mut DefaultHost::default())
            .unwrap();
        assert_eq!(*claim.kernel(), KernelDescriptor::default());
        assert_eq!(*claim.stack_inputs(), StackInputs::default());
        assert_eq!(*claim.stack_outputs(), StackOutputs::default());
        let (vm_witness, _) = witness.into_parts();
        let trace = build_trace(vm_witness, &miden_vm_stark::memory::default_budget()).unwrap();
        let proof = miden_vm_stark::prover::prove(trace, HashFunction::Eidos, false).unwrap();
        std::fs::write(directory.join("vm_eidos_v1_0.bin"), proof.to_bytes()).unwrap();
        std::fs::write(directory.join("vm_eidos_v1_0.program"), claim.program_root().to_bytes())
            .unwrap();
    });
}
