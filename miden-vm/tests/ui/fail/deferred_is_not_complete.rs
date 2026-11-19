use miden_vm::{CompleteProof, DefaultHost, Processor, Program, Prover, ProvingOutput};

fn invalid(program: &Program, prover: &Prover) {
    let ProvingOutput { proof, .. } = Processor::new(program)
        .prove_deferred(prover)
        .run_sync(&mut DefaultHost::default())
        .unwrap();
    let _: CompleteProof = proof;
}

fn main() {}
