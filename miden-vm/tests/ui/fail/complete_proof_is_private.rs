use miden_vm::{CompleteProof, ExecutionProof};

fn invalid(proof: ExecutionProof) {
    let _ = CompleteProof(proof);
}

fn main() {}
