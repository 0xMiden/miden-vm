use miden_vm::{Prover, TraceOutput, VmTrace};

fn invalid_trace(prover: &Prover, trace: VmTrace) {
    let _ = prover.prove_trace(trace);
}

fn invalid_output(prover: &Prover, output: TraceOutput) {
    let _ = prover.prove_trace(output);
}

fn main() {}
