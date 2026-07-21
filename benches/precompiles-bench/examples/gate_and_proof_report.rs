//! Reports precompile ACE circuit size, proof size, and native verify time for the default
//! ECDSA+Keccak precompile workload.
//!
//! Used to track how these metrics move across changes to the precompile chiplet AIR set. Prints
//! a single JSON line to stdout.

use std::time::Instant;

use miden_precompiles_prover::ace::precompile_ace_circuit_stats;
use miden_vm::HashFunction;
use miden_vm_precompiles_bench::{
    DEFAULT_ECDSAS, DEFAULT_KECCAKS, PrecompileFixture, PrecompileWorkload, prove_once_with_hash,
    verify_once,
};

const VERIFY_ITERS: u32 = 10;

fn main() {
    let workload = PrecompileWorkload {
        keccaks: DEFAULT_KECCAKS,
        ecdsas: DEFAULT_ECDSAS,
    };
    let fixture = PrecompileFixture::generate(workload);

    let (stack_outputs, proof) = prove_once_with_hash(&fixture, HashFunction::Poseidon2);

    let proof_bytes = proof.to_bytes().len();
    let miden_proof_bytes = proof.miden_proof().bytes().len();
    let deferred_proof_bytes = proof
        .deferred_proof()
        .as_stark()
        .map(|(stark_proof, _)| stark_proof.bytes().len());

    let mut total_verify_time = std::time::Duration::ZERO;
    for _ in 0..VERIFY_ITERS {
        let started_at = Instant::now();
        verify_once(&fixture, stack_outputs, proof.clone());
        total_verify_time += started_at.elapsed();
    }
    let native_verify_ns = (total_verify_time / VERIFY_ITERS).as_nanos();

    let ace = precompile_ace_circuit_stats().expect("precompile ACE circuit should build");

    println!(
        "{{\"ace_num_inputs\":{},\"ace_num_eval_gates\":{},\"ace_circuit_digest\":\"{:?}\",\
         \"proof_bytes\":{},\"miden_proof_bytes\":{},\"deferred_proof_bytes\":{:?},\
         \"native_verify_ns\":{}}}",
        ace.num_inputs,
        ace.num_eval_gates,
        ace.circuit_digest,
        proof_bytes,
        miden_proof_bytes,
        deferred_proof_bytes,
        native_verify_ns,
    );
}
