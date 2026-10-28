//! Reports precompile ACE circuit size, proof size, and native verify time for the default
//! ECDSA+Keccak precompile workload.
//!
//! Used to track how these metrics move across changes to the precompile chiplet AIR set. Prints
//! a single JSON line to stdout.

use std::time::Instant;

use miden_air::precompiles::protocol::recursive_circuit;
use miden_core::proof::PrecompileStatus;
use miden_vm::HashFunction;
use miden_vm_precompiles_bench::{
    PrecompileFixture, PrecompileWorkload, prove_once_with_hash, verify_once,
};

const VERIFY_ITERS: u32 = 10;

fn main() {
    let defaults = PrecompileWorkload::default();
    let workload = PrecompileWorkload {
        keccaks: defaults.keccaks,
        ecdsas: defaults.ecdsas,
        eddsas: 0,
        ecdsa_p256s: 0,
        sha256_64b: 0,
        sha256_1kib: 0,
    };
    let fixture = PrecompileFixture::generate(workload);

    let (stack_outputs, proof) = prove_once_with_hash(&fixture, HashFunction::Eidos);

    let proof_bytes = proof.to_bytes().len();
    let miden_proof_bytes = proof.vm().proof.bytes().len();
    let deferred_proof_bytes = match proof.precompile() {
        PrecompileStatus::Proven(proof) => proof.proof.bytes().len().to_string(),
        _ => "null".to_string(),
    };

    let mut total_verify_time = std::time::Duration::ZERO;
    for _ in 0..VERIFY_ITERS {
        let started_at = Instant::now();
        verify_once(&fixture, stack_outputs, &proof);
        total_verify_time += started_at.elapsed();
    }
    let native_verify_ns = (total_verify_time / VERIFY_ITERS).as_nanos();

    let ace = recursive_circuit();

    println!(
        "{{\"ace_num_inputs\":{},\"ace_num_eval_gates\":{},\"ace_circuit_digest\":\"{:?}\",\
         \"proof_bytes\":{},\"miden_proof_bytes\":{},\"deferred_proof_bytes\":{},\
         \"native_verify_ns\":{}}}",
        ace.num_inputs,
        ace.num_eval_gates,
        ace.commitment,
        proof_bytes,
        miden_proof_bytes,
        deferred_proof_bytes,
        native_verify_ns,
    );
}
