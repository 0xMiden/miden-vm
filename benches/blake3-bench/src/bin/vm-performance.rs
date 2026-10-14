//! Measures the Blake3 MASM workload with selectable STARK proof hashes.

use std::{path::PathBuf, time::Instant};

use clap::Parser;
use miden_vm::{
    HashFunction, Prover, Verifier,
    advice::{AdviceInputs, AdviceStack},
};
use miden_vm_blake3_bench::{
    Blake3Fixture, build_trace, execute_for_proving, execute_program, repo_root_from_manifest,
};
use serde::Serialize;

#[derive(Parser)]
#[command(about = "Measure VM execution, proving, and verification; emit JSON samples.")]
struct Args {
    #[arg(long)]
    repo_root: Option<PathBuf>,
    /// Number of Blake3 invocations in the MASM program.
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..))]
    iterations: u32,
    #[arg(long, default_value = "eidos", value_parser = ["eidos", "blake3-256", "poseidon2"])]
    hash: String,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    threads: u32,
    /// Measured proofs after one unmeasured warmup proof.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(1..))]
    samples: u32,
}

#[derive(Serialize)]
struct Sample {
    execute_ms: f64,
    witness_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
    conjectured_security_bits: u32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    rayon::ThreadPoolBuilder::new()
        .num_threads(args.threads as usize)
        .build_global()?;
    let root = args.repo_root.unwrap_or_else(repo_root_from_manifest);
    let mut fixture = Blake3Fixture::load_from_repo(&root);
    fixture.advice_inputs = AdviceInputs::default()
        .with_stack(AdviceStack::try_from_values([u64::from(args.iterations)])?);
    let hash = HashFunction::try_from(args.hash.as_str())?;
    let prover = Prover::new().with_hash_fn(hash);
    let verifier = Verifier::new();

    let trace = build_trace(execute_for_proving(&fixture));
    let shape = *trace.trace_len_summary();
    drop(trace);

    let mut samples = Vec::new();
    for iteration in 0..=args.samples {
        let start = Instant::now();
        let output = execute_program(&fixture);
        let execute_ms = start.elapsed().as_secs_f64() * 1_000.0;

        let start = Instant::now();
        let witness = execute_for_proving(&fixture);
        let witness_ms = start.elapsed().as_secs_f64() * 1_000.0;
        let claim = witness.claim();
        assert_eq!(&output.stack, claim.stack_outputs());

        let start = Instant::now();
        let proof = prover.prove_full(witness)?;
        let prove_ms = start.elapsed().as_secs_f64() * 1_000.0;

        let start = Instant::now();
        let outcome = verifier.verify(&claim, &proof)?;
        let verify_ms = start.elapsed().as_secs_f64() * 1_000.0;
        assert!(outcome.is_complete());
        let sample = Sample {
            execute_ms,
            witness_ms,
            prove_ms,
            verify_ms,
            proof_bytes: proof.to_bytes().len(),
            conjectured_security_bits: outcome
                .vm_security_parameters()
                .conjectured_security_level(),
        };
        if iteration > 0 {
            samples.push(sample);
        }
    }

    let result = serde_json::json!({
        "workload": "blake3_1to1",
        "iterations": args.iterations,
        "proof_hash": args.hash,
        "rayon_threads": rayon::current_num_threads(),
        "warmup_proofs": 1,
        "trace": {
            "core_rows": shape.core_rows(),
            "chiplets_rows": shape.chiplets_rows(),
            "eidos_compression_rows": shape.eidos_compression_rows(),
            "and8_rows": shape.byte_pair_lookup_rows(),
            "padded_heights": shape.padded_heights(),
        },
        "samples": samples,
    });
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
