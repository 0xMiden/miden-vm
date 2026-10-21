//! Isolated Eidos PVM measurements over default and custom precompile workloads.

use std::{collections::BTreeSet, hint::black_box, time::Duration};

use codspeed_criterion_compat::{
    BatchSize, Criterion, SamplingMode, criterion_group, criterion_main,
};
use miden_air::precompile::ChipletAir;
use miden_core::{Felt, field::QuadFelt};
use miden_precompiles_prover::{
    DEFAULT_MAX_PRECOMPILE_PROVER_MEMORY_BYTES, HashFunction,
    prove_precompiles_with_limits_and_budget, testing,
};
use miden_stark::air::{BaseAir, LiftedAir};
use miden_vm::Verifier;
use miden_vm_precompiles_bench::{PrecompileFixture, PrecompileWorkload, benchmark_workloads};

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).map_or(default, |raw| {
        raw.parse().unwrap_or_else(|error| panic!("{name} must be numeric: {error}"))
    })
}

fn env_count(name: &str) -> Option<usize> {
    std::env::var_os(name).map(|raw| {
        raw.to_str()
            .unwrap_or_else(|| panic!("{name} must be a non-negative integer"))
            .parse()
            .unwrap_or_else(|error| panic!("{name} must be a non-negative integer: {error}"))
    })
}

fn selected_workloads() -> Vec<(String, PrecompileWorkload)> {
    let filter = std::env::var("PVM_BENCH_WORKLOAD").ok();
    let ecdsas = env_count("PVM_BENCH_ECDSAS");
    let keccaks = env_count("PVM_BENCH_KECCAKS");
    if ecdsas.is_some() || keccaks.is_some() {
        assert!(filter.is_none(), "custom counts cannot be combined with PVM_BENCH_WORKLOAD");
        let ecdsas = ecdsas.unwrap_or(0);
        let keccaks = keccaks.unwrap_or(0);
        assert!(
            ecdsas != 0 || keccaks != 0,
            "custom PVM workload must contain at least one operation"
        );
        return vec![(
            format!("custom_ecdsa_k256_{ecdsas}_keccak_32b_{keccaks}"),
            PrecompileWorkload {
                keccaks,
                ecdsas,
                eddsas: 0,
                ecdsa_p256s: 0,
                sha256_64b: 0,
                sha256_1kib: 0,
            },
        )];
    }

    let workloads: Vec<_> = benchmark_workloads()
        .into_iter()
        .filter(|(name, _)| filter.as_ref().is_none_or(|filter| name.contains(filter)))
        .map(|(name, workload)| (name.to_string(), workload))
        .collect();
    assert!(!workloads.is_empty(), "PVM_BENCH_WORKLOAD matched no workloads");
    workloads
}

fn pvm_bench(c: &mut Criterion) {
    let workloads = selected_workloads();
    let axes = std::env::var("PVM_BENCH_AXES")
        .unwrap_or_else(|_| "import,build_trace,prove,verify".to_string());
    let axes: BTreeSet<_> = axes.split(',').map(str::trim).collect();
    for axis in &axes {
        assert!(
            ["import", "build_trace", "prove", "verify"].contains(axis),
            "unsupported PVM_BENCH_AXES value: {axis}"
        );
    }
    for (name, workload) in workloads {
        let fixture = PrecompileFixture::generate(workload);
        let (witness, root) = fixture.precompile_witness();
        let limits = fixture.verification_limits;
        let traces = testing::import(vec![witness.clone()], &limits)
            .expect("import PVM workload")
            .build_trace();
        for (air, (height, width)) in ChipletAir::all().iter().zip(traces.main_trace_shapes()) {
            let aux_width = LiftedAir::<Felt, QuadFelt>::aux_width(air);
            let preprocessed_width = BaseAir::<Felt>::preprocessed_width(air);
            println!(
                "BENCH_PVM_SHAPE workload={name} air={air:?} height={height} main_width={width} aux_width={aux_width} preprocessed_width={preprocessed_width}"
            );
        }
        let proof = traces.prove().expect("prove PVM workload");
        Verifier::new().verify_precompile(&proof, root).expect("verify PVM workload");
        println!(
            "BENCH_PVM_PROOF workload={name} hash=Eidos proof_bytes={} roots={}",
            proof.proof.bytes().len(),
            proof.roots.len(),
        );
        if std::env::var_os("PVM_PROFILE_ONLY").is_some() {
            continue;
        }

        let mut group = c.benchmark_group(format!("pvm/{name}/eidos"));
        let sample_size = usize::try_from(env_u64("PVM_BENCH_SAMPLE_SIZE", 10))
            .expect("PVM_BENCH_SAMPLE_SIZE must fit usize");
        assert!(sample_size >= 10, "PVM_BENCH_SAMPLE_SIZE must be at least 10");
        group
            .sampling_mode(SamplingMode::Flat)
            .sample_size(sample_size)
            .warm_up_time(Duration::from_secs(env_u64("PVM_BENCH_WARM_UP_SECS", 1)))
            .measurement_time(Duration::from_secs(env_u64("PVM_BENCH_MEASUREMENT_SECS", 30)));
        if axes.contains("import") {
            group.bench_function("import", |b| {
                b.iter_batched(
                    || vec![witness.clone()],
                    |witnesses| black_box(testing::import(witnesses, &limits).expect("import")),
                    BatchSize::PerIteration,
                );
            });
        }
        if axes.contains("build_trace") {
            group.bench_function("build_trace", |b| {
                b.iter_batched(
                    || testing::import(vec![witness.clone()], &limits).expect("import"),
                    |session| black_box(session.build_trace()),
                    BatchSize::PerIteration,
                );
            });
        }
        if axes.contains("prove") {
            group.bench_function("prove", |b| {
                b.iter_batched(
                    || vec![witness.clone()],
                    |witnesses| {
                        black_box(
                            prove_precompiles_with_limits_and_budget(
                                witnesses,
                                HashFunction::Eidos,
                                &limits,
                                DEFAULT_MAX_PRECOMPILE_PROVER_MEMORY_BYTES,
                            )
                            .expect("prove"),
                        )
                    },
                    BatchSize::PerIteration,
                );
            });
        }
        if axes.contains("verify") {
            group.bench_function("verify", |b| {
                b.iter(|| {
                    black_box(
                        Verifier::new()
                            .verify_precompile(black_box(&proof), black_box(root))
                            .expect("verify"),
                    )
                });
            });
        }
        group.finish();
    }
}

criterion_group!(benches, pvm_bench);
criterion_main!(benches);
