//! Compare native proving with a warm service round trip for a small execution.
//! Native timing excludes witness preparation; RPC timing includes server decoding
//! and proof serialization. Run with `RAYON_NUM_THREADS=8 make bench benchmark=proving_service`.

use std::{hint::black_box, time::Duration};

use codspeed_criterion_compat::{
    BatchSize, Criterion, SamplingMode, criterion_group, criterion_main,
};
use miden_assembly::Assembler;
use miden_core::{proof::ExecutionProof, serde::Serializable};
use miden_processor::{DefaultHost, ExecutionWitness, FastProcessor, StackInputs};
use miden_prover::Prover;
use miden_prover_service::{
    PROTOCOL_VERSION, ProvingService, ServerConfig,
    protocol::{ProveRequest, prover_service_client::ProverServiceClient},
};
use miden_verifier::Verifier;
use tokio::{net::TcpListener, runtime::Builder, time::timeout};

fn proving_service(c: &mut Criterion) {
    let program = Assembler::default()
        .assemble_program(
            "small",
            "begin push.4096 dup neq.0 while.true sub.1 dup neq.0 end drop end",
        )
        .unwrap()
        .unwrap_program();
    let witness = FastProcessor::new(StackInputs::default())
        .execute_for_proving_sync(&program, &mut DefaultHost::default())
        .unwrap();
    let claim = witness.claim();
    let bytes = witness.to_bytes();
    let prover = Prover::new();
    let config = ServerConfig::new(
        bytes.len(),
        1 << 20,
        Duration::from_secs(60),
        prover.max_prover_memory_bytes(),
        prover.max_precompile_prover_memory_bytes(),
    )
    .unwrap();
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    let (service, server, mut client) = runtime.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = ProvingService::new(config);
        let serving = service.clone();
        let server = tokio::spawn(async move { serving.serve_with_listener(listener).await });
        let client = ProverServiceClient::connect(format!("http://{address}")).await.unwrap();
        (service, server, client)
    });
    let request = || ProveRequest {
        protocol_version: PROTOCOL_VERSION,
        execution_witness: bytes.clone(),
    };

    // Warm both paths and check complete proofs outside the timed iterations.
    let proof = prover.prove_full(witness).unwrap();
    assert!(Verifier::new().verify(&claim, &proof).unwrap().is_complete());
    let response = runtime.block_on(client.prove(request())).unwrap().into_inner();
    let proof = ExecutionProof::read_from_bytes(&response.execution_proof).unwrap();
    assert!(Verifier::new().verify(&claim, &proof).unwrap().is_complete());

    let mut group = c.benchmark_group("tiny_proof");
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(20)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(10));
    group.bench_function("native", |b| {
        b.iter_batched(
            || ExecutionWitness::read_from_bytes(&bytes).unwrap(),
            |witness| black_box(prover.prove_full(witness).unwrap()),
            BatchSize::PerIteration,
        );
    });
    group.bench_function("grpc", |b| {
        b.iter_batched(
            request,
            |request| black_box(runtime.block_on(client.prove(request)).unwrap().into_inner()),
            BatchSize::PerIteration,
        );
    });
    group.finish();

    drop(client);
    runtime.block_on(async {
        service.shutdown().await;
        timeout(Duration::from_secs(60), server).await.unwrap().unwrap().unwrap();
    });
}

criterion_group!(benches, proving_service);
criterion_main!(benches);
