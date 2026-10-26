#![cfg(unix)]

use std::{
    ffi::OsString, net::SocketAddr, os::unix::ffi::OsStringExt, process::Stdio, time::Duration,
};

use miden_assembly::{Assembler, Linkage};
use miden_core::{
    proof::{ExecutionProof, PrecompileStatus},
    serde::Serializable,
};
use miden_processor::{DefaultHost, ExecutionWitness, FastProcessor, StackInputs};
use miden_prover_service::{
    PROTOCOL_VERSION,
    protocol::{ErrorCode, ErrorDetail, ProveRequest, prover_service_client::ProverServiceClient},
};
use prost::Message;
use tokio::{
    io::{AsyncBufReadExt, BufReader, Lines},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdout, Command},
    time::{sleep, timeout},
};
use tonic::{Status, transport::Channel};
use tonic_health::pb::{
    HealthCheckRequest, health_check_response::ServingStatus, health_client::HealthClient,
};

const UNTRUSTED: &str = env!("CARGO_BIN_EXE_miden-prover-service");
const TRUSTED: &str = env!("CARGO_BIN_EXE_miden-prover-service-trusted");
const WAIT: Duration = Duration::from_secs(60);
const LIMITS: [&str; 10] = [
    "--max-witness-bytes",
    "8388608",
    "--max-proof-bytes",
    "8388608",
    "--request-timeout-ms",
    "60000",
    "--vm-memory-bytes",
    "34359738368",
    "--precompile-memory-bytes",
    "34359738368",
];

fn command(binary: &str) -> Command {
    let mut command = Command::new(binary);
    command.kill_on_drop(true).env_remove("RUST_LOG");
    command
}

struct Process {
    child: Child,
    address: SocketAddr,
    client: ProverServiceClient<Channel>,
    logs: Lines<BufReader<ChildStdout>>,
}

impl Process {
    async fn start(binary: &str, args: &[&str]) -> Self {
        Self::with_limits(binary, &LIMITS, args).await
    }

    async fn with_limits(binary: &str, limits: &[&str], args: &[&str]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let child = command(binary)
            .args(limits)
            .args(["--listen", &address.to_string()])
            .args(args)
            .env("RUST_LOG", "miden_prover_service=debug")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut child = child;
        let logs = BufReader::new(child.stdout.take().unwrap()).lines();
        let client = timeout(WAIT, async {
            loop {
                assert!(child.try_wait().unwrap().is_none(), "service exited before listening");
                if let Ok(client) = ProverServiceClient::connect(format!("http://{address}")).await
                {
                    break client.max_decoding_message_size(8 << 20);
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        Self { child, address, client, logs }
    }

    async fn while_proving(&mut self, expected: &str) {
        timeout(WAIT, async {
            loop {
                let line = self.logs.next_line().await.unwrap().expect("service stdout closed");
                assert!(
                    !line.contains("proof job finished"),
                    "proof finished before {expected}: {line}"
                );
                if line.contains(expected) {
                    return;
                }
            }
        })
        .await
        .unwrap();
    }

    async fn prove(&mut self, bytes: Vec<u8>) -> Result<Vec<u8>, Status> {
        timeout(
            WAIT,
            self.client.prove(ProveRequest {
                protocol_version: PROTOCOL_VERSION,
                execution_witness: bytes,
            }),
        )
        .await
        .unwrap()
        .map(|response| response.into_inner().execution_proof)
    }

    async fn signal(&self, signal: &str) {
        let status = timeout(
            WAIT,
            Command::new("kill")
                .kill_on_drop(true)
                .args([signal, &self.child.id().unwrap().to_string()])
                .status(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(status.success());
    }

    async fn finish(mut self) {
        let status = timeout(WAIT, self.child.wait()).await.unwrap().unwrap();
        assert!(status.success(), "service failed: {status}");
        assert!(TcpStream::connect(self.address).await.is_err());
    }

    async fn stop(self) {
        self.signal("-TERM").await;
        self.finish().await;
    }
}

fn witness(hash_bytes: Option<u32>) -> ExecutionWitness {
    let source = match hash_bytes {
        // Unwritten memory supplies bytes with value zero.
        Some(size) => format!(
            "begin push.256 push.{size} push.128 exec.::miden::core::precompiles::hashes::keccak256::hash_bytes_mem end"
        ),
        None => "begin push.1 drop end".into(),
    };
    execute(&source)
}

fn execute(source: &str) -> ExecutionWitness {
    let library = miden_core_lib::CoreLibrary::default();
    let mut assembler = Assembler::default();
    assembler.link_package(library.package(), Linkage::Dynamic).unwrap();
    let program = assembler.assemble_program("binary-test", source).unwrap().unwrap_program();
    let mut host = DefaultHost::default().with_library(&library).unwrap();
    FastProcessor::new(StackInputs::default())
        .execute_for_proving_sync(&program, &mut host)
        .unwrap()
}

fn code(error: Status) -> ErrorCode {
    ErrorDetail::decode(error.details()).unwrap().code()
}

#[tokio::test]
async fn cli_binaries_choose_their_reader_policy() {
    let bytes = witness(None).to_bytes();
    for (binary, trusted) in [(UNTRUSTED, false), (TRUSTED, true)] {
        let mut process = Process::start(binary, &[]).await;
        let mut trailing = bytes.clone();
        trailing.push(0);
        if trusted {
            assert!(process.prove(trailing).await.is_ok());
        } else {
            assert_eq!(code(process.prove(trailing).await.unwrap_err()), ErrorCode::InvalidWitness);
        }
        process.stop().await;
    }
}

#[tokio::test]
async fn cli_resource_options_reach_the_prover() {
    let mut vm = LIMITS;
    vm[7] = "1";
    let mut precompile_memory = LIMITS;
    precompile_memory[9] = "1";
    let plain = witness(None).to_bytes();
    let precompile = witness(Some(1)).to_bytes();
    for (limits, args, input) in [
        (vm, &[][..], &plain),
        (precompile_memory, &[][..], &precompile),
        (LIMITS, &["--precompile-max-elements", "0"][..], &precompile),
    ] {
        let mut process = Process::with_limits(UNTRUSTED, &limits, args).await;
        assert_eq!(
            code(process.prove(input.clone()).await.unwrap_err()),
            ErrorCode::ProverLimitExceeded
        );
        process.stop().await;
    }

    // Two distinct calls use four bytes total, with three in the largest call.
    let accepted = execute(
        "begin
            push.256 push.1 push.128
            exec.::miden::core::precompiles::hashes::keccak256::hash_bytes_mem
            push.512 push.3 push.128
            exec.::miden::core::precompiles::hashes::keccak256::hash_bytes_mem
        end",
    );
    let mut process = Process::start(UNTRUSTED, &["--precompile-work-limit", "hash:2:4:3"]).await;
    assert!(process.prove(accepted.to_bytes()).await.is_ok());
    assert_eq!(
        code(process.prove(witness(Some(4)).to_bytes()).await.unwrap_err()),
        ErrorCode::ProverLimitExceeded
    );
    process.stop().await;
}

#[tokio::test]
async fn cli_invalid_logging_configuration_fails_startup() {
    for binary in [UNTRUSTED, TRUSTED] {
        for (value, expected) in [
            (OsString::from("miden_prover_service=invalid-level"), "invalid RUST_LOG:"),
            (OsString::from_vec(vec![0xff]), "RUST_LOG must contain Unicode text\n"),
        ] {
            let output = timeout(
                WAIT,
                command(binary)
                    .args(LIMITS)
                    .args(["--listen", "127.0.0.1:0"])
                    .env("RUST_LOG", value)
                    .output(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8(output.stderr).unwrap().starts_with(expected));
        }
    }
}

#[tokio::test]
async fn cli_signals_drain_active_proofs_and_reject_queued_work() {
    let queued_bytes = witness(None).to_bytes();
    let witness = execute("begin push.4096 dup neq.0 while.true sub.1 dup neq.0 end drop end");
    let claim = witness.claim();
    let bytes = witness.to_bytes();
    for binary in [UNTRUSTED, TRUSTED] {
        for signal in ["-INT", "-TERM"] {
            let mut process = Process::start(binary, &["--capacity", "2"]).await;
            let channel = timeout(
                WAIT,
                Channel::from_shared(format!("http://{}", process.address)).unwrap().connect(),
            )
            .await
            .unwrap()
            .unwrap();
            let mut health = HealthClient::new(channel);
            let mut watch =
                timeout(WAIT, health.watch(HealthCheckRequest { service: String::new() }))
                    .await
                    .unwrap()
                    .unwrap()
                    .into_inner();
            assert_eq!(
                timeout(WAIT, watch.message()).await.unwrap().unwrap().unwrap().status(),
                ServingStatus::Serving
            );

            let mut client = process.client.clone();
            let active = ProveRequest {
                protocol_version: PROTOCOL_VERSION,
                execution_witness: bytes.clone(),
            };
            let active = tokio::spawn(async move { client.prove(active).await });
            process.while_proving("proof job started").await;
            let mut client = process.client.clone();
            let queued = ProveRequest {
                protocol_version: PROTOCOL_VERSION,
                execution_witness: queued_bytes.clone(),
            };
            let queued = tokio::spawn(async move { client.prove(queued).await });
            process.while_proving("proof request admitted").await;
            process.signal(signal).await;
            process.while_proving("shutdown requested").await;
            assert_eq!(
                timeout(WAIT, watch.message()).await.unwrap().unwrap().unwrap().status(),
                ServingStatus::NotServing
            );
            assert!(timeout(WAIT, watch.message()).await.unwrap().unwrap().is_none());
            let error = timeout(WAIT, queued).await.unwrap().unwrap().unwrap_err();
            assert_eq!(error.code(), tonic::Code::Unavailable);
            assert_eq!(code(error), ErrorCode::ShuttingDown);

            let response = timeout(WAIT, active).await.unwrap().unwrap().unwrap().into_inner();
            let proof = ExecutionProof::read_from_bytes(&response.execution_proof).unwrap();
            assert!(matches!(proof.precompile(), PrecompileStatus::Empty));
            assert!(miden_verifier::Verifier::new().verify(&claim, &proof).unwrap().is_complete());
            let finished = timeout(WAIT, async {
                let mut finished = 0;
                while let Some(line) = process.logs.next_line().await.unwrap() {
                    assert!(!line.contains("proof job started"), "queued work started: {line}");
                    finished += usize::from(line.contains("proof job finished"));
                }
                finished
            })
            .await
            .unwrap();
            assert_eq!(finished, 1);
            process.finish().await;
        }
    }
}

#[tokio::test]
async fn cli_requires_valid_resource_limits_and_rejects_trust_selectors() {
    let binary = UNTRUSTED;
    let help = timeout(WAIT, command(binary).arg("--help").output()).await.unwrap().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("--precompile-work-limit"));
    assert!(!help.contains("--trusted"));
    for omitted in (0..LIMITS.len()).step_by(2) {
        let args: Vec<_> = LIMITS
            .as_chunks::<2>()
            .0
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != omitted / 2)
            .flat_map(|(_, pair)| pair.iter().copied())
            .collect();
        let output = timeout(WAIT, command(binary).args(args).output()).await.unwrap().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr).unwrap().contains(LIMITS[omitted]));
    }
    for zeroed in (0..LIMITS.len()).step_by(2) {
        let mut args = LIMITS;
        args[zeroed + 1] = "0";
        let output = timeout(WAIT, command(binary).args(args).output()).await.unwrap().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr).unwrap().contains("must be nonzero"));
    }
    for args in [
        vec!["--trusted"],
        vec!["--untrusted"],
        vec!["--trust-mode", "trusted"],
        vec!["--capacity", "0"],
        vec!["--precompile-work-limit", "unknown:1:1:1"],
        vec!["--precompile-work-limit", "hash:1:1"],
        vec!["--precompile-work-limit", "hash:1:1:4294967296"],
        vec!["--precompile-work-limit", "hash:1:1:1", "--precompile-work-limit", "hash:0:0:0"],
    ] {
        let output = timeout(WAIT, command(binary).args(LIMITS).args(&args).output())
            .await
            .unwrap()
            .unwrap();
        assert!(!output.status.success(), "accepted {args:?}");
    }
}

#[tokio::test]
async fn cli_bind_failure_returns_an_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    for binary in [UNTRUSTED, TRUSTED] {
        let output =
            timeout(WAIT, command(binary).args(LIMITS).args(["--listen", &address]).output())
                .await
                .unwrap()
                .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr).unwrap().contains("proving listener failed"));
    }
}
