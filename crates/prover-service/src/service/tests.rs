use std::{
    sync::{
        Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

use miden_assembly::{Assembler, Linkage};
use miden_core::serde::Serializable;
use miden_processor::{DefaultHost, ExecutionWitness, FastProcessor, StackInputs};
use prost::Message;
use tokio::{sync::oneshot, task::JoinHandle, time::timeout};

use super::*;
use crate::{Trusted, protocol::ErrorDetail};

mod transport;

const WAIT: Duration = Duration::from_secs(10);

#[test]
fn protocol_envelopes_have_stable_bytes() {
    let request = ProveRequest::decode(b"\x08\x01\x12\x01w".as_slice()).unwrap();
    assert_eq!(request.protocol_version, PROTOCOL_VERSION);
    assert_eq!(request.execution_witness, [b'w']);
    assert_eq!(request.encode_to_vec(), b"\x08\x01\x12\x01w");
    let response = ProveResponse::decode(b"\x0a\x01p".as_slice()).unwrap();
    assert_eq!(response.execution_proof, [b'p']);
    assert_eq!(response.encode_to_vec(), b"\x0a\x01p");
}

#[test]
fn application_errors_have_stable_wire_identifiers() {
    use tonic::Code;

    for (error, id, grpc) in [
        (ErrorCode::UnsupportedVersion, 1, Code::InvalidArgument),
        (ErrorCode::InvalidWitness, 2, Code::InvalidArgument),
        (ErrorCode::RequestTooLarge, 3, Code::ResourceExhausted),
        (ErrorCode::QueueFull, 4, Code::ResourceExhausted),
        (ErrorCode::ProverLimitExceeded, 5, Code::ResourceExhausted),
        (ErrorCode::DeadlineExceeded, 6, Code::DeadlineExceeded),
        (ErrorCode::Cancelled, 7, Code::Cancelled),
        (ErrorCode::ShuttingDown, 8, Code::Unavailable),
        (ErrorCode::ProvingFailed, 9, Code::Internal),
        (ErrorCode::Internal, 10, Code::Internal),
        (ErrorCode::ResponseTooLarge, 11, Code::ResourceExhausted),
    ] {
        let response = status(error).into_http::<()>();
        assert_eq!(response.headers()["grpc-status"], (grpc as i32).to_string());
        let decoded = Status::from_header_map(response.headers()).unwrap();
        assert_eq!(decoded.details(), [8, id]);
        assert_eq!(ErrorDetail::decode(decoded.details()).unwrap().code(), error);
    }
}

fn config() -> ServerConfig {
    ServerConfig::new(8 << 20, 8 << 20, Duration::from_secs(60), 32 << 30, 32 << 30).unwrap()
}

fn witness(source: &str) -> ExecutionWitness {
    let program = Assembler::default().assemble_program("test", source).unwrap().unwrap_program();
    FastProcessor::new(StackInputs::default())
        .execute_for_proving_sync(&program, &mut DefaultHost::default())
        .unwrap()
}

fn bytes() -> Vec<u8> {
    witness("begin push.1 drop end").to_bytes()
}

fn keccak_witness() -> ExecutionWitness {
    let library = miden_core_lib::CoreLibrary::default();
    let mut assembler = Assembler::default();
    assembler.link_package(library.package(), Linkage::Dynamic).unwrap();
    // Hash one zero byte from unwritten memory into a separate output buffer.
    let program = assembler.assemble_program("keccak", "begin push.256 push.1 push.128 exec.::miden::core::precompiles::hashes::keccak256::hash_bytes_mem end")
        .unwrap().unwrap_program();
    let mut host = DefaultHost::default().with_library(&library).unwrap();
    FastProcessor::new(StackInputs::default())
        .execute_for_proving_sync(&program, &mut host)
        .unwrap()
}

async fn submit<P: InputPolicy>(
    service: &ProvingService<P>,
    bytes: Vec<u8>,
) -> Result<Vec<u8>, Status> {
    service
        .prove(Request::new(ProveRequest {
            protocol_version: PROTOCOL_VERSION,
            execution_witness: bytes,
        }))
        .await
        .map(|response| response.into_inner().execution_proof)
}

fn code(error: Status) -> ErrorCode {
    ErrorDetail::decode(error.details()).unwrap().code()
}

fn fake<P: InputPolicy>(service: &mut ProvingService<P>, prove: TestProver) {
    Arc::get_mut(&mut service.state).unwrap().test_prover = Some(prove);
}

// Unblocks the fake worker even if an assertion unwinds before explicit release.
struct Release(Option<mpsc::Sender<()>>);

impl Release {
    fn send(mut self) {
        self.0.take().unwrap().send(()).unwrap();
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

fn blocking<P: InputPolicy>(
    service: &mut ProvingService<P>,
) -> (oneshot::Receiver<()>, Release, Arc<AtomicUsize>) {
    let (start, started) = oneshot::channel();
    let start = StdMutex::new(Some(start));
    let (release, released) = mpsc::channel();
    let released = StdMutex::new(released);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    fake(
        service,
        Arc::new(move |_| {
            let index = count.fetch_add(1, Ordering::SeqCst);
            if index == 0 {
                start.lock().unwrap().take().unwrap().send(()).unwrap();
                released.lock().unwrap().recv_timeout(WAIT).unwrap();
            }
            Ok(vec![index as u8])
        }),
    );
    (started, Release(Some(release)), calls)
}

fn spawn(service: &ProvingService, bytes: Vec<u8>) -> JoinHandle<Result<Vec<u8>, Status>> {
    let service = service.clone();
    tokio::spawn(async move { submit(&service, bytes).await })
}

async fn admitted(service: &ProvingService, remaining: usize) {
    timeout(WAIT, async {
        while service.state.admission.available_permits() != remaining {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_envelopes_never_reach_the_prover_and_service_remains_usable() {
    let bytes = bytes();
    let mut service = ProvingService::new(config());
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    fake(
        &mut service,
        Arc::new(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(vec![1])
        }),
    );
    let error = service
        .prove(Request::new(ProveRequest {
            protocol_version: u32::MAX,
            execution_witness: bytes.clone(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(code(error), ErrorCode::UnsupportedVersion);
    let mut unsupported = bytes.clone();
    unsupported[0] = u8::MAX;
    for malformed in [vec![], vec![u8::MAX; 16], unsupported, bytes[..bytes.len() / 2].to_vec()] {
        assert_eq!(code(submit(&service, malformed).await.unwrap_err()), ErrorCode::InvalidWitness);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(submit(&service, bytes).await.unwrap(), [1]);
    service.shutdown().await;
}

#[tokio::test]
async fn exact_witness_and_proof_field_limits() {
    let bytes = bytes();
    let mut service = ProvingService::new(
        ServerConfig::new(bytes.len(), 1, Duration::from_secs(1), 1, 1).unwrap(),
    );
    fake(&mut service, Arc::new(|_| Ok(vec![1])));
    assert_eq!(submit(&service, bytes.clone()).await.unwrap(), [1]);
    let mut oversized = bytes.clone();
    oversized.push(0);
    assert_eq!(code(submit(&service, oversized).await.unwrap_err()), ErrorCode::RequestTooLarge);
    service.shutdown().await;

    let mut service = ProvingService::new(
        ServerConfig::new(bytes.len(), 1, Duration::from_secs(1), 1, 1).unwrap(),
    );
    fake(&mut service, Arc::new(|_| Ok(vec![1, 2])));
    assert_eq!(code(submit(&service, bytes).await.unwrap_err()), ErrorCode::ResponseTooLarge);
    service.shutdown().await;
}

#[tokio::test]
async fn real_vm_budget_applies_to_both_policies() {
    let config = ServerConfig::new(8 << 20, 8 << 20, WAIT, 1, 32 << 30).unwrap();
    let untrusted = ProvingService::new(config.clone());
    let trusted = ProvingService::<Trusted>::new_trusted(config);
    assert_eq!(
        code(submit(&untrusted, bytes()).await.unwrap_err()),
        ErrorCode::ProverLimitExceeded
    );
    assert_eq!(
        code(submit(&trusted, bytes()).await.unwrap_err()),
        ErrorCode::ProverLimitExceeded
    );
    untrusted.shutdown().await;
    trusted.shutdown().await;
}

#[tokio::test]
async fn real_precompile_budget_and_structural_policy_apply() {
    let bytes = witness("begin log_deferred end").to_bytes();
    let memory = ServerConfig::new(8 << 20, 8 << 20, Duration::from_secs(60), 32 << 30, 1).unwrap();
    let service = ProvingService::new(memory);
    assert_eq!(
        code(submit(&service, bytes.clone()).await.unwrap_err()),
        ErrorCode::ProverLimitExceeded
    );
    service.shutdown().await;
    let service = ProvingService::<Trusted>::new_trusted(
        config()
            .with_verification_precompile_limits(miden_core::deferred::PrecompileLimits::new(0)),
    );
    assert_eq!(code(submit(&service, bytes).await.unwrap_err()), ErrorCode::ProverLimitExceeded);
    service.shutdown().await;
}

#[tokio::test]
async fn native_precompile_work_class_limit_applies_to_both_policies() {
    let bytes = keccak_witness().to_bytes();
    let limits = miden_precompiles::default_verification_precompile_limits().with_class(
        miden_precompiles::HASH_WORK,
        miden_core::deferred::WorkLimit {
            max_count: 0,
            max_total_size: 0,
            max_size: 0,
        },
    );
    let untrusted =
        ProvingService::new(config().with_verification_precompile_limits(limits.clone()));
    let trusted = ProvingService::<Trusted>::new_trusted(
        config().with_verification_precompile_limits(limits),
    );
    for error in [
        submit(&untrusted, bytes.clone()).await.unwrap_err(),
        submit(&trusted, bytes).await.unwrap_err(),
    ] {
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert_eq!(code(error), ErrorCode::ProverLimitExceeded);
    }
    untrusted.shutdown().await;
    trusted.shutdown().await;
}

#[tokio::test]
async fn capacity_counts_active_and_fifo_waiters() {
    let mut service = ProvingService::new(config().with_capacity(3).unwrap());
    let (started, release, calls) = blocking(&mut service);
    let bytes = bytes();
    let first = spawn(&service, bytes.clone());
    timeout(WAIT, started).await.unwrap().unwrap();
    let second = spawn(&service, bytes.clone());
    admitted(&service, 1).await;
    let third = spawn(&service, bytes.clone());
    admitted(&service, 0).await;
    assert_eq!(code(submit(&service, bytes).await.unwrap_err()), ErrorCode::QueueFull);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    release.send();
    assert_eq!(timeout(WAIT, first).await.unwrap().unwrap().unwrap(), [0]);
    assert_eq!(timeout(WAIT, second).await.unwrap().unwrap().unwrap(), [1]);
    assert_eq!(timeout(WAIT, third).await.unwrap().unwrap().unwrap(), [2]);
    service.shutdown().await;
}

#[tokio::test]
async fn timed_out_running_job_retains_capacity_until_exit() {
    let config = ServerConfig::new(8 << 20, 8 << 20, Duration::from_millis(200), 1, 1).unwrap();
    let mut service = ProvingService::new(config);
    let (started, release, _) = blocking(&mut service);
    let bytes = bytes();
    let first = spawn(&service, bytes.clone());
    timeout(WAIT, started).await.unwrap().unwrap();
    assert_eq!(
        code(timeout(WAIT, first).await.unwrap().unwrap().unwrap_err()),
        ErrorCode::DeadlineExceeded
    );
    assert_eq!(code(submit(&service, bytes).await.unwrap_err()), ErrorCode::QueueFull);
    let shutdown = {
        let service = service.clone();
        tokio::spawn(async move { service.shutdown().await })
    };
    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished());
    release.send();
    timeout(WAIT, shutdown).await.unwrap().unwrap();
    assert!(service.state.tasks.is_empty());
    assert!(service.state.worker.try_lock().is_ok());
}

#[tokio::test]
async fn queued_deadline_releases_admission_without_dispatch() {
    let config = ServerConfig::new(8 << 20, 8 << 20, Duration::from_millis(200), 1, 1)
        .unwrap()
        .with_capacity(2)
        .unwrap();
    let mut service = ProvingService::new(config);
    let (started, release, calls) = blocking(&mut service);
    let bytes = bytes();
    let first = spawn(&service, bytes.clone());
    timeout(WAIT, started).await.unwrap().unwrap();
    let queued = spawn(&service, bytes);
    admitted(&service, 0).await;
    let error = timeout(WAIT, queued).await.unwrap().unwrap().unwrap_err();
    assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
    assert_eq!(code(error), ErrorCode::DeadlineExceeded);
    assert_eq!(
        code(timeout(WAIT, first).await.unwrap().unwrap().unwrap_err()),
        ErrorCode::DeadlineExceeded
    );
    admitted(&service, 1).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    release.send();
    service.shutdown().await;
}

#[tokio::test]
async fn typed_instances_have_independent_admission_and_shutdown() {
    let mut untrusted = ProvingService::new(config());
    let mut trusted = ProvingService::<Trusted>::new_trusted(config());
    fake(&mut trusted, Arc::new(|_| Ok(vec![7])));
    let (started, release, _) = blocking(&mut untrusted);
    let bytes = bytes();
    let first = spawn(&untrusted, bytes.clone());
    timeout(WAIT, started).await.unwrap().unwrap();
    assert_eq!(submit(&trusted, bytes.clone()).await.unwrap(), [7]);
    untrusted.state.begin_shutdown();
    assert_eq!(submit(&trusted, bytes).await.unwrap(), [7]);
    release.send();
    timeout(WAIT, first).await.unwrap().unwrap().unwrap();
    untrusted.shutdown().await;
    trusted.shutdown().await;
}

#[tokio::test]
async fn shutdown_cancellation_preserves_its_committed_state_and_can_resume() {
    let mut service = ProvingService::new(config().with_capacity(2).unwrap());
    let (started, release, calls) = blocking(&mut service);
    drop(service.shutdown());
    let bytes = bytes();
    let first = spawn(&service, bytes.clone());
    timeout(WAIT, started).await.unwrap().unwrap();
    let queued = spawn(&service, bytes.clone());
    admitted(&service, 0).await;

    let mut shutdown = Box::pin(service.shutdown());
    assert!(timeout(Duration::from_millis(25), &mut shutdown).await.is_err());
    drop(shutdown);
    assert_eq!(
        code(timeout(WAIT, queued).await.unwrap().unwrap().unwrap_err()),
        ErrorCode::ShuttingDown
    );
    assert_eq!(code(submit(&service, bytes).await.unwrap_err()), ErrorCode::ShuttingDown);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(service.state.tasks.len(), 1);
    assert!(!first.is_finished());
    let control = service.clone();
    let mut resumed = Box::pin(control.shutdown());
    assert!(timeout(Duration::from_millis(25), &mut resumed).await.is_err());
    release.send();
    timeout(WAIT, resumed).await.unwrap();
    assert_eq!(timeout(WAIT, first).await.unwrap().unwrap().unwrap(), [0]);
    assert!(service.state.tasks.is_empty());
}

#[tokio::test]
async fn worker_error_and_unwinding_panic_allow_subsequent_jobs() {
    for panic in [false, true] {
        let mut service = ProvingService::new(config());
        let calls = AtomicUsize::new(0);
        fake(
            &mut service,
            Arc::new(move |_| {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    assert!(!panic, "test worker panic");
                    return Err(status(ErrorCode::ProvingFailed));
                }
                Ok(vec![1])
            }),
        );
        let expected = if panic {
            ErrorCode::Internal
        } else {
            ErrorCode::ProvingFailed
        };
        assert_eq!(code(submit(&service, bytes()).await.unwrap_err()), expected);
        assert_eq!(submit(&service, bytes()).await.unwrap(), [1]);
        service.shutdown().await;
    }
}
