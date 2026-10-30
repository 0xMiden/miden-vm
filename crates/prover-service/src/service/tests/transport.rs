use std::{convert::Infallible, error::Error, net::SocketAddr};

use http_body::Body as HttpBody;
use http_body_util::{Full, StreamBody};
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use miden_core::proof::{ExecutionProof, PrecompileStatus};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tonic::{
    Code,
    codegen::{Bytes, http},
    transport::Channel,
};
use tonic_health::pb::{
    HealthCheckRequest, health_check_response::ServingStatus, health_client::HealthClient,
};

use super::*;
use crate::{ServerError, protocol::prover_service_client::ProverServiceClient};

const PROVE_PATH: &str = "/miden.prover.v1.ProverService/Prove";

fn grpc_message(payload: &[u8]) -> Bytes {
    let mut frame = vec![0];
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(payload);
    Bytes::from(frame)
}

async fn raw_rejection(address: SocketAddr, path: &str, parts: Vec<Bytes>) -> Status {
    let frames: Vec<_> = parts
        .into_iter()
        .map(|data| Ok::<_, Infallible>(http_body::Frame::data(data)))
        .collect();
    let body = StreamBody::new(tokio_stream::iter(frames));
    let (mut sender, driver) = http2(address).await;
    let response = timeout(WAIT, sender.send_request(request_to(address, path, body)))
        .await
        .unwrap()
        .unwrap();
    let error = Status::from_header_map(response.headers()).unwrap();
    drop(response);
    drop(sender);
    close_http2(driver).await;
    error
}

struct Running<P: InputPolicy> {
    service: ProvingService<P>,
    address: SocketAddr,
    task: Option<JoinHandle<Result<(), ServerError>>>,
}

impl<P: InputPolicy> Running<P> {
    async fn start(service: ProvingService<P>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let worker = service.clone();
        let task = tokio::spawn(async move { worker.serve_with_listener(listener).await });
        Self { service, address, task: Some(task) }
    }

    async fn client(&self) -> ProverServiceClient<Channel> {
        timeout(WAIT, ProverServiceClient::connect(format!("http://{}", self.address)))
            .await
            .unwrap()
            .unwrap()
            .max_decoding_message_size(self.service.config().response_message_limit())
    }

    async fn stop(mut self) {
        timeout(WAIT, self.service.shutdown()).await.unwrap();
        timeout(WAIT, self.task.as_mut().unwrap()).await.unwrap().unwrap().unwrap();
        self.task.take();
        assert!(self.service.state.tasks.is_empty());
    }
}

impl<P: InputPolicy> Drop for Running<P> {
    fn drop(&mut self) {
        self.service.state.begin_shutdown();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn request(bytes: Vec<u8>) -> ProveRequest {
    ProveRequest {
        protocol_version: PROTOCOL_VERSION,
        execution_witness: bytes,
    }
}

fn verify(claim: &miden_core::program::ExecutionClaim, bytes: &[u8], precompile: bool) {
    let proof = ExecutionProof::read_from_bytes(bytes).unwrap();
    if precompile {
        assert!(matches!(proof.precompile(), PrecompileStatus::Proven(_)));
    } else {
        assert!(matches!(proof.precompile(), PrecompileStatus::Empty));
    }
    let outcome = miden_verifier::Verifier::new().verify(claim, &proof).unwrap();
    assert!(outcome.is_complete());
    assert_eq!(outcome.precompile_security_parameters().is_some(), precompile);
}

async fn ingress<P: InputPolicy>(service: &ProvingService<P>, remaining: usize) {
    available(&service.state.ingress, remaining).await;
}

async fn available(semaphore: &Semaphore, remaining: usize) {
    timeout(WAIT, async {
        while semaphore.available_permits() != remaining {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn health_client(address: SocketAddr) -> HealthClient<Channel> {
    let endpoint = Channel::from_shared(format!("http://{address}")).unwrap();
    HealthClient::new(timeout(WAIT, endpoint.connect()).await.unwrap().unwrap())
}

async fn http2<B>(address: SocketAddr) -> (SendRequest<B>, JoinHandle<Result<(), hyper::Error>>)
where
    B: HttpBody<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Error + Send + Sync,
{
    let socket = TcpStream::connect(address).await.unwrap();
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(socket))
            .await
            .unwrap();
    (sender, tokio::spawn(connection))
}

async fn close_http2(driver: JoinHandle<Result<(), hyper::Error>>) {
    driver.abort();
    match driver.await {
        Ok(result) => result.unwrap(),
        Err(error) => assert!(error.is_cancelled()),
    }
}

async fn disconnectable_http2(
    address: SocketAddr,
) -> (
    SendRequest<Full<Bytes>>,
    JoinHandle<Result<(), hyper::Error>>,
    std::net::TcpStream,
) {
    let socket = TcpStream::connect(address).await.unwrap().into_std().unwrap();
    let control = socket.try_clone().unwrap();
    let socket = TcpStream::from_std(socket).unwrap();
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(socket))
            .await
            .unwrap();
    (sender, tokio::spawn(connection), control)
}

fn http_request<B>(address: SocketAddr, body: B) -> http::Request<B> {
    request_to(address, PROVE_PATH, body)
}

fn request_to<B>(address: SocketAddr, path: &str, body: B) -> http::Request<B> {
    http::Request::builder()
        .method("POST")
        .uri(format!("http://{address}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(body)
        .unwrap()
}

#[tokio::test]
async fn persistent_clients_and_coexisting_reader_policies() {
    let witness = witness("begin push.1 drop end");
    let claim = witness.claim();
    let bytes = witness.to_bytes();
    let mut trailing = bytes.clone();
    trailing.push(0);
    let untrusted = Running::start(ProvingService::new(config())).await;
    let trusted = Running::start(ProvingService::<Trusted>::new_trusted(config())).await;
    let mut untrusted_client = untrusted.client().await;
    let mut trusted_client = trusted.client().await;
    let error = untrusted_client.prove(request(trailing.clone())).await.unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(code(error), ErrorCode::InvalidWitness);
    let response = trusted_client.prove(request(trailing)).await.unwrap().into_inner();
    verify(&claim, &response.execution_proof, false);
    for _ in 0..2 {
        let response = untrusted_client.prove(request(bytes.clone())).await.unwrap().into_inner();
        verify(&claim, &response.execution_proof, false);
    }
    untrusted.stop().await;
    let response = trusted_client.prove(request(bytes)).await.unwrap().into_inner();
    verify(&claim, &response.execution_proof, false);
    trusted.stop().await;
}

#[tokio::test]
async fn native_precompile_round_trip_over_grpc_for_both_policies() {
    let witness = keccak_witness();
    let claim = witness.claim();
    let bytes = witness.to_bytes();
    let untrusted = Running::start(ProvingService::new(config())).await;
    let trusted = Running::start(ProvingService::<Trusted>::new_trusted(config())).await;
    for mut client in [untrusted.client().await, trusted.client().await] {
        let response = client.prove(request(bytes.clone())).await.unwrap().into_inner();
        verify(&claim, &response.execution_proof, true);
    }
    untrusted.stop().await;
    trusted.stop().await;
}

#[tokio::test]
async fn grpc_field_boundary_and_raw_oversized_frame() {
    let bytes = bytes();
    let config = ServerConfig::new(bytes.len(), 1, WAIT, 1, 1).unwrap();
    let mut service = ProvingService::new(config);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    fake(
        &mut service,
        Arc::new(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(vec![1])
        }),
    );
    let running = Running::start(service).await;
    let mut client = running.client().await;
    assert_eq!(
        client.prove(request(bytes.clone())).await.unwrap().into_inner().execution_proof,
        [1]
    );
    let mut oversized = bytes;
    oversized.push(0);
    let error = client.prove(request(oversized)).await.unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
    assert_eq!(code(error), ErrorCode::RequestTooLarge);

    let length = u32::try_from(running.service.config().request_message_limit() + 1).unwrap();
    let mut header = vec![0];
    header.extend_from_slice(&length.to_be_bytes());
    let (mut sender, driver) = http2(running.address).await;
    let response = timeout(
        WAIT,
        sender.send_request(http_request(running.address, Full::new(Bytes::from(header)))),
    )
    .await
    .unwrap()
    .unwrap();
    let error = Status::from_header_map(response.headers()).unwrap();
    assert_eq!(error.code(), Code::ResourceExhausted);
    assert_eq!(code(error), ErrorCode::RequestTooLarge);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(response);
    drop(sender);
    close_http2(driver).await;
    running.stop().await;
}

#[tokio::test]
async fn unary_proof_requests_reject_extra_messages_and_aggregate_overflow_before_proving() {
    let input = bytes();
    let config = ServerConfig::new(input.len(), 16, WAIT, 1, 1).unwrap();
    let limit = config.request_message_limit();
    let mut service = ProvingService::new(config);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    fake(
        &mut service,
        Arc::new(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(vec![9])
        }),
    );
    let running = Running::start(service).await;
    let message = grpc_message(&request(input).encode_to_vec());
    let extra = grpc_message(&[]);
    let combined = Bytes::from([message.as_ref(), extra.as_ref()].concat());
    assert!(combined.len() <= limit + 5);
    for parts in [
        vec![combined.clone()],
        vec![
            combined.slice(..2),
            combined.slice(2..message.len() + 3),
            combined.slice(message.len() + 3..),
        ],
    ] {
        let error = raw_rejection(running.address, PROVE_PATH, parts).await;
        assert_eq!(error.code(), Code::InvalidArgument);
        assert_eq!(error.message(), "unary RPC requires exactly one request message");
        assert!(error.details().is_empty());
    }
    let overflowing = Bytes::from([message.as_ref(), message.as_ref()].concat());
    assert!(overflowing.len() > limit + 5);
    let error = raw_rejection(running.address, PROVE_PATH, vec![overflowing]).await;
    assert_eq!(error.code(), Code::ResourceExhausted);
    assert_eq!(code(error), ErrorCode::RequestTooLarge);
    for incomplete in
        [Bytes::new(), Bytes::from_static(&[0, 0, 0]), message.slice(..message.len() - 1)]
    {
        let error = raw_rejection(running.address, PROVE_PATH, vec![incomplete]).await;
        assert_eq!(error.code(), Code::InvalidArgument);
        assert_eq!(error.message(), "incomplete unary request message");
        assert!(error.details().is_empty());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut client = running.client().await;
    assert_eq!(client.prove(request(bytes())).await.unwrap().into_inner().execution_proof, [9]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    running.stop().await;
}

#[tokio::test]
async fn complete_unary_messages_wait_for_eof_and_reject_delayed_trailing_bytes() {
    let mut service = ProvingService::new(config());
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    fake(
        &mut service,
        Arc::new(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(vec![9])
        }),
    );
    let running = Running::start(service).await;
    for path in [PROVE_PATH, "/grpc.health.v1.Health/Check", "/grpc.health.v1.Health/Watch"] {
        let message = if path == PROVE_PATH {
            grpc_message(&request(bytes()).encode_to_vec())
        } else {
            grpc_message(&HealthCheckRequest { service: String::new() }.encode_to_vec())
        };
        for extra in [grpc_message(&[]), Bytes::from_static(&[0])] {
            let (upload, receiver) =
                mpsc::channel::<Result<http_body::Frame<Bytes>, Infallible>>(1);
            upload.send(Ok(http_body::Frame::data(message.clone()))).await.unwrap();
            let (mut sender, driver) = http2(running.address).await;
            let body = StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(receiver));
            let mut response =
                tokio::spawn(sender.send_request(request_to(running.address, path, body)));
            let allowance = if path == PROVE_PATH {
                &running.service.state.ingress
            } else {
                &running.service.state.health_ingress
            };
            available(allowance, 0).await;
            // Keep the first complete message on the wire while EOF is withheld.
            assert!(timeout(Duration::from_millis(100), &mut response).await.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(running.service.state.admission.available_permits(), 1);
            upload.send(Ok(http_body::Frame::data(extra))).await.unwrap();
            drop(upload);
            let response = timeout(WAIT, response).await.unwrap().unwrap().unwrap();
            let error = Status::from_header_map(response.headers()).unwrap();
            assert_eq!(error.code(), Code::InvalidArgument);
            assert_eq!(error.message(), "unary RPC requires exactly one request message");
            assert!(error.details().is_empty());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            drop(response);
            drop(sender);
            close_http2(driver).await;
            available(allowance, 1).await;
        }
    }
    running.stop().await;
}

#[tokio::test]
async fn ingress_is_global_before_decode_and_incomplete_bodies_time_out() {
    let config = ServerConfig::new(8 << 20, 8 << 20, Duration::from_millis(300), 1, 1).unwrap();
    let mut service = ProvingService::new(config);
    fake(&mut service, Arc::new(|_| Ok(vec![1])));
    let running = Running::start(service).await;
    let (body_sender, body_receiver) =
        mpsc::channel::<Result<http_body::Frame<Bytes>, Infallible>>(1);
    body_sender
        .send(Ok(http_body::Frame::data(Bytes::from_static(&[0, 0, 0, 0, 64]))))
        .await
        .unwrap();
    let (mut sender, driver) = http2(running.address).await;
    let response = sender.send_request(http_request(
        running.address,
        StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(body_receiver)),
    ));
    let response = tokio::spawn(response);
    ingress(&running.service, 0).await;
    assert_eq!(running.service.state.admission.available_permits(), 1);
    let error = running.client().await.prove(request(bytes())).await.unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
    assert_eq!(code(error), ErrorCode::QueueFull);
    let response = timeout(WAIT, response).await.unwrap().unwrap().unwrap();
    let error = Status::from_header_map(response.headers()).unwrap();
    assert_eq!(error.code(), Code::DeadlineExceeded);
    assert_eq!(code(error), ErrorCode::DeadlineExceeded);
    ingress(&running.service, 1).await;
    assert_eq!(
        running
            .client()
            .await
            .prove(request(bytes()))
            .await
            .unwrap()
            .into_inner()
            .execution_proof,
        [1]
    );
    drop(body_sender);
    drop(response);
    drop(sender);
    close_http2(driver).await;
    running.stop().await;
}

#[tokio::test]
async fn real_client_cancellation_removes_a_queued_job() {
    let mut service = ProvingService::new(config().with_capacity(2).unwrap());
    let (started, release, calls) = blocking(&mut service);
    let running = Running::start(service).await;
    let mut first_client = running.client().await;
    let first = tokio::spawn(async move { first_client.prove(request(bytes())).await });
    timeout(WAIT, started).await.unwrap().unwrap();
    let mut queued_client = running.client().await;
    let queued = tokio::spawn(async move { queued_client.prove(request(bytes())).await });
    admitted(&running.service, 0).await;
    queued.abort();
    assert!(queued.await.unwrap_err().is_cancelled());
    admitted(&running.service, 1).await;
    ingress(&running.service, 1).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    release.send();
    timeout(WAIT, first).await.unwrap().unwrap().unwrap();
    assert_eq!(
        running
            .client()
            .await
            .prove(request(bytes()))
            .await
            .unwrap()
            .into_inner()
            .execution_proof,
        [1]
    );
    running.stop().await;
}

#[tokio::test]
async fn client_grpc_timeout_removes_queued_work_without_dispatch() {
    let mut service = ProvingService::new(config().with_capacity(2).unwrap());
    assert!(service.config().request_timeout() > WAIT);
    let (started, release, calls) = blocking(&mut service);
    let running = Running::start(service).await;
    let mut first_client = running.client().await;
    let first = tokio::spawn(async move { first_client.prove(request(bytes())).await });
    timeout(WAIT, started).await.unwrap().unwrap();

    // This raw client has no request timer. Only the server can honor the header.
    let (mut sender, driver) = http2(running.address).await;
    let body = Full::new(grpc_message(&request(bytes()).encode_to_vec()));
    let mut queued = http_request(running.address, body);
    queued.headers_mut().insert("grpc-timeout", "1S".parse().unwrap());
    let response = tokio::spawn(sender.send_request(queued));
    admitted(&running.service, 0).await;
    let response = timeout(WAIT, response).await.unwrap().unwrap().unwrap();
    let error = Status::from_header_map(response.headers()).unwrap();
    assert!(matches!(error.code(), Code::Cancelled | Code::DeadlineExceeded));
    assert!(error.details().is_empty());
    admitted(&running.service, 1).await;
    ingress(&running.service, 1).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!first.is_finished());
    release.send();
    assert_eq!(
        timeout(WAIT, first)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_inner()
            .execution_proof,
        [0]
    );
    let fresh = running.client().await.prove(request(bytes())).await.unwrap().into_inner();
    assert_eq!(fresh.execution_proof, [1]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(response);
    drop(sender);
    close_http2(driver).await;
    running.stop().await;
}

#[tokio::test]
async fn client_grpc_timeout_keeps_running_work_accounted_until_exit() {
    let mut service = ProvingService::new(config());
    assert!(service.config().request_timeout() > WAIT);
    let (started, release, calls) = blocking(&mut service);
    let running = Running::start(service).await;
    let (mut sender, driver) = http2(running.address).await;
    let body = Full::new(grpc_message(&request(bytes()).encode_to_vec()));
    let mut active = http_request(running.address, body);
    active.headers_mut().insert("grpc-timeout", "1S".parse().unwrap());
    let response = tokio::spawn(sender.send_request(active));
    timeout(WAIT, started).await.unwrap().unwrap();
    let response = timeout(WAIT, response).await.unwrap().unwrap().unwrap();
    let error = Status::from_header_map(response.headers()).unwrap();
    assert!(matches!(error.code(), Code::Cancelled | Code::DeadlineExceeded));
    assert!(error.details().is_empty());
    ingress(&running.service, 1).await;
    assert_eq!(running.service.state.admission.available_permits(), 0);
    assert_eq!(running.service.state.tasks.len(), 1);
    assert!(running.service.state.worker.try_lock().is_err());
    let error = running.client().await.prove(request(bytes())).await.unwrap_err();
    assert_eq!(code(error), ErrorCode::QueueFull);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    release.send();
    admitted(&running.service, 1).await;
    let fresh = running.client().await.prove(request(bytes())).await.unwrap().into_inner();
    assert_eq!(fresh.execution_proof, [1]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(response);
    drop(sender);
    close_http2(driver).await;
    running.stop().await;
}

#[tokio::test]
async fn client_disconnect_after_dispatch_preserves_worker_and_recovers() {
    let mut service = ProvingService::new(config().with_capacity(2).unwrap());
    let (started, release, calls) = blocking(&mut service);
    let running = Running::start(service).await;
    let (mut sender, driver, connection) = disconnectable_http2(running.address).await;
    let body = Full::new(grpc_message(&request(bytes()).encode_to_vec()));
    let response = tokio::spawn(sender.send_request(http_request(running.address, body)));
    timeout(WAIT, started).await.unwrap().unwrap();
    // Drop the actual TCP transport, not merely the future waiting for its result.
    connection.shutdown(std::net::Shutdown::Both).unwrap();
    assert!(timeout(WAIT, response).await.unwrap().unwrap().is_err());
    drop(sender);
    let _connection_result = timeout(WAIT, driver).await.unwrap().unwrap();
    ingress(&running.service, 2).await;
    assert_eq!(running.service.state.admission.available_permits(), 1);
    assert_eq!(running.service.state.tasks.len(), 1);
    assert!(running.service.state.worker.try_lock().is_err());

    let mut client = running.client().await;
    let queued = tokio::spawn(async move { client.prove(request(bytes())).await });
    admitted(&running.service, 0).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!queued.is_finished());
    release.send();
    assert_eq!(
        timeout(WAIT, queued)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_inner()
            .execution_proof,
        [1]
    );
    let fresh = running.client().await.prove(request(bytes())).await.unwrap().into_inner();
    assert_eq!(fresh.execution_proof, [2]);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    running.stop().await;
}

#[tokio::test]
async fn client_disconnect_after_dispatch_does_not_bypass_shutdown_join() {
    let mut service = ProvingService::new(config());
    let (started, release, calls) = blocking(&mut service);
    let running = Running::start(service).await;
    let (mut sender, driver, connection) = disconnectable_http2(running.address).await;
    let body = Full::new(grpc_message(&request(bytes()).encode_to_vec()));
    let response = tokio::spawn(sender.send_request(http_request(running.address, body)));
    timeout(WAIT, started).await.unwrap().unwrap();
    connection.shutdown(std::net::Shutdown::Both).unwrap();
    assert!(timeout(WAIT, response).await.unwrap().unwrap().is_err());
    drop(sender);
    let _connection_result = timeout(WAIT, driver).await.unwrap().unwrap();
    ingress(&running.service, 1).await;
    let control = running.service.clone();
    let mut shutdown = Box::pin(control.shutdown());
    assert!(timeout(Duration::from_millis(25), &mut shutdown).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(running.service.state.tasks.len(), 1);
    assert_eq!(running.service.state.admission.available_permits(), 0);
    assert!(running.service.state.worker.try_lock().is_err());
    assert!(!running.task.as_ref().unwrap().is_finished());
    release.send();
    timeout(WAIT, shutdown).await.unwrap();
    running.stop().await;
}

#[tokio::test]
async fn shutdown_drains_work_and_closes_health_watch_streams() {
    let mut service = ProvingService::new(config().with_capacity(2).unwrap());
    let (started, release, _) = blocking(&mut service);
    let running = Running::start(service).await;
    let mut health = health_client(running.address).await;
    let health_status = health
        .check(HealthCheckRequest {
            service: "miden.prover.v1.ProverService".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(health_status.status, ServingStatus::Serving as i32);
    let mut watcher = health
        .watch(HealthCheckRequest { service: "".into() })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(watcher.message().await.unwrap().unwrap().status, ServingStatus::Serving as i32);
    let mut first_client = running.client().await;
    let first = tokio::spawn(async move { first_client.prove(request(bytes())).await });
    timeout(WAIT, started).await.unwrap().unwrap();
    let mut queued_client = running.client().await;
    let queued = tokio::spawn(async move { queued_client.prove(request(bytes())).await });
    admitted(&running.service, 0).await;
    let health_status = health
        .check(HealthCheckRequest { service: "".into() })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(health_status.status, ServingStatus::Serving as i32);
    running.service.state.begin_shutdown();
    let error = timeout(WAIT, queued).await.unwrap().unwrap().unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(code(error), ErrorCode::ShuttingDown);
    let not_serving = timeout(WAIT, async {
        let mut not_serving = false;
        while let Some(message) = watcher.message().await.unwrap() {
            not_serving |= message.status == ServingStatus::NotServing as i32;
        }
        not_serving
    })
    .await
    .unwrap();
    assert!(not_serving);
    assert!(!running.task.as_ref().unwrap().is_finished());
    release.send();
    timeout(WAIT, first).await.unwrap().unwrap().unwrap();
    running.stop().await;
}

#[tokio::test]
async fn incomplete_health_bodies_are_bounded_and_have_deadlines() {
    for path in ["/grpc.health.v1.Health/Check", "/grpc.health.v1.Health/Watch"] {
        let config = ServerConfig::new(8 << 20, 8 << 20, Duration::from_secs(1), 1, 1).unwrap();
        let mut service = ProvingService::new(config);
        fake(&mut service, Arc::new(|_| Ok(vec![1])));
        let running = Running::start(service).await;
        let (body_sender, body_receiver) =
            mpsc::channel::<Result<http_body::Frame<Bytes>, Infallible>>(1);
        body_sender
            .send(Ok(http_body::Frame::data(Bytes::from_static(&[0, 0, 0, 0, 64]))))
            .await
            .unwrap();
        let (mut sender, driver) = http2(running.address).await;
        let response = sender.send_request(request_to(
            running.address,
            path,
            StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(body_receiver)),
        ));
        let response = tokio::spawn(response);
        available(&running.service.state.health_ingress, 0).await;
        let mut health = health_client(running.address).await;
        let error = health.check(HealthCheckRequest { service: "".into() }).await.unwrap_err();
        assert_eq!(error.code(), Code::ResourceExhausted);
        assert_eq!(code(error), ErrorCode::QueueFull);
        assert_eq!(
            running
                .client()
                .await
                .prove(request(bytes()))
                .await
                .unwrap()
                .into_inner()
                .execution_proof,
            [1]
        );
        let response = timeout(WAIT, response).await.unwrap().unwrap().unwrap();
        let error = Status::from_header_map(response.headers()).unwrap();
        assert_eq!(error.code(), Code::DeadlineExceeded);
        assert_eq!(code(error), ErrorCode::DeadlineExceeded);
        available(&running.service.state.health_ingress, 1).await;
        assert_eq!(
            health
                .check(HealthCheckRequest { service: "".into() })
                .await
                .unwrap()
                .into_inner()
                .status,
            ServingStatus::Serving as i32
        );
        // The peer still holds its incomplete upload open while shutdown joins.
        running.stop().await;
        drop(body_sender);
        drop(response);
        drop(sender);
        close_http2(driver).await;
    }
}

#[tokio::test]
async fn shutdown_interrupts_incomplete_bodies_without_peer_cooperation() {
    for path in [PROVE_PATH, "/grpc.health.v1.Health/Check", "/grpc.health.v1.Health/Watch"] {
        let running = Running::start(ProvingService::new(config())).await;
        let (body_sender, body_receiver) =
            mpsc::channel::<Result<http_body::Frame<Bytes>, Infallible>>(1);
        body_sender
            .send(Ok(http_body::Frame::data(Bytes::from_static(&[0, 0, 0, 0, 64]))))
            .await
            .unwrap();
        let (mut sender, driver) = http2(running.address).await;
        let response = sender.send_request(request_to(
            running.address,
            path,
            StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(body_receiver)),
        ));
        let response = tokio::spawn(response);
        let allowance = if path == PROVE_PATH {
            &running.service.state.ingress
        } else {
            &running.service.state.health_ingress
        };
        available(allowance, 0).await;
        running.service.state.begin_shutdown();
        let response = timeout(WAIT, response).await.unwrap().unwrap().unwrap();
        let error = Status::from_header_map(response.headers()).unwrap();
        assert_eq!(error.code(), Code::Unavailable);
        assert_eq!(code(error), ErrorCode::ShuttingDown);
        running.stop().await;
        drop(body_sender);
        drop(response);
        drop(sender);
        close_http2(driver).await;
    }
}

#[tokio::test]
async fn forced_connection_closure_still_waits_for_actual_proof_work() {
    let config = ServerConfig::new(8 << 20, 8 << 20, Duration::from_millis(500), 1, 1)
        .unwrap()
        .with_capacity(2)
        .unwrap();
    let mut service = ProvingService::new(config);
    let (start, started) = oneshot::channel();
    let start = StdMutex::new(Some(start));
    let (release, released) = std::sync::mpsc::channel();
    let release = Release(Some(release));
    let released = StdMutex::new(released);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    fake(
        &mut service,
        Arc::new(move |_| {
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                return Ok(vec![1; 64 << 10]);
            }
            start.lock().unwrap().take().unwrap().send(()).unwrap();
            released.lock().unwrap().recv_timeout(WAIT).unwrap();
            Ok(vec![1])
        }),
    );
    let mut running = Running::start(service).await;
    let socket = TcpStream::connect(running.address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .initial_stream_window_size(0u32)
        .handshake(TokioIo::new(socket))
        .await
        .unwrap();
    let mut driver = tokio::spawn(connection);
    let payload = request(bytes()).encode_to_vec();
    let mut frame = vec![0];
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&payload);
    let response = timeout(
        WAIT,
        sender.send_request(http_request(running.address, Full::new(Bytes::from(frame.clone())))),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(Status::from_header_map(response.headers()).is_none());
    let active = tokio::spawn(
        sender.send_request(http_request(running.address, Full::new(Bytes::from(frame)))),
    );
    timeout(WAIT, started).await.unwrap().unwrap();
    assert_eq!(running.service.state.tasks.len(), 1);
    running.service.state.begin_shutdown();

    // Keep the upload sender and stalled response alive until the connection
    // driver observes the server closing its transport after the network grace.
    let _connection_result = timeout(WAIT, &mut driver).await.unwrap().unwrap();
    assert!(
        timeout(Duration::from_millis(50), running.task.as_mut().unwrap())
            .await
            .is_err()
    );
    assert_eq!(running.service.state.tasks.len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(running.service.state.admission.available_permits(), 1);
    release.send();
    timeout(WAIT, running.task.as_mut().unwrap()).await.unwrap().unwrap().unwrap();
    running.task.take();
    assert!(running.service.state.tasks.is_empty());
    let _active_response = timeout(WAIT, active).await.unwrap().unwrap();
    drop(response);
    drop(sender);
}

#[tokio::test]
async fn dropping_serving_future_preserves_active_work_for_clone_shutdown() {
    let config = ServerConfig::new(8 << 20, 8 << 20, Duration::from_millis(500), 1, 1).unwrap();
    let mut service = ProvingService::new(config);
    let (started, release, _) = blocking(&mut service);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (cancel, cancelled) = oneshot::channel();
    let worker = service.clone();
    let server = tokio::spawn(async move {
        tokio::select! {
            result = worker.serve_with_listener(listener) => Some(result),
            _ = cancelled => None,
        }
    });
    let mut client = timeout(WAIT, ProverServiceClient::connect(format!("http://{address}")))
        .await
        .unwrap()
        .unwrap();
    let rpc = tokio::spawn(async move { client.prove(request(bytes())).await });
    timeout(WAIT, started).await.unwrap().unwrap();
    cancel.send(()).unwrap();
    assert!(timeout(WAIT, server).await.unwrap().unwrap().is_none());
    assert!(service.state.shutdown_token().is_cancelled());
    assert_eq!(service.state.tasks.len(), 1);
    assert_eq!(service.state.admission.available_permits(), 0);

    let mut shutdown = Box::pin(service.shutdown());
    assert!(timeout(Duration::from_millis(25), &mut shutdown).await.is_err());
    release.send();
    timeout(WAIT, shutdown).await.unwrap();
    assert!(service.state.tasks.is_empty());
    let _response = timeout(WAIT, rpc).await.unwrap().unwrap();
}

#[tokio::test]
async fn stalled_response_retains_capacity_and_expires_without_shutdown() {
    let config = ServerConfig::new(8 << 20, 8 << 20, Duration::from_millis(300), 1, 1).unwrap();
    let mut service = ProvingService::new(config);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    fake(
        &mut service,
        Arc::new(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(vec![1; 64 << 10])
        }),
    );
    let running = Running::start(service).await;
    let socket = TcpStream::connect(running.address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .initial_stream_window_size(0u32)
        .handshake(TokioIo::new(socket))
        .await
        .unwrap();
    let mut driver = tokio::spawn(connection);
    let payload = request(bytes()).encode_to_vec();
    let mut frame = vec![0];
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&payload);
    let response = timeout(
        WAIT,
        sender.send_request(http_request(running.address, Full::new(Bytes::from(frame.clone())))),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(Status::from_header_map(response.headers()).is_none());
    available(&running.service.state.ingress, 0).await;
    for _ in 0..4 {
        let rejected = timeout(
            WAIT,
            sender
                .send_request(http_request(running.address, Full::new(Bytes::from(frame.clone())))),
        )
        .await
        .unwrap()
        .unwrap();
        let error = Status::from_header_map(rejected.headers()).unwrap();
        assert_eq!(error.code(), Code::ResourceExhausted);
        assert_eq!(code(error), ErrorCode::QueueFull);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // The peer neither reads its body nor sends reset/shutdown. The independent
    // response deadline must close this connection and recover the allowance.
    let _connection_result = timeout(WAIT, &mut driver).await.unwrap().unwrap();
    available(&running.service.state.ingress, 1).await;
    assert!(!running.service.state.shutdown_token().is_cancelled());
    assert!(running.service.state.response_tasks.is_empty());
    let mut client = running.client().await;
    assert_eq!(
        client.prove(request(bytes())).await.unwrap().into_inner().execution_proof.len(),
        64 << 10
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(response);
    drop(sender);
    running.stop().await;
}

#[tokio::test]
async fn idle_health_watch_survives_response_deadline_and_releases_capacity() {
    let config = ServerConfig::new(8 << 20, 8 << 20, Duration::from_millis(100), 1, 1).unwrap();
    let mut service = ProvingService::new(config);
    fake(&mut service, Arc::new(|_| Ok(vec![1])));
    let running = Running::start(service).await;
    let mut health = health_client(running.address).await;
    let mut watch = health
        .watch(HealthCheckRequest { service: String::new() })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(watch.message().await.unwrap().unwrap().status(), ServingStatus::Serving);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(timeout(Duration::from_millis(25), watch.message()).await.is_err());
    assert_eq!(running.service.state.health_ingress.available_permits(), 0);
    assert_eq!(
        code(health.check(HealthCheckRequest { service: String::new() }).await.unwrap_err()),
        ErrorCode::QueueFull
    );
    let mut client = running.client().await;
    assert_eq!(client.prove(request(bytes())).await.unwrap().into_inner().execution_proof, [1]);
    drop(watch);
    available(&running.service.state.health_ingress, 1).await;
    assert_eq!(
        health
            .check(HealthCheckRequest { service: String::new() })
            .await
            .unwrap()
            .into_inner()
            .status(),
        ServingStatus::Serving
    );
    running.stop().await;
}
