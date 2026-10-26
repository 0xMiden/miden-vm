use std::{
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_stream::{Stream, StreamExt, wrappers::TcpListenerStream};
use tokio_util::sync::CancellationToken;
use tonic::{
    body::Body,
    codegen::http,
    server::NamedService,
    transport::{
        Server,
        server::{Connected, TcpConnectInfo},
    },
};
use tonic_health::{ServingStatus, server::HealthReporter};
use tower::{Service, ServiceExt};

use crate::{
    InputPolicy, ProvingService,
    failure::status,
    protocol::{ErrorCode, prover_service_server::ProverServiceServer},
    service::State,
};

mod request;
mod response;

use request::RequestBody;
use response::ResponseBody;

const HEALTH_MESSAGE_LIMIT: usize = 1024;

/// A listener or gRPC transport failure after active proof work has been joined.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("proving listener failed: {0}")]
    Listener(#[from] io::Error),
    #[error("proving transport failed: {0}")]
    Transport(#[from] tonic::transport::Error),
}

impl<P: InputPolicy> ProvingService<P> {
    /// Binds the configured address and serves until [`Self::shutdown`] is requested.
    ///
    /// # Cancel safety
    ///
    /// Once serving has started, dropping this future requests shutdown for the
    /// instance and all its clones. Active proof jobs continue, and dropping the
    /// future skips graceful health and connection cleanup and the proof-job join.
    ///
    /// For graceful shutdown, retain a service clone, call [`Self::shutdown`] on
    /// it, and keep this future alive until it completes. If this future has
    /// already been dropped, a retained clone can still call `shutdown().await`
    /// to join proof jobs. That call does not recover graceful transport cleanup.
    pub async fn serve(self) -> Result<(), ServerError> {
        let listener = match TcpListener::bind(self.config().listen_addr()).await {
            Ok(listener) => listener,
            Err(error) => {
                self.shutdown().await;
                return Err(ServerError::Listener(error));
            },
        };
        self.serve_with_listener(listener).await
    }

    /// Serves on an existing listener and joins active work before returning.
    ///
    /// Retain a clone to request shutdown, then await this future to join the
    /// transport and close its connections. Each instance has its own global
    /// transport allowance, retained through response delivery, in addition to
    /// its active and queued proof capacity.
    /// Connections receive one configured request timeout to drain on shutdown;
    /// actual proof work is always joined before this method returns.
    ///
    /// # Cancel safety
    ///
    /// Once polled, dropping this future requests shutdown for the instance and
    /// all its clones. It skips graceful health and connection cleanup and does
    /// not wait for active proof jobs. Keep this future alive and use a retained
    /// service clone to request [`Self::shutdown`], then await this future to
    /// completion. If it has already been dropped, `shutdown().await` on a clone
    /// can still join proof jobs, but cannot recover graceful transport cleanup.
    pub async fn serve_with_listener(self, listener: TcpListener) -> Result<(), ServerError> {
        self.serve_incoming(TcpListenerStream::new(listener)).await
    }

    async fn serve_incoming<S>(self, incoming: S) -> Result<(), ServerError>
    where
        S: Stream<Item = io::Result<TcpStream>> + Send + 'static,
    {
        let state = Arc::clone(&self.state);
        let guard = ShutdownGuard(Arc::clone(&state));
        let name = ProverServiceServer::<Self>::NAME;
        let (mut reporter, health) = tonic_health::server::health_reporter();
        reporter.set_serving::<ProverServiceServer<Self>>().await;

        // Tonic normally logs accept errors and continues. Capture the original
        // error and trigger shutdown so a broken listener terminates this server.
        let accept_error = Arc::new(Mutex::new(None));
        let errors = Arc::clone(&accept_error);
        let accept_state = Arc::clone(&state);
        let accept_reporter = reporter.clone();
        let incoming = incoming
            .chain(tokio_stream::once(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "listener stream ended",
            ))))
            .then(move |connection| {
                let state = Arc::clone(&accept_state);
                let errors = Arc::clone(&errors);
                let mut reporter = accept_reporter.clone();
                async move {
                    match connection {
                        Ok(stream) => Ok(ShutdownIo::new(
                            stream,
                            state.shutdown_token(),
                            state.config.request_timeout(),
                        )),
                        Err(error) => {
                            {
                                let mut stored =
                                    errors.lock().expect("listener error lock poisoned");
                                if stored.is_none() {
                                    *stored = Some(error);
                                }
                            }
                            state.begin_shutdown();
                            stop_health(&mut reporter, name).await;
                            Err(io::Error::other("proving listener stopped"))
                        },
                    }
                }
            });
        let shutdown = state.shutdown_token();
        let mut shutdown_reporter = reporter.clone();
        let prover = ProverServiceServer::new(self)
            .max_decoding_message_size(state.config.request_message_limit())
            .max_encoding_message_size(state.config.response_message_limit());
        let health = health
            .max_decoding_message_size(HEALTH_MESSAGE_LIMIT)
            .max_encoding_message_size(HEALTH_MESSAGE_LIMIT);
        let result = Server::builder()
            .add_service(Endpoint::new(
                prover,
                state.ingress_semaphore(),
                state.config.request_message_limit(),
                Arc::clone(&state),
            ))
            .add_service(Endpoint::new(
                health,
                state.health_ingress_semaphore(),
                HEALTH_MESSAGE_LIMIT,
                Arc::clone(&state),
            ))
            .serve_with_incoming_shutdown(incoming, async move {
                shutdown.cancelled().await;
                stop_health(&mut shutdown_reporter, name).await;
            })
            .await;

        drop(guard);
        stop_health(&mut reporter, name).await;
        state.tasks.wait().await;
        state.response_tasks.wait().await;
        if let Some(error) = accept_error.lock().expect("listener error lock poisoned").take() {
            return Err(ServerError::Listener(error));
        }
        result.map_err(ServerError::Transport)
    }
}

async fn stop_health(reporter: &mut HealthReporter, name: &str) {
    reporter.set_service_status(name, ServingStatus::NotServing).await;
    reporter.set_service_status("", ServingStatus::NotServing).await;
    // Closing the status channels also ends Health/Watch streams, which would
    // otherwise keep graceful HTTP/2 shutdown waiting for clients to disconnect.
    reporter.clear_service_status(name).await;
    reporter.clear_service_status("").await;
}

struct ShutdownGuard(Arc<State>);

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        self.0.begin_shutdown();
    }
}

// Tonic's graceful shutdown waits for HTTP/2 streams indefinitely. A peer can
// keep a stream alive by withholding response flow-control credit, even after
// its application handler has finished. Bound that network drain independently
// of the tracked synchronous proof work.
struct ShutdownIo {
    inner: TcpStream,
    info: ConnectionInfo,
    close: Pin<Box<dyn Future<Output = ()> + Send>>,
    closed: bool,
}

impl ShutdownIo {
    fn new(inner: TcpStream, shutdown: CancellationToken, grace: Duration) -> Self {
        let info = ConnectionInfo {
            tcp: inner.connect_info(),
            close: CancellationToken::new(),
        };
        let close_connection = info.close.clone();
        let close = Box::pin(async move {
            tokio::select! {
                _ = close_connection.cancelled_owned() => {},
                _ = async {
                    shutdown.cancelled_owned().await;
                    tokio::time::sleep(grace).await;
                } => {},
            }
        });
        Self { inner, info, close, closed: false }
    }

    fn closing(&mut self, cx: &mut Context<'_>) -> bool {
        if !self.closed && self.close.as_mut().poll(cx).is_ready() {
            self.closed = true;
        }
        self.closed
    }
}

impl Drop for ShutdownIo {
    fn drop(&mut self) {
        self.info.close.cancel();
    }
}

#[derive(Clone, Debug)]
struct ConnectionInfo {
    tcp: TcpConnectInfo,
    close: CancellationToken,
}

impl Connected for ShutdownIo {
    type ConnectInfo = ConnectionInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
    }
}

impl AsyncRead for ShutdownIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closing(cx) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ShutdownIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closing(cx) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection drain deadline elapsed",
            )));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closing(cx) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection drain deadline elapsed",
            )));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closing(cx) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// Acquire ingress before decoding, then transfer its lease to response bytes.
// The semaphore belongs to the instance and is shared across listeners and clients.
#[derive(Clone)]
struct Endpoint<S> {
    inner: S,
    ingress: Arc<Semaphore>,
    message_limit: usize,
    state: Arc<State>,
}

impl<S> Endpoint<S> {
    fn new(server: S, ingress: Arc<Semaphore>, message_limit: usize, state: Arc<State>) -> Self {
        Self {
            inner: server,
            ingress,
            message_limit,
            state,
        }
    }
}

impl<S: NamedService> NamedService for Endpoint<S> {
    const NAME: &'static str = S::NAME;
}

impl<S> Service<http::Request<Body>> for Endpoint<S>
where
    S: Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
        let inner = self.inner.clone();
        let state = Arc::clone(&self.state);
        let ingress = Arc::clone(&self.ingress);
        let timeout = state.config.request_timeout();
        let message_limit = self.message_limit;
        Box::pin(async move {
            let shutdown = state.shutdown_token();
            if shutdown.is_cancelled() {
                return Ok(status(ErrorCode::ShuttingDown).into_http());
            }
            let permit = match ingress.try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => return Ok(status(ErrorCode::QueueFull).into_http()),
            };
            let connection = request
                .extensions()
                .get::<ConnectionInfo>()
                .cloned()
                .expect("proving transport must attach connection information");
            // Preserve Tonic's peer-address accessors alongside our close signal.
            request.extensions_mut().insert(connection.tcp.clone());
            let request =
                request.map(|body| Body::new(RequestBody::new(body, shutdown, message_limit)));
            let response = match tokio::time::timeout(timeout, inner.oneshot(request)).await {
                Ok(Ok(response)) => response,
                Ok(Err(never)) => match never {},
                Err(_) => return Ok(status(ErrorCode::DeadlineExceeded).into_http()),
            };
            Ok(response.map(|body| ResponseBody::wrap(body, permit, timeout, connection, &state)))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;
    use crate::ServerConfig;

    #[tokio::test]
    async fn listener_failure_returns_the_original_error() {
        let service = ProvingService::new(
            ServerConfig::new(1024, 1024, Duration::from_secs(1), 1, 1).unwrap(),
        );
        let incoming =
            tokio_stream::iter([Err::<TcpStream, _>(io::Error::other("synthetic accept failure"))]);
        let result = timeout(Duration::from_secs(5), service.clone().serve_incoming(incoming))
            .await
            .unwrap();
        let ServerError::Listener(error) = result.unwrap_err() else {
            panic!("expected listener error");
        };
        assert_eq!(error.to_string(), "synthetic accept failure");
        assert!(service.state.shutdown_token().is_cancelled());
        assert!(service.state.tasks.is_empty());
    }

    #[tokio::test]
    async fn bind_failure_stops_the_instance() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = ServerConfig::new(1024, 1024, Duration::from_secs(1), 1, 1)
            .unwrap()
            .with_listen_addr(listener.local_addr().unwrap());
        let service = ProvingService::new(config);
        let result = timeout(Duration::from_secs(5), service.clone().serve()).await.unwrap();
        let ServerError::Listener(error) = result.unwrap_err() else {
            panic!("expected bind error");
        };
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(service.state.shutdown_token().is_cancelled());
        drop(listener);
    }
}
