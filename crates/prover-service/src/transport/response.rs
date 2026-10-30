use std::{
    future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http_body::{Body as HttpBody, Frame, SizeHint};
use tokio::{
    sync::{OwnedSemaphorePermit, watch},
    time::{Instant, sleep_until},
};
use tonic::{body::Body, codegen::Bytes};

use super::{ConnectionInfo, State};

// The body and every outstanding byte allocation share the permit. In
// particular, Hyper/h2 may retain bytes after the body producer has finished.
struct ResponseLease {
    _permit: OwnedSemaphorePermit,
    buffered: watch::Sender<Option<(usize, Instant)>>,
    timeout: Duration,
}

impl ResponseLease {
    fn retain(&self) {
        self.buffered.send_modify(|state| match state {
            Some((count, _)) => *count += 1,
            None => *state = Some((1, Instant::now() + self.timeout)),
        });
    }

    fn release(&self) {
        self.buffered.send_modify(|state| {
            let (count, _) = state.as_mut().expect("response buffer lease missing");
            *count -= 1;
            if *count == 0 {
                *state = None;
            }
        });
    }
}

struct ResponseData {
    data: Bytes,
    lease: Arc<ResponseLease>,
}

impl AsRef<[u8]> for ResponseData {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for ResponseData {
    fn drop(&mut self) {
        self.lease.release();
    }
}

pub(super) struct ResponseBody {
    inner: Body,
    lease: Arc<ResponseLease>,
    first_poll: bool,
}

impl ResponseBody {
    pub(super) fn wrap(
        inner: Body,
        permit: OwnedSemaphorePermit,
        timeout: Duration,
        connection: ConnectionInfo,
        state: &State,
    ) -> Body {
        if inner.is_end_stream() || connection.close.is_cancelled() {
            return Body::empty();
        }
        // Initially cover a response that has not been polled at all. Once
        // polled, only buffered chunks arm the deadline, so idle health watches
        // can stay open without withholding any bytes.
        let (buffered, mut receiver) = watch::channel(Some((1, Instant::now() + timeout)));
        let lease = Arc::new(ResponseLease { _permit: permit, buffered, timeout });
        state.track_response(async move {
            loop {
                let pending = *receiver.borrow_and_update();
                tokio::select! {
                    biased;
                    _ = connection.close.cancelled() => return,
                    changed = receiver.changed() => if changed.is_err() { return },
                    _ = async {
                        match pending {
                            Some((_, deadline)) => sleep_until(deadline).await,
                            None => future::pending().await,
                        }
                    } => {
                        connection.close.cancel();
                        return;
                    },
                }
            }
        });
        Body::new(Self { inner, lease, first_poll: true })
    }
}

impl HttpBody for ResponseBody {
    type Data = Bytes;
    type Error = tonic::Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.first_poll {
            self.first_poll = false;
            self.lease.release();
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let lease = Arc::clone(&self.lease);
                Poll::Ready(Some(Ok(frame.map_data(|data| {
                    if data.is_empty() {
                        return data;
                    }
                    lease.retain();
                    Bytes::from_owner(ResponseData { data, lease })
                }))))
            },
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::{BodyExt, Full};
    use tokio::{sync::Semaphore, time::timeout};
    use tonic::transport::server::TcpConnectInfo;

    use super::*;
    use crate::ServerConfig;

    fn state() -> State {
        State::new(ServerConfig::new(1024, 1024, Duration::from_millis(100), 1, 1).unwrap())
    }

    fn connection() -> ConnectionInfo {
        ConnectionInfo {
            tcp: TcpConnectInfo { local_addr: None, remote_addr: None },
            close: tokio_util::sync::CancellationToken::new(),
        }
    }

    #[tokio::test]
    async fn byte_clones_keep_capacity_and_deadline_after_body_drop() {
        let state = state();
        let ingress = Arc::new(Semaphore::new(1));
        let connection = connection();
        let close = connection.close.clone();
        let mut body = ResponseBody::wrap(
            Body::new(Full::new(Bytes::from_static(b"proof"))),
            Arc::clone(&ingress).try_acquire_owned().unwrap(),
            state.config.request_timeout(),
            connection,
            &state,
        );
        let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let copy = data.clone();
        drop(body);
        drop(data);
        assert_eq!(ingress.available_permits(), 0);
        timeout(Duration::from_secs(2), close.cancelled()).await.unwrap();
        // Closing the transport cannot release memory still owned by its buffers.
        assert_eq!(ingress.available_permits(), 0);
        drop(copy);
        assert_eq!(ingress.available_permits(), 1);
        state.begin_shutdown();
        timeout(Duration::from_secs(2), state.response_tasks.wait()).await.unwrap();
    }

    #[tokio::test]
    async fn unpolled_response_has_an_independent_deadline() {
        let state = state();
        let ingress = Arc::new(Semaphore::new(1));
        let connection = connection();
        let close = connection.close.clone();
        let body = ResponseBody::wrap(
            Body::new(Full::new(Bytes::from_static(b"proof"))),
            Arc::clone(&ingress).try_acquire_owned().unwrap(),
            state.config.request_timeout(),
            connection,
            &state,
        );
        timeout(Duration::from_secs(2), close.cancelled()).await.unwrap();
        assert_eq!(ingress.available_permits(), 0);
        drop(body);
        assert_eq!(ingress.available_permits(), 1);
        state.begin_shutdown();
        timeout(Duration::from_secs(2), state.response_tasks.wait()).await.unwrap();
    }
}
