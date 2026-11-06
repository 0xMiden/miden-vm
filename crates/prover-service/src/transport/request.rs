use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http_body::{Body as HttpBody, Frame, SizeHint};
use tokio_util::sync::CancellationToken;
use tonic::{Status, body::Body, codegen::Bytes};

use crate::{failure::status, protocol::ErrorCode};

const HEADER_BYTES: usize = 5;

// Keep framing state across HTTP/2 DATA frames without buffering another copy of
// the request. Tonic drains and discards extra messages on unary calls, so enforce
// the single-message contract before those bytes reach its decoder.
pub(super) struct RequestBody {
    inner: Body,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    message_limit: usize,
    header: [u8; HEADER_BYTES],
    received: usize,
    ended: bool,
}

impl RequestBody {
    pub(super) fn new(inner: Body, shutdown: CancellationToken, message_limit: usize) -> Self {
        Self {
            inner,
            cancelled: Box::pin(shutdown.cancelled_owned()),
            message_limit,
            header: [0; HEADER_BYTES],
            received: 0,
            ended: false,
        }
    }

    fn total_size(&self) -> Result<usize, Status> {
        let [_, a, b, c, d] = self.header;
        let length = u32::from_be_bytes([a, b, c, d]) as usize;
        if length > self.message_limit {
            return Err(status(ErrorCode::RequestTooLarge));
        }
        length
            .checked_add(HEADER_BYTES)
            .ok_or_else(|| status(ErrorCode::RequestTooLarge))
    }

    fn accept(&mut self, data: &[u8]) -> Result<(), Status> {
        let received = self
            .received
            .checked_add(data.len())
            .ok_or_else(|| status(ErrorCode::RequestTooLarge))?;
        if received > self.message_limit.saturating_add(HEADER_BYTES) {
            return Err(status(ErrorCode::RequestTooLarge));
        }
        let offset = self.received.min(HEADER_BYTES);
        let copied = data.len().min(HEADER_BYTES - offset);
        self.header[offset..offset + copied].copy_from_slice(&data[..copied]);
        self.received = received;
        if self.received >= HEADER_BYTES && self.received > self.total_size()? {
            return Err(Status::invalid_argument("unary RPC requires exactly one request message"));
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), Status> {
        if self.received < HEADER_BYTES || self.received != self.total_size()? {
            return Err(Status::invalid_argument("incomplete unary request message"));
        }
        Ok(())
    }
}

impl HttpBody for RequestBody {
    type Data = Bytes;
    type Error = Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        if self.cancelled.as_mut().poll(cx).is_ready() {
            self.ended = true;
            return Poll::Ready(Some(Err(status(ErrorCode::ShuttingDown))));
        }
        let frame = match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(frame) => frame,
        };
        let validation = match &frame {
            Some(Ok(frame)) if frame.is_data() => {
                self.accept(frame.data_ref().expect("DATA frame missing data"))
            },
            Some(Ok(_)) | None => self.finish(),
            Some(Err(_)) => Ok(()),
        };
        if let Err(error) = validation {
            self.ended = true;
            return Poll::Ready(Some(Err(error)));
        }
        if !matches!(frame, Some(Ok(ref frame)) if frame.is_data()) {
            self.ended = true;
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        // Always observe EOF or trailers ourselves before exposing completion.
        self.ended
    }

    fn size_hint(&self) -> SizeHint {
        if self.ended {
            SizeHint::with_exact(0)
        } else {
            self.inner.size_hint()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, time::Duration};

    use http_body_util::{BodyExt, StreamBody};
    use tokio::time::timeout;
    use tonic::codegen::http;

    use super::*;

    #[tokio::test]
    async fn one_message_at_limit_preserves_bytes_and_trailers_for_every_split() {
        let bytes = Bytes::from_static(&[0, 0, 0, 0, 2, 8, 1]);
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-test", "metadata".parse().unwrap());
        for split in 0..=bytes.len() {
            let frames = vec![
                Ok::<_, Infallible>(Frame::data(bytes.slice(..split))),
                Ok(Frame::data(bytes.slice(split..))),
                Ok(Frame::trailers(trailers.clone())),
            ];
            let inner = Body::new(StreamBody::new(tokio_stream::iter(frames)));
            let body = RequestBody::new(inner, CancellationToken::new(), 2);
            let collected = timeout(Duration::from_secs(2), body.collect()).await.unwrap().unwrap();
            assert_eq!(collected.trailers(), Some(&trailers));
            assert_eq!(collected.to_bytes(), bytes);
        }
    }
}
