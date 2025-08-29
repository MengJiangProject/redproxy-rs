use anyhow::Result;
use bytes::Bytes;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::HttpResponse;

use super::parser::{Http1Parser, ParseResult};

pub type HeaderTransformFn = dyn Fn(&mut HttpResponse) + Send + Sync;
/// HTTP/1.1 client stream wrapper for keep-alive connection sharing  
/// Wraps client stream to handle HTTP response writing while keeping connection alive
pub struct HttpClientStream<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
    inner: Option<T>,
    parser: Http1Parser,
    inherited_read_buffer: Vec<u8>,
    completion_callback: Option<Box<dyn FnOnce(T) + Send + Sync>>,
    header_transform: Option<Box<HeaderTransformFn>>,
    pending_output: Option<Bytes>,
    leftover_input: Option<Bytes>,
}

impl<T> HttpClientStream<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
    pub fn new(inner: T, completion_callback: Box<dyn FnOnce(T) + Send + Sync>) -> Self {
        Self {
            inner: Some(inner),
            parser: Http1Parser::new(),
            inherited_read_buffer: Vec::new(),
            completion_callback: Some(completion_callback),
            header_transform: None,
            pending_output: None,
            leftover_input: None,
        }
    }

    pub fn with_header_transform<F>(mut self, transform: F) -> Self
    where
        F: Fn(&mut HttpResponse) + Send + Sync + 'static,
    {
        self.header_transform = Some(Box::new(transform));
        self
    }

    pub fn pre_populate_read_buffer(&mut self, data: &[u8]) {
        self.inherited_read_buffer.extend_from_slice(data);
    }

    fn notify_completion(&mut self) {
        if let Some(callback) = self.completion_callback.take()
            && let Some(inner) = self.inner.take()
        {
            callback(inner);
        }
    }

    pub fn into_inner(self) -> Option<T> {
        self.inner
    }

    pub fn is_response_complete(&self) -> bool {
        self.parser.is_complete()
    }

    fn handle_headers_phase(
        &mut self,
        _cx: &mut TaskContext<'_>,
        buf: &Bytes,
    ) -> Result<usize, std::io::Error> {
        match self.parser.process_data(buf) {
            Ok(ParseResult::HeadersComplete {
                body_start,
                mut response,
                interim_responses,
            }) => {
                println!(
                    "DEBUG: Stream - Headers complete for status {}, body_start: {}",
                    response.status_code, body_start
                );

                // Apply header transformation for final responses
                if response.status_code >= 200
                    && let Some(ref transform) = self.header_transform
                {
                    transform(&mut response);
                }

                // Create complete response blob
                let mut response_blob = interim_responses;
                response_blob.extend_from_slice(
                    format!(
                        "HTTP/1.1 {} {}\r\n",
                        response.status_code, response.reason_phrase
                    )
                    .as_bytes(),
                );
                for (name, value) in &response.headers {
                    response_blob.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
                }
                response_blob.extend_from_slice(b"\r\n");

                // Store any leftover body data for next poll_write call
                if body_start < buf.len() {
                    let body_data = &buf[body_start..];
                    self.leftover_input = Some(Bytes::copy_from_slice(body_data));
                    println!(
                        "DEBUG: Stream - Stored {} bytes of body data as leftover input",
                        body_data.len()
                    );
                }

                // Store the complete blob for writing
                self.pending_output = Some(Bytes::from(response_blob));
                println!(
                    "DEBUG: Stream - Generated {} bytes of output: {:?}",
                    self.pending_output.as_ref().unwrap().len(),
                    self.pending_output
                );

                Ok(buf.len()) // Consumed all input
            }
            Ok(ParseResult::HeadersIncomplete { interim_data }) => {
                if let Some(data) = interim_data {
                    // Forward interim response immediately
                    self.pending_output = Some(Bytes::from(data));
                    println!("DEBUG: Stream - Generated interim response");
                }
                Ok(buf.len()) // Consumed input, need more data
            }
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        }
    }

    fn handle_body_phase(
        &mut self,
        _cx: &mut TaskContext<'_>,
        buf: &Bytes,
    ) -> Result<usize, std::io::Error> {
        match self.parser.process_data(buf) {
            Ok(ParseResult::BodyData { consumed }) => {
                // Generate output blob for body data
                self.pending_output = Some(Bytes::copy_from_slice(&buf[..consumed]));
                Ok(consumed)
            }
            Ok(ParseResult::Complete) => {
                // Generate final body data and notify completion
                self.pending_output = Some(Bytes::copy_from_slice(buf));
                Ok(buf.len())
            }
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        }
    }
}

impl<T> AsyncWrite for HttpClientStream<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        println!("DEBUG: Stream - poll_write {} bytes", buf.len());
        if self.inner.is_none() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Stream has been extracted",
            )));
        }

        // Phase 1: Drain pending output data
        if let Some(pending) = self.pending_output.take() {
            let inner = self.inner.as_mut().unwrap();
            match Pin::new(inner).poll_write(cx, &pending) {
                Poll::Ready(Ok(written)) => {
                    if written < pending.len() {
                        // Partial write, restore remaining data
                        self.pending_output = Some(pending.slice(written..));
                        cx.waker().wake_by_ref();
                        return Poll::Pending; // Retry when inner stream is ready
                    }
                    // All pending data written, continue to phase 2
                }
                Poll::Ready(Err(e)) => {
                    // Restore pending data on error
                    self.pending_output = Some(pending);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    // Restore pending data and retry later
                    self.pending_output = Some(pending);
                    return Poll::Pending; // Inner stream will handle waking
                }
            }
        }

        // Phase 2: Process input data (leftovers first, then new buffer)
        let input_slice: Bytes;
        let is_from_buffer;
        let leftover = self.leftover_input.take();
        if let Some(leftover) = leftover {
            // Use leftover input data first
            println!(
                "DEBUG: Stream - Processing {} bytes of leftover input",
                leftover.len()
            );
            input_slice = leftover;
            is_from_buffer = false;
        } else {
            // Use new input buffer (need to copy to match type)
            input_slice = Bytes::copy_from_slice(buf);
            is_from_buffer = true;
        }

        // Process the input data and generate output
        let consumed = if self.parser.is_complete() {
            input_slice.len() // Accept all data when complete
        } else if self.parser.get_response().is_some() {
            self.handle_body_phase(cx, &input_slice)?
        } else {
            self.handle_headers_phase(cx, &input_slice)?
        };

        // If we didn't consume all input, store leftovers and return Pending
        if consumed < input_slice.len() {
            let leftover_data = &input_slice[consumed..];
            if is_from_buffer {
                // Store leftover from new buffer
                self.leftover_input = Some(Bytes::copy_from_slice(leftover_data));
            } else {
                // Restore the original leftover with updated offset
                self.leftover_input = Some(Bytes::copy_from_slice(leftover_data));
            }
            println!(
                "DEBUG: Stream - Stored {} bytes of leftover input",
                leftover_data.len()
            );
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        // All input consumed
        if is_from_buffer {
            Poll::Ready(Ok(buf.len())) // We processed the new buffer
        } else {
            if self.parser.is_complete() && self.pending_output.is_none() {
                // If response is complete after writing pending data, notify completion
                self.notify_completion();
            }
            Poll::Ready(Ok(0)) // We processed leftover data, accept no new data this round
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        println!(
            "DEBUG: Stream - poll_flush pending_output={:?}, leftover_input={:?}",
            self.pending_output.as_ref(),
            self.leftover_input.as_ref()
        );
        // First, try to drain any pending data to the inner stream
        if let Some(pending) = self.pending_output.take() {
            let inner = self.inner.as_mut().unwrap();
            match Pin::new(inner).poll_write(cx, &pending) {
                Poll::Ready(Ok(written)) => {
                    if written == pending.len() {
                        // All pending data written, keep pending_data as None
                    } else {
                        // Partial write, restore remaining data
                        self.pending_output = Some(pending.slice(written..));
                        cx.waker().wake_by_ref();
                        return Poll::Pending; // Need to retry until all pending data is written
                    }
                }
                Poll::Ready(Err(e)) => {
                    // Restore pending data on error
                    self.pending_output = Some(pending);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    // Restore pending data when inner stream isn't ready
                    self.pending_output = Some(pending);
                    return Poll::Pending; // Inner stream will handle waking
                }
            }
        }

        // Process any leftover input data when no pending output
        if self.leftover_input.is_some() {
            // Recursively call poll_write with empty buffer to process leftovers
            match self.as_mut().poll_write(cx, &[]) {
                Poll::Ready(Ok(_)) => {
                    // Leftover processed, but it may have generated new pending data
                    if self.pending_output.is_some() {
                        // New pending data generated, wake immediately and return Pending
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    // No new pending data, continue to inner flush
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending, // poll_write will handle waking
            }
        }

        if self.parser.is_complete() {
            // If response is complete after writing pending data, notify completion
            self.notify_completion();
        }
        // Finally flush the inner stream
        if let Some(ref mut inner) = self.inner {
            Pin::new(inner).poll_flush(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if let Some(ref mut inner) = self.inner {
            Pin::new(inner).poll_shutdown(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl<T> AsyncRead for HttpClientStream<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if !self.inherited_read_buffer.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), self.inherited_read_buffer.len());
            let data = self
                .inherited_read_buffer
                .drain(..to_copy)
                .collect::<Vec<_>>();
            buf.put_slice(&data);
            return Poll::Ready(Ok(()));
        }

        if let Some(ref mut inner) = self.inner {
            Pin::new(inner).poll_read(cx, buf)
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use test_log::test;
    use tokio::io::AsyncWriteExt;
    use tokio_test::io::Builder;

    fn make_bidirectional_mock(read_data: &[u8], write_data: &[u8]) -> tokio_test::io::Mock {
        Builder::new().read(read_data).write(write_data).build()
    }

    /// Helper to write data in chaotic chunks to stress test the state machine
    async fn write_chaotically<W: AsyncWrite + Unpin>(
        writer: &mut W,
        data: &[u8],
    ) -> std::io::Result<()> {
        let mut pos = 0;

        while pos < data.len() {
            // Use data content itself to determine chunk size (1-10 bytes)
            let chunk_size = std::cmp::min(
                (data[pos] % 10) as usize + 1, // Based on actual data byte
                data.len() - pos,
            );
            let chunk = &data[pos..pos + chunk_size];

            let written = writer.write(chunk).await?;
            pos += written;

            // Flush based on position to create pressure
            if pos % 7 == 0 {
                writer.flush().await?;
            }
        }

        writer.flush().await?;
        Ok(())
    }

    #[test(tokio::test)]
    async fn test_response_stream_creation() {
        let inner = make_bidirectional_mock(b"", b"");
        let callback_called = Arc::new(AtomicBool::new(false));
        let callback_called_clone = callback_called.clone();

        let callback = Box::new(move |_| {
            callback_called_clone.store(true, Ordering::Relaxed);
        });

        let stream = HttpClientStream::new(inner, callback);

        // Check initial state
        assert!(!stream.is_response_complete());

        // Callback should not be called yet
        assert!(!callback_called.load(Ordering::Relaxed));
    }

    #[test(tokio::test)]
    async fn test_content_length_response() {
        let callback_called = Arc::new(AtomicBool::new(false));
        let callback_called_clone = callback_called.clone();

        let returned_stream = Arc::new(std::sync::Mutex::new(None));
        let returned_stream_clone = returned_stream.clone();

        let callback = Box::new(move |_stream| {
            callback_called_clone.store(true, Ordering::Relaxed);
            *returned_stream_clone.lock().unwrap() = Some(());
        });

        // Simulate writing HTTP response data
        let response_data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

        // Expected output after modification (Connection: keep-alive + body)
        let expected_output =
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello";

        // Create a bidirectional mock that expects the modified write data
        let inner = make_bidirectional_mock(b"", expected_output);

        let mut stream = HttpClientStream::new(inner, callback).with_header_transform(|response| {
            // Add Connection: keep-alive header
            response.add_header("Connection".to_string(), "keep-alive".to_string());
        });

        // Use chaotic writing to stress test interim response handling
        write_chaotically(&mut stream, response_data).await.unwrap();

        // Callback should be called when response is complete
        assert!(callback_called.load(Ordering::Relaxed));
        assert!(returned_stream.lock().unwrap().is_some());
    }

    #[test(tokio::test)]
    async fn test_chunked_response() {
        let callback_called = Arc::new(AtomicBool::new(false));
        let callback_called_clone = callback_called.clone();

        let returned_stream = Arc::new(std::sync::Mutex::new(None));
        let returned_stream_clone = returned_stream.clone();

        let callback = Box::new(move |_stream| {
            callback_called_clone.store(true, Ordering::Relaxed);
            *returned_stream_clone.lock().unwrap() = Some(());
        });

        // Simulate writing chunked HTTP response data
        let response_data =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nhello\r\n5\r\nhello\r\n5\r\nhello\r\n0\r\n\r\n";

        // Create a bidirectional mock that expects the exact write data
        let inner = make_bidirectional_mock(b"", response_data);

        let mut stream = HttpClientStream::new(inner, callback);

        // Use chaotic writing to stress test interim response handling
        write_chaotically(&mut stream, response_data).await.unwrap();

        // Callback should be called when chunked response is complete
        assert!(callback_called.load(Ordering::Relaxed));
        assert!(returned_stream.lock().unwrap().is_some());
    }

    #[test(tokio::test)]
    async fn test_interim_response_handling() {
        let callback_called = Arc::new(AtomicBool::new(false));
        let callback_called_clone = callback_called.clone();

        let returned_stream = Arc::new(std::sync::Mutex::new(None));
        let returned_stream_clone = returned_stream.clone();

        let callback = Box::new(move |_stream| {
            callback_called_clone.store(true, Ordering::Relaxed);
            *returned_stream_clone.lock().unwrap() = Some(());
        });

        // Simulate writing HTTP response with 100 Continue
        let response_data =
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

        // Create a bidirectional mock that expects the exact write data
        let inner = make_bidirectional_mock(b"", response_data);
        let mut stream = HttpClientStream::new(inner, callback);

        // Use chaotic writing to stress test interim response handling
        write_chaotically(&mut stream, response_data).await.unwrap();

        // Callback should be called when final response is complete
        assert!(callback_called.load(Ordering::Relaxed));
        assert!(returned_stream.lock().unwrap().is_some());
    }

    #[test(tokio::test)]
    async fn test_connection_close_response() {
        let callback_called = Arc::new(AtomicBool::new(false));
        let callback_called_clone = callback_called.clone();

        let callback = Box::new(move |_| {
            callback_called_clone.store(true, Ordering::Relaxed);
        });

        // Simulate writing HTTP response without content-length (read until EOF)
        let response_data = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello world";

        // Create a bidirectional mock that expects the exact write data
        let inner = make_bidirectional_mock(b"", response_data);
        let mut stream = HttpClientStream::new(inner, callback);

        // Use chaotic writing to stress test interim response handling
        write_chaotically(&mut stream, response_data).await.unwrap();

        // For responses without content-length, we transition to UntilEof state
        // Callback won't be called until connection actually closes (EOF)
        // For this test, we just verify the write was processed
        assert!(!callback_called.load(Ordering::Relaxed));
    }

    #[test(tokio::test)]
    async fn test_flush_passthrough() {
        let callback = Box::new(|_| {});

        // Create a bidirectional mock with empty data for flush test
        let inner = make_bidirectional_mock(b"", b"");
        let mut stream = HttpClientStream::new(inner, callback);

        // Flush should pass through to inner stream
        let result = stream.flush().await;
        assert!(result.is_ok());
    }

    #[test(tokio::test)]
    async fn test_shutdown_passthrough() {
        let callback = Box::new(|_| {});

        // Create a bidirectional mock with empty data for shutdown test
        let inner = make_bidirectional_mock(b"", b"");
        let mut stream = HttpClientStream::new(inner, callback);

        // Shutdown should pass through to inner stream
        let result = stream.shutdown().await;
        assert!(result.is_ok());
    }

    #[test(tokio::test)]
    async fn test_error_state_handling() {
        let callback_called = Arc::new(AtomicBool::new(false));
        let callback_called_clone = callback_called.clone();

        let callback = Box::new(move |_| {
            callback_called_clone.store(true, Ordering::Relaxed);
        });

        // Simulate writing invalid HTTP response (complete headers but invalid status line)
        let invalid_response = b"INVALID HTTP RESPONSE\r\n\r\n";

        // Create a bidirectional mock that doesn't expect any writes (error should prevent writes)
        let inner = make_bidirectional_mock(b"", b"");
        let mut stream = HttpClientStream::new(inner, callback);

        // Write should return error for invalid HTTP response
        let result = stream.write(invalid_response).await;

        // Should return error for invalid response
        assert!(result.is_err());

        // Callback should not be called for invalid response (no completion detected)
        assert!(!callback_called.load(Ordering::Relaxed));
    }
}
