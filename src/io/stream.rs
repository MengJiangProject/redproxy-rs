use crate::io::BufferedStream;
use std::any::Any;
use tokio::io::{AsyncRead, AsyncWrite};

/// A trait for type-erased async streams that supports Linux splice optimization
///
/// This trait extends the standard AsyncRead + AsyncWrite with capabilities for:
/// - Type erasure through Any trait (checking for TcpStream specialization)
/// - Raw file descriptor access for splice() operations on Linux
#[allow(dead_code)]
pub trait IOStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    fn as_any(&self) -> &dyn Any;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;

    /// Check if this stream supports Linux splice() operations (has raw file descriptor)
    #[cfg(target_os = "linux")]
    fn has_raw_fd(&self) -> bool;

    /// Convert this stream into an owned file descriptor for splice operations
    #[cfg(target_os = "linux")]
    fn into_owned_fd(self: Box<Self>) -> Option<std::os::unix::prelude::OwnedFd>;
}

impl<T> IOStream for T
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    // used to check if underlying stream is TcpStream, since specialization is unstable, we have to use dyn Any instead.
    // TODO: should use specialization when it's ready.
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }

    #[cfg(target_os = "linux")]
    fn has_raw_fd(&self) -> bool {
        self.as_any().is::<tokio::net::TcpStream>()
    }

    #[cfg(target_os = "linux")]
    fn into_owned_fd(self: Box<Self>) -> Option<std::os::unix::prelude::OwnedFd> {
        let stream = self.into_any().downcast::<tokio::net::TcpStream>().ok()?;
        let std_fd = stream.into_std().ok()?;
        Some(std_fd.into())
    }
}

/// Create a BufferedStream from any IOStream
pub fn make_buffered_stream<T: IOStream + 'static>(stream: T) -> BufferedStream {
    BufferedStream::new(Box::new(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite};

    // Mock stream for testing IOStream trait
    #[derive(Debug)]
    struct MockStream {
        data: Cursor<Vec<u8>>,
    }

    impl MockStream {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data: Cursor::new(data),
            }
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.data).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Write not supported",
            )))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    unsafe impl Send for MockStream {}
    unsafe impl Sync for MockStream {}
    impl Unpin for MockStream {}

    #[test]
    fn test_iostream_trait_object() {
        let mock = MockStream::new(b"test data".to_vec());

        // Test that we can create a trait object
        let stream: Box<dyn IOStream> = Box::new(mock);

        // Test that the trait object works
        let any_ref = stream.as_any();
        // Since we're behind a trait object, the type is actually the concrete MockStream
        // This test mainly verifies that the trait object can be created and as_any() works
        assert!(!any_ref.is::<tokio::net::TcpStream>());
    }

    #[test]
    fn test_iostream_into_any() {
        let mock = MockStream::new(b"test data".to_vec());
        let stream: Box<dyn IOStream> = Box::new(mock);

        let any_box = stream.into_any();
        let recovered = any_box.downcast::<MockStream>();
        assert!(recovered.is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_iostream_has_raw_fd() {
        let mock = MockStream::new(b"test data".to_vec());
        let stream: Box<dyn IOStream> = Box::new(mock);

        // MockStream should not have raw fd
        assert!(!stream.has_raw_fd());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_iostream_into_owned_fd() {
        let mock = MockStream::new(b"test data".to_vec());
        let stream: Box<dyn IOStream> = Box::new(mock);

        // MockStream should not be able to provide raw fd
        assert!(stream.into_owned_fd().is_none());
    }

    #[test]
    fn test_make_buffered_stream() {
        let mock = MockStream::new(b"test data".to_vec());
        let buffered = make_buffered_stream(mock);

        // Test that BufferedStream was created successfully
        assert_eq!(buffered.read_leftover_size(), 0);
        assert_eq!(buffered.write_pending_size(), 0);
        assert!(buffered.is_safe_to_unwrap());
    }

}
