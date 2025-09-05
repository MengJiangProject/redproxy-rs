use crate::io::{BidirectionalCopy, CopyOperation, IOStream};
use anyhow::Result as AnyhowResult;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite};

#[cfg(target_os = "linux")]
use std::os::unix::prelude::{AsRawFd, FromRawFd};

pub type IOBufStream = BufferedStream;

pin_project_lite::pin_project! {
    /// Custom buffered stream wrapper that provides fine-grained control over read and write buffers
    ///
    /// Unlike tokio's BufReader/BufWriter, this exposes internal buffers for:
    /// - Safe unwrapping for keep-alive connections
    /// - Linux splice() optimization when buffers are empty
    /// - Leftover data handling during protocol switching
    pub struct BufferedStream {
        #[pin]
        pub(crate) inner: Option<Box<dyn IOStream>>,
        pub(crate) read_buffer: Vec<u8>,
        pub(crate) write_buffer: Vec<u8>,
        pub(crate) read_pos: usize,   // Current read position in read_buffer
        pub(crate) write_pos: usize,  // Current write position in write_buffer (for flushing)
    }
}

impl BufferedStream {
    pub fn new(inner: Box<dyn IOStream>) -> Self {
        Self::with_capacity(inner, 8192) // Default 8KB buffers
    }

    pub fn with_capacity(inner: Box<dyn IOStream>, capacity: usize) -> Self {
        Self {
            inner: Some(inner),
            read_buffer: Vec::with_capacity(capacity),
            write_buffer: Vec::with_capacity(capacity),
            read_pos: 0,
            write_pos: 0,
        }
    }

    /// Create with existing leftover data from parsing
    pub fn with_leftover(inner: Box<dyn IOStream>, leftover: bytes::Bytes) -> Self {
        let mut stream = Self::new(inner);
        stream.read_buffer.extend_from_slice(&leftover);
        stream
    }

    /// Check if there's unread data in the read buffer
    pub fn has_read_leftover(&self) -> bool {
        self.read_pos < self.read_buffer.len()
    }

    /// Check if there's unwritten data in the write buffer
    pub fn has_write_pending(&self) -> bool {
        self.write_pos < self.write_buffer.len()
    }

    /// Check if it's safe to unwrap (no buffered data in either direction)
    pub fn is_safe_to_unwrap(&self) -> bool {
        !self.has_read_leftover() && !self.has_write_pending()
    }

    /// Get size of unread data in read buffer
    pub fn read_leftover_size(&self) -> usize {
        self.read_buffer.len() - self.read_pos
    }

    /// Get size of unwritten data in write buffer  
    pub fn write_pending_size(&self) -> usize {
        self.write_buffer.len() - self.write_pos
    }

    /// Try to unwrap to raw stream safely (fails if any buffered data exists)
    pub fn try_into_raw(self) -> AnyhowResult<Box<dyn IOStream>> {
        if !self.is_safe_to_unwrap() {
            return Err(anyhow::anyhow!("Cannot unwrap stream with buffered data"));
        }

        self.inner
            .ok_or_else(|| anyhow::anyhow!("Inner stream is temporarily unavailable"))
    }

    /// Unwrap to raw stream, returning any read leftover data separately
    /// Returns None if there's pending write data that would be lost
    pub fn into_raw_with_read_leftover(self) -> Option<(Box<dyn IOStream>, Option<bytes::Bytes>)> {
        if self.has_write_pending() {
            return None; // Cannot safely unwrap with pending writes
        }

        let leftover = if self.read_pos >= self.read_buffer.len() {
            None
        } else {
            Some(bytes::Bytes::copy_from_slice(
                &self.read_buffer[self.read_pos..],
            ))
        };
        Some((
            self.inner.expect("Inner stream should be present"),
            leftover,
        ))
    }

    /// Check if splice optimization is possible with another BufferedStream
    #[cfg(target_os = "linux")]
    pub fn can_splice_to(&self, dst: &BufferedStream) -> bool {
        // Can only splice if:
        // 1. Both streams are safe to unwrap (no buffered data)
        // 2. Both underlying streams have raw file descriptors
        self.is_safe_to_unwrap()
            && dst.is_safe_to_unwrap()
            && self.inner.as_ref().is_some_and(|s| s.has_raw_fd())
            && dst.inner.as_ref().is_some_and(|s| s.has_raw_fd())
    }

    /// Check if this stream can use splice operations
    #[cfg(target_os = "linux")]
    pub fn supports_splice(&self) -> bool {
        self.is_safe_to_unwrap() && self.inner.as_ref().is_some_and(|s| s.has_raw_fd())
    }

    /// Temporarily take the inner stream for operations that need ownership
    /// Returns an error if the stream is not safe to take or already taken
    pub(crate) fn take_inner(&mut self) -> std::io::Result<Box<dyn IOStream>> {
        if !self.is_safe_to_unwrap() {
            return Err(IoError::new(
                IoErrorKind::InvalidData,
                "Cannot take inner stream with buffered data",
            ));
        }

        self.inner
            .take()
            .ok_or_else(|| IoError::other("Inner stream is temporarily unavailable"))
    }

    /// Restore the inner stream after temporary operations
    pub(crate) fn restore_inner(&mut self, stream: Box<dyn IOStream>) -> std::io::Result<()> {
        if self.inner.is_some() {
            return Err(IoError::new(
                IoErrorKind::InvalidData,
                "Inner stream already present",
            ));
        }

        self.inner = Some(stream);
        Ok(())
    }

    /// Take raw file descriptor for splice operations, ensuring buffers are handled
    #[cfg(target_os = "linux")]
    pub fn take_rawfd(&mut self) -> std::io::Result<Option<std::os::unix::prelude::OwnedFd>> {
        if !self.is_safe_to_unwrap() {
            return Err(IoError::new(
                IoErrorKind::InvalidData,
                "Cannot take raw fd with buffered data",
            ));
        }

        let stream = self
            .inner
            .take()
            .ok_or_else(|| IoError::other("Inner stream is unavailable"))?;

        Ok(stream.into_owned_fd())
    }

    /// Restore stream from raw file descriptor after splice operations
    #[cfg(target_os = "linux")]
    pub fn restore_rawfd(&mut self, fd: std::os::unix::prelude::OwnedFd) -> std::io::Result<()> {
        if self.inner.is_some() {
            return Err(IoError::new(
                IoErrorKind::InvalidData,
                "Inner stream already present",
            ));
        }

        // Convert OwnedFd back to tokio TcpStream or appropriate stream type
        let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd.as_raw_fd()) };
        std_stream.set_nonblocking(true)?;
        let tokio_stream = tokio::net::TcpStream::from_std(std_stream)?;

        self.inner = Some(Box::new(tokio_stream));
        std::mem::forget(fd); // Prevent double-close
        Ok(())
    }

    /// Convert BufferedStream back to raw IOStream for keep-alive connections
    /// Only use this when absolutely necessary (like keep-alive handoff)
    pub fn into_raw_stream(self) -> std::io::Result<Box<dyn IOStream>> {
        if !self.is_safe_to_unwrap() {
            return Err(IoError::new(
                IoErrorKind::InvalidData,
                "Cannot unwrap BufferedStream with pending data",
            ));
        }

        self.inner
            .ok_or_else(|| IoError::new(IoErrorKind::InvalidData, "Inner stream unavailable"))
    }

    /// Read a line with size limit to prevent memory exhaustion
    /// Returns error if line exceeds max_size before finding newline
    /// Returns Ok(0) on EOF with no data read or partial line was read (incomplete line)
    pub async fn read_line_limited(
        &mut self,
        buf: &mut String,
        max_size: usize,
    ) -> std::io::Result<usize> {
        use tokio::io::AsyncBufReadExt;

        let mut total_read = 0;

        loop {
            // Fill internal buffer if needed
            let available = self.fill_buf().await?;
            if available.is_empty() {
                return Ok(total_read); // EOF
            }

            // Look for newline in available data
            if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
                let line_len = newline_pos + 1; // Include the newline

                // Check size limit before consuming
                if total_read + line_len > max_size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Line too long: {} bytes (max {})",
                            total_read + line_len,
                            max_size
                        ),
                    ));
                }

                // Safe to consume the line
                buf.push_str(&String::from_utf8_lossy(&available[..line_len]));
                self.consume(line_len);
                total_read += line_len;
                return Ok(total_read);
            } else {
                // No newline found, check if we would exceed limit if we consume all available data
                if total_read + available.len() > max_size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Line too long: >{} bytes (max {})",
                            total_read + available.len(),
                            max_size
                        ),
                    ));
                }

                // Consume all available data and continue reading
                buf.push_str(&String::from_utf8_lossy(available));
                let consumed = available.len();
                self.consume(consumed);
                total_read += consumed;
            }
        }
    }

    /// Create a copy operation builder (takes ownership)
    pub fn copy_to(self, dst: BufferedStream) -> CopyOperation {
        CopyOperation::new(self, dst)
    }

    /// Create a bidirectional copy operation (takes ownership)
    pub fn copy_bidirectional(stream_a: Self, stream_b: Self) -> BidirectionalCopy {
        BidirectionalCopy::new(stream_a, stream_b)
    }
}

impl AsyncRead for BufferedStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut this = self.project();

        // First, consume from read_buffer if available
        let available = this.read_buffer.len() - *this.read_pos;
        if available > 0 {
            let to_copy = std::cmp::min(available, buf.remaining());
            buf.put_slice(&this.read_buffer[*this.read_pos..*this.read_pos + to_copy]);
            *this.read_pos += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }

        // If buffer is empty, read directly from inner stream
        match this.inner.as_mut().as_pin_mut() {
            Some(inner) => inner.poll_read(cx, buf),
            None => std::task::Poll::Ready(Err(IoError::other("Inner stream is unavailable"))),
        }
    }
}

impl AsyncWrite for BufferedStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let mut this = self.project();

        // If write buffer would overflow, try to flush first
        if this.write_buffer.len() + buf.len() > this.write_buffer.capacity() {
            // Flush existing buffer directly
            while *this.write_pos < this.write_buffer.len() {
                let pending = &this.write_buffer[*this.write_pos..];
                match this.inner.as_mut().as_pin_mut() {
                    Some(inner) => match inner.poll_write(cx, pending) {
                        std::task::Poll::Ready(Ok(n)) => {
                            *this.write_pos += n;
                        }
                        std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                        std::task::Poll::Pending => return std::task::Poll::Pending,
                    },
                    None => {
                        return std::task::Poll::Ready(Err(IoError::other(
                            "Inner stream is unavailable",
                        )));
                    }
                }
            }
            // Reset buffer after flush
            this.write_buffer.clear();
            *this.write_pos = 0;
        }

        // Add to write buffer
        this.write_buffer.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut this = self.project();

        while *this.write_pos < this.write_buffer.len() {
            let pending = &this.write_buffer[*this.write_pos..];
            match this.inner.as_mut().as_pin_mut() {
                Some(inner) => match inner.poll_write(cx, pending) {
                    std::task::Poll::Ready(Ok(n)) => {
                        *this.write_pos += n;
                    }
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                },
                None => {
                    return std::task::Poll::Ready(Err(IoError::other(
                        "Inner stream is unavailable",
                    )));
                }
            }
        }

        // Reset buffer after complete flush
        this.write_buffer.clear();
        *this.write_pos = 0;

        match this.inner.as_mut().as_pin_mut() {
            Some(inner) => inner.poll_flush(cx),
            None => std::task::Poll::Ready(Err(IoError::other("Inner stream is unavailable"))),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut this = self.project();

        // Flush all buffered data first
        while *this.write_pos < this.write_buffer.len() {
            let pending = &this.write_buffer[*this.write_pos..];
            match this.inner.as_mut().as_pin_mut() {
                Some(inner) => match inner.poll_write(cx, pending) {
                    std::task::Poll::Ready(Ok(n)) => {
                        *this.write_pos += n;
                    }
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                },
                None => {
                    return std::task::Poll::Ready(Err(IoError::other(
                        "Inner stream is unavailable",
                    )));
                }
            }
        }

        // Then flush and shutdown the inner stream
        match this.inner.as_mut().as_pin_mut() {
            Some(mut inner) => match inner.as_mut().poll_flush(cx) {
                std::task::Poll::Ready(Ok(())) => inner.poll_shutdown(cx),
                other => other,
            },
            None => std::task::Poll::Ready(Err(IoError::other("Inner stream is unavailable"))),
        }
    }
}

impl AsyncBufRead for BufferedStream {
    fn poll_fill_buf(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<&[u8]>> {
        let mut this = self.project();

        // Check if we have unread data in the buffer
        if *this.read_pos < this.read_buffer.len() {
            return std::task::Poll::Ready(Ok(&this.read_buffer[*this.read_pos..]));
        }

        // Buffer is consumed, reset for new data
        this.read_buffer.clear();
        *this.read_pos = 0;

        // Ensure we have capacity for reading
        if this.read_buffer.capacity() == 0 {
            this.read_buffer.reserve(8192);
        }

        // Resize to full capacity for reading
        let capacity = this.read_buffer.capacity();
        this.read_buffer.resize(capacity, 0);

        let mut read_buf = tokio::io::ReadBuf::new(&mut this.read_buffer[..]);

        match this.inner.as_mut().as_pin_mut() {
            Some(inner) => match inner.poll_read(cx, &mut read_buf) {
                std::task::Poll::Ready(Ok(())) => {
                    let bytes_read = read_buf.filled().len();
                    this.read_buffer.truncate(bytes_read);
                }
                std::task::Poll::Ready(Err(e)) => {
                    this.read_buffer.clear();
                    return std::task::Poll::Ready(Err(e));
                }
                std::task::Poll::Pending => {
                    this.read_buffer.clear();
                    return std::task::Poll::Pending;
                }
            },
            None => {
                this.read_buffer.clear();
                return std::task::Poll::Ready(Err(IoError::other("Inner stream is unavailable")));
            }
        }

        std::task::Poll::Ready(Ok(&this.read_buffer[..]))
    }

    fn consume(self: std::pin::Pin<&mut Self>, amt: usize) {
        let this = self.project();
        let available = this.read_buffer.len() - *this.read_pos;
        let to_consume = std::cmp::min(amt, available);
        *this.read_pos += to_consume;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite};

    // Mock stream for testing
    #[derive(Debug)]
    struct MockStream {
        data: Cursor<Vec<u8>>,
        write_calls: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl MockStream {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data: Cursor::new(data),
                write_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        #[allow(dead_code)]
        fn get_write_calls(&self) -> Vec<Vec<u8>> {
            self.write_calls.lock().unwrap().clone()
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
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            self.write_calls.lock().unwrap().push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
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
    fn test_buffered_stream_new() {
        let mock = MockStream::new(b"test data".to_vec());
        let stream = BufferedStream::new(Box::new(mock));

        assert_eq!(stream.read_leftover_size(), 0);
        assert_eq!(stream.write_pending_size(), 0);
        assert!(stream.is_safe_to_unwrap());
    }

    #[test]
    fn test_buffered_stream_with_capacity() {
        let mock = MockStream::new(b"test data".to_vec());
        let stream = BufferedStream::with_capacity(Box::new(mock), 4096);

        assert_eq!(stream.read_buffer.capacity(), 4096);
        assert_eq!(stream.write_buffer.capacity(), 4096);
    }

    #[test]
    fn test_buffered_stream_with_leftover() {
        let mock = MockStream::new(b"test data".to_vec());
        let leftover = bytes::Bytes::from("leftover");
        let stream = BufferedStream::with_leftover(Box::new(mock), leftover);

        assert_eq!(stream.read_leftover_size(), 8); // "leftover" is 8 bytes
        assert!(!stream.is_safe_to_unwrap());
        assert!(stream.has_read_leftover());
    }

    #[test]
    fn test_buffer_state_checks() {
        let mock = MockStream::new(b"test data".to_vec());
        let mut stream = BufferedStream::new(Box::new(mock));

        // Initially should be safe to unwrap
        assert!(stream.is_safe_to_unwrap());
        assert!(!stream.has_read_leftover());
        assert!(!stream.has_write_pending());

        // Add some read data
        stream.read_buffer.extend_from_slice(b"test");
        assert!(!stream.is_safe_to_unwrap());
        assert!(stream.has_read_leftover());
        assert_eq!(stream.read_leftover_size(), 4);

        // Add some write data
        stream.write_buffer.extend_from_slice(b"write");
        assert!(stream.has_write_pending());
        assert_eq!(stream.write_pending_size(), 5);
    }

    #[test]
    fn test_try_into_raw_with_buffered_data() {
        let mock = MockStream::new(b"test data".to_vec());
        let mut stream = BufferedStream::new(Box::new(mock));

        // Add buffered data
        stream.read_buffer.extend_from_slice(b"buffered");

        // Should fail to unwrap
        let result = stream.try_into_raw();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("buffered data"));
        }
    }

    #[test]
    fn test_try_into_raw_success() {
        let mock = MockStream::new(b"test data".to_vec());
        let stream = BufferedStream::new(Box::new(mock));

        // Should succeed when no buffered data
        let result = stream.try_into_raw();
        assert!(result.is_ok());
    }

    #[test]
    fn test_into_raw_with_read_leftover() {
        let mock = MockStream::new(b"test data".to_vec());
        let mut stream = BufferedStream::new(Box::new(mock));

        // Add read leftover
        stream.read_buffer.extend_from_slice(b"leftover");

        let result = stream.into_raw_with_read_leftover();
        assert!(result.is_some());

        let (_, leftover) = result.unwrap();
        assert!(leftover.is_some());
        assert_eq!(&leftover.unwrap()[..], b"leftover");
    }

    #[test]
    fn test_into_raw_with_write_pending() {
        let mock = MockStream::new(b"test data".to_vec());
        let mut stream = BufferedStream::new(Box::new(mock));

        // Add write pending data
        stream.write_buffer.extend_from_slice(b"pending");

        let result = stream.into_raw_with_read_leftover();
        assert!(result.is_none()); // Should fail with pending writes
    }

    #[tokio::test]
    async fn test_read_line_limited_normal_case() {
        let data = "line1\nline2\nline3\n";
        let mock = MockStream::new(data.as_bytes().to_vec());
        let mut stream = BufferedStream::new(Box::new(mock));

        let mut line = String::new();
        let bytes_read = stream.read_line_limited(&mut line, 1000).await.unwrap();

        assert_eq!(bytes_read, 6); // "line1\n"
        assert_eq!(line, "line1\n");
    }

    #[tokio::test]
    async fn test_read_line_limited_exceeds_limit() {
        let long_line = format!("{}\n", "A".repeat(2000));
        let mock = MockStream::new(long_line.as_bytes().to_vec());
        let mut stream = BufferedStream::new(Box::new(mock));

        let mut line = String::new();
        let result = stream.read_line_limited(&mut line, 1000).await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("Line too long"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_splice_support_checks() {
        let mock = MockStream::new(b"test data".to_vec());
        let stream = BufferedStream::new(Box::new(mock));

        // MockStream doesn't support splice (no raw fd)
        assert!(!stream.supports_splice());

        let mock2 = MockStream::new(b"test data 2".to_vec());
        let stream2 = BufferedStream::new(Box::new(mock2));

        assert!(!stream.can_splice_to(&stream2));
    }

    #[test]
    fn test_take_and_restore_inner() {
        let mock = MockStream::new(b"test data".to_vec());
        let mut stream = BufferedStream::new(Box::new(mock));

        // Should be able to take inner when safe
        let inner = stream.take_inner().unwrap();
        assert!(stream.inner.is_none());

        // Should be able to restore
        stream.restore_inner(inner).unwrap();
        assert!(stream.inner.is_some());
    }

    #[test]
    fn test_take_inner_with_buffered_data() {
        let mock = MockStream::new(b"test data".to_vec());
        let mut stream = BufferedStream::new(Box::new(mock));

        // Add buffered data
        stream.read_buffer.extend_from_slice(b"buffered");

        // Should fail to take inner
        let result = stream.take_inner();
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        }
    }
}
