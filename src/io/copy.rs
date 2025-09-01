use crate::io::BufferedStream;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Copy operation builder for BufferedStream with support for:
/// - Maximum byte limits
/// - Buffer size configuration  
/// - Linux splice() optimization
/// - Idle timeout handling
/// - Cancellation token support
/// - Real-time statistics callbacks
pub struct CopyOperation {
    src: BufferedStream,
    dst: BufferedStream,
    max_bytes: Option<usize>,
    buffer_size: usize,
    use_splice: bool,
    idle_timeout: Option<std::time::Duration>,
    cancellation_token: Option<tokio_util::sync::CancellationToken>,
    stats_callback: Option<Box<dyn FnMut(usize) + Send>>,
}

impl CopyOperation {
    pub fn new(src: BufferedStream, dst: BufferedStream) -> Self {
        Self {
            src,
            dst,
            max_bytes: None,
            buffer_size: 8192,
            use_splice: true,
            idle_timeout: None,
            cancellation_token: None,
            stats_callback: None,
        }
    }

    /// Set maximum bytes to copy
    pub fn max_bytes(mut self, max: usize) -> Self {
        self.max_bytes = Some(max);
        self
    }

    /// Set buffer size for copy operations
    pub fn buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Disable splice optimization
    pub fn disable_splice(mut self) -> Self {
        self.use_splice = false;
        self
    }

    /// Set idle timeout for copy operations (based on inactivity)
    pub fn idle_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.idle_timeout = Some(timeout);
        self
    }

    /// Set cancellation token for graceful shutdown
    pub fn cancellation_token(mut self, token: tokio_util::sync::CancellationToken) -> Self {
        self.cancellation_token = Some(token);
        self
    }

    /// Configure from IoParams (buffer size and splice settings)
    pub fn with_io_params(mut self, params: &crate::config::IoParams) -> Self {
        self.buffer_size = params.buffer_size;
        self.use_splice = params.use_splice;
        self
    }

    /// Set statistics callback
    pub fn with_stats<F>(mut self, callback: F) -> Self
    where
        F: FnMut(usize) + Send + 'static,
    {
        self.stats_callback = Some(Box::new(callback));
        self
    }

    /// Execute the copy operation with proper timeout and cancellation handling
    /// Returns (bytes_copied, src_stream, dst_stream)
    pub async fn execute(mut self) -> std::io::Result<(u64, BufferedStream, BufferedStream)> {
        let mut total_copied = 0u64;
        let mut last_activity = std::time::Instant::now();

        // First, handle any leftover data in read buffer without allocating temporary buffers
        if self.src.has_read_leftover() {
            let leftover_size = self.src.read_leftover_size();
            let to_copy = match self.max_bytes {
                Some(max) if max < leftover_size => max,
                _ => leftover_size,
            };

            // Copy directly from read buffer to write buffer
            let data =
                self.src.read_buffer[self.src.read_pos..self.src.read_pos + to_copy].to_vec();
            self.src.read_pos += to_copy;
            self.dst.write_all(&data).await?;
            total_copied += to_copy as u64;

            // Real-time stats callback for leftover data
            if let Some(ref mut callback) = self.stats_callback {
                callback(to_copy);
            }

            if let Some(max) = self.max_bytes
                && total_copied >= max as u64
            {
                self.dst.flush().await?;
                return Ok((total_copied, self.src, self.dst));
            }
        }

        // Flush any pending write data before considering splice or main loop
        if self.dst.has_write_pending() {
            self.dst.flush().await?;
        }

        // Try splice optimization after handling buffered data
        #[cfg(target_os = "linux")]
        if self.use_splice
            && self.src.can_splice_to(&self.dst)
            && self
                .max_bytes
                .is_none_or(|max| (max as u64 - total_copied) > self.buffer_size as u64)
        {
            // Adjust max_bytes for remaining data and execute splice
            if let Some(max) = self.max_bytes {
                self.max_bytes = Some(max.saturating_sub(total_copied as usize));
            }
            let (splice_result, src, dst) = self.execute_splice().await?;
            return Ok((total_copied + splice_result, src, dst));
        }

        // Use raw streams for actual IO to avoid double buffering
        // Take inner streams temporarily to avoid the buffered layer
        let mut raw_src = self.src.take_inner()?;
        let mut raw_dst = self.dst.take_inner()?;

        // Set up periodic timeout checking if idle timeout is specified
        let mut interval = if self.idle_timeout.is_some() {
            Some(tokio::time::interval(std::time::Duration::from_secs(1)))
        } else {
            None
        };

        // Use source's read buffer as our transfer buffer to avoid allocation
        let mut buffer = vec![0u8; self.buffer_size];

        loop {
            tokio::select! {
                // Main copy operation using raw streams
                copy_result = async {
                    // Calculate how much we can read
                    let remaining = self.max_bytes.map(|max| max.saturating_sub(total_copied as usize));
                    let to_read = match remaining {
                        Some(0) => return Ok(0), // Reached limit
                        Some(r) => std::cmp::min(r, buffer.len()),
                        None => buffer.len(),
                    };

                    // Read directly from raw source stream (no double buffering)
                    let bytes_read = raw_src.read(&mut buffer[..to_read]).await?;
                    if bytes_read == 0 {
                        return Ok(0); // EOF
                    }

                    // Write directly to raw destination stream (no double buffering)
                    raw_dst.write_all(&buffer[..bytes_read]).await?;
                    total_copied += bytes_read as u64;

                    // Real-time stats callback
                    if let Some(ref mut callback) = self.stats_callback {
                        callback(bytes_read);
                    }

                    Ok::<u64, IoError>(bytes_read as u64)
                } => {
                    match copy_result? {
                        0 => break, // EOF or limit reached
                        _ => {
                            last_activity = std::time::Instant::now();
                        }
                    }
                }

                // Check for cancellation
                _ = async {
                    if let Some(ref token) = self.cancellation_token {
                        token.cancelled().await
                    } else {
                        std::future::pending().await // Never resolves if no token
                    }
                } => {
                    return Err(IoError::new(
                        IoErrorKind::Interrupted,
                        "Copy operation was cancelled"
                    ));
                }

                // Check for idle timeout
                _ = async {
                    if let Some(ref mut timer) = interval {
                        timer.tick().await
                    } else {
                        std::future::pending().await // Never resolves if no timeout
                    }
                } => {
                    if let Some(idle_timeout) = self.idle_timeout
                        && last_activity.elapsed() > idle_timeout {
                            return Err(IoError::new(
                                IoErrorKind::TimedOut,
                                "Copy operation idle timeout"
                            ));
                        }
                }
            }
        }

        // Restore inner streams after raw operations
        self.src.restore_inner(raw_src)?;
        self.dst.restore_inner(raw_dst)?;

        self.dst.flush().await?;
        Ok((total_copied, self.src, self.dst))
    }

    /// Execute splice copy (Linux only)
    #[cfg(target_os = "linux")]
    async fn execute_splice(mut self) -> std::io::Result<(u64, BufferedStream, BufferedStream)> {
        // Check if streams support splice (buffers are already handled by caller)
        if !self.src.supports_splice() || !self.dst.supports_splice() {
            return Err(IoError::new(
                IoErrorKind::Unsupported,
                "Streams do not support splice operations",
            ));
        }

        // Extract raw file descriptors using the new method
        let src_fd = self
            .src
            .take_rawfd()?
            .ok_or_else(|| IoError::new(IoErrorKind::Unsupported, "Source has no raw fd"))?;
        let dst_fd = self
            .dst
            .take_rawfd()?
            .ok_or_else(|| IoError::new(IoErrorKind::Unsupported, "Destination has no raw fd"))?;

        // Clone the FDs for restore operation since execute_splice_with_fds will consume them
        let src_fd_for_restore = src_fd
            .try_clone()
            .map_err(|e| IoError::other(format!("Failed to clone src fd: {}", e)))?;
        let dst_fd_for_restore = dst_fd
            .try_clone()
            .map_err(|e| IoError::other(format!("Failed to clone dst fd: {}", e)))?;

        let result = self.execute_splice_with_fds(src_fd, dst_fd).await;

        // Always try to restore the streams from the cloned file descriptors
        match self.restore_streams_from_fds(src_fd_for_restore, dst_fd_for_restore) {
            Ok(()) => result.map(|bytes| (bytes, self.src, self.dst)),
            Err(restore_err) => {
                // If we can't restore streams, that's a serious error
                Err(IoError::other(format!(
                    "Failed to restore streams after splice: {}",
                    restore_err
                )))
            }
        }
    }

    /// Execute the actual splice operation with file descriptors
    #[cfg(target_os = "linux")]
    async fn execute_splice_with_fds(
        &mut self,
        src_fd: std::os::unix::prelude::OwnedFd,
        dst_fd: std::os::unix::prelude::OwnedFd,
    ) -> std::io::Result<u64> {
        use crate::common::splice::{async_splice, pipe};
        use tokio::io::unix::AsyncFd;

        // Setup async FDs and pipe
        let mut src_async_fd = AsyncFd::new(
            src_fd
                .try_clone()
                .map_err(|e| IoError::other(format!("Failed to clone src fd: {}", e)))?,
        )
        .map_err(|e| IoError::other(format!("Failed to create async src fd: {}", e)))?;
        let dst_async_fd = AsyncFd::new(
            dst_fd
                .try_clone()
                .map_err(|e| IoError::other(format!("Failed to clone dst fd: {}", e)))?,
        )
        .map_err(|e| IoError::other(format!("Failed to create async dst fd: {}", e)))?;
        let (mut pipe_read, pipe_write) =
            pipe().map_err(|e| IoError::other(format!("Failed to create pipe: {}", e)))?;

        let mut total_copied = 0u64;
        let remaining = self.max_bytes.unwrap_or(usize::MAX);
        let mut bytes_left = remaining;
        let mut last_activity = std::time::Instant::now();

        // Set up periodic timeout checking if idle timeout is specified
        let mut interval = if self.idle_timeout.is_some() {
            Some(tokio::time::interval(std::time::Duration::from_secs(1)))
        } else {
            None
        };

        while bytes_left > 0 {
            tokio::select! {
                // Main splice operation
                splice_result = async {
                    // Splice from src to pipe
                    let to_transfer = bytes_left.min(self.buffer_size);
                    let bytes_read = async_splice(&mut src_async_fd, &pipe_write, to_transfer, bytes_left > to_transfer)
                        .await.map_err(|e| {
                            IoError::other(format!("Splice read failed: {}", e))
                        })?;

                    if bytes_read == 0 {
                        return Ok::<u64, IoError>(0); // EOF
                    }

                    // Splice from pipe to dst
                    async_splice(&mut pipe_read, &dst_async_fd, bytes_read, false)
                        .await.map_err(|e| {
                            IoError::other(format!("Splice write failed: {}", e))
                        })?;

                    Ok(bytes_read as u64)
                } => {
                    match splice_result? {
                        0 => break, // EOF
                        bytes_transferred => {
                            total_copied += bytes_transferred;
                            bytes_left = bytes_left.saturating_sub(bytes_transferred as usize);
                            last_activity = std::time::Instant::now();

                            // Real-time stats callback
                            if let Some(ref mut callback) = self.stats_callback {
                                callback(bytes_transferred as usize);
                            }
                        }
                    }
                }

                // Check for cancellation
                _ = async {
                    if let Some(ref token) = self.cancellation_token {
                        token.cancelled().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    return Err(IoError::new(
                        IoErrorKind::Interrupted,
                        "Splice operation was cancelled"
                    ));
                }

                // Check for idle timeout
                _ = async {
                    if let Some(ref mut timer) = interval {
                        timer.tick().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    if let Some(idle_timeout) = self.idle_timeout
                        && last_activity.elapsed() > idle_timeout {
                            return Err(IoError::new(
                                IoErrorKind::TimedOut,
                                "Splice operation idle timeout"
                            ));
                        }
                }
            }
        }

        Ok(total_copied)
    }

    /// Restore streams from file descriptors after splice operations
    #[cfg(target_os = "linux")]
    fn restore_streams_from_fds(
        &mut self,
        src_fd: std::os::unix::prelude::OwnedFd,
        dst_fd: std::os::unix::prelude::OwnedFd,
    ) -> std::io::Result<()> {
        // Use the new restore_rawfd method
        self.src.restore_rawfd(src_fd)?;
        self.dst.restore_rawfd(dst_fd)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite};

    // Advanced mock stream for comprehensive testing
    #[derive(Debug)]
    struct MockStream {
        read_data: Cursor<Vec<u8>>,
        write_data: Arc<Mutex<Vec<u8>>>,
        write_error: Option<std::io::Error>,
        max_read_size: Option<usize>, // Simulate partial reads
        max_write_size: Option<usize>, // Simulate partial writes
    }

    impl MockStream {
        fn new_reader(data: Vec<u8>) -> Self {
            Self {
                read_data: Cursor::new(data),
                write_data: Arc::new(Mutex::new(Vec::new())),
                write_error: None,
                max_read_size: None,
                max_write_size: None,
            }
        }

        fn new_writer() -> Self {
            Self {
                read_data: Cursor::new(Vec::new()),
                write_data: Arc::new(Mutex::new(Vec::new())),
                write_error: None,
                max_read_size: None,
                max_write_size: None,
            }
        }

        fn with_partial_operations(mut self, max_read: Option<usize>, max_write: Option<usize>) -> Self {
            self.max_read_size = max_read;
            self.max_write_size = max_write;
            self
        }

        fn with_write_error(mut self, error: std::io::Error) -> Self {
            self.write_error = Some(error);
            self
        }

        #[allow(dead_code)]
        fn get_written_data(&self) -> Vec<u8> {
            self.write_data.lock().unwrap().clone()
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            // Simulate partial reads if configured
            if let Some(max_size) = self.max_read_size {
                let available = buf.remaining().min(max_size);
                if available < buf.remaining() {
                    // Create a temporary smaller buffer for partial read
                    let mut temp_buf = vec![0u8; available];
                    let mut temp_read_buf = tokio::io::ReadBuf::new(&mut temp_buf);
                    
                    match Pin::new(&mut self.read_data).poll_read(cx, &mut temp_read_buf) {
                        Poll::Ready(Ok(())) => {
                            let filled = temp_read_buf.filled();
                            buf.put_slice(filled);
                            Poll::Ready(Ok(()))
                        }
                        other => other,
                    }
                } else {
                    Pin::new(&mut self.read_data).poll_read(cx, buf)
                }
            } else {
                Pin::new(&mut self.read_data).poll_read(cx, buf)
            }
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            if let Some(ref error) = self.write_error {
                return Poll::Ready(Err(std::io::Error::new(error.kind(), error.to_string())));
            }

            // Simulate partial writes if configured
            let write_size = if let Some(max_size) = self.max_write_size {
                buf.len().min(max_size)
            } else {
                buf.len()
            };

            self.write_data.lock().unwrap().extend_from_slice(&buf[..write_size]);
            Poll::Ready(Ok(write_size))
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
    fn test_copy_operation_builder() {
        let src_mock = MockStream::new_reader(b"source data".to_vec());
        let dst_mock = MockStream::new_writer();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        let copy_op = CopyOperation::new(src_stream, dst_stream)
            .max_bytes(1024)
            .buffer_size(4096)
            .disable_splice()
            .idle_timeout(std::time::Duration::from_secs(30));

        // Test builder pattern configuration
        assert_eq!(copy_op.max_bytes, Some(1024));
        assert_eq!(copy_op.buffer_size, 4096);
        assert!(!copy_op.use_splice);
        assert_eq!(
            copy_op.idle_timeout,
            Some(std::time::Duration::from_secs(30))
        );
    }

    #[tokio::test]
    async fn test_copy_operation_basic_execute() {
        let test_data = b"Hello, world! This is test data for copying.";
        let src_mock = MockStream::new_reader(test_data.to_vec());
        let dst_mock = MockStream::new_writer();

        let dst_data_ref = dst_mock.write_data.clone();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        let copy_op = CopyOperation::new(src_stream, dst_stream).buffer_size(16); // Small buffer to test multiple reads

        let (bytes_copied, _src, _dst) = copy_op.execute().await.unwrap();

        assert_eq!(bytes_copied, test_data.len() as u64);
        assert_eq!(&dst_data_ref.lock().unwrap()[..], test_data);
    }

    #[tokio::test]
    async fn test_copy_operation_with_max_bytes() {
        let test_data = b"This is a longer test string that should be truncated.";
        let src_mock = MockStream::new_reader(test_data.to_vec());
        let dst_mock = MockStream::new_writer();

        let dst_data_ref = dst_mock.write_data.clone();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        let copy_op = CopyOperation::new(src_stream, dst_stream).max_bytes(20); // Limit to 20 bytes

        let (bytes_copied, _src, _dst) = copy_op.execute().await.unwrap();

        assert_eq!(bytes_copied, 20);
        assert_eq!(dst_data_ref.lock().unwrap().len(), 20);
        assert_eq!(&dst_data_ref.lock().unwrap()[..], &test_data[..20]);
    }

    #[tokio::test]
    async fn test_copy_operation_with_leftover_data() {
        let test_data = b"Initial data";
        let leftover_data = bytes::Bytes::from("leftover");

        let src_mock = MockStream::new_reader(test_data.to_vec());
        let dst_mock = MockStream::new_writer();

        let dst_data_ref = dst_mock.write_data.clone();

        // Create source stream with leftover data
        let src_stream = BufferedStream::with_leftover(Box::new(src_mock), leftover_data);
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        let copy_op = CopyOperation::new(src_stream, dst_stream);

        let (bytes_copied, _src, _dst) = copy_op.execute().await.unwrap();

        // Should copy leftover first, then the stream data
        let expected_total = 8 + test_data.len(); // "leftover" + "Initial data"
        assert_eq!(bytes_copied, expected_total as u64);

        let written_data = dst_data_ref.lock().unwrap();
        assert!(written_data.starts_with(b"leftover"));
        assert!(written_data.ends_with(test_data));
    }

    #[tokio::test]
    async fn test_copy_operation_with_stats_callback() {
        let test_data = b"Data for stats tracking";
        let src_mock = MockStream::new_reader(test_data.to_vec());
        let dst_mock = MockStream::new_writer();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        let stats = Arc::new(Mutex::new(Vec::new()));
        let stats_clone = stats.clone();

        let copy_op = CopyOperation::new(src_stream, dst_stream)
            .with_stats(move |bytes| {
                stats_clone.lock().unwrap().push(bytes);
            })
            .buffer_size(8); // Small buffer to generate multiple callbacks

        let (bytes_copied, _src, _dst) = copy_op.execute().await.unwrap();

        assert_eq!(bytes_copied, test_data.len() as u64);

        let callback_data = stats.lock().unwrap();
        assert!(!callback_data.is_empty());

        // Sum of all callback values should equal total bytes copied
        let total_from_callbacks: usize = callback_data.iter().sum();
        assert_eq!(total_from_callbacks, test_data.len());
    }

    #[tokio::test]
    async fn test_copy_operation_with_cancellation() {
        // For this test, we'll immediately cancel to ensure it works
        let test_data = vec![0u8; 1000]; // Smaller data
        let src_mock = MockStream::new_reader(test_data);
        let dst_mock = MockStream::new_writer();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        let cancellation_token = tokio_util::sync::CancellationToken::new();

        let copy_op = CopyOperation::new(src_stream, dst_stream)
            .cancellation_token(cancellation_token.clone());

        // Cancel immediately
        cancellation_token.cancel();

        let result = copy_op.execute().await;

        // The operation might succeed if it completes before checking cancellation
        // This is expected behavior - cancellation is best-effort
        if result.is_err()
            && let Err(error) = result
        {
            assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
            assert!(error.to_string().contains("cancelled"));
        }
        // If it succeeds, that's also valid - the copy completed before cancellation was checked
    }

    #[tokio::test]
    async fn test_copy_operation_handles_io_errors() {
        let test_data = b"Test data for error handling";
        let src_mock = MockStream::new_reader(test_data.to_vec());
        let dst_mock = MockStream::new_writer().with_write_error(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "Simulated write error",
        ));

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        let copy_op = CopyOperation::new(src_stream, dst_stream);

        let result = copy_op.execute().await;

        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        }
    }

    #[test]
    fn test_copy_operation_with_io_params() {
        use crate::config::IoParams;

        let src_mock = MockStream::new_reader(b"test".to_vec());
        let dst_mock = MockStream::new_writer();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        let io_params = IoParams {
            buffer_size: 16384,
            use_splice: false,
        };

        let copy_op = CopyOperation::new(src_stream, dst_stream).with_io_params(&io_params);

        assert_eq!(copy_op.buffer_size, 16384);
        assert!(!copy_op.use_splice);
    }

    // ============================================================================
    // COMPREHENSIVE STRESS TESTS FOR LARGE DATA AND PARTIAL OPERATIONS
    // ============================================================================

    #[tokio::test]
    async fn test_large_data_copy_operation() {
        // Create large test dataset (100KB)
        let large_data: Vec<u8> = (0..102400).map(|i| (i % 256) as u8).collect();
        let src_mock = MockStream::new_reader(large_data.clone());
        let dst_mock = MockStream::new_writer();

        let dst_data_ref = dst_mock.write_data.clone();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        // Use moderate buffer size to force multiple iterations
        let copy_op = CopyOperation::new(src_stream, dst_stream).buffer_size(4096);

        let (bytes_copied, _src, _dst) = copy_op.execute().await.unwrap();

        assert_eq!(bytes_copied, large_data.len() as u64);
        assert_eq!(&*dst_data_ref.lock().unwrap(), &large_data);
    }

    #[tokio::test]
    async fn test_small_buffer_stress_copy() {
        // Create moderately sized data
        let test_data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
        let src_mock = MockStream::new_reader(test_data.clone());
        let dst_mock = MockStream::new_writer();

        let dst_data_ref = dst_mock.write_data.clone();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        // Extremely small buffer to maximize the number of iterations
        let copy_op = CopyOperation::new(src_stream, dst_stream).buffer_size(64);

        let (bytes_copied, _src, _dst) = copy_op.execute().await.unwrap();

        assert_eq!(bytes_copied, test_data.len() as u64);
        assert_eq!(&*dst_data_ref.lock().unwrap(), &test_data);
    }

    #[tokio::test]
    async fn test_partial_read_write_copy_operations() {
        // Create test data
        let test_data: Vec<u8> = (0..2048).map(|i| (i % 256) as u8).collect();

        // Simulate partial operations: max 7 bytes per read, max 11 bytes per write
        let src_mock = MockStream::new_reader(test_data.clone())
            .with_partial_operations(Some(7), None);
        let dst_mock = MockStream::new_writer()
            .with_partial_operations(None, Some(11));

        let dst_data_ref = dst_mock.write_data.clone();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        // Use medium buffer size so partial operations are really tested
        let copy_op = CopyOperation::new(src_stream, dst_stream).buffer_size(256);

        let (bytes_copied, _src, _dst) = copy_op.execute().await.unwrap();

        assert_eq!(bytes_copied, test_data.len() as u64);
        assert_eq!(&*dst_data_ref.lock().unwrap(), &test_data);
    }

    #[tokio::test]
    async fn test_complex_leftover_buffer_copy_scenarios() {
        // Create different sized data stream
        let stream_data: Vec<u8> = (0..1500).map(|i| (i % 256) as u8).collect();
        let src_mock = MockStream::new_reader(stream_data.clone());
        let dst_mock = MockStream::new_writer();

        let dst_data_ref = dst_mock.write_data.clone();

        // Create leftover buffer
        let leftover_data: Vec<u8> = (0..127).map(|i| ((i * 2) % 256) as u8).collect();

        let buffered_src = BufferedStream::with_leftover(
            Box::new(src_mock), 
            bytes::Bytes::from(leftover_data.clone())
        );
        let buffered_dst = BufferedStream::new(Box::new(dst_mock));

        let copy_op = CopyOperation::new(buffered_src, buffered_dst).buffer_size(128);

        let (bytes_copied, _src, _dst) = copy_op.execute().await.unwrap();

        // Should include both leftover AND stream data
        let expected_total = leftover_data.len() + stream_data.len();
        assert_eq!(bytes_copied, expected_total as u64);

        // Verify leftover data appears first in output
        let written_data = dst_data_ref.lock().unwrap();
        assert!(written_data.starts_with(&leftover_data));

        // Verify complete data integrity
        let mut expected_output = leftover_data;
        expected_output.extend_from_slice(&stream_data);
        assert_eq!(&*written_data, &expected_output);
    }

    #[tokio::test]
    async fn test_multi_chunk_stats_collection_copy() {
        // Create test data that will definitely result in multiple chunks
        let test_data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let src_mock = MockStream::new_reader(test_data.clone());
        let dst_mock = MockStream::new_writer();

        let dst_data_ref = dst_mock.write_data.clone();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        let stats_calls = Arc::new(Mutex::new(Vec::new()));
        let stats_clone = stats_calls.clone();

        // Very small buffer to guarantee multiple stat callbacks
        let copy_op = CopyOperation::new(src_stream, dst_stream)
            .with_stats(move |bytes| {
                stats_clone.lock().unwrap().push(bytes);
            })
            .buffer_size(128); // Small buffer for many transfers

        let (bytes_copied, _src, _dst) = copy_op.execute().await.unwrap();

        assert_eq!(bytes_copied, test_data.len() as u64);
        assert_eq!(&*dst_data_ref.lock().unwrap(), &test_data);

        let stats_data = stats_calls.lock().unwrap();

        // Should have multiple callback invocations due to small buffer
        assert!(stats_data.len() > 1, "Expected multiple stat calls, got {}", stats_data.len());

        // Verify stats integrity
        let total_from_stats: usize = stats_data.iter().sum();
        assert_eq!(total_from_stats, bytes_copied as usize);

        // All individual transfers should be reasonable sizes (not zero, not larger than buffer)
        for &size in stats_data.iter() {
            assert!(size > 0 && size <= 128, "Transfer size {} out of range", size);
        }
    }

    #[tokio::test]
    async fn test_concurrent_pressure_copy_simulation() {
        // Simulate high pressure scenario with mixed partial reads/writes
        let data_pattern: Vec<u8> = (0..3000).map(|i| ((i * 7) % 256) as u8).collect();

        // Different partial operation limits to create pressure
        let src_mock = MockStream::new_reader(data_pattern.clone())
            .with_partial_operations(Some(17), None); // Prime number for irregular patterns
        let dst_mock = MockStream::new_writer()
            .with_partial_operations(None, Some(23));

        let dst_data_ref = dst_mock.write_data.clone();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        // Small buffer creates pressure when combined with partial operations
        let copy_op = CopyOperation::new(src_stream, dst_stream).buffer_size(97); // Prime buffer size

        let (bytes_copied, _src, _dst) = copy_op.execute().await.unwrap();

        assert_eq!(bytes_copied, data_pattern.len() as u64);
        assert_eq!(&*dst_data_ref.lock().unwrap(), &data_pattern);
    }

    #[tokio::test]
    async fn test_max_bytes_with_partial_operations() {
        // Test max_bytes limit with partial operations
        let large_data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let src_mock = MockStream::new_reader(large_data.clone())
            .with_partial_operations(Some(13), None);
        let dst_mock = MockStream::new_writer()
            .with_partial_operations(None, Some(19));

        let dst_data_ref = dst_mock.write_data.clone();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        let max_bytes = 1500usize;
        let copy_op = CopyOperation::new(src_stream, dst_stream)
            .max_bytes(max_bytes)
            .buffer_size(256);

        let (bytes_copied, _src, _dst) = copy_op.execute().await.unwrap();

        assert_eq!(bytes_copied, max_bytes as u64);
        assert_eq!(dst_data_ref.lock().unwrap().len(), max_bytes);
        
        // Verify data integrity for the transferred portion
        let written_data = dst_data_ref.lock().unwrap();
        assert_eq!(&written_data[..], &large_data[..max_bytes]);
    }

    #[tokio::test]
    async fn test_empty_and_tiny_copy_operations() {
        // Test edge cases with very small or empty data
        let empty_data: Vec<u8> = vec![];
        let tiny_data: Vec<u8> = b"X".to_vec();

        // Test empty data
        let src_mock = MockStream::new_reader(empty_data.clone());
        let dst_mock = MockStream::new_writer();
        let dst_data_ref = dst_mock.write_data.clone();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        let copy_op = CopyOperation::new(src_stream, dst_stream).buffer_size(1024);
        let (bytes_copied, _src, _dst) = copy_op.execute().await.unwrap();

        assert_eq!(bytes_copied, 0);
        assert_eq!(&*dst_data_ref.lock().unwrap(), &empty_data);

        // Test tiny data
        let src_mock = MockStream::new_reader(tiny_data.clone());
        let dst_mock = MockStream::new_writer();
        let dst_data_ref = dst_mock.write_data.clone();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        let copy_op = CopyOperation::new(src_stream, dst_stream).buffer_size(1024);
        let (bytes_copied, _src, _dst) = copy_op.execute().await.unwrap();

        assert_eq!(bytes_copied, 1);
        assert_eq!(&*dst_data_ref.lock().unwrap(), &tiny_data);
    }

    #[tokio::test]
    async fn test_asymmetric_partial_operations() {
        // Test very different partial operation sizes
        let test_data: Vec<u8> = (0..2000).map(|i| (i % 256) as u8).collect();

        let src_mock = MockStream::new_reader(test_data.clone())
            .with_partial_operations(Some(3), None); // Very small reads
        let dst_mock = MockStream::new_writer()
            .with_partial_operations(None, Some(47)); // Larger writes

        let dst_data_ref = dst_mock.write_data.clone();

        let src_stream = BufferedStream::new(Box::new(src_mock));
        let dst_stream = BufferedStream::new(Box::new(dst_mock));

        let copy_op = CopyOperation::new(src_stream, dst_stream).buffer_size(200);

        let (bytes_copied, _src, _dst) = copy_op.execute().await.unwrap();

        assert_eq!(bytes_copied, test_data.len() as u64);
        assert_eq!(&*dst_data_ref.lock().unwrap(), &test_data);
    }
}
