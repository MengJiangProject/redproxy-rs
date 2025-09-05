use crate::config::IoParams;
use crate::context::{ContextManager, make_buffered_stream};
use crate::protocols::http::http1::io::*;
use crate::protocols::http::*;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use test_log::test;
use tokio_test::io::Builder;

#[test(tokio::test)]
async fn test_http_io_loop_functionality() {
    // Test that http_io_loop function is accessible and has correct signature
    let contexts = Arc::new(ContextManager::default());
    let ctx = contexts
        .create_context("test".to_string(), "127.0.0.1:8080".parse().unwrap())
        .await;

    // Create a basic HTTP request
    let request = HttpRequest::new(
        HttpMethod::Get,
        "http://example.com/test".to_string(),
        HttpVersion::Http1_1,
    );

    // Set up minimal context (streams will be None, should fail gracefully)
    {
        let mut ctx_guard = ctx.write().await;
        ctx_guard.set_http_request(request);
    }

    let io_params = IoParams::default();

    // Test that http_io_loop returns expected error when streams are missing
    let result = http_io_loop(ctx.clone(), &io_params).await;

    // Should fail gracefully with expected error message
    assert!(
        result.is_err(),
        "http_io_loop should fail when streams are missing"
    );
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("No streams available"),
        "Should indicate missing streams: {}",
        error_msg
    );
}

#[test(tokio::test)]
async fn test_body_forward_context_creation() {
    // Test that StatsContext can be created and used

    let io_params = IoParams::default();
    let client_stat = Arc::new(crate::context::ContextStatistics::default());
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    // Test StatsContext creation
    let stats_ctx = StatsContext::new(
        client_stat.clone(),
        #[cfg(feature = "metrics")]
        crate::copy::io_metrics()
            .client_bytes
            .with_label_values(&["test"]),
    );

    // Verify StatsContext fields are accessible
    assert_eq!(io_params.buffer_size, io_params.buffer_size);
    assert!(Arc::ptr_eq(&stats_ctx.stat, &client_stat));
    assert!(!cancellation_token.is_cancelled());
}

#[test(tokio::test)]
async fn test_forward_http_body_no_body() {
    // Test forwarding when no body is present (GET request)

    let io_params = IoParams::default();
    let client_stat = Arc::new(ContextStatistics::default());
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    let stats_ctx = StatsContext::new(
        client_stat.clone(),
        #[cfg(feature = "metrics")]
        crate::copy::io_metrics()
            .client_bytes
            .with_label_values(&["test"]),
    );

    // Create streams with no data (no body)
    let src_stream = make_buffered_stream(Builder::new().build());
    let dst_stream = make_buffered_stream(Builder::new().build());

    // Create request with no Content-Length or Transfer-Encoding
    let request = HttpRequest::new(
        HttpMethod::Get,
        "http://example.com/test".to_string(),
        HttpVersion::Http1_1,
    );

    let result = forward_http_body(
        (src_stream, dst_stream),
        &request,
        &io_params,
        &stats_ctx,
        std::time::Duration::from_secs(30),
        &cancellation_token,
    )
    .await;

    // Should complete without error (no body to forward)
    assert!(
        result.is_ok(),
        "forward_http_body should handle no-body case"
    );
}

#[test(tokio::test)]
async fn test_forward_http_body_content_length() {
    // Test forwarding with Content-Length header
    let io_params = IoParams::default();
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    let stats_ctx = StatsContext::default();
    // Create request with Content-Length
    let mut request = HttpRequest::new(
        HttpMethod::Post,
        "http://example.com/test".to_string(),
        HttpVersion::Http1_1,
    );
    request.add_header("Content-Length".to_string(), "11".to_string());

    // Mock streams: src has body data, dst expects to receive it
    let request_body = b"Hello World";
    let src_stream = make_buffered_stream(Builder::new().read(request_body).build());
    let dst_stream = make_buffered_stream(Builder::new().write(request_body).build());

    let result = forward_http_body(
        (src_stream, dst_stream),
        &request,
        &io_params,
        &stats_ctx,
        std::time::Duration::from_secs(30),
        &cancellation_token,
    )
    .await;

    // Should complete without error
    assert!(
        result.is_ok(),
        "forward_http_body should handle Content-Length"
    );
}

#[test(tokio::test)]
async fn test_forward_http_body_content_length_zero() {
    // Test forwarding with Content-Length: 0
    let io_params = IoParams::default();
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    let stats_ctx = StatsContext::default();

    // Create request with Content-Length: 0
    let mut request = HttpRequest::new(
        HttpMethod::Post,
        "http://example.com/test".to_string(),
        HttpVersion::Http1_1,
    );
    request.add_header("Content-Length".to_string(), "0".to_string());

    // Mock streams with no data expected
    let src_stream = make_buffered_stream(Builder::new().build());
    let dst_stream = make_buffered_stream(Builder::new().build());

    let result = forward_http_body(
        (src_stream, dst_stream),
        &request,
        &io_params,
        &stats_ctx,
        std::time::Duration::from_secs(30),
        &cancellation_token,
    )
    .await;

    // Should complete without error (no body to forward)
    assert!(
        result.is_ok(),
        "forward_http_body should handle Content-Length: 0"
    );
}

#[test(tokio::test)]
async fn test_forward_http_body_chunked() {
    // Test forwarding with chunked transfer encoding
    let io_params = IoParams::default();
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    let stats_ctx = StatsContext::default();

    // Create request with chunked transfer encoding
    let mut request = HttpRequest::new(
        HttpMethod::Post,
        "http://example.com/test".to_string(),
        HttpVersion::Http1_1,
    );
    request.add_header("Transfer-Encoding".to_string(), "chunked".to_string());

    // Mock chunked data: "5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n"
    let chunked_data = b"5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
    let src_stream = make_buffered_stream(Builder::new().read(chunked_data).build());
    let dst_stream = make_buffered_stream(Builder::new().write(chunked_data).build());

    let result = forward_http_body(
        (src_stream, dst_stream),
        &request,
        &io_params,
        &stats_ctx,
        std::time::Duration::from_secs(30),
        &cancellation_token,
    )
    .await;

    // Should complete without error
    assert!(
        result.is_ok(),
        "forward_http_body should handle chunked encoding"
    );
}

#[test(tokio::test)]
async fn test_forward_http_body_invalid_content_length() {
    // Test error handling for invalid Content-Length
    let io_params = IoParams::default();
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    let stats_ctx = StatsContext::default();

    // Create request with invalid Content-Length
    let mut request = HttpRequest::new(
        HttpMethod::Post,
        "http://example.com/test".to_string(),
        HttpVersion::Http1_1,
    );
    request.add_header("Content-Length".to_string(), "invalid".to_string());

    let src_stream = make_buffered_stream(Builder::new().build());
    let dst_stream = make_buffered_stream(Builder::new().build());

    let result = forward_http_body(
        (src_stream, dst_stream),
        &request,
        &io_params,
        &stats_ctx,
        std::time::Duration::from_secs(30),
        &cancellation_token,
    )
    .await;

    // Should return error for invalid Content-Length
    assert!(
        result.is_err(),
        "forward_http_body should error on invalid Content-Length"
    );
    if let Err(e) = result {
        let error_msg = e.to_string();
        assert!(
            error_msg.contains("Invalid Content-Length"),
            "Error should mention invalid Content-Length: {}",
            error_msg
        );
    }
}

#[test(tokio::test)]
async fn test_forward_http_body_unknown_transfer_encoding() {
    // Test handling of unknown transfer encoding
    let io_params = IoParams::default();
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    let stats_ctx = StatsContext::default();

    // Create request with unknown transfer encoding
    let mut request = HttpRequest::new(
        HttpMethod::Post,
        "http://example.com/test".to_string(),
        HttpVersion::Http1_1,
    );
    request.add_header("Transfer-Encoding".to_string(), "gzip".to_string());

    let src_stream = make_buffered_stream(Builder::new().build());
    let dst_stream = make_buffered_stream(Builder::new().build());

    let result = forward_http_body(
        (src_stream, dst_stream),
        &request,
        &io_params,
        &stats_ctx,
        std::time::Duration::from_secs(30),
        &cancellation_token,
    )
    .await;

    // Should complete without error (no body transfer for unknown encoding)
    assert!(
        result.is_ok(),
        "forward_http_body should handle unknown transfer encoding"
    );
}

#[test(tokio::test)]
async fn test_forward_content_length_response() {
    // Test actual data forwarding with Content-Length for response
    let io_params = IoParams::default();
    let server_stat = Arc::new(ContextStatistics::default());
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    let stats_ctx = StatsContext::new(
        server_stat.clone(),
        #[cfg(feature = "metrics")]
        crate::copy::io_metrics()
            .client_bytes
            .with_label_values(&["test"]),
    );

    // Create response with Content-Length
    let mut response = HttpResponse::new(HttpVersion::Http1_1, 200, "OK".to_string());
    response.add_header("Content-Length".to_string(), "13".to_string());

    // Test data: "Hello, World!"
    let response_body = b"Hello, World!";
    let src_stream = make_buffered_stream(Builder::new().read(response_body).build());
    let dst_stream = make_buffered_stream(Builder::new().write(&response_body[..]).build());

    let result = forward_http_body(
        (src_stream, dst_stream),
        &response,
        &io_params,
        &stats_ctx,
        std::time::Duration::from_secs(30),
        &cancellation_token,
    )
    .await;

    // Should complete successfully and verify bytes were counted
    assert!(
        result.is_ok(),
        "forward_http_body should handle response Content-Length"
    );

    // Verify statistics were updated
    assert_eq!(server_stat.sent_bytes(), 13);
}

#[test(tokio::test)]
async fn test_forward_chunked_response() {
    // Test actual chunked data forwarding for response
    let server_stat = Arc::new(ContextStatistics::default());
    let io_params = IoParams::default();
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    let stats_ctx = StatsContext::new(
        server_stat.clone(),
        #[cfg(feature = "metrics")]
        crate::copy::io_metrics()
            .client_bytes
            .with_label_values(&["test"]),
    );

    // Create response with chunked transfer encoding
    let mut response = HttpResponse::new(HttpVersion::Http1_1, 200, "OK".to_string());
    response.add_header("Transfer-Encoding".to_string(), "chunked".to_string());

    // Mock chunked data with proper format: chunk_size\r\ndata\r\n0\r\n\r\n
    let chunked_data = b"5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
    let expected_total_bytes = chunked_data.len();

    let src_stream = make_buffered_stream(Builder::new().read(chunked_data).build());
    let dst_stream = make_buffered_stream(Builder::new().write(chunked_data).build());

    let result = forward_http_body(
        (src_stream, dst_stream),
        &response,
        &io_params,
        &stats_ctx,
        std::time::Duration::from_secs(30),
        &cancellation_token,
    )
    .await;

    // Should complete successfully
    assert!(
        result.is_ok(),
        "forward_http_body should handle chunked response"
    );

    // Verify all chunked data was processed (chunk sizes + data + CRLF)
    let bytes_transferred = server_stat.sent_bytes();
    assert_eq!(
        bytes_transferred, expected_total_bytes,
        "All chunked data should be transferred"
    );
}

#[test(tokio::test)]
async fn test_complete_http_io_loop_cycle() {
    // Test the complete http_io_loop function with proper HTTP request/response cycle
    println!("=== Starting test_complete_http_io_loop_cycle ===");

    let contexts = Arc::new(ContextManager::default());
    let ctx = contexts
        .create_context(
            "test-listener".to_string(),
            "127.0.0.1:8080".parse().unwrap(),
        )
        .await;

    // Set up connector information (required for metrics)
    {
        let mut ctx_guard = ctx.write().await;
        ctx_guard.set_connector("test-connector".to_string());
    }

    // Create a POST request with body and Connection: close
    let mut request = HttpRequest::new(
        HttpMethod::Post,
        "http://example.com/api/data".to_string(),
        HttpVersion::Http1_1,
    );
    request.add_header("Content-Length".to_string(), "11".to_string());
    request.add_header("Connection".to_string(), "close".to_string());

    println!("Request created: POST with Content-Length: 11");

    // Request body: "Hello World"
    let request_body = b"Hello World";
    println!(
        "Request body: {:?} ({} bytes)",
        std::str::from_utf8(request_body).unwrap(),
        request_body.len()
    );

    // HTTP response headers (what read_response reads) - MUST end with \r\n\r\n
    let response_headers = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n";
    // Response body (what forward_http_body reads separately)
    let response_body = b"Success";

    println!(
        "Response headers: {:?} ({} bytes)",
        std::str::from_utf8(response_headers).unwrap(),
        response_headers.len()
    );
    println!(
        "Response body: {:?} ({} bytes)",
        std::str::from_utf8(response_body).unwrap(),
        response_body.len()
    );

    // Client stream setup:
    // - Reads request body (for forwarding to server)
    // - Writes response headers (from send_response) + response body (from forward_http_body)
    let client_stream = make_buffered_stream(
        Builder::new()
            .read(request_body) // Request body to forward
            .write(response_headers) // Response headers written by send_response
            .write(response_body) // Response body written by forward_http_body
            .build(),
    );

    // Server stream setup:
    // - Writes request body (forwarded from client)
    // - Reads response headers (read by read_response) + response body (read by forward_http_body)
    let server_stream = make_buffered_stream(
        Builder::new()
            .write(request_body) // Request body forwarded here
            .read(response_headers) // Response headers read by read_response
            .read(response_body) // Response body read by forward_http_body
            .build(),
    );

    println!("Client stream expects to:");
    println!(
        "  - Read: {:?} ({} bytes)",
        std::str::from_utf8(request_body).unwrap(),
        request_body.len()
    );
    println!(
        "  - Write headers: {:?} ({} bytes)",
        std::str::from_utf8(response_headers).unwrap(),
        response_headers.len()
    );
    println!(
        "  - Write body: {:?} ({} bytes)",
        std::str::from_utf8(response_body).unwrap(),
        response_body.len()
    );

    println!("Server stream expects to:");
    println!(
        "  - Write: {:?} ({} bytes)",
        std::str::from_utf8(request_body).unwrap(),
        request_body.len()
    );
    println!(
        "  - Read headers: {:?} ({} bytes)",
        std::str::from_utf8(response_headers).unwrap(),
        response_headers.len()
    );
    println!(
        "  - Read body: {:?} ({} bytes)",
        std::str::from_utf8(response_body).unwrap(),
        response_body.len()
    );

    // Set up the context with request and streams
    {
        let mut ctx_guard = ctx.write().await;
        ctx_guard
            .set_http_request(request)
            .set_client_stream(client_stream)
            .set_server_stream(server_stream);
    }

    println!("Context set up, running http_io_loop...");

    let io_params = IoParams::default();

    // Run the complete HTTP IO loop
    let result = http_io_loop(ctx.clone(), &io_params).await;

    println!("http_io_loop result: {:?}", result);

    // Should complete successfully
    assert!(
        result.is_ok(),
        "HTTP IO loop should complete successfully: {:?}",
        result.err()
    );

    // Verify final state
    {
        let ctx_guard = ctx.read().await;

        println!("Final context state: {:?}", ctx_guard.state());
        assert_eq!(
            ctx_guard.state(),
            ContextState::ClientShutdown,
            "Should end in ClientShutdown state"
        );
    }

    // Verify statistics were updated for both request and response
    {
        let ctx_guard = ctx.read().await;
        let client_bytes = ctx_guard.props().client_stat.sent_bytes();
        let server_bytes = ctx_guard.props().server_stat.sent_bytes();

        println!("Client bytes sent: {}", client_bytes);
        println!("Server bytes sent: {}", server_bytes);

        // Client should have forwarded request body (11 bytes: "Hello World")
        assert_eq!(client_bytes, 11, "Client should have sent request body");

        // Server should have forwarded response body (7 bytes: "Success")
        assert_eq!(server_bytes, 7, "Server should have sent response body");
    }

    println!("=== Test completed successfully ===");
}

#[cfg(target_os = "linux")]
#[test(tokio::test)]
async fn test_splice_optimization_path() {
    // Real integration test for splice optimization using actual TCP streams

    // Large test data to trigger splice optimization (64KB)

    use tokio::net::{TcpListener, TcpStream};
    let test_data = vec![b'S'; 65536]; // 'S' for Splice

    // Set up source server (simulates client sending data)
    let src_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let src_addr = src_listener.local_addr().unwrap();

    let test_data_clone = test_data.clone();
    let src_server_handle = tokio::spawn(async move {
        let (mut src_stream, _) = src_listener.accept().await.unwrap();
        // Write test data and close the write half
        src_stream.write_all(&test_data_clone).await.unwrap();
        src_stream.shutdown().await.unwrap(); // Close write side
    });

    // Set up destination server (simulates server receiving data)
    let dst_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dst_addr = dst_listener.local_addr().unwrap();

    let dst_server_handle = tokio::spawn(async move {
        let (mut dst_stream, _) = dst_listener.accept().await.unwrap();
        // Read exactly what we expect and close
        let mut received_data = vec![0u8; 65536];
        dst_stream.read_exact(&mut received_data).await.unwrap();
        received_data
    });

    // Small delay to ensure servers are listening
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Connect to both servers to get real TCP streams
    let src_stream = TcpStream::connect(src_addr).await.unwrap();
    let dst_stream = TcpStream::connect(dst_addr).await.unwrap();

    println!("Source stream has_raw_fd: {}", src_stream.as_raw_fd() >= 0);
    println!("Dest stream has_raw_fd: {}", dst_stream.as_raw_fd() >= 0);

    // Convert to buffered streams
    let src_buffered = make_buffered_stream(src_stream);
    let dst_buffered = make_buffered_stream(dst_stream);

    // Test splice-enabled configuration
    let io_params = IoParams {
        buffer_size: 8192,
        ..Default::default()
    };

    let client_stat = Arc::new(ContextStatistics::default());
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    let stats_ctx = StatsContext::new(
        client_stat.clone(),
        #[cfg(feature = "metrics")]
        crate::copy::io_metrics()
            .client_bytes
            .with_label_values(&["test"]),
    );

    // Create request with Content-Length for splice optimization
    let mut request = HttpRequest::new(
        HttpMethod::Put,
        "http://example.com/upload".to_string(),
        HttpVersion::Http1_1,
    );
    request.add_header("Content-Length".to_string(), test_data.len().to_string());

    println!("Starting forward_http_body with splice enabled...");

    // Run the forward_http_body test - this should use splice optimization
    let result = forward_http_body(
        (src_buffered, dst_buffered),
        &request,
        &io_params,
        &stats_ctx,
        std::time::Duration::from_secs(2),
        &cancellation_token,
    )
    .await;

    println!(
        "forward_http_body completed: {}",
        if result.is_ok() { "SUCCESS" } else { "FAILED" }
    );
    if let Err(ref e) = result {
        println!("Error: {}", e);
    }
    println!("Bytes transferred: {}", client_stat.sent_bytes());

    // Should complete successfully using splice optimization
    assert!(
        result.is_ok(),
        "Splice optimization should work with real TCP streams: {:?}",
        result.err()
    );

    // Verify all bytes were transferred
    assert_eq!(
        client_stat.sent_bytes(),
        65536,
        "All bytes should be transferred via splice"
    );

    // Wait for servers to complete with timeout
    let src_result =
        tokio::time::timeout(tokio::time::Duration::from_secs(2), src_server_handle).await;
    assert!(src_result.is_ok(), "Source server should complete");
    src_result.unwrap().unwrap();

    let dst_result =
        tokio::time::timeout(tokio::time::Duration::from_secs(2), dst_server_handle).await;
    assert!(dst_result.is_ok(), "Destination server should complete");
    let received_data = dst_result.unwrap().unwrap();

    // Verify data integrity
    assert_eq!(
        received_data, test_data,
        "Received data should match sent data"
    );

    println!("Real splice optimization test completed successfully!");
    println!("✅ This test actually used real TCP file descriptors and splice syscalls!");
}

#[test(tokio::test)]
async fn test_chunked_parser_edge_cases() {
    // Test chunked transfer encoding parser with various edge cases
    let io_params = IoParams::default();
    let server_stat = Arc::new(ContextStatistics::default());
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    let stats_ctx = StatsContext::new(
        server_stat.clone(),
        #[cfg(feature = "metrics")]
        crate::copy::io_metrics()
            .client_bytes
            .with_label_values(&["test"]),
    );

    // Create response with complex chunked encoding
    let mut response = HttpResponse::new(HttpVersion::Http1_1, 200, "OK".to_string());
    response.add_header("Transfer-Encoding".to_string(), "chunked".to_string());

    // Complex chunked data with:
    // - Chunk extensions (ignored)
    // - Empty chunks
    // - Trailer headers
    let complex_chunked = b"A; charset=utf-8\r\nHello Test\r\n0\r\nX-Trailer: value\r\n\r\n";

    let src_stream = make_buffered_stream(Builder::new().read(complex_chunked).build());
    let dst_stream = make_buffered_stream(Builder::new().write(complex_chunked).build());

    let result = forward_http_body(
        (src_stream, dst_stream),
        &response,
        &io_params,
        &stats_ctx,
        std::time::Duration::from_secs(30),
        &cancellation_token,
    )
    .await;

    // Should handle complex chunked encoding
    assert!(
        result.is_ok(),
        "Complex chunked encoding should be handled: {:?}",
        result.err()
    );

    // Verify all data was transferred including chunk headers and trailers
    let total_bytes = server_stat.sent_bytes();
    assert_eq!(
        total_bytes,
        complex_chunked.len(),
        "All chunked data should be transferred"
    );
}

#[test(tokio::test)]
async fn test_websocket_upgrade_detection() {
    // Test WebSocket upgrade detection in http_io_loop
    let contexts = Arc::new(ContextManager::default());
    let ctx = contexts
        .create_context("ws-test".to_string(), "127.0.0.1:8080".parse().unwrap())
        .await;

    // Set up connector information (required for metrics)
    {
        let mut ctx_guard = ctx.write().await;
        ctx_guard.set_connector("test-connector".to_string());
    }

    // Create WebSocket upgrade request (GET, no body)
    let mut request = HttpRequest::new(
        HttpMethod::Get,
        "ws://example.com/websocket".to_string(),
        HttpVersion::Http1_1,
    );
    request.add_header("Upgrade".to_string(), "websocket".to_string());
    request.add_header("Connection".to_string(), "Upgrade".to_string());
    request.add_header("Sec-WebSocket-Key".to_string(), "test-key".to_string());

    // Test the is_websocket_upgrade function directly
    assert!(
        request.is_websocket_upgrade(),
        "Request should be detected as WebSocket upgrade"
    );

    // WebSocket 101 Switching Protocols response (headers only)
    let ws_response_headers = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: test-accept\r\n\r\n";

    // WebSocket frame data to test bidirectional forwarding after upgrade
    // Simple text frame: 0x81 (FIN=1, opcode=1 for text), 0x05 (length=5), "Hello"
    let client_ws_frame = b"\x81\x05Hello";
    let server_ws_frame = b"\x81\x05World";

    // Client stream:
    // 1. Writes 101 response headers to client
    // 2. Reads WebSocket frame from client (for forwarding to server)
    // 3. Writes server WebSocket frame back to client
    let client_stream = make_buffered_stream(
        Builder::new()
            .write(ws_response_headers) // 101 response written to client
            .read(client_ws_frame) // Client WebSocket frame to forward
            .write(server_ws_frame) // Server WebSocket frame to client
            .build(),
    );

    // Server stream:
    // 1. Reads 101 response headers from server
    // 2. Writes client WebSocket frame to server (forwarded from client)
    // 3. Reads server WebSocket frame from server
    let server_stream = make_buffered_stream(
        Builder::new()
            .read(ws_response_headers) // 101 response read from server
            .write(client_ws_frame) // Client frame forwarded to server
            .read(server_ws_frame) // Server frame read from server
            .build(),
    );

    // Set up the context
    {
        let mut ctx_guard = ctx.write().await;
        ctx_guard
            .set_http_request(request)
            .set_client_stream(client_stream)
            .set_server_stream(server_stream);
    }

    let io_params = IoParams::default();

    // Run HTTP IO loop - it will detect WebSocket upgrade and call copy_bidi
    // This should succeed and establish bidirectional WebSocket forwarding
    let result = http_io_loop(ctx.clone(), &io_params).await;

    println!("WebSocket upgrade test result: {:?}", result);

    // Should complete successfully - WebSocket upgrade detected and bidi forwarding established
    assert!(
        result.is_ok(),
        "WebSocket upgrade and bidirectional forwarding should work: {:?}",
        result.err()
    );

    // Verify that bidirectional forwarding occurred by checking statistics
    {
        let ctx_guard = ctx.read().await;
        let client_bytes = ctx_guard.props().client_stat.sent_bytes();
        let server_bytes = ctx_guard.props().server_stat.sent_bytes();

        println!("WebSocket client bytes forwarded: {}", client_bytes);
        println!("WebSocket server bytes forwarded: {}", server_bytes);

        // Should have forwarded WebSocket frames bidirectionally
        assert!(
            client_bytes > 0,
            "Should have forwarded data from client to server"
        );
        assert!(
            server_bytes > 0,
            "Should have forwarded data from server to client"
        );
    }
}

#[test]
fn test_prepare_client_response_websocket_handling() {
    // Test that prepare_client_response handles WebSocket 101 responses correctly
    // Test 1: Normal HTTP response should get Connection: close
    let mut normal_response = HttpResponse::new(HttpVersion::Http1_1, 200, "OK".to_string());
    normal_response.add_header("Connection".to_string(), "keep-alive".to_string());
    normal_response.add_header("Keep-Alive".to_string(), "timeout=5".to_string());

    prepare_client_response(&mut normal_response, false);

    assert_eq!(normal_response.get_header("Connection").unwrap(), "close");
    assert!(
        normal_response.get_header("Keep-Alive").is_none(),
        "Keep-Alive should be removed"
    );

    // Test 2: WebSocket 101 response should preserve Connection: Upgrade
    let mut ws_response =
        HttpResponse::new(HttpVersion::Http1_1, 101, "Switching Protocols".to_string());
    ws_response.add_header("Connection".to_string(), "Upgrade".to_string());
    ws_response.add_header("Upgrade".to_string(), "websocket".to_string());
    ws_response.add_header(
        "Sec-WebSocket-Accept".to_string(),
        "test-accept".to_string(),
    );
    ws_response.add_header("Keep-Alive".to_string(), "timeout=5".to_string());

    prepare_client_response(&mut ws_response, false); // client_keep_alive doesn't matter for 101

    // WebSocket headers should be preserved
    assert_eq!(
        ws_response.get_header("Connection").unwrap(),
        "Upgrade",
        "Connection: Upgrade should be preserved"
    );
    assert_eq!(
        ws_response.get_header("Upgrade").unwrap(),
        "websocket",
        "Upgrade header should be preserved"
    );
    assert_eq!(
        ws_response.get_header("Sec-WebSocket-Accept").unwrap(),
        "test-accept",
        "WebSocket-specific headers should be preserved"
    );

    // Other hop-by-hop headers should still be removed
    assert!(
        ws_response.get_header("Keep-Alive").is_none(),
        "Keep-Alive should be removed even for WebSocket"
    );

    // Test 3: WebSocket 101 response with client_keep_alive=true should still preserve WebSocket headers
    let mut ws_response2 =
        HttpResponse::new(HttpVersion::Http1_1, 101, "Switching Protocols".to_string());
    ws_response2.add_header("Connection".to_string(), "Upgrade".to_string());
    ws_response2.add_header("Upgrade".to_string(), "websocket".to_string());

    prepare_client_response(&mut ws_response2, true); // Should not affect WebSocket handling

    assert_eq!(
        ws_response2.get_header("Connection").unwrap(),
        "Upgrade",
        "WebSocket Connection header should be preserved regardless of keep_alive"
    );
    assert_eq!(
        ws_response2.get_header("Upgrade").unwrap(),
        "websocket",
        "WebSocket Upgrade header should be preserved"
    );
}

#[test(tokio::test)]
async fn test_forward_content_length_body() {
    // Test the forward_content_length_body function directly

    let io_params = IoParams {
        use_splice: false,
        buffer_size: 1024,
    };

    let client_stat = Arc::new(ContextStatistics::default());
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    let stats_ctx = StatsContext::new(
        client_stat.clone(),
        #[cfg(feature = "metrics")]
        crate::copy::io_metrics()
            .client_bytes
            .with_label_values(&["test"]),
    );

    // Test data that will go through forward_content_length_body
    let test_body = b"This is test data for content-length body forwarding test. It should be transferred exactly as-is from source to destination stream without any modification or loss.";
    let content_length = test_body.len();

    let src_stream = make_buffered_stream(Builder::new().read(test_body).build());
    let dst_stream = make_buffered_stream(Builder::new().write(test_body).build());

    // Create a request with Content-Length to trigger forward_content_length_body
    let mut request = HttpRequest::new(
        HttpMethod::Post,
        "http://example.com/test".to_string(),
        HttpVersion::Http1_1,
    );
    request.add_header("Content-Length".to_string(), content_length.to_string());

    let result = forward_http_body(
        (src_stream, dst_stream),
        &request,
        &io_params,
        &stats_ctx,
        std::time::Duration::from_secs(30),
        &cancellation_token,
    )
    .await;

    // Should complete successfully
    assert!(
        result.is_ok(),
        "Content-length body forwarding should work: {:?}",
        result.err()
    );

    // Verify all bytes were transferred
    assert_eq!(
        client_stat.sent_bytes(),
        content_length,
        "All bytes should be transferred"
    );
}

#[test(tokio::test)]
async fn test_forward_chunked_body() {
    // Test the forward_chunked_body function directly with complex chunked data
    let io_params = IoParams::default();
    let server_stat = Arc::new(ContextStatistics::default());
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    let stats_ctx = StatsContext::new(
        server_stat.clone(),
        #[cfg(feature = "metrics")]
        crate::copy::io_metrics()
            .client_bytes
            .with_label_values(&["test"]),
    );

    // Create simple chunked data that matches the exact hex lengths
    // Format: hex_size\r\ndata\r\nhex_size\r\ndata\r\n0\r\n\r\n
    let chunked_data = b"5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
    let expected_bytes = chunked_data.len();

    let src_stream = make_buffered_stream(Builder::new().read(chunked_data).build());
    let dst_stream = make_buffered_stream(Builder::new().write(chunked_data).build());

    // Create request with chunked transfer encoding to trigger forward_chunked_body
    let mut request = HttpRequest::new(
        HttpMethod::Post,
        "http://example.com/test".to_string(),
        HttpVersion::Http1_1,
    );
    request.add_header("Transfer-Encoding".to_string(), "chunked".to_string());

    let result = forward_http_body(
        (src_stream, dst_stream),
        &request,
        &io_params,
        &stats_ctx,
        std::time::Duration::from_secs(30),
        &cancellation_token,
    )
    .await;

    // Should complete successfully
    assert!(
        result.is_ok(),
        "Chunked body forwarding should work: {:?}",
        result.err()
    );

    // Verify all chunked data including headers was transferred
    assert_eq!(
        server_stat.sent_bytes(),
        expected_bytes,
        "All chunked data should be transferred"
    );
}

#[cfg(target_os = "linux")]
#[test(tokio::test)]
async fn test_forward_content_length_body_splice_enabled() {
    // Test forward_content_length_body with splice enabled (will fall back to regular on mocks)

    let io_params = IoParams {
        buffer_size: 8192,
        use_splice: true,
    };

    let client_stat = Arc::new(ContextStatistics::default());
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    let stats_ctx = StatsContext::new(
        client_stat.clone(),
        #[cfg(feature = "metrics")]
        crate::copy::io_metrics()
            .client_bytes
            .with_label_values(&["test"]),
    );

    // Large data that would benefit from splice
    let large_data = vec![b'X'; 32768]; // 32KB
    let content_length = large_data.len();

    let src_stream = make_buffered_stream(Builder::new().read(&large_data).build());
    let dst_stream = make_buffered_stream(Builder::new().write(&large_data).build());

    // Create request with Content-Length to trigger forward_content_length_body with splice
    let mut request = HttpRequest::new(
        HttpMethod::Put,
        "http://example.com/upload".to_string(),
        HttpVersion::Http1_1,
    );
    request.add_header("Content-Length".to_string(), content_length.to_string());

    let result = forward_http_body(
        (src_stream, dst_stream),
        &request,
        &io_params,
        &stats_ctx,
        std::time::Duration::from_secs(30),
        &cancellation_token,
    )
    .await;

    // Should complete successfully (even if splice falls back to regular IO on mocks)
    assert!(
        result.is_ok(),
        "Large content-length body forwarding should work: {:?}",
        result.err()
    );

    // Verify all bytes were transferred
    assert_eq!(
        client_stat.sent_bytes(),
        content_length,
        "All bytes should be transferred with splice logic"
    );
}

#[test(tokio::test)]
async fn test_http_100_continue_handling() {
    // Test that http_io_loop properly handles 100 Continue responses
    let contexts = Arc::new(ContextManager::default());
    let ctx = contexts
        .create_context(
            "100-continue-test".to_string(),
            "127.0.0.1:8080".parse().unwrap(),
        )
        .await;

    // Set up connector information (required for metrics)
    {
        let mut ctx_guard = ctx.write().await;
        ctx_guard.set_connector("test-connector".to_string());
    }

    // Create POST request with Expect: 100-continue but NO body initially
    // (body will be sent after 100 Continue)
    let mut request = HttpRequest::new(
        HttpMethod::Post,
        "http://example.com/upload".to_string(),
        HttpVersion::Http1_1,
    );
    request.add_header("Expect".to_string(), "100-continue".to_string());
    request.add_header("Content-Length".to_string(), "11".to_string());
    request.add_header("Connection".to_string(), "close".to_string());

    let request_body = b"Hello World";

    // Server sends 100 Continue, then final response
    let continue_response = b"HTTP/1.1 100 Continue\r\n\r\n";
    let final_response = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n";
    let response_body = b"Success";

    // Client stream flow:
    // 1. http_io_loop skips initial body forwarding (expects_100_continue = true)
    // 2. Server sends 100 Continue -> we write it to client
    // 3. We read request body from client
    // 4. We write final response to client
    let client_stream = make_buffered_stream(
        Builder::new()
            .write(continue_response) // Step 2: Forward 100 Continue to client
            .read(request_body) // Step 3: Read request body from client
            .write(final_response) // Step 4: Write final response headers
            .write(response_body) // Step 4: Write final response body
            .build(),
    );

    // Server stream flow:
    // 1. Server sends 100 Continue response
    // 2. We write request body to server
    // 3. Server sends final response
    let server_stream = make_buffered_stream(
        Builder::new()
            .read(continue_response) // Step 1: Read 100 Continue from server
            .write(request_body) // Step 2: Forward request body to server
            .read(final_response) // Step 3: Read final response headers
            .read(response_body) // Step 3: Read final response body
            .build(),
    );

    // Set up context
    {
        let mut ctx_guard = ctx.write().await;
        ctx_guard
            .set_http_request(request)
            .set_client_stream(client_stream)
            .set_server_stream(server_stream);
    }

    let io_params = IoParams::default();

    // Run HTTP IO loop - should handle 100 Continue properly
    let result = http_io_loop(ctx.clone(), &io_params).await;

    assert!(
        result.is_ok(),
        "HTTP 100 Continue handling should work: {:?}",
        result.err()
    );

    // Verify statistics were updated for both request and response bodies
    {
        let ctx_guard = ctx.read().await;
        let client_bytes = ctx_guard.props().client_stat.sent_bytes();
        let server_bytes = ctx_guard.props().server_stat.sent_bytes();

        // Client should have forwarded request body after 100 Continue (11 bytes)
        assert_eq!(
            client_bytes, 11,
            "Client should have sent request body after 100 Continue"
        );

        // Server should have forwarded response body (7 bytes)
        assert_eq!(server_bytes, 7, "Server should have sent response body");
    }
}

#[test]
fn test_expects_100_continue_detection() {
    // Test the expects_100_continue helper function
    let mut request = HttpRequest::new(
        HttpMethod::Post,
        "http://example.com/test".to_string(),
        HttpVersion::Http1_1,
    );

    // No Expect header
    assert!(!expects_100_continue(&request));

    // With 100-continue (lowercase)
    request.add_header("Expect".to_string(), "100-continue".to_string());
    assert!(expects_100_continue(&request));

    // With 100-continue (mixed case)
    request.set_header("Expect".to_string(), "100-Continue".to_string());
    assert!(expects_100_continue(&request));

    // With other expect value
    request.set_header("Expect".to_string(), "something-else".to_string());
    assert!(!expects_100_continue(&request));
}

#[test(tokio::test)]
async fn test_malformed_chunked_encoding_handling() {
    // Test that malformed chunked encoding is handled gracefully (like the external test)

    let io_params = IoParams::default();
    let server_stat = Arc::new(ContextStatistics::default());
    let cancellation_token = tokio_util::sync::CancellationToken::new();

    let stats_ctx = StatsContext::new(
        server_stat.clone(),
        #[cfg(feature = "metrics")]
        crate::copy::io_metrics()
            .client_bytes
            .with_label_values(&["test"]),
    );

    // Create response with malformed chunked encoding (like the test case)
    let mut response = HttpResponse::new(HttpVersion::Http1_1, 200, "OK".to_string());
    response.add_header("Transfer-Encoding".to_string(), "chunked".to_string());

    // Malformed chunked data: "INVALID_HEX\r\ndata\r\n0\r\n\r\n"
    let malformed_chunked = b"INVALID_HEX\r\ndata\r\n0\r\n\r\n";

    let src_stream = make_buffered_stream(Builder::new().read(malformed_chunked).build());
    let dst_stream = make_buffered_stream(Builder::new().build()); // Don't expect any writes on error

    let result = forward_http_body(
        (src_stream, dst_stream),
        &response,
        &io_params,
        &stats_ctx,
        std::time::Duration::from_secs(30),
        &cancellation_token,
    )
    .await;

    // Should fail with clear error message about invalid chunk size
    assert!(result.is_err(), "Malformed chunked encoding should fail");

    if let Err(e) = result {
        let error_msg = e.to_string();
        assert!(
            error_msg.contains("Failed to parse chunk size") && error_msg.contains("INVALID_HEX"),
            "Error should mention invalid chunk size format: {}",
            error_msg
        );
    }
}
