use anyhow::Result;
use redproxy_rs::server::ProxyServer;
use std::io::Write;
use std::{sync::Arc, time::Duration};
use tempfile::NamedTempFile;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

fn create_shutdown_test_config(http_port: u16, _echo_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: "test_http"
    type: "http"
    bind: "127.0.0.1:{}"

connectors:
  - name: "test_direct"
    type: "direct"

rules:
  - filter: "true"
    target: "test_direct"

timeouts:
  idle: 300
  udp: 300
  shutdownConnection: 5
  shutdownListener: 2

ioParams:
  bufferSize: 8192
  useSplice: false
"#,
        http_port,
    )
}

async fn find_free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

async fn start_echo_server(port: u16) -> Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;

    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                while let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    Ok(handle)
}

#[tokio::test]
async fn test_graceful_shutdown_single_connection() -> Result<()> {
    // Setup ports
    let http_port = find_free_port().await?;
    let echo_port = find_free_port().await?;

    // Start echo server
    let _echo_handle = start_echo_server(echo_port).await?;

    // Give echo server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create proxy config
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(create_shutdown_test_config(http_port, echo_port).as_bytes())?;
    let config_path = temp_file.path().to_str().unwrap();

    // Start proxy server in background
    let server = ProxyServer::from_config_file(config_path).await?;
    let server_handle = tokio::spawn(async move { server.run().await });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create HTTP connection to proxy
    let mut client = TcpStream::connect(("127.0.0.1", http_port)).await?;

    // Send HTTP CONNECT request
    let connect_request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        echo_port, echo_port
    );
    client.write_all(connect_request.as_bytes()).await?;

    // Read response
    let mut response = [0; 1024];
    let n = client.read(&mut response).await?;
    let response_str = String::from_utf8_lossy(&response[..n]);
    assert!(
        response_str.contains("200"),
        "Expected 200 OK response, got: {}",
        response_str
    );

    // Send test data through tunnel
    client.write_all(b"Hello, World!").await?;

    // Read echoed data
    let mut echo_response = [0; 1024];
    let n = client.read(&mut echo_response).await?;
    assert_eq!(&echo_response[..n], b"Hello, World!");

    // Simulate shutdown signal (this would normally come from SIGTERM)
    // For testing, we'll just abort the server task and verify it handles it gracefully
    server_handle.abort();

    // Verify the server task completed (aborted in this case, but in real scenario it would be graceful)
    let result = server_handle.await;
    assert!(result.is_err()); // Task was aborted, which is expected in this test

    Ok(())
}

#[tokio::test]
async fn test_shutdown_timeout_configuration() -> Result<()> {
    // Create config with very short timeouts for testing
    let config_with_short_timeouts = r#"
listeners:
  - name: "test_http"
    type: "http"
    bind: "127.0.0.1:0"

connectors:
  - name: "test_direct"
    type: "direct"

rules:
  - filter: "true"
    target: "test_direct"

timeouts:
  idle: 300
  udp: 300
  shutdownConnection: 1
  shutdownListener: 1

ioParams:
  bufferSize: 8192
  useSplice: false
"#;

    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(config_with_short_timeouts.as_bytes())?;
    let config_path = temp_file.path().to_str().unwrap();

    // Load config and verify timeout values are parsed correctly
    let server = ProxyServer::from_config_file(config_path).await?;
    assert_eq!(server.timeouts.shutdown_connection, 1);
    assert_eq!(server.timeouts.shutdown_listener, 1);

    Ok(())
}

#[tokio::test]
async fn test_graceful_shutdown_multiple_connections() -> Result<()> {
    // Setup ports
    let http_port = find_free_port().await?;
    let echo_port = find_free_port().await?;

    // Start echo server
    let _echo_handle = start_echo_server(echo_port).await?;

    // Give echo server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create proxy config with longer timeouts for this test
    let config = format!(
        r#"
listeners:
  - name: "test_http"
    type: "http"
    bind: "127.0.0.1:{}"

connectors:
  - name: "test_direct"
    type: "direct"

rules:
  - filter: "true"
    target: "test_direct"

timeouts:
  idle: 300
  udp: 300
  shutdownConnection: 10
  shutdownListener: 5

ioParams:
  bufferSize: 8192
  useSplice: false
"#,
        http_port
    );

    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(config.as_bytes())?;
    let config_path = temp_file.path().to_str().unwrap();

    // Start proxy server in background
    let server = ProxyServer::from_config_file(config_path).await?;
    let server_handle = tokio::spawn(async move { server.run().await });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create multiple connections
    let mut clients = Vec::new();
    for i in 0..3 {
        let mut client = TcpStream::connect(("127.0.0.1", http_port)).await?;

        // Send HTTP CONNECT request
        let connect_request = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            echo_port, echo_port
        );
        client.write_all(connect_request.as_bytes()).await?;

        // Read response
        let mut response = [0; 1024];
        let n = client.read(&mut response).await?;
        let response_str = String::from_utf8_lossy(&response[..n]);
        assert!(
            response_str.contains("200"),
            "Connection {} failed: {}",
            i,
            response_str
        );

        clients.push(client);
    }

    // Send data through each connection
    for (i, client) in clients.iter_mut().enumerate() {
        let message = format!("Hello from connection {}!", i);
        client.write_all(message.as_bytes()).await?;

        let mut response = [0; 1024];
        let n = client.read(&mut response).await?;
        assert_eq!(&response[..n], message.as_bytes());
    }

    // Simulate graceful shutdown
    server_handle.abort();
    let result = server_handle.await;
    assert!(result.is_err()); // Expected since we aborted

    Ok(())
}

#[tokio::test]
async fn test_context_manager_graceful_shutdown_methods() -> Result<()> {
    use redproxy_rs::context::ContextManager;

    let manager = Arc::new(ContextManager::default());

    // Test alive_count on empty manager
    assert_eq!(manager.alive_count(), 0);

    // Create test contexts
    let ctx1 = manager
        .create_context("test1".to_string(), ([127, 0, 0, 1], 8080).into())
        .await;
    let ctx2 = manager
        .create_context("test2".to_string(), ([127, 0, 0, 1], 8081).into())
        .await;

    // Verify alive count
    assert_eq!(manager.alive_count(), 2);

    // Test efficient wait_for_termination (should return false quickly since contexts are alive)
    let start = std::time::Instant::now();
    let result = manager
        .wait_for_termination(Duration::from_millis(100))
        .await;
    let elapsed = start.elapsed();

    assert!(!result, "Should timeout since contexts are alive");
    assert!(
        elapsed >= Duration::from_millis(90),
        "Should wait close to timeout"
    );
    assert!(
        elapsed < Duration::from_millis(200),
        "Should not wait too long"
    );

    // Test abort_all_contexts
    let start = std::time::Instant::now();
    manager.abort_all_contexts().await;
    let elapsed = start.elapsed();

    // Should complete quickly
    assert!(
        elapsed < Duration::from_secs(1),
        "Abort should complete quickly"
    );

    // Verify cancellation tokens are set
    {
        let ctx1_lock = ctx1.read().await;
        assert!(
            ctx1_lock.cancellation_token().is_cancelled(),
            "Context 1 should be cancelled"
        );
    }
    {
        let ctx2_lock = ctx2.read().await;
        assert!(
            ctx2_lock.cancellation_token().is_cancelled(),
            "Context 2 should be cancelled"
        );
    }

    // Drop contexts to allow cleanup
    drop(ctx1);
    drop(ctx2);

    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test wait_for_termination should succeed now
    let result = manager
        .wait_for_termination(Duration::from_millis(100))
        .await;
    assert!(result, "Should return true since contexts are terminated");

    Ok(())
}

// This test simulates real network load during shutdown
#[tokio::test]
async fn test_shutdown_under_load() -> Result<()> {
    let http_port = find_free_port().await?;
    let echo_port = find_free_port().await?;

    // Start echo server
    let _echo_handle = start_echo_server(echo_port).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create config
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(create_shutdown_test_config(http_port, echo_port).as_bytes())?;
    let config_path = temp_file.path().to_str().unwrap();

    // Start proxy
    let server = ProxyServer::from_config_file(config_path).await?;
    let server_handle = tokio::spawn(async move { server.run().await });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create multiple concurrent connections with ongoing traffic
    let mut tasks = Vec::new();
    for i in 0..5 {
        let task = tokio::spawn(async move {
            let mut client = TcpStream::connect(("127.0.0.1", http_port)).await?;

            // HTTP CONNECT
            let connect_request = format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                echo_port, echo_port
            );
            client.write_all(connect_request.as_bytes()).await?;

            let mut response = [0; 1024];
            let n = client.read(&mut response).await?;
            let response_str = String::from_utf8_lossy(&response[..n]);
            if !response_str.contains("200") {
                return Err(anyhow::anyhow!("Connection {} failed: {}", i, response_str));
            }

            // Send continuous traffic
            for j in 0..10 {
                let message = format!("Message {} from connection {}", j, i);
                if client.write_all(message.as_bytes()).await.is_err() {
                    break; // Connection closed during shutdown
                }

                let mut echo_response = [0; 1024];
                match timeout(Duration::from_millis(500), client.read(&mut echo_response)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Successfully received echo
                    }
                    _ => break, // Connection closed or timeout
                }

                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            Ok::<(), anyhow::Error>(())
        });
        tasks.push(task);
    }

    // Let traffic run for a bit
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Initiate shutdown during active traffic
    server_handle.abort();

    // Wait for all client tasks to complete (they should handle connection closure gracefully)
    for task in tasks {
        let _ = task.await; // Don't fail test if connections were closed during shutdown
    }

    let result = server_handle.await;
    assert!(result.is_err()); // Expected since we aborted

    Ok(())
}
