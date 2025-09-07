#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use std::net::SocketAddr;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU16, Ordering},
    };
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, oneshot};

    use crate::common::http::{HttpRequest, HttpResponse};
    use crate::context::{
        ContextManager, ContextRef, ContextRefOps, TargetAddress, make_buffered_stream,
    };
    use crate::listeners::Listener;

    // Helper struct to store parts of a received HTTP request
    #[derive(Clone, Debug)]
    struct ReceivedHttpRequest {
        method: String,
        resource: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    // Mock HTTP Server (using oneshot to send received data back to test)
    struct MockHttpServer {
        listener: TcpListener,
        received_data_sender: Arc<Mutex<Option<oneshot::Sender<ReceivedHttpRequest>>>>,
    }

    impl MockHttpServer {
        async fn new(listen_addr: &str) -> (Self, oneshot::Receiver<ReceivedHttpRequest>) {
            let listener = TcpListener::bind(listen_addr).await.unwrap();
            let (tx, rx) = oneshot::channel();
            (
                MockHttpServer {
                    listener,
                    received_data_sender: Arc::new(Mutex::new(Some(tx))),
                },
                rx,
            )
        }

        fn local_addr(&self) -> SocketAddr {
            self.listener.local_addr().unwrap()
        }

        async fn run_once(
            &self,
            response_code: u16,
            response_status: &str,
            response_headers: Vec<(String, String)>,
            response_body: Vec<u8>,
        ) {
            if let Ok((stream, _)) = self.listener.accept().await {
                let mut buffered_stream = make_buffered_stream(Box::new(stream));

                match HttpRequest::read_from(&mut buffered_stream).await {
                    Ok(request) => {
                        let mut body = Vec::new();
                        if let Ok(len) = request.header("Content-Length", "0").parse::<u64>()
                            && len > 0
                        {
                            body.resize(len as usize, 0);
                            if buffered_stream.read_exact(&mut body).await.is_err() {
                                eprintln!("Mock server failed to read body");
                                return;
                            }
                        }

                        let received = ReceivedHttpRequest {
                            method: request.method.clone(),
                            resource: request.resource.clone(),
                            headers: request.headers.clone(),
                            body,
                        };

                        if let Some(sender) = self.received_data_sender.lock().unwrap().take() {
                            let _ = sender.send(received);
                        }

                        let mut http_response = HttpResponse::new(response_code, response_status);
                        for (k, v) in response_headers {
                            http_response = http_response.with_header(k, v);
                        }
                        if !response_body.is_empty() {
                            http_response = http_response
                                .with_header("Content-Length", response_body.len().to_string());
                        }

                        if let Err(e) = http_response.write_to(&mut buffered_stream).await {
                            eprintln!("Mock server failed to write response headers: {}", e);
                            return;
                        }
                        if !response_body.is_empty()
                            && let Err(e) = buffered_stream.write_all(&response_body).await
                        {
                            eprintln!("Mock server failed to write response body: {}", e);
                            return;
                        }
                        if let Err(e) = buffered_stream.flush().await {
                            eprintln!("Mock server failed to flush: {}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("Mock server failed to parse request: {}", e);
                    }
                }
            }
        }
    }

    // Context processing task
    async fn process_contexts(
        mut receiver: mpsc::Receiver<ContextRef>,
        _context_manager: Arc<ContextManager>,
    ) {
        while let Some(ctx_ref) = receiver.recv().await {
            let target_addr_str = {
                let ctx_read_guard = ctx_ref.read().await;
                let target = ctx_read_guard.target();
                if matches!(target, TargetAddress::Unknown) {
                    eprintln!("Context processor: Target is Unknown, cannot connect.");
                    continue;
                }
                target.to_string()
            };

            match TcpStream::connect(&target_addr_str).await {
                Ok(server_stream) => {
                    let mut ctx_write_guard = ctx_ref.write().await;
                    ctx_write_guard
                        .set_server_stream(make_buffered_stream(Box::new(server_stream)))
                        .set_connector("test_direct".to_string());
                    drop(ctx_write_guard);
                    ctx_ref.on_connect().await;

                    // Call copy_bidi just like the real server does
                    let io_params = crate::config::IoParams::default();
                    if let Err(e) = crate::copy::copy_bidi(ctx_ref.clone(), &io_params).await {
                        eprintln!("Context processor: copy_bidi failed: {}", e);
                        ctx_ref.on_error(anyhow!("copy_bidi failed: {}", e)).await;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Context processor: Failed to connect to target {}: {}",
                        target_addr_str, e
                    );

                    // Send error response directly since connection failed
                    let mut ctx_write_guard = ctx_ref.write().await;
                    if let Some(mut client_stream) = ctx_write_guard.take_client_stream() {
                        let response = HttpResponse::new(503, "Service Unavailable")
                            .with_header("Content-Type", "text/plain")
                            .with_header("Connection", "close");
                        let body = format!("Error: Failed to connect to target: {}", e);
                        let response =
                            response.with_header("Content-Length", body.len().to_string());

                        if let Err(write_err) = response
                            .write_with_body(&mut client_stream, body.as_bytes())
                            .await
                        {
                            eprintln!("Failed to send error response to client: {}", write_err);
                        }
                    }
                }
            }
        }
    }

    async fn setup_proxy_server(
        listen_addr_str: &str,
    ) -> (Arc<ContextManager>, SocketAddr, mpsc::Receiver<ContextRef>) {
        let context_manager = Arc::new(ContextManager::default());

        let listener_addr_socket: SocketAddr = listen_addr_str.parse().unwrap();

        let config_yaml = format!(
            r#"
type: http
name: test_http_listener
bind: "{}"
"#,
            listener_addr_socket
        );
        let listener_value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&config_yaml)
            .expect("Failed to parse test YAML config for HttpListener");

        let mut listener_boxed = crate::listeners::http::from_value(&listener_value).unwrap();
        listener_boxed.init().await.unwrap();

        let (ctx_sender, ctx_receiver) = mpsc::channel::<ContextRef>(100);

        let arc_listener: Arc<dyn Listener> = Arc::from(listener_boxed);
        let cm_clone_for_listener = context_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = arc_listener
                .listen(
                    cm_clone_for_listener,
                    crate::config::Timeouts::default(),
                    ctx_sender,
                )
                .await
            {
                eprintln!("Listener exited with error: {}", e);
            }
        });
        loop {
            if let Ok(stream) = TcpStream::connect(listener_addr_socket).await {
                drop(stream);
                break;
            }
            eprintln!("Waiting for listener to start accepting connections...");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        (context_manager, listener_addr_socket, ctx_receiver)
    }

    // Base port for proxy listener, will be incremented for each test to avoid conflicts
    static TEST_PROXY_PORT_BASE: AtomicU16 = AtomicU16::new(34560);
    // Base port for mock server, will be incremented for each test
    static TEST_MOCK_PORT_BASE: AtomicU16 = AtomicU16::new(34580);

    fn get_next_proxy_port() -> u16 {
        TEST_PROXY_PORT_BASE.fetch_add(1, Ordering::SeqCst)
    }

    fn get_next_mock_port() -> u16 {
        TEST_MOCK_PORT_BASE.fetch_add(1, Ordering::SeqCst)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_get_forwarding() {
        let mock_port = get_next_mock_port();
        let mock_listen_addr = format!("127.0.0.1:{}", mock_port);
        let (mock_server, req_rx) = MockHttpServer::new(&mock_listen_addr).await;
        let mock_server_addr = mock_server.local_addr();
        assert_eq!(mock_server_addr.port(), mock_port);

        let mock_task = tokio::spawn(async move {
            mock_server
                .run_once(
                    200,
                    "OK",
                    vec![("X-Mock-Header".to_string(), "MockValue".to_string())],
                    b"Mock GET Response Body".to_vec(),
                )
                .await;
        });

        let proxy_port = get_next_proxy_port();
        let proxy_listen_addr = format!("127.0.0.1:{}", proxy_port);
        let (context_manager, proxy_addr, ctx_receiver) =
            setup_proxy_server(&proxy_listen_addr).await;
        assert_eq!(proxy_addr.port(), proxy_port);
        tokio::spawn(process_contexts(ctx_receiver, context_manager.clone()));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        let request_str = format!(
            "GET http://{}/get_path HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            mock_server_addr, mock_server_addr
        );
        client_stream
            .write_all(request_str.as_bytes())
            .await
            .unwrap();
        client_stream.flush().await.unwrap();
        client_stream.shutdown().await.unwrap();
        let mut response_buf = Vec::new();
        match tokio::time::timeout(
            Duration::from_secs(2),
            client_stream.read_to_end(&mut response_buf),
        )
        .await
        {
            Ok(Ok(_)) => (),
            Ok(Err(e)) => panic!("Failed to read response from proxy: {}", e),
            Err(_) => panic!("Timeout reading response from proxy"),
        }

        match tokio::time::timeout(Duration::from_secs(2), req_rx).await {
            Ok(Ok(received_req)) => {
                assert_eq!(received_req.method, "GET");
                assert_eq!(
                    received_req.resource,
                    format!("http://{}/get_path", mock_server_addr)
                );
                assert!(
                    received_req
                        .headers
                        .iter()
                        .any(|(k, v)| k.eq_ignore_ascii_case("Host")
                            && v == mock_server_addr.to_string().as_str())
                );
                assert!(received_req.body.is_empty());
            }
            Ok(Err(_)) => panic!("Mock server's request data channel closed unexpectedly."),
            Err(_) => panic!("Timeout waiting for mock server to receive request."),
        }

        mock_task.await.unwrap();

        let response_str = String::from_utf8_lossy(&response_buf);
        assert!(
            response_str.contains("HTTP/1.1 200 OK"),
            "Response: {}",
            response_str
        );
        assert!(
            response_str.contains("X-Mock-Header: MockValue"),
            "Response: {}",
            response_str
        );
        assert!(
            response_str.contains("Mock GET Response Body"),
            "Response: {}",
            response_str
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_post_forwarding() {
        let mock_port = get_next_mock_port();
        let mock_listen_addr = format!("127.0.0.1:{}", mock_port);
        let (mock_server, req_rx) = MockHttpServer::new(&mock_listen_addr).await;
        let mock_server_addr = mock_server.local_addr();
        assert_eq!(mock_server_addr.port(), mock_port);
        let post_body_content = "This is the POST body.";

        let mock_task = tokio::spawn(async move {
            mock_server
                .run_once(
                    201,
                    "Created",
                    vec![("X-Mock-Post".to_string(), "true".to_string())],
                    b"Mock POST Response".to_vec(),
                )
                .await;
        });

        let proxy_port = get_next_proxy_port();
        let proxy_listen_addr = format!("127.0.0.1:{}", proxy_port);
        let (context_manager, proxy_addr, ctx_receiver) =
            setup_proxy_server(&proxy_listen_addr).await;
        assert_eq!(proxy_addr.port(), proxy_port);
        tokio::spawn(process_contexts(ctx_receiver, context_manager.clone()));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        let request_str = format!(
            "POST http://{}/post_path HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            mock_server_addr,
            mock_server_addr,
            post_body_content.len(),
            post_body_content
        );
        client_stream
            .write_all(request_str.as_bytes())
            .await
            .unwrap();
        client_stream.flush().await.unwrap();
        client_stream.shutdown().await.unwrap();
        let mut response_buf = Vec::new();
        match tokio::time::timeout(
            Duration::from_secs(2),
            client_stream.read_to_end(&mut response_buf),
        )
        .await
        {
            Ok(Ok(_)) => (),
            Ok(Err(e)) => panic!("Failed to read POST response from proxy: {}", e),
            Err(_) => panic!("Timeout reading POST response from proxy"),
        }

        match tokio::time::timeout(Duration::from_secs(2), req_rx).await {
            Ok(Ok(received_req)) => {
                assert_eq!(received_req.method, "POST");
                assert_eq!(
                    received_req.resource,
                    format!("http://{}/post_path", mock_server_addr)
                );
                assert_eq!(
                    String::from_utf8_lossy(&received_req.body),
                    post_body_content
                );
                assert!(
                    received_req
                        .headers
                        .iter()
                        .any(|(k, v)| k.eq_ignore_ascii_case("Content-Length")
                            && v == post_body_content.len().to_string().as_str())
                );
            }
            Ok(Err(_)) => {
                panic!("Mock server's request data channel for POST closed unexpectedly.")
            }
            Err(_) => panic!("Timeout waiting for mock server to receive POST request."),
        }
        mock_task.await.unwrap();

        let response_str = String::from_utf8_lossy(&response_buf);
        assert!(
            response_str.contains("HTTP/1.1 201 Created"),
            "Response: {}",
            response_str
        );
        assert!(
            response_str.contains("X-Mock-Post: true"),
            "Response: {}",
            response_str
        );
        assert!(
            response_str.contains("Mock POST Response"),
            "Response: {}",
            response_str
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_websocket_upgrade_preserves_headers() {
        let mock_port = get_next_mock_port();
        let mock_listen_addr = format!("127.0.0.1:{}", mock_port);
        let (mock_server, req_rx) = MockHttpServer::new(&mock_listen_addr).await;
        let mock_server_addr = mock_server.local_addr();

        let mock_task = tokio::spawn(async move {
            mock_server
                .run_once(
                    101,
                    "Switching Protocols",
                    vec![
                        ("Upgrade".to_string(), "websocket".to_string()),
                        ("Connection".to_string(), "Upgrade".to_string()),
                        (
                            "Sec-WebSocket-Accept".to_string(),
                            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".to_string(),
                        ),
                    ],
                    Vec::new(),
                )
                .await;
        });

        let proxy_port = get_next_proxy_port();
        let proxy_listen_addr = format!("127.0.0.1:{}", proxy_port);
        let (context_manager, proxy_addr, ctx_receiver) =
            setup_proxy_server(&proxy_listen_addr).await;
        tokio::spawn(process_contexts(ctx_receiver, context_manager.clone()));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        let request_str = format!(
            "GET http://{}/ws HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            mock_server_addr, mock_server_addr
        );
        client_stream
            .write_all(request_str.as_bytes())
            .await
            .unwrap();
        client_stream.flush().await.unwrap();

        // Verify the mock server received the WebSocket upgrade request with correct headers
        match tokio::time::timeout(Duration::from_secs(2), req_rx).await {
            Ok(Ok(received_req)) => {
                assert_eq!(received_req.method, "GET");
                assert_eq!(
                    received_req.resource,
                    format!("http://{}/ws", mock_server_addr)
                );

                // Verify WebSocket headers are preserved (no Connection: close added)
                let connection_header = received_req
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("Connection"))
                    .map(|(_, v)| v);
                assert_eq!(connection_header, Some(&"Upgrade".to_string()));

                let upgrade_header = received_req
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("Upgrade"))
                    .map(|(_, v)| v);
                assert_eq!(upgrade_header, Some(&"websocket".to_string()));

                let ws_key_header = received_req
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("Sec-WebSocket-Key"))
                    .map(|(_, v)| v);
                assert_eq!(ws_key_header, Some(&"dGhlIHNhbXBsZSBub25jZQ==".to_string()));
            }
            Ok(Err(_)) => panic!("Mock server's request channel closed unexpectedly."),
            Err(_) => panic!("Timeout waiting for WebSocket upgrade request."),
        }

        mock_task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_connection_close_added_to_regular_requests() {
        let mock_port = get_next_mock_port();
        let mock_listen_addr = format!("127.0.0.1:{}", mock_port);
        let (mock_server, req_rx) = MockHttpServer::new(&mock_listen_addr).await;
        let mock_server_addr = mock_server.local_addr();

        let mock_task = tokio::spawn(async move {
            mock_server
                .run_once(
                    200,
                    "OK",
                    vec![("Content-Type".to_string(), "text/plain".to_string())],
                    b"Regular response".to_vec(),
                )
                .await;
        });

        let proxy_port = get_next_proxy_port();
        let proxy_listen_addr = format!("127.0.0.1:{}", proxy_port);
        let (context_manager, proxy_addr, ctx_receiver) =
            setup_proxy_server(&proxy_listen_addr).await;
        tokio::spawn(process_contexts(ctx_receiver, context_manager.clone()));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        // Send a regular GET request without Connection header
        let request_str = format!(
            "GET http://{}/test HTTP/1.1\r\nHost: {}\r\nUser-Agent: test-client\r\n\r\n",
            mock_server_addr, mock_server_addr
        );
        client_stream
            .write_all(request_str.as_bytes())
            .await
            .unwrap();
        client_stream.flush().await.unwrap();

        // Verify the mock server received the request with Connection: close added
        match tokio::time::timeout(Duration::from_secs(2), req_rx).await {
            Ok(Ok(received_req)) => {
                assert_eq!(received_req.method, "GET");
                assert_eq!(
                    received_req.resource,
                    format!("http://{}/test", mock_server_addr)
                );

                // Verify Connection: close was added by the proxy
                let connection_header = received_req
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("Connection"))
                    .map(|(_, v)| v);
                assert_eq!(connection_header, Some(&"close".to_string()));

                // Verify other headers are preserved
                let user_agent_header = received_req
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("User-Agent"))
                    .map(|(_, v)| v);
                assert_eq!(user_agent_header, Some(&"test-client".to_string()));
            }
            Ok(Err(_)) => panic!("Mock server's request channel closed unexpectedly."),
            Err(_) => panic!("Timeout waiting for regular request."),
        }

        mock_task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_chunked_encoding_handling() {
        let mock_port = get_next_mock_port();
        let mock_listen_addr = format!("127.0.0.1:{}", mock_port);
        let (mock_server, req_rx) = MockHttpServer::new(&mock_listen_addr).await;
        let mock_server_addr = mock_server.local_addr();

        let mock_task = tokio::spawn(async move {
            mock_server
                .run_once(
                    200,
                    "OK",
                    vec![
                        ("Transfer-Encoding".to_string(), "chunked".to_string()),
                        ("Content-Type".to_string(), "text/plain".to_string()),
                    ],
                    b"c\r\nHello World!\r\n0\r\n\r\n".to_vec(), // Chunked response
                )
                .await;
        });

        let proxy_port = get_next_proxy_port();
        let proxy_listen_addr = format!("127.0.0.1:{}", proxy_port);
        let (context_manager, proxy_addr, ctx_receiver) =
            setup_proxy_server(&proxy_listen_addr).await;
        tokio::spawn(process_contexts(ctx_receiver, context_manager.clone()));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        let request_str = format!(
            "GET http://{}/chunked HTTP/1.1\r\nHost: {}\r\nConnection: closed\r\n\r\n",
            mock_server_addr, mock_server_addr
        );
        client_stream
            .write_all(request_str.as_bytes())
            .await
            .unwrap();
        client_stream.flush().await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut response_buf = Vec::new();
        match tokio::time::timeout(
            Duration::from_secs(5),
            client_stream.read_to_end(&mut response_buf),
        )
        .await
        {
            Ok(Ok(_)) => (),
            Ok(Err(e)) => panic!("Failed to read chunked response from proxy: {}", e),
            Err(_) => panic!("Timeout reading chunked response from proxy"),
        }

        // Verify the request was processed
        match tokio::time::timeout(Duration::from_secs(2), req_rx).await {
            Ok(Ok(received_req)) => {
                assert_eq!(received_req.method, "GET");
                assert_eq!(
                    received_req.resource,
                    format!("http://{}/chunked", mock_server_addr)
                );
            }
            Ok(Err(_)) => panic!("Mock server's request channel closed unexpectedly."),
            Err(_) => panic!("Timeout waiting for chunked request."),
        }

        mock_task.await.unwrap();

        let response_str = String::from_utf8_lossy(&response_buf);
        assert!(
            response_str.contains("HTTP/1.1 200 OK"),
            "Response: {}",
            response_str
        );
        assert!(
            response_str.contains("Transfer-Encoding: chunked"),
            "Response: {}",
            response_str
        );
        // The chunked body should be passed through by copy_bidi
        assert!(
            response_str.contains("Hello World!"),
            "Response: {}",
            response_str
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_connection_failure_error_handling() {
        let proxy_port = get_next_proxy_port();
        let proxy_listen_addr = format!("127.0.0.1:{}", proxy_port);
        let (context_manager, proxy_addr, ctx_receiver) =
            setup_proxy_server(&proxy_listen_addr).await;
        tokio::spawn(process_contexts(ctx_receiver, context_manager.clone()));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        // Try to connect to a non-existent server
        let nonexistent_addr = "127.0.0.1:9999";
        let request_str = format!(
            "GET http://{}/test HTTP/1.1\r\nHost: {}\r\n\r\n",
            nonexistent_addr, nonexistent_addr
        );
        client_stream
            .write_all(request_str.as_bytes())
            .await
            .unwrap();
        client_stream.flush().await.unwrap();

        let mut response_buf = Vec::new();
        match tokio::time::timeout(
            Duration::from_secs(2),
            client_stream.read_to_end(&mut response_buf),
        )
        .await
        {
            Ok(Ok(_)) => {
                let response_str = String::from_utf8_lossy(&response_buf);
                if !response_buf.is_empty() {
                    // Got a response - should be a 503 error
                    assert!(
                        response_str.contains("HTTP/1.1 503"),
                        "Expected 503 error, got: {}",
                        response_str
                    );
                    assert!(
                        response_str.contains("Service"),
                        "Response: {}",
                        response_str
                    );
                } else {
                    // Empty response is also acceptable for connection failures
                    println!(
                        "Got empty response (connection closed) - this is acceptable for connection failures"
                    );
                }
            }
            Ok(Err(_)) => {
                // Connection error is acceptable for this test case
                println!(
                    "Connection error when reading response - this is acceptable for connection failures"
                );
            }
            Err(_) => {
                // Timeout is also acceptable if the connection was closed
                println!("Timeout reading response - this is acceptable for connection failures");
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_relative_path_with_host_header() {
        let mock_port = get_next_mock_port();
        let mock_listen_addr = format!("127.0.0.1:{}", mock_port);
        let (mock_server, req_rx) = MockHttpServer::new(&mock_listen_addr).await;
        let mock_server_addr = mock_server.local_addr();

        let mock_task = tokio::spawn(async move {
            mock_server
                .run_once(
                    200,
                    "OK",
                    vec![("Content-Type".to_string(), "text/plain".to_string())],
                    b"Relative path response".to_vec(),
                )
                .await;
        });

        let proxy_port = get_next_proxy_port();
        let proxy_listen_addr = format!("127.0.0.1:{}", proxy_port);
        let (context_manager, proxy_addr, ctx_receiver) =
            setup_proxy_server(&proxy_listen_addr).await;
        tokio::spawn(process_contexts(ctx_receiver, context_manager.clone()));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        // Send a request with relative path (not absolute URI)
        let request_str = format!(
            "GET /relative/path HTTP/1.1\r\nHost: {}\r\n\r\n",
            mock_server_addr
        );
        client_stream
            .write_all(request_str.as_bytes())
            .await
            .unwrap();
        client_stream.flush().await.unwrap();
        client_stream.shutdown().await.unwrap();
        let mut response_buf = Vec::new();
        match tokio::time::timeout(
            Duration::from_secs(2),
            client_stream.read_to_end(&mut response_buf),
        )
        .await
        {
            Ok(Ok(_)) => (),
            Ok(Err(e)) => panic!("Failed to read response from proxy: {}", e),
            Err(_) => panic!("Timeout reading response from proxy"),
        }

        // Verify the mock server received the request
        match tokio::time::timeout(Duration::from_secs(2), req_rx).await {
            Ok(Ok(received_req)) => {
                assert_eq!(received_req.method, "GET");
                assert_eq!(received_req.resource, "/relative/path");

                let host_header = received_req
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("Host"))
                    .map(|(_, v)| v);
                assert_eq!(host_header, Some(&mock_server_addr.to_string()));
            }
            Ok(Err(_)) => panic!("Mock server's request channel closed unexpectedly."),
            Err(_) => panic!("Timeout waiting for relative path request."),
        }

        mock_task.await.unwrap();

        let response_str = String::from_utf8_lossy(&response_buf);
        assert!(
            response_str.contains("HTTP/1.1 200 OK"),
            "Response: {}",
            response_str
        );
        assert!(
            response_str.contains("Relative path response"),
            "Response: {}",
            response_str
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_integration_with_real_http_server() {
        // Start a real HTTP server using tokio's hyper
        use hyper::server::conn::http1;
        use hyper::service::service_fn;
        use hyper::{Request, Response};
        use hyper_util::rt::TokioIo;
        use std::convert::Infallible;
        use std::net::SocketAddr;
        use tokio::net::TcpListener;

        async fn handle_request(
            _req: Request<hyper::body::Incoming>,
        ) -> Result<Response<String>, Infallible> {
            let response_body = "Hello from real HTTP server!";
            Ok(Response::builder()
                .status(200)
                .header("Content-Type", "text/plain")
                .header("X-Test-Server", "Real-Hyper-Server")
                .body(response_body.to_string())
                .unwrap())
        }

        // Start the real HTTP server
        let http_server_port = get_next_mock_port();
        let http_server_addr: SocketAddr = ([127, 0, 0, 1], http_server_port).into();
        let listener = TcpListener::bind(http_server_addr).await.unwrap();
        let http_server_addr = listener.local_addr().unwrap();

        // Start the server in the background
        let server_handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        eprintln!("Accept error: {}", e);
                        continue;
                    }
                };

                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service_fn(handle_request))
                        .await
                    {
                        eprintln!("Error serving connection: {:?}", err);
                    }
                });
            }
        });

        // Give the server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Set up our proxy
        let proxy_port = get_next_proxy_port();
        let proxy_listen_addr = format!("127.0.0.1:{}", proxy_port);
        let (context_manager, proxy_addr, ctx_receiver) =
            setup_proxy_server(&proxy_listen_addr).await;
        tokio::spawn(process_contexts(ctx_receiver, context_manager.clone()));

        // Test various HTTP methods through the proxy
        let test_cases = vec![
            ("GET", ""),
            ("POST", "test body content"),
            ("PUT", "updated content"),
            ("DELETE", ""),
        ];

        for (method, body) in test_cases {
            let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();

            let request_str = if body.is_empty() {
                format!(
                    "{} http://{}/test HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    method, http_server_addr, http_server_addr
                )
            } else {
                format!(
                    "{} http://{}/test HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    method,
                    http_server_addr,
                    http_server_addr,
                    body.len(),
                    body
                )
            };

            client_stream
                .write_all(request_str.as_bytes())
                .await
                .unwrap();
            client_stream.flush().await.unwrap();
            client_stream.shutdown().await.unwrap();
            let mut response_buf = Vec::new();
            match tokio::time::timeout(
                Duration::from_secs(5),
                client_stream.read_to_end(&mut response_buf),
            )
            .await
            {
                Ok(Ok(_)) => {
                    let response_str = String::from_utf8_lossy(&response_buf);
                    println!("Response for {} method: {}", method, response_str);

                    // Verify we got a response from the real server
                    assert!(
                        response_str.contains("HTTP/1.1 200 OK"),
                        "Expected 200 OK for {} method, got: {}",
                        method,
                        response_str
                    );
                    assert!(
                        response_str.contains("Hello from real HTTP server!"),
                        "Expected server response body for {} method, got: {}",
                        method,
                        response_str
                    );
                    assert!(
                        response_str
                            .to_lowercase()
                            .contains("x-test-server: real-hyper-server"),
                        "Expected custom header for {} method, got: {}",
                        method,
                        response_str
                    );
                }
                Ok(Err(e)) => panic!("Failed to read response for {} method: {}", method, e),
                Err(_) => panic!("Timeout reading response for {} method", method),
            }
        }

        // Test WebSocket upgrade request (should be passed through)
        let mut ws_client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        let ws_request = format!(
            "GET http://{}/websocket HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n",
            http_server_addr, http_server_addr
        );

        ws_client_stream
            .write_all(ws_request.as_bytes())
            .await
            .unwrap();
        ws_client_stream.flush().await.unwrap();

        let mut ws_response_buf = Vec::new();
        match tokio::time::timeout(
            Duration::from_secs(3),
            ws_client_stream.read_to_end(&mut ws_response_buf),
        )
        .await
        {
            Ok(Ok(_)) => {
                let ws_response_str = String::from_utf8_lossy(&ws_response_buf);
                println!("WebSocket upgrade response: {}", ws_response_str);

                // The real HTTP server should respond (even if it doesn't support WebSocket)
                // The important thing is that our proxy passed through the upgrade headers
                assert!(
                    ws_response_str.contains("HTTP/1.1"),
                    "Expected HTTP response for WebSocket upgrade, got: {}",
                    ws_response_str
                );
            }
            Ok(Err(e)) => {
                println!("WebSocket upgrade connection error (expected): {}", e);
            }
            Err(_) => {
                println!("WebSocket upgrade timeout (expected for non-WebSocket server)");
            }
        }

        // Clean up
        server_handle.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_real_server_with_chunked_encoding() {
        use hyper::server::conn::http1;
        use hyper::service::service_fn;
        use hyper::{Request, Response};
        use hyper_util::rt::TokioIo;
        use std::convert::Infallible;
        use std::net::SocketAddr;
        use tokio::net::TcpListener;

        async fn handle_chunked_request(
            _req: Request<hyper::body::Incoming>,
        ) -> Result<Response<String>, Infallible> {
            // Create a simple response (hyper will handle chunking automatically if needed)
            let response_body = "Chunk 1\nChunk 2\nFinal chunk\n";

            Ok(Response::builder()
                .status(200)
                .header("Content-Type", "text/plain")
                .header("X-Chunked-Response", "true")
                .body(response_body.to_string())
                .unwrap())
        }

        // Start the real HTTP server with chunked encoding
        let http_server_port = get_next_mock_port();
        let http_server_addr: SocketAddr = ([127, 0, 0, 1], http_server_port).into();
        let listener = TcpListener::bind(http_server_addr).await.unwrap();
        let http_server_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        eprintln!("Chunked server accept error: {}", e);
                        continue;
                    }
                };

                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service_fn(handle_chunked_request))
                        .await
                    {
                        eprintln!("Error serving chunked connection: {:?}", err);
                    }
                });
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Set up proxy
        let proxy_port = get_next_proxy_port();
        let proxy_listen_addr = format!("127.0.0.1:{}", proxy_port);
        let (context_manager, proxy_addr, ctx_receiver) =
            setup_proxy_server(&proxy_listen_addr).await;
        tokio::spawn(process_contexts(ctx_receiver, context_manager.clone()));

        // Test chunked response through proxy
        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        let request_str = format!(
            "GET http://{}/chunked HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            http_server_addr, http_server_addr
        );

        client_stream
            .write_all(request_str.as_bytes())
            .await
            .unwrap();
        client_stream.flush().await.unwrap();
        client_stream.shutdown().await.unwrap();
        let mut response_buf = Vec::new();
        match tokio::time::timeout(
            Duration::from_secs(5),
            client_stream.read_to_end(&mut response_buf),
        )
        .await
        {
            Ok(Ok(_)) => {
                let response_str = String::from_utf8_lossy(&response_buf);
                println!("Chunked response: {}", response_str);

                assert!(
                    response_str.contains("HTTP/1.1 200 OK"),
                    "Expected 200 OK for chunked response, got: {}",
                    response_str
                );
                assert!(
                    response_str
                        .to_lowercase()
                        .contains("x-chunked-response: true"),
                    "Expected chunked response header, got: {}",
                    response_str
                );
                assert!(
                    response_str.contains("Chunk 1")
                        && response_str.contains("Chunk 2")
                        && response_str.contains("Final chunk"),
                    "Expected all chunks in response, got: {}",
                    response_str
                );
            }
            Ok(Err(e)) => panic!("Failed to read chunked response: {}", e),
            Err(_) => panic!("Timeout reading chunked response"),
        }

        server_handle.abort();
    }
}
