#[cfg(test)]
mod tests {
    // All necessary imports, moved from top-level and combined
    use easy_error::err_msg;
    use std::net::SocketAddr;
    use std::sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Mutex,
    }; // Added atomic for ports
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, oneshot};

    use crate::common::http::{HttpRequest, HttpResponse};
    use crate::config::IoParams;
    use crate::context::{make_buffered_stream, ContextRef, ContextRefOps, TargetAddress};
    use crate::listeners::Listener;
    use crate::GlobalState;
    // HttpListener struct itself is used for config, then from_value is a free function
    // use crate::listeners::http::HttpListener as HttpListenerConfigStruct; // No longer needed as alias

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
                        if let Ok(len) = request.header("Content-Length", "0").parse::<u64>() {
                            if len > 0 {
                                body.resize(len as usize, 0);
                                if buffered_stream.read_exact(&mut body).await.is_err() {
                                    eprintln!("Mock server failed to read body");
                                    return;
                                }
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
                        if !response_body.is_empty() {
                            if let Err(e) = buffered_stream.write_all(&response_body).await {
                                eprintln!("Mock server failed to write response body: {}", e);
                                return;
                            }
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
        _global_state: Arc<GlobalState>, // _global_state might be unused if not needed for deeper context interactions
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
                        .set_server_stream(make_buffered_stream(Box::new(server_stream)));
                    drop(ctx_write_guard);
                    ctx_ref.on_connect().await;
                }
                Err(e) => {
                    eprintln!(
                        "Context processor: Failed to connect to target {}: {}",
                        target_addr_str, e
                    );
                    ctx_ref
                        .on_error(err_msg(format!(
                            "Failed to connect in process_contexts: {}",
                            e
                        )))
                        .await;
                }
            }
        }
    }

    async fn setup_proxy_server(
        listen_addr_str: &str,
    ) -> (Arc<GlobalState>, SocketAddr, mpsc::Receiver<ContextRef>) {
        let global_state = Arc::new(GlobalState {
            io_params: IoParams::default(),
            ..Default::default()
        });

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
        let gs_clone_for_listener = global_state.clone();
        tokio::spawn(async move {
            if let Err(e) = arc_listener.listen(gs_clone_for_listener, ctx_sender).await {
                eprintln!("Listener exited with error: {}", e);
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        (global_state, listener_addr_socket, ctx_receiver)
    }

    // Base port for proxy listener, will be incremented for each test to avoid conflicts
    static TEST_PROXY_PORT_BASE: AtomicU16 = AtomicU16::new(34560); // Renamed from previous version which was inside mod tests
                                                                    // Base port for mock server, will be incremented for each test
    static TEST_MOCK_PORT_BASE: AtomicU16 = AtomicU16::new(34580); // Renamed

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
        let (global_state, proxy_addr, ctx_receiver) = setup_proxy_server(&proxy_listen_addr).await;
        assert_eq!(proxy_addr.port(), proxy_port);
        tokio::spawn(process_contexts(ctx_receiver, global_state.clone()));

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
                assert!(received_req
                    .headers
                    .iter()
                    .any(|(k, v)| k.eq_ignore_ascii_case("Host")
                        && v == mock_server_addr.to_string().as_str()));
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
        let (global_state, proxy_addr, ctx_receiver) = setup_proxy_server(&proxy_listen_addr).await;
        assert_eq!(proxy_addr.port(), proxy_port);
        tokio::spawn(process_contexts(ctx_receiver, global_state.clone()));

        let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
        let request_str = format!(
            "POST http://{}/post_path HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            mock_server_addr, mock_server_addr, post_body_content.len(), post_body_content
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
                assert!(received_req
                    .headers
                    .iter()
                    .any(|(k, v)| k.eq_ignore_ascii_case("Content-Length")
                        && v == post_body_content.len().to_string().as_str()));
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

    // TODO: test_http_put_forwarding
    // TODO: test_http_delete_forwarding
}
