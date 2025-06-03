#[cfg(test)]
mod tests {
    use easy_error::err_msg;
    use std::net::SocketAddr;
    use std::sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Mutex,
    };
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, oneshot};
    use std::any::Any; // Required for as_any

    use crate::common::http::{HttpRequest, HttpResponse};
    use crate::config::IoParams; // Corrected: Removed unresolved Config types
    use crate::connectors;
    use crate::context::{make_buffered_stream, ContextRef, ContextRefOps, TargetAddress, Context}; // Added Context
    use crate::listeners::Listener;
    use crate::rules;
    use crate::GlobalState;
    use serde_yaml_ng::Value as YamlValue; // Use YamlValue for config parsing
    use std::collections::HashMap; // For HashMap type

    // Helper struct to store parts of a received HTTP request
    #[derive(Clone, Debug)]
    struct ReceivedHttpRequest {
        method: String,
        resource: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    // Enum for different types of data mock server can receive
    #[derive(Debug, Clone)]
    enum MockServerReceivedData {
        DirectRequest(ReceivedHttpRequest),
        TunneledRequest {
            connect_request_target: String,
            proxied_request: ReceivedHttpRequest,
        },
        ConnectOnly(String), // Target from CONNECT request
    }

    // Mock HTTP Server
    struct MockHttpServer {
        listener: TcpListener,
        received_data_sender: Arc<Mutex<Option<oneshot::Sender<MockServerReceivedData>>>>,
    }

    impl MockHttpServer {
        async fn new(listen_addr: &str) -> (Self, oneshot::Receiver<MockServerReceivedData>) {
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

        async fn run_handling_connect(
            &self,
            response_code: u16,
            response_status: &str,
            response_headers: Vec<(String, String)>,
            response_body: Vec<u8>,
            expect_proxied_request_after_connect: bool,
        ) {
            if let Ok((stream, _)) = self.listener.accept().await {
                let mut buffered_stream = make_buffered_stream(Box::new(stream));
                match HttpRequest::read_from(&mut buffered_stream).await {
                    Ok(initial_request) => {
                        if initial_request.method.eq_ignore_ascii_case("CONNECT") {
                            let connect_request_target = initial_request.resource.clone();
                            let connect_response = HttpResponse::new(200, "Connection established");
                            if connect_response.write_to(&mut buffered_stream).await.is_err() || buffered_stream.flush().await.is_err() {
                                return;
                            }
                            if !expect_proxied_request_after_connect {
                                if let Some(sender) = self.received_data_sender.lock().unwrap().take() {
                                    let _ = sender.send(MockServerReceivedData::ConnectOnly(connect_request_target));
                                }
                                return;
                            }
                            match HttpRequest::read_from(&mut buffered_stream).await {
                                Ok(proxied_request_obj) => {
                                    let mut body = Vec::new();
                                    if let Ok(len) = proxied_request_obj.header("Content-Length", "0").parse::<u64>() {
                                        if len > 0 {
                                            body.resize(len as usize, 0);
                                            if buffered_stream.read_exact(&mut body).await.is_err() { return; }
                                        }
                                    }
                                    let received_proxied_http_req = ReceivedHttpRequest {
                                        method: proxied_request_obj.method.clone(),
                                        resource: proxied_request_obj.resource.clone(),
                                        headers: proxied_request_obj.headers.clone(),
                                        body,
                                    };
                                    if let Some(sender) = self.received_data_sender.lock().unwrap().take() {
                                        let _ = sender.send(MockServerReceivedData::TunneledRequest {
                                            connect_request_target,
                                            proxied_request: received_proxied_http_req,
                                        });
                                    }
                                }
                                Err(_) => {
                                    if let Some(sender) = self.received_data_sender.lock().unwrap().take() {
                                        let _ = sender.send(MockServerReceivedData::ConnectOnly(format!("CONNECT_OK_BUT_PROXY_READ_ERR: {}", connect_request_target)));
                                    }
                                    return;
                                }
                            }
                        } else {
                            let mut body = Vec::new();
                            if let Ok(len) = initial_request.header("Content-Length", "0").parse::<u64>() {
                                if len > 0 {
                                    body.resize(len as usize, 0);
                                    if buffered_stream.read_exact(&mut body).await.is_err() { return; }
                                }
                            }
                            let received_direct_http_req = ReceivedHttpRequest {
                                method: initial_request.method.clone(),
                                resource: initial_request.resource.clone(),
                                headers: initial_request.headers.clone(),
                                body,
                            };
                            if let Some(sender) = self.received_data_sender.lock().unwrap().take() {
                                let _ = sender.send(MockServerReceivedData::DirectRequest(received_direct_http_req));
                            }
                        }

                        let mut http_response = HttpResponse::new(response_code, response_status);
                        for (k, v) in response_headers { http_response = http_response.with_header(k, v); }
                        if !response_body.is_empty() {
                            http_response = http_response.with_header("Content-Length", response_body.len().to_string());
                        }
                        if http_response.write_to(&mut buffered_stream).await.is_err() { return; }
                        if !response_body.is_empty() && buffered_stream.write_all(&response_body).await.is_err() { return; }
                        let _ = buffered_stream.flush().await;
                    }
                    Err(e) => eprintln!("Mock server failed to parse initial request: {}", e),
                }
            }
        }
    }

    async fn _old_process_contexts( mut receiver: mpsc::Receiver<ContextRef>, _global_state: Arc<GlobalState>) {
        while let Some(ctx_ref) = receiver.recv().await {
            let target_addr_str = {
                let ctx_read_guard = ctx_ref.read().await;
                let target = ctx_read_guard.target();
                if matches!(target, TargetAddress::Unknown) { continue; }
                target.to_string()
            };
            match TcpStream::connect(&target_addr_str).await {
                Ok(server_stream) => {
                    let mut ctx_write_guard = ctx_ref.write().await;
                    ctx_write_guard.set_server_stream(make_buffered_stream(Box::new(server_stream)));
                    drop(ctx_write_guard);
                    ctx_ref.on_connect().await;
                }
                Err(e) => ctx_ref.on_error(err_msg(format!("Failed in old_process_contexts: {}", e))).await,
            }
        }
    }

    async fn setup_full_proxy(
        _proxy_listen_addr_str: &str, // For assertion, actual bind from listener_configs_yaml
        listener_configs_yaml: Vec<String>,
        connector_configs_yaml: Vec<String>,
        rule_configs_yaml: Vec<String>,
    ) -> (
        Arc<GlobalState>,
        SocketAddr,
        mpsc::Receiver<ContextRef>,
        Arc<Vec<Arc<rules::Rule>>>, // Corrected
        Arc<HashMap<String, Arc<dyn connectors::Connector>>>, // Corrected
    ) {
        let global_state = Arc::new(GlobalState { io_params: IoParams::default(), ..Default::default() });

        let parsed_listeners_values: Vec<YamlValue> = listener_configs_yaml.into_iter().map(|s| serde_yaml_ng::from_str(&s).unwrap()).collect();
        let parsed_connectors_values: Vec<YamlValue> = connector_configs_yaml.into_iter().map(|s| serde_yaml_ng::from_str(&s).unwrap()).collect();
        let parsed_rules_values: Vec<YamlValue> = rule_configs_yaml.into_iter().map(|s| serde_yaml_ng::from_str(&s).unwrap()).collect();

        if parsed_listeners_values.is_empty() { panic!("No listener configs for setup_full_proxy"); }

        let actual_listeners_map = crate::listeners::from_config(&parsed_listeners_values).expect("Failed listeners from_config");
        let actual_connectors_map = crate::connectors::from_config(&parsed_connectors_values).expect("Failed connectors from_config");
        let actual_rules_vec = crate::rules::from_config(&parsed_rules_values).expect("Failed rules from_config");

        let rules_arc = Arc::new(actual_rules_vec);
        let connectors_arc = Arc::new(actual_connectors_map);

        let first_listener_name = parsed_listeners_values[0].get("name").and_then(YamlValue::as_str).map(String::from).expect("Listener name missing");
        let listener_to_run = actual_listeners_map.get(&first_listener_name).cloned().expect("Listener not found");

        let http_listener_ref = listener_to_run.as_any().downcast_ref::<crate::listeners::http::HttpListener>().expect("Test listener not HttpListener");
        let actual_listener_addr = http_listener_ref.local_addr().expect("Listener no local_addr");

        let (ctx_sender, ctx_receiver) = mpsc::channel::<ContextRef>(100);
        let gs_clone_for_listener = global_state.clone();

        tokio::spawn(async move {
            if let Err(e) = listener_to_run.listen(gs_clone_for_listener, ctx_sender).await {
                eprintln!("Listener ({}) exited: {}", actual_listener_addr, e);
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        (global_state.clone(), actual_listener_addr, ctx_receiver, rules_arc, connectors_arc)
    }

    async fn proxy_processing_loop(
        mut receiver: mpsc::Receiver<ContextRef>,
        global_state: Arc<GlobalState>,
        rules_container: Arc<Vec<Arc<rules::Rule>>>, // Corrected
        connectors_map: Arc<HashMap<String, Arc<dyn connectors::Connector>>>, // Corrected
    ) {
        while let Some(ctx_ref) = receiver.recv().await {
            let final_connector_name = {
                let mut name = "direct".to_string();
                let ctx_read_guard = ctx_ref.read().await;
                for rule_arc in rules_container.iter() {
                    if rule_arc.evaluate(&*ctx_read_guard).await { // Pass &Context
                        name = rule_arc.target_name().to_string();
                        break;
                    }
                }
                name
            };

            if final_connector_name.eq_ignore_ascii_case("deny") {
                if let Some(mut cs) = ctx_ref.write().await.take_client_stream() { let _ = cs.shutdown().await; }
                continue;
            }

            let connector = match connectors_map.get(&final_connector_name) {
                Some(conn) => conn.clone(),
                None => {
                    if let Some(mut cs) = ctx_ref.write().await.take_client_stream() { let _ = cs.shutdown().await; }
                    continue;
                }
            };

            let gs_clone = global_state.clone();
            let ctx_clone_for_task = ctx_ref.clone();
            tokio::spawn(async move {
                match connector.connect(gs_clone.clone(), ctx_clone_for_task.clone()).await {
                    Ok(_) => {
                        if let Err(e) = crate::copy::copy_bidi(ctx_clone_for_task.clone(), &gs_clone.io_params).await { // Corrected copy_bidi
                            let e_str = e.to_string();
                            if !e_str.contains("Connection reset") && !e_str.contains("timed out") && !e_str.contains("Broken pipe") && !e_str.contains("forcibly closed") {
                                eprintln!("copy_bidi error: {}", e_str);
                            }
                            ctx_clone_for_task.on_error(e).await;
                        }
                    }
                    Err(e) => ctx_clone_for_task.on_error(e).await,
                }
            });
        }
    }

    static TEST_PROXY_PORT_BASE: AtomicU16 = AtomicU16::new(34600);
    static TEST_MOCK_PORT_BASE: AtomicU16 = AtomicU16::new(34800);
    fn get_next_proxy_port() -> u16 { TEST_PROXY_PORT_BASE.fetch_add(1, Ordering::SeqCst) }
    fn get_next_mock_port() -> u16 { TEST_MOCK_PORT_BASE.fetch_add(1, Ordering::SeqCst) }

    async fn setup_basic_http_listener(listen_addr_str: &str) -> (Arc<GlobalState>, SocketAddr, mpsc::Receiver<ContextRef>) {
        let global_state = Arc::new(GlobalState { io_params: IoParams::default(), ..Default::default() });
        let listener_addr_socket: SocketAddr = listen_addr_str.parse().unwrap();
        let listener_yaml_val: YamlValue = serde_yaml_ng::from_str(&format!(r#"type: http\nname: test_basic_listener\nbind: "{}"\n"#, listener_addr_socket)).unwrap();

        let mut listener_boxed = crate::listeners::from_value(&listener_yaml_val).expect("from_value failed for basic listener");
        listener_boxed.init().await.unwrap();

        let actual_bound_addr = listener_boxed.as_any().downcast_ref::<crate::listeners::http::HttpListener>()
            .expect("Basic listener not HttpListener").local_addr().unwrap_or(listener_addr_socket);

        let (ctx_sender, ctx_receiver) = mpsc::channel::<ContextRef>(100);
        let listener_arc = Arc::from(listener_boxed); // Convert Box to Arc for listen
        let gs_clone_for_listener = global_state.clone();
        tokio::spawn(async move {
            if let Err(e) = listener_arc.listen(gs_clone_for_listener, ctx_sender).await {
                eprintln!("Basic Listener exited: {}", e);
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        (global_state, actual_bound_addr, ctx_receiver)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_get_forwarding_old_setup() {
        let mock_port = get_next_mock_port();
        let mock_listen_addr = format!("127.0.0.1:{}", mock_port);
        let (mock_server, req_rx_oneshot) = MockHttpServer::new(&mock_listen_addr).await;
        let mock_server_addr = mock_server.local_addr();

        let mock_task = tokio::spawn(async move {
            mock_server.run_handling_connect(200, "OK", vec![("X-Mock-Header".to_string(), "MockValue".to_string())], b"Mock GET Response Body".to_vec(), false).await;
        });

        let proxy_port = get_next_proxy_port();
        let proxy_listen_addr_str = format!("127.0.0.1:{}", proxy_port);
        let (global_state, bound_addr, ctx_receiver) = setup_basic_http_listener(&proxy_listen_addr_str).await;
        assert_eq!(bound_addr.port(), proxy_port);
        tokio::spawn(_old_process_contexts(ctx_receiver, global_state.clone()));

        let mut client_stream = TcpStream::connect(bound_addr).await.unwrap();
        let request_str = format!("GET http://{}/get_path HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", mock_server_addr, mock_server_addr);
        client_stream.write_all(request_str.as_bytes()).await.unwrap();
        client_stream.flush().await.unwrap();

        let mut response_buf = Vec::new();
        match tokio::time::timeout(Duration::from_secs(2), client_stream.read_to_end(&mut response_buf)).await {
            Ok(Ok(_)) => (), Ok(Err(e)) => panic!("Failed to read response: {}", e), Err(_) => panic!("Timeout reading response"),
        }

        match tokio::time::timeout(Duration::from_secs(2), req_rx_oneshot).await {
            Ok(Ok(received_data)) => match received_data {
                MockServerReceivedData::DirectRequest(req) => {
                    assert_eq!(req.method, "GET");
                    assert_eq!(req.resource, format!("http://{}/get_path", mock_server_addr));
                }
                _ => panic!("Expected DirectRequest, got {:?}", received_data),
            },
            Ok(Err(_)) => panic!("Mock server channel closed."), Err(_) => panic!("Timeout mock server."),
        }
        mock_task.await.unwrap();
        let response_str = String::from_utf8_lossy(&response_buf);
        assert!(response_str.contains("HTTP/1.1 200 OK"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_post_forwarding_old_setup() {
        let mock_port = get_next_mock_port();
        let mock_listen_addr = format!("127.0.0.1:{}", mock_port);
        let (mock_server, req_rx_oneshot) = MockHttpServer::new(&mock_listen_addr).await;
        let mock_server_addr = mock_server.local_addr();
        let post_body_content = "This is the POST body.";

        let mock_task = tokio::spawn(async move {
            mock_server.run_handling_connect(201, "Created", vec![("X-Mock-Post".to_string(), "true".to_string())], b"Mock POST Response".to_vec(), false).await;
        });

        let proxy_port = get_next_proxy_port();
        let proxy_listen_addr_str = format!("127.0.0.1:{}", proxy_port);
        let (global_state, bound_addr, ctx_receiver) = setup_basic_http_listener(&proxy_listen_addr_str).await;
        tokio::spawn(_old_process_contexts(ctx_receiver, global_state.clone()));

        let mut client_stream = TcpStream::connect(bound_addr).await.unwrap();
        let request_str = format!("POST http://{}/post_path HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", mock_server_addr, mock_server_addr, post_body_content.len(), post_body_content);
        client_stream.write_all(request_str.as_bytes()).await.unwrap();

        let mut response_buf = Vec::new();
        match tokio::time::timeout(Duration::from_secs(2), client_stream.read_to_end(&mut response_buf)).await {
            Ok(Ok(_)) => (), Ok(Err(e)) => panic!("Read POST response error: {}", e), Err(_) => panic!("Timeout POST response"),
        }

        match tokio::time::timeout(Duration::from_secs(2), req_rx_oneshot).await {
            Ok(Ok(received_data)) => match received_data {
                MockServerReceivedData::DirectRequest(req) => {
                    assert_eq!(req.method, "POST");
                    assert_eq!(String::from_utf8_lossy(&req.body), post_body_content);
                }
                _ => panic!("Expected DirectRequest for POST, got {:?}", received_data),
            },
            Ok(Err(_)) => panic!("Mock POST channel closed."), Err(_) => panic!("Timeout mock POST."),
        }
        mock_task.await.unwrap();
        assert!(String::from_utf8_lossy(&response_buf).contains("HTTP/1.1 201 Created"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_get_always_connect_true() {
        let mock_server_port = get_next_mock_port();
        let mock_server_listen_addr = format!("127.0.0.1:{}", mock_server_port);
        let (mock_server, req_rx) = MockHttpServer::new(&mock_server_listen_addr).await;
        let mock_server_socket_addr = mock_server.local_addr();

        let mock_task = tokio::spawn(async move {
            mock_server.run_handling_connect(200, "OK", vec![("X-Tunneled-Marker".to_string(), "true".to_string())], b"Tunneled Hello".to_vec(), true).await;
        });

        let proxy_port = get_next_proxy_port();
        let proxy_listen_addr = format!("127.0.0.1:{}", proxy_port);
        let listener_yaml = vec![format!(r#"type: http\nname: test_always_connect_listener\nbind: "{}"\n"#, proxy_listen_addr)];
        let connector_yaml = vec![format!(r#"name: always-connect-proxy\ntype: http\nserver: {}\nport: {}\nalways_use_connect: true\n"#, mock_server_socket_addr.ip(), mock_server_socket_addr.port())];
        let rule_yaml = vec![r#"target: always-connect-proxy\n"#.to_string()];

        let (global_state, actual_proxy_addr, ctx_receiver, rules, connectors) = setup_full_proxy(&proxy_listen_addr, listener_yaml, connector_yaml, rule_yaml).await;
        assert_eq!(actual_proxy_addr.port(), proxy_port);
        tokio::spawn(proxy_processing_loop(ctx_receiver, global_state, rules, connectors));

        let final_target_host = "final.destination.example";
        let final_target_path = "/somepath";
        let mut client_stream = TcpStream::connect(actual_proxy_addr).await.unwrap();
        let request_str = format!("GET http://{}:{}{} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n", final_target_host, 80, final_target_path, final_target_host, 80);
        client_stream.write_all(request_str.as_bytes()).await.unwrap();
        client_stream.flush().await.unwrap();

        let mut response_buf = Vec::new();
        match tokio::time::timeout(Duration::from_secs(5), client_stream.read_to_end(&mut response_buf)).await {
            Ok(Ok(_)) => (), Ok(Err(e)) => panic!("Client read response error: {}", e), Err(_) => panic!("Client read timeout"),
        }
        let response_str = String::from_utf8_lossy(&response_buf);
        assert!(response_str.contains("HTTP/1.1 200 OK"));

        match tokio::time::timeout(Duration::from_secs(5), req_rx).await {
            Ok(Ok(received_data)) => match received_data {
                MockServerReceivedData::TunneledRequest { connect_request_target, proxied_request } => {
                    assert_eq!(connect_request_target, format!("{}:{}", final_target_host, 80));
                    assert_eq!(proxied_request.method, "GET");
                    assert_eq!(proxied_request.resource, final_target_path);
                }
                _ => panic!("Expected TunneledRequest, got {:?}", received_data),
            },
            Ok(Err(_)) => panic!("Mock server channel closed (always_connect_true)."), Err(_) => panic!("Timeout mock server (always_connect_true)."),
        }
        mock_task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_get_always_connect_false() {
        let mock_server_port = get_next_mock_port();
        let mock_server_listen_addr = format!("127.0.0.1:{}", mock_server_port);
        let (mock_server, req_rx) = MockHttpServer::new(&mock_server_listen_addr).await;
        let mock_server_socket_addr = mock_server.local_addr();

        let mock_task = tokio::spawn(async move {
            mock_server.run_handling_connect(200, "OK", vec![], b"Tunneled Hello (false)".to_vec(), true).await;
        });

        let proxy_port = get_next_proxy_port();
        let proxy_listen_addr = format!("127.0.0.1:{}", proxy_port);
        let listener_yaml = vec![format!(r#"type: http\nname: test_ac_false_listener\nbind: "{}"\n"#, proxy_listen_addr)];
        let connector_yaml = vec![format!(r#"name: ac-false-proxy\ntype: http\nserver: {}\nport: {}\nalways_use_connect: false\n"#, mock_server_socket_addr.ip(), mock_server_socket_addr.port())];
        let rule_yaml = vec![r#"target: ac-false-proxy\n"#.to_string()];

        let (global_state, actual_proxy_addr, ctx_receiver, rules, connectors) = setup_full_proxy(&proxy_listen_addr, listener_yaml, connector_yaml, rule_yaml).await;
        tokio::spawn(proxy_processing_loop(ctx_receiver, global_state, rules, connectors));

        let final_target_host = "final.destination.false.example";
        let final_target_path = "/someotherpath";
        let mut client_stream = TcpStream::connect(actual_proxy_addr).await.unwrap();
        let request_str = format!("GET http://{}:{}{} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n", final_target_host, 80, final_target_path, final_target_host, 80);
        client_stream.write_all(request_str.as_bytes()).await.unwrap();

        let mut response_buf = Vec::new();
        match tokio::time::timeout(Duration::from_secs(5), client_stream.read_to_end(&mut response_buf)).await {
            Ok(Ok(_)) => (), Ok(Err(e)) => panic!("Client read error (ac_false): {}", e), Err(_) => panic!("Client read timeout (ac_false)"),
        }
        assert!(String::from_utf8_lossy(&response_buf).contains("HTTP/1.1 200 OK"));

        match tokio::time::timeout(Duration::from_secs(5), req_rx).await {
            Ok(Ok(received_data)) => match received_data {
                MockServerReceivedData::TunneledRequest { connect_request_target, proxied_request } => {
                    assert_eq!(connect_request_target, format!("{}:{}", final_target_host, 80));
                    assert_eq!(proxied_request.method, "GET");
                }
                _ => panic!("Expected TunneledRequest (ac_false), got {:?}", received_data),
            },
            Ok(Err(_)) => panic!("Mock server channel closed (ac_false)."), Err(_) => panic!("Timeout mock server (ac_false)."),
        }
        mock_task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_https_connect_request_with_always_connect_true_connector() {
        let mock_server_port = get_next_mock_port();
        let mock_server_listen_addr = format!("127.0.0.1:{}", mock_server_port);
        let (mock_server, req_rx) = MockHttpServer::new(&mock_server_listen_addr).await;
        let mock_server_socket_addr = mock_server.local_addr();

        let mock_task = tokio::spawn(async move {
            mock_server.run_handling_connect(200, "OK", vec![], Vec::new(), false).await; // Expect ConnectOnly
        });

        let proxy_port = get_next_proxy_port();
        let proxy_listen_addr = format!("127.0.0.1:{}", proxy_port);
        let listener_yaml = vec![format!(r#"type: http\nname: test_client_connect_listener\nbind: "{}"\n"#, proxy_listen_addr)];
        let connector_yaml = vec![format!(r#"name: ac-https-proxy\ntype: http\nserver: {}\nport: {}\nalways_use_connect: true\n"#, mock_server_socket_addr.ip(), mock_server_socket_addr.port())];
        let rule_yaml = vec![r#"target: ac-https-proxy\n"#.to_string()];

        let (global_state, actual_proxy_addr, ctx_receiver, rules, connectors) = setup_full_proxy(&proxy_listen_addr, listener_yaml, connector_yaml, rule_yaml).await;
        tokio::spawn(proxy_processing_loop(ctx_receiver, global_state, rules, connectors));

        let secure_target_host = "secure.target.example";
        let secure_target_port = 443;
        let mut client_stream = TcpStream::connect(actual_proxy_addr).await.unwrap();
        let connect_request_str = format!("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n", secure_target_host, secure_target_port, secure_target_host, secure_target_port);
        client_stream.write_all(connect_request_str.as_bytes()).await.unwrap();

        let mut response_buf = [0; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), client_stream.read(&mut response_buf)).await.expect("Timeout client CONNECT response").expect("Read client CONNECT error");
        assert!(String::from_utf8_lossy(&response_buf[..n]).contains("HTTP/1.1 200 Connection established"));

        match tokio::time::timeout(Duration::from_secs(5), req_rx).await {
            Ok(Ok(received_data)) => match received_data {
                MockServerReceivedData::ConnectOnly(target) => assert_eq!(target, format!("{}:{}", secure_target_host, secure_target_port)),
                _ => panic!("Expected ConnectOnly (ac_https), got {:?}", received_data),
            },
            Ok(Err(_)) => panic!("Mock server channel closed (ac_https)."), Err(_) => panic!("Timeout mock server (ac_https)."),
        }
        mock_task.await.unwrap();
        let _ = client_stream.shutdown().await;
    }
}
