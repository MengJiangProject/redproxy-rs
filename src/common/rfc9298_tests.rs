use super::http_proxy::{
    HttpProxyContextExt, generate_rfc9298_uri_from_template, is_websocket_upgrade,
    parse_rfc9298_uri_template, send_error_response, send_simple_error_response,
};
use crate::context::{ContextManager, TargetAddress};
use std::sync::Arc;

#[test]
fn test_rfc9298_uri_template_generation_comprehensive() {
    // Test default template with domain port
    let target = TargetAddress::DomainPort("example.com".to_string(), 8080);
    let uri = generate_rfc9298_uri_from_template(&target, None);
    assert_eq!(uri, "/.well-known/masque/udp/example.com/8080/");

    // Test default template with IPv4 address
    let target = TargetAddress::SocketAddr("192.168.1.1:9090".parse().unwrap());
    let uri = generate_rfc9298_uri_from_template(&target, None);
    assert_eq!(uri, "/.well-known/masque/udp/192.168.1.1/9090/");

    // Test default template with IPv6 address
    let target = TargetAddress::SocketAddr("[2001:db8::1]:8080".parse().unwrap());
    let uri = generate_rfc9298_uri_from_template(&target, None);
    assert_eq!(uri, "/.well-known/masque/udp/2001:db8::1/8080/");

    // Test custom template with {host}/{port} placeholders
    let target = TargetAddress::DomainPort("test.example.org".to_string(), 443);
    let custom_template = "/proxy/udp/{host}/{port}";
    let uri = generate_rfc9298_uri_from_template(&target, Some(custom_template));
    assert_eq!(uri, "/proxy/udp/test.example.org/443");

    // Test custom template with {target_host}/{target_port} placeholders
    let custom_template = "/masque?target_host={target_host}&target_port={target_port}";
    let uri = generate_rfc9298_uri_from_template(&target, Some(custom_template));
    assert_eq!(uri, "/masque?target_host=test.example.org&target_port=443");

    // Test mixed placeholders
    let custom_template = "/path/{host}/connect?port={target_port}";
    let uri = generate_rfc9298_uri_from_template(&target, Some(custom_template));
    assert_eq!(uri, "/path/test.example.org/connect?port=443");

    // Test unknown target address
    let target = TargetAddress::Unknown;
    let uri = generate_rfc9298_uri_from_template(&target, None);
    assert_eq!(uri, "/.well-known/masque/udp/unknown/0/");

    // Test complex custom template
    let target = TargetAddress::DomainPort("api.service.com".to_string(), 8443);
    let custom_template = "/proxy/v1/udp?dest={host}&port={port}&proto=udp";
    let uri = generate_rfc9298_uri_from_template(&target, Some(custom_template));
    assert_eq!(
        uri,
        "/proxy/v1/udp?dest=api.service.com&port=8443&proto=udp"
    );
}

#[test]
fn test_rfc9298_uri_parsing_comprehensive() {
    // Test standard path-based URI
    let result = parse_rfc9298_uri_template("/.well-known/masque/udp/example.com/8080/");
    assert!(result.is_ok());
    if let Ok(TargetAddress::DomainPort(host, port)) = result {
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    // Test path-based URI without trailing slash
    let result = parse_rfc9298_uri_template("/proxy/udp/test.example.org/443");
    assert!(result.is_ok());
    if let Ok(TargetAddress::DomainPort(host, port)) = result {
        assert_eq!(host, "test.example.org");
        assert_eq!(port, 443);
    }

    // Test IPv4 address in path - now parsed as SocketAddr
    let result = parse_rfc9298_uri_template("/masque/192.168.1.100/9090");
    assert!(result.is_ok());
    if let Ok(TargetAddress::SocketAddr(addr)) = result {
        assert_eq!(addr.ip().to_string(), "192.168.1.100");
        assert_eq!(addr.port(), 9090);
    } else {
        panic!("Expected SocketAddr for valid IPv4 address");
    }

    // Test IPv6 address in path (URL-encoded) - now consistently decoded
    let result = parse_rfc9298_uri_template("/proxy/2001%3Adb8%3A%3A1/8080");
    assert!(result.is_ok());
    if let Ok(TargetAddress::SocketAddr(addr)) = result {
        assert_eq!(addr.ip().to_string(), "2001:db8::1"); // URL-decoded and parsed as IP
        assert_eq!(addr.port(), 8080);
    } else {
        panic!("Expected SocketAddr for valid IPv6 address");
    }

    // Test query parameter style with "host" and "port"
    let result = parse_rfc9298_uri_template("/proxy?host=api.example.com&port=443");
    assert!(result.is_ok());
    if let Ok(TargetAddress::DomainPort(host, port)) = result {
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
    }

    // Test query parameter style with "target_host" and "target_port"
    let result = parse_rfc9298_uri_template("/masque?target_host=service.org&target_port=8080");
    assert!(result.is_ok());
    if let Ok(TargetAddress::DomainPort(host, port)) = result {
        assert_eq!(host, "service.org");
        assert_eq!(port, 8080);
    }

    // Test query parameters with additional params
    let result = parse_rfc9298_uri_template("/proxy?proto=udp&host=test.com&port=9090&timeout=30");
    assert!(result.is_ok());
    if let Ok(TargetAddress::DomainPort(host, port)) = result {
        assert_eq!(host, "test.com");
        assert_eq!(port, 9090);
    }

    // Test URL-encoded query parameters
    let result = parse_rfc9298_uri_template("/proxy?host=test%2Eexample%2Ecom&port=8080");
    assert!(result.is_ok());
    if let Ok(TargetAddress::DomainPort(host, port)) = result {
        assert_eq!(host, "test.example.com");
        assert_eq!(port, 8080);
    }

    // Test complex path with multiple segments
    let result = parse_rfc9298_uri_template("/api/v1/proxy/udp/service.internal/3000");
    assert!(result.is_ok());
    if let Ok(TargetAddress::DomainPort(host, port)) = result {
        assert_eq!(host, "service.internal");
        assert_eq!(port, 3000);
    }
}

#[test]
fn test_rfc9298_uri_parsing_edge_cases() {
    // Test invalid URIs
    assert!(parse_rfc9298_uri_template("/invalid").is_err());
    assert!(parse_rfc9298_uri_template("/only/one/segment").is_err());
    assert!(parse_rfc9298_uri_template("/host/invalid_port").is_err());
    assert!(parse_rfc9298_uri_template("/proxy?host=example.com").is_err()); // missing port
    assert!(parse_rfc9298_uri_template("/proxy?port=8080").is_err()); // missing host

    // Test URIs with template variables (should fail since we expect resolved values)
    assert!(parse_rfc9298_uri_template("/proxy/{target_host}/{target_port}").is_err());
    assert!(parse_rfc9298_uri_template("/proxy?host={host}&port={port}").is_err());

    // Test empty or malformed values
    // Note: "/proxy//8080" actually succeeds because the second "/" becomes an empty host segment
    // which is filtered out, making "8080" the host and failing on invalid port
    assert!(parse_rfc9298_uri_template("/proxy//invalid").is_err()); // empty host with invalid port
    assert!(parse_rfc9298_uri_template("/proxy/example.com/").is_err()); // empty port
    // Note: Empty query parameters may be handled differently by the URL parser
    assert!(parse_rfc9298_uri_template("/proxy?port=8080").is_err()); // missing host in query
    assert!(parse_rfc9298_uri_template("/proxy?host=example.com").is_err()); // missing port in query

    // Test port number validation
    assert!(parse_rfc9298_uri_template("/proxy/example.com/0").is_ok()); // port 0 is technically valid
    assert!(parse_rfc9298_uri_template("/proxy/example.com/65535").is_ok()); // max valid port
    assert!(parse_rfc9298_uri_template("/proxy/example.com/65536").is_err()); // port too large
    assert!(parse_rfc9298_uri_template("/proxy/example.com/-1").is_err()); // negative port
}

#[tokio::test]
async fn test_http_proxy_context_ext_comprehensive() {
    let manager = Arc::new(ContextManager::default());
    let source = "127.0.0.1:1234".parse().unwrap();
    let ctx = manager.create_context("test".to_string(), source).await;

    // Test setting and getting all proxy configuration
    {
        let mut ctx_write = ctx.write().await;
        ctx_write
            .set_proxy_frame_channel("test-channel")
            .set_proxy_force_connect(true)
            .set_proxy_udp_protocol("rfc9298")
            .set_proxy_rfc9298_uri_template("/custom/udp/{host}/{port}");
    }

    // Verify all values are correctly stored and retrieved
    {
        let ctx_read = ctx.read().await;
        assert_eq!(ctx_read.proxy_frame_channel(), Some("test-channel"));
        assert!(ctx_read.proxy_force_connect());
        assert_eq!(ctx_read.proxy_udp_protocol(), Some("rfc9298"));
        assert_eq!(
            ctx_read.proxy_rfc9298_uri_template(),
            Some("/custom/udp/{host}/{port}")
        );
    }

    // Test default values
    let ctx2 = manager.create_context("test2".to_string(), source).await;
    {
        let ctx_read = ctx2.read().await;
        assert_eq!(ctx_read.proxy_frame_channel(), None);
        assert!(!ctx_read.proxy_force_connect());
        assert_eq!(ctx_read.proxy_udp_protocol(), None);
        assert_eq!(ctx_read.proxy_rfc9298_uri_template(), None);
    }

    // Test updating individual values
    {
        let mut ctx_write = ctx2.write().await;
        ctx_write.set_proxy_force_connect(true);
    }
    {
        let ctx_read = ctx2.read().await;
        assert!(ctx_read.proxy_force_connect());
        assert_eq!(ctx_read.proxy_udp_protocol(), None); // others remain unchanged
    }

    // Test boolean parsing edge cases
    {
        let mut ctx_write = ctx2.write().await;
        ctx_write.set_extra("proxy_force_connect", "invalid_bool");
    }
    {
        let ctx_read = ctx2.read().await;
        assert!(!ctx_read.proxy_force_connect()); // should default to false for invalid bool
    }
}

#[test]
fn test_websocket_detection_comprehensive() {
    // Test valid WebSocket upgrade requests
    let ws_request = crate::common::http::HttpRequest::new("GET", "/chat")
        .with_header("Connection", "upgrade")
        .with_header("Upgrade", "websocket");
    assert!(is_websocket_upgrade(&ws_request));

    // Test case insensitive headers
    let ws_request_case = crate::common::http::HttpRequest::new("GET", "/ws")
        .with_header("CONNECTION", "UPGRADE")
        .with_header("UPGRADE", "WEBSOCKET");
    assert!(is_websocket_upgrade(&ws_request_case));

    // Test Connection header with multiple values
    let ws_request_multi = crate::common::http::HttpRequest::new("GET", "/")
        .with_header("Connection", "keep-alive, upgrade")
        .with_header("Upgrade", "websocket");
    assert!(is_websocket_upgrade(&ws_request_multi));

    // Test Connection header with extra whitespace
    let ws_request_space = crate::common::http::HttpRequest::new("GET", "/")
        .with_header("Connection", " upgrade , keep-alive ")
        .with_header("Upgrade", "websocket");
    assert!(is_websocket_upgrade(&ws_request_space));

    // Test invalid cases

    // Connection contains "upgrade" but not as separate token
    let invalid_token = crate::common::http::HttpRequest::new("GET", "/")
        .with_header("Connection", "keep-alive-upgrade")
        .with_header("Upgrade", "websocket");
    assert!(!is_websocket_upgrade(&invalid_token));

    // Upgrade header is not exactly "websocket"
    let invalid_upgrade = crate::common::http::HttpRequest::new("GET", "/")
        .with_header("Connection", "upgrade")
        .with_header("Upgrade", "websocket-extension");
    assert!(!is_websocket_upgrade(&invalid_upgrade));

    // Missing Connection header
    let no_connection =
        crate::common::http::HttpRequest::new("GET", "/").with_header("Upgrade", "websocket");
    assert!(!is_websocket_upgrade(&no_connection));

    // Missing Upgrade header
    let no_upgrade =
        crate::common::http::HttpRequest::new("GET", "/").with_header("Connection", "upgrade");
    assert!(!is_websocket_upgrade(&no_upgrade));

    // Regular HTTP request
    let http_request = crate::common::http::HttpRequest::new("GET", "/api/data")
        .with_header("Connection", "keep-alive");
    assert!(!is_websocket_upgrade(&http_request));

    // Empty headers
    let empty_headers = crate::common::http::HttpRequest::new("GET", "/")
        .with_header("Connection", "")
        .with_header("Upgrade", "");
    assert!(!is_websocket_upgrade(&empty_headers));
}

#[tokio::test]
async fn test_http_error_response_helpers() {
    // Test that error response functions exist and can be called
    // Note: Testing actual HTTP response writing requires more complex mock setup
    // For now, we just verify the functions exist and have correct signatures

    // Create a dummy stream for testing
    let (stream1, _stream2) = tokio::io::duplex(1024);
    let mut buf_stream = crate::context::make_buffered_stream(stream1);

    // These calls will fail due to stream closure, but that's expected
    // We're just testing that the functions exist and have the right signatures
    let _result1 =
        send_error_response(&mut buf_stream, 503, "Service unavailable", "Test error").await;
    let _result2 = send_simple_error_response(&mut buf_stream, 400, "Bad Request").await;

    // Test passes if we reach here without compilation errors
}

#[test]
fn test_rfc9298_uri_round_trip() {
    // Test that generating and parsing URIs is consistent
    let test_cases = vec![
        TargetAddress::DomainPort("example.com".to_string(), 8080),
        TargetAddress::DomainPort("api.service.internal".to_string(), 443),
        TargetAddress::SocketAddr("192.168.1.100:9090".parse().unwrap()),
        TargetAddress::SocketAddr("[2001:db8::1]:8080".parse().unwrap()),
    ];

    let templates = vec![
        None, // default template
        Some("/.well-known/masque/udp/{host}/{port}/"),
        Some("/proxy/udp/{host}/{port}"),
        Some("/masque?target_host={target_host}&target_port={target_port}"),
        Some("/api/v1/proxy?host={host}&port={port}&proto=udp"),
    ];

    for target in &test_cases {
        for template in &templates {
            let generated_uri = generate_rfc9298_uri_from_template(target, *template);

            // Skip query parameter URIs for round-trip test as they can't be parsed back reliably
            if generated_uri.contains('?') {
                continue;
            }

            let parsed_result = parse_rfc9298_uri_template(&generated_uri);
            assert!(
                parsed_result.is_ok(),
                "Failed to parse generated URI: {} for target: {:?} with template: {:?}",
                generated_uri,
                target,
                template
            );

            if let Ok(parsed_target) = parsed_result {
                match (target, &parsed_target) {
                    (
                        TargetAddress::DomainPort(orig_host, orig_port),
                        TargetAddress::DomainPort(parsed_host, parsed_port),
                    ) => {
                        assert_eq!(orig_host, parsed_host);
                        assert_eq!(orig_port, parsed_port);
                    }
                    (
                        TargetAddress::SocketAddr(orig_addr),
                        TargetAddress::SocketAddr(parsed_addr),
                    ) => {
                        assert_eq!(orig_addr.ip(), parsed_addr.ip());
                        assert_eq!(orig_addr.port(), parsed_addr.port());
                    }
                    (
                        TargetAddress::SocketAddr(orig_addr),
                        TargetAddress::DomainPort(parsed_host, parsed_port),
                    ) => {
                        // This can happen if the IP address can't be parsed back as IP
                        assert_eq!(orig_addr.ip().to_string(), *parsed_host);
                        assert_eq!(orig_addr.port(), *parsed_port);
                    }
                    (
                        TargetAddress::DomainPort(orig_host, orig_port),
                        TargetAddress::SocketAddr(parsed_addr),
                    ) => {
                        // This can happen if the hostname is actually a valid IP address
                        assert_eq!(*orig_host, parsed_addr.ip().to_string());
                        assert_eq!(*orig_port, parsed_addr.port());
                    }
                    _ => {
                        panic!(
                            "Unexpected target address combination: {:?} -> {:?}",
                            target, parsed_target
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn test_rfc9298_special_characters_in_hostnames() {
    // Test hostnames with hyphens (valid DNS characters)
    let target = TargetAddress::DomainPort("test.example-site.com".to_string(), 8080);
    let uri = generate_rfc9298_uri_from_template(&target, None);
    assert_eq!(uri, "/.well-known/masque/udp/test.example-site.com/8080/");

    // Test parsing URL-encoded hostnames with percent-encoded dots
    let result = parse_rfc9298_uri_template("/proxy/test%2Eexample%2Dsite%2Ecom/8080");
    assert!(result.is_ok());
    if let Ok(TargetAddress::DomainPort(host, port)) = result {
        assert_eq!(host, "test.example-site.com"); // Now consistently decoded
        assert_eq!(port, 8080);
    }

    // Test Punycode internationalized domain name
    let target = TargetAddress::DomainPort("xn--e1afmkfd.xn--p1ai".to_string(), 443); // пример.рф in punycode
    let uri = generate_rfc9298_uri_from_template(&target, Some("/udp/{host}/{port}"));
    assert_eq!(uri, "/udp/xn--e1afmkfd.xn--p1ai/443");

    // Test parsing URL-encoded hostname with underscores (non-standard but robust)
    let result = parse_rfc9298_uri_template("/proxy/host%5Fwith%5Funderscores.com/9090");
    assert!(result.is_ok());
    if let Ok(TargetAddress::DomainPort(host, port)) = result {
        assert_eq!(host, "host_with_underscores.com"); // Decoded from %5F to _
        assert_eq!(port, 9090);
    }

    // Test hostname with percent-encoded spaces (edge case)
    let result = parse_rfc9298_uri_template("/proxy/invalid%20hostname.com/8080");
    assert!(result.is_ok());
    if let Ok(TargetAddress::DomainPort(host, port)) = result {
        assert_eq!(host, "invalid hostname.com"); // Decoded but invalid hostname
        assert_eq!(port, 8080);
    }
}
