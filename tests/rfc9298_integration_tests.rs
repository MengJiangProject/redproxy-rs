use redproxy_rs::common::http_proxy::{
    generate_rfc9298_uri_from_template, is_websocket_upgrade, parse_rfc9298_uri_template,
};
use redproxy_rs::connectors::http::UdpProtocolConfig;
use redproxy_rs::context::TargetAddress;

#[test]
fn test_rfc9298_integration_http_upgrade_flow() {
    // Test the full HTTP upgrade flow for RFC 9298

    let mock_request = redproxy_rs::common::http::HttpRequest {
        method: "GET".to_string(),
        resource: "/.well-known/masque/udp/example.com/8080/".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: vec![
            ("Host".to_string(), "proxy.example.com".to_string()),
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Connection".to_string(), "Upgrade".to_string()),
            (
                "Sec-WebSocket-Key".to_string(),
                "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            ),
            ("Sec-WebSocket-Version".to_string(), "13".to_string()),
        ],
    };

    assert!(is_websocket_upgrade(&mock_request));

    // Test URI parsing from the request path
    let parsed_target = parse_rfc9298_uri_template(&mock_request.resource).unwrap();
    match parsed_target {
        TargetAddress::DomainPort(host, port) => {
            assert_eq!(host, "example.com");
            assert_eq!(port, 8080);
        }
        _ => panic!("Expected DomainPort target"),
    }
}

#[test]
fn test_rfc9298_connector_integration() {
    // Test RFC 9298 connector configuration and validation
    let default_config = UdpProtocolConfig::default();

    // Test that default configuration works
    assert_eq!(default_config.protocol_name(), "custom");
    assert!(default_config.validate().is_ok());

    // Test URI generation with different templates
    let target = TargetAddress::DomainPort("api.example.com".to_string(), 443);

    let default_uri = generate_rfc9298_uri_from_template(&target, None);
    let custom_uri = generate_rfc9298_uri_from_template(&target, Some("/proxy/{host}/{port}"));

    assert_eq!(default_uri, "/.well-known/masque/udp/api.example.com/443/");
    assert_eq!(custom_uri, "/proxy/api.example.com/443");

    // Test that different templates produce different URIs
    assert_ne!(default_uri, custom_uri);
}

#[test]
fn test_rfc9298_end_to_end_mock_scenario() {
    // End-to-end test simulating a complete RFC 9298 proxy scenario

    // Step 1: Client sends HTTP upgrade request
    let client_request = redproxy_rs::common::http::HttpRequest {
        method: "GET".to_string(),
        resource: "/.well-known/masque/udp/192.168.1.100/53/".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: vec![
            ("Host".to_string(), "dns-proxy.internal".to_string()),
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Connection".to_string(), "Upgrade".to_string()),
            (
                "Sec-WebSocket-Key".to_string(),
                "x3JJHMbDL1EzLkh9GBhXDw==".to_string(),
            ),
            ("Sec-WebSocket-Version".to_string(), "13".to_string()),
        ],
    };

    // Step 2: Validate it's a WebSocket upgrade
    assert!(is_websocket_upgrade(&client_request));

    // Step 3: Parse target from URI
    let target = parse_rfc9298_uri_template(&client_request.resource).unwrap();
    match target {
        TargetAddress::SocketAddr(addr) => {
            assert_eq!(addr.ip().to_string(), "192.168.1.100");
            assert_eq!(addr.port(), 53);
        }
        _ => panic!("Expected SocketAddr for IP address"),
    }
}

#[test]
fn test_rfc9298_error_handling_integration() {
    // Test error handling and edge cases in integration context

    // Test invalid URI parsing
    let invalid_uris = [
        "/invalid/path",
        "/proxy/",
        "/proxy/host",
        "/proxy/host/invalid_port",
        "/proxy/{template_var}/8080",
        "invalid_uri_format",
    ];

    for uri in &invalid_uris {
        let result = parse_rfc9298_uri_template(uri);
        assert!(result.is_err(), "Expected error for URI: {}", uri);
    }

    // Test missing WebSocket headers
    let non_websocket_request = redproxy_rs::common::http::HttpRequest {
        method: "GET".to_string(),
        resource: "/.well-known/masque/udp/example.com/8080/".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: vec![("Host".to_string(), "proxy.example.com".to_string())],
    };

    assert!(!is_websocket_upgrade(&non_websocket_request));
}
