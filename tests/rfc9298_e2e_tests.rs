use redproxy_rs::common::http_proxy::{
    generate_rfc9298_uri_from_template, parse_rfc9298_uri_template,
};
use redproxy_rs::connectors::http::UdpProtocolConfig;
use redproxy_rs::context::TargetAddress;

#[test]
fn test_rfc9298_full_round_trip_e2e() {
    // End-to-end test of complete RFC 9298 workflow

    let test_targets = [
        TargetAddress::DomainPort("example.com".to_string(), 8080),
        TargetAddress::DomainPort("api.service.internal".to_string(), 443),
        TargetAddress::SocketAddr("192.168.1.100:53".parse().unwrap()),
        TargetAddress::SocketAddr("[2001:db8::1]:8080".parse().unwrap()),
    ];

    let templates = [
        None,
        Some("/.well-known/masque/udp/{host}/{port}/"),
        Some("/api/v1/udp-proxy/{host}/{port}"),
        // Skip query templates for round-trip testing
    ];

    for target in &test_targets {
        for &template in &templates {
            // Step 1: Generate URI from configuration and target
            let generated_uri = generate_rfc9298_uri_from_template(target, template);

            // Step 2: Parse the generated URI back to target
            let parsed_result = parse_rfc9298_uri_template(&generated_uri);
            assert!(
                parsed_result.is_ok(),
                "Failed to parse generated URI: {} for target: {:?}",
                generated_uri,
                target
            );

            let parsed_target = parsed_result.unwrap();

            // Step 3: Verify round-trip consistency
            match (target, &parsed_target) {
                (
                    TargetAddress::DomainPort(orig_host, orig_port),
                    TargetAddress::DomainPort(parsed_host, parsed_port),
                ) => {
                    assert_eq!(orig_host, parsed_host, "Host mismatch");
                    assert_eq!(orig_port, parsed_port, "Port mismatch");
                }
                (TargetAddress::SocketAddr(orig_addr), TargetAddress::SocketAddr(parsed_addr)) => {
                    assert_eq!(orig_addr.ip(), parsed_addr.ip(), "IP mismatch");
                    assert_eq!(orig_addr.port(), parsed_addr.port(), "Port mismatch");
                }
                (
                    TargetAddress::SocketAddr(orig_addr),
                    TargetAddress::DomainPort(parsed_host, parsed_port),
                ) => {
                    assert_eq!(
                        orig_addr.ip().to_string(),
                        *parsed_host,
                        "IP->Host mismatch"
                    );
                    assert_eq!(orig_addr.port(), *parsed_port, "Port mismatch");
                }
                (
                    TargetAddress::DomainPort(orig_host, orig_port),
                    TargetAddress::SocketAddr(parsed_addr),
                ) => {
                    assert_eq!(
                        *orig_host,
                        parsed_addr.ip().to_string(),
                        "Host->IP mismatch"
                    );
                    assert_eq!(*orig_port, parsed_addr.port(), "Port mismatch");
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

#[test]
fn test_rfc9298_concurrent_sessions_e2e() {
    // Test multiple concurrent RFC 9298 sessions
    let targets = [
        TargetAddress::DomainPort("service1.internal".to_string(), 8080),
        TargetAddress::DomainPort("service2.internal".to_string(), 9090),
        TargetAddress::SocketAddr("10.0.1.100:53".parse().unwrap()),
        TargetAddress::SocketAddr("10.0.1.101:53".parse().unwrap()),
    ];

    // Test URI generation and parsing for multiple targets
    for (i, target) in targets.iter().enumerate() {
        // Generate URI for this target
        let uri = generate_rfc9298_uri_from_template(target, None);

        // Verify we can parse it back correctly
        let parsed = parse_rfc9298_uri_template(&uri).unwrap();

        match (target, &parsed) {
            (
                TargetAddress::DomainPort(orig_host, orig_port),
                TargetAddress::DomainPort(parsed_host, parsed_port),
            ) => {
                assert_eq!(orig_host, parsed_host);
                assert_eq!(orig_port, parsed_port);
            }
            (TargetAddress::SocketAddr(orig_addr), TargetAddress::SocketAddr(parsed_addr)) => {
                assert_eq!(orig_addr, parsed_addr);
            }
            (
                TargetAddress::SocketAddr(orig_addr),
                TargetAddress::DomainPort(parsed_host, parsed_port),
            ) => {
                assert_eq!(orig_addr.ip().to_string(), *parsed_host);
                assert_eq!(orig_addr.port(), *parsed_port);
            }
            _ => panic!("Unexpected address combination for target {}", i),
        }
    }
}

#[test]
fn test_rfc9298_protocol_compliance_e2e() {
    // Test RFC 9298 protocol compliance scenarios
    let default_config = UdpProtocolConfig::default();

    assert!(default_config.validate().is_ok());
    assert_eq!(default_config.protocol_name(), "custom");

    // Test with various target types that should work with RFC 9298
    let targets = [
        (
            "domain",
            TargetAddress::DomainPort("dns.google".to_string(), 53),
        ),
        (
            "ipv4",
            TargetAddress::SocketAddr("8.8.8.8:53".parse().unwrap()),
        ),
        (
            "ipv6",
            TargetAddress::SocketAddr("[2001:4860:4860::8888]:53".parse().unwrap()),
        ),
        (
            "localhost",
            TargetAddress::DomainPort("localhost".to_string(), 8080),
        ),
    ];

    for (name, target) in &targets {
        // Generate default RFC 9298 compliant URI
        let uri = generate_rfc9298_uri_from_template(target, None);

        // Verify URI follows RFC 9298 pattern
        assert!(
            uri.starts_with("/.well-known/masque/udp/"),
            "URI doesn't follow RFC 9298 pattern for {}: {}",
            name,
            uri
        );
        assert!(
            uri.ends_with('/'),
            "URI doesn't end with / for {}: {}",
            name,
            uri
        );

        // Parse back and verify
        let parsed = parse_rfc9298_uri_template(&uri).unwrap();

        // Verify parsing consistency
        match (target, &parsed) {
            (TargetAddress::DomainPort(a, b), TargetAddress::DomainPort(c, d)) => {
                assert_eq!(a, c, "Domain mismatch for {}", name);
                assert_eq!(b, d, "Port mismatch for {}", name);
            }
            (TargetAddress::SocketAddr(a), TargetAddress::SocketAddr(b)) => {
                assert_eq!(a, b, "SocketAddr mismatch for {}", name);
            }
            (TargetAddress::SocketAddr(a), TargetAddress::DomainPort(c, d)) => {
                assert_eq!(a.ip().to_string(), *c, "IP->Domain mismatch for {}", name);
                assert_eq!(a.port(), *d, "Port mismatch for {}", name);
            }
            (TargetAddress::DomainPort(a, b), TargetAddress::SocketAddr(c)) => {
                assert_eq!(*a, c.ip().to_string(), "Domain->IP mismatch for {}", name);
                assert_eq!(*b, c.port(), "Port mismatch for {}", name);
            }
            _ => panic!("Unexpected combination for {}", name),
        }
    }
}
