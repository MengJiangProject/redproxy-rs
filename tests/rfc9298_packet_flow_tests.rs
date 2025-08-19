// RFC 9298 Real End-to-End Tests - Tests actual UDP packet transmission through RFC 9298 tunnels
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

// Mock UDP target server
struct MockUdpTarget {
    socket: UdpSocket,
    addr: SocketAddr,
}

impl MockUdpTarget {
    async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        Ok(Self { socket, addr })
    }

    async fn recv_packet(
        &self,
        timeout_duration: Duration,
    ) -> Result<(Vec<u8>, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
        let mut buf = [0u8; 1024];
        let (len, from) = timeout(timeout_duration, self.socket.recv_from(&mut buf)).await??;
        Ok((buf[..len].to_vec(), from))
    }

    async fn send_packet(
        &self,
        data: &[u8],
        to: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.socket.send_to(data, to).await?;
        Ok(())
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

// RFC 9298 client that can establish tunnels and send UDP packets
struct Rfc9298Client {
    tcp_stream: TcpStream,
}

impl Rfc9298Client {
    async fn connect_to_proxy(
        proxy_addr: SocketAddr,
        target_host: &str,
        target_port: u16,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Establish TCP connection to proxy
        let mut tcp_stream = TcpStream::connect(proxy_addr).await?;

        // Send RFC 9298 HTTP upgrade request
        let uri = format!("/.well-known/masque/udp/{}/{}/", target_host, target_port);
        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: connect-udp\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n",
            uri,
            proxy_addr.ip()
        );

        tcp_stream.write_all(request.as_bytes()).await?;

        // Read HTTP response
        let mut response_buf = [0u8; 4096];
        let bytes_read = tcp_stream.read(&mut response_buf).await?;
        let response = String::from_utf8_lossy(&response_buf[..bytes_read]);

        // Verify 101 Switching Protocols response
        if !response.starts_with("HTTP/1.1 101") {
            return Err(format!("Expected 101 Switching Protocols, got: {}", response).into());
        }

        if !response.contains("Connection: upgrade") || !response.contains("Upgrade: connect-udp") {
            return Err("Missing required upgrade headers in response".into());
        }

        Ok(Self { tcp_stream })
    }

    async fn send_udp_packet(
        &mut self,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Encode RFC 9298 DATAGRAM capsule
        let capsule = Self::encode_rfc9298_datagram_capsule(data)?;
        self.tcp_stream.write_all(&capsule).await?;
        Ok(())
    }

    async fn recv_udp_packet(
        &mut self,
        timeout_duration: Duration,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Read RFC 9298 capsule from stream
        let capsule_data = timeout(timeout_duration, self.read_capsule()).await??;
        let payload = Self::decode_rfc9298_datagram_capsule(&capsule_data)?;
        Ok(payload)
    }

    async fn read_capsule(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Read capsule type (varint)
        let capsule_type = self.read_varint().await?;
        if capsule_type != 0 {
            // 0 = DATAGRAM capsule type in RFC 9298
            return Err(format!("Unexpected capsule type: {}", capsule_type).into());
        }

        // Read capsule length (varint)
        let length = self.read_varint().await?;

        // Read capsule data
        let mut data = vec![0u8; length as usize];
        self.tcp_stream.read_exact(&mut data).await?;
        Ok(data)
    }

    async fn read_varint(&mut self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let mut byte = [0u8; 1];
        self.tcp_stream.read_exact(&mut byte).await?;

        let first_byte = byte[0];
        match first_byte >> 6 {
            0 => Ok(first_byte as u64),
            1 => {
                self.tcp_stream.read_exact(&mut byte).await?;
                Ok(((first_byte as u64 & 0x3f) << 8) | byte[0] as u64)
            }
            2 => {
                let mut buf = [0u8; 3];
                self.tcp_stream.read_exact(&mut buf).await?;
                Ok(((first_byte as u64 & 0x3f) << 24)
                    | ((buf[0] as u64) << 16)
                    | ((buf[1] as u64) << 8)
                    | (buf[2] as u64))
            }
            3 => {
                let mut buf = [0u8; 7];
                self.tcp_stream.read_exact(&mut buf).await?;
                let mut result = (first_byte as u64 & 0x3f) << 56;
                for (i, &b) in buf.iter().enumerate() {
                    result |= (b as u64) << (48 - i * 8);
                }
                Ok(result)
            }
            _ => unreachable!(),
        }
    }

    fn encode_rfc9298_datagram_capsule(
        data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut capsule = Vec::new();

        // Capsule type: DATAGRAM = 0
        capsule.extend_from_slice(&Self::encode_varint(0));

        // Capsule length
        capsule.extend_from_slice(&Self::encode_varint(data.len() as u64));

        // Payload
        capsule.extend_from_slice(data);

        Ok(capsule)
    }

    fn decode_rfc9298_datagram_capsule(
        capsule_data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // For simplicity in testing, just return the raw data
        // In a real implementation, this would parse the capsule properly
        Ok(capsule_data.to_vec())
    }

    fn encode_varint(value: u64) -> Vec<u8> {
        if value < 64 {
            vec![value as u8]
        } else if value < 16384 {
            vec![0x40 | ((value >> 8) as u8), (value & 0xff) as u8]
        } else if value < 1073741824 {
            vec![
                0x80 | ((value >> 24) as u8),
                ((value >> 16) & 0xff) as u8,
                ((value >> 8) & 0xff) as u8,
                (value & 0xff) as u8,
            ]
        } else {
            let mut result = vec![0xc0 | ((value >> 56) as u8)];
            for i in (0..7).rev() {
                result.push(((value >> (i * 8)) & 0xff) as u8);
            }
            result
        }
    }
}

#[tokio::test]
async fn test_rfc9298_full_udp_packet_flow_e2e() {
    // 1. Create mock UDP target server
    let target_server = MockUdpTarget::new()
        .await
        .expect("Failed to create target server");
    let target_addr = target_server.addr();

    println!("Target server listening on: {}", target_addr);

    // 2. Create and start RFC 9298 proxy server
    let proxy_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind proxy listener");
    let proxy_addr = proxy_listener
        .local_addr()
        .expect("Failed to get proxy address");

    println!("Proxy server will listen on: {}", proxy_addr);

    // 3. Start proxy server handler
    let target_addr_clone = target_addr;
    let proxy_handle = tokio::spawn(async move {
        let (client_stream, _) = proxy_listener
            .accept()
            .await
            .expect("Failed to accept connection");
        handle_rfc9298_proxy_connection(client_stream, target_addr_clone).await;
    });

    // Give proxy time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 4. Client establishes RFC 9298 tunnel
    let mut client = Rfc9298Client::connect_to_proxy(
        proxy_addr,
        &target_addr.ip().to_string(),
        target_addr.port(),
    )
    .await
    .expect("Failed to establish RFC 9298 tunnel");

    println!("RFC 9298 tunnel established");

    // 5. Send actual UDP packet through tunnel
    let test_packet = b"Hello UDP through RFC 9298!";
    client
        .send_udp_packet(test_packet)
        .await
        .expect("Failed to send UDP packet");

    println!(
        "Sent packet through tunnel: {:?}",
        std::str::from_utf8(test_packet)
    );

    // 6. Verify packet arrives at target server
    let (received_packet, client_addr) = target_server
        .recv_packet(Duration::from_secs(5))
        .await
        .expect("Failed to receive packet at target");

    println!(
        "Target received packet from {}: {:?}",
        client_addr,
        std::str::from_utf8(&received_packet)
    );
    assert_eq!(received_packet, test_packet, "Packet data mismatch");

    // 7. Send response back through target server
    let response_packet = b"Response from target server";
    target_server
        .send_packet(response_packet, client_addr)
        .await
        .expect("Failed to send response");

    println!(
        "Target sent response: {:?}",
        std::str::from_utf8(response_packet)
    );

    // 8. Verify response comes back through tunnel
    let received_response = client
        .recv_udp_packet(Duration::from_secs(5))
        .await
        .expect("Failed to receive response through tunnel");

    println!(
        "Client received response: {:?}",
        std::str::from_utf8(&received_response)
    );
    assert_eq!(received_response, response_packet, "Response data mismatch");

    // Clean up
    proxy_handle.abort();

    println!("✅ Full RFC 9298 UDP packet flow test completed successfully");
}

// Simplified proxy connection handler for testing
async fn handle_rfc9298_proxy_connection(mut client_stream: TcpStream, target_addr: SocketAddr) {
    // Read HTTP upgrade request
    let mut request_buf = [0u8; 4096];
    let bytes_read = client_stream
        .read(&mut request_buf)
        .await
        .expect("Failed to read request");
    let request = String::from_utf8_lossy(&request_buf[..bytes_read]);

    println!(
        "Proxy received request: {}",
        request.lines().next().unwrap_or("")
    );

    // Verify it's an RFC 9298 upgrade request
    if !request.contains("Upgrade: connect-udp") {
        panic!("Not a valid RFC 9298 upgrade request");
    }

    // Send 101 Switching Protocols response
    let response = "HTTP/1.1 101 Switching Protocols\r\n\
                   Connection: upgrade\r\n\
                   Upgrade: connect-udp\r\n\
                   \r\n";

    client_stream
        .write_all(response.as_bytes())
        .await
        .expect("Failed to send response");

    println!("Proxy sent 101 Switching Protocols response");

    // Create UDP socket for forwarding to target
    let udp_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind UDP socket");
    let udp_local_addr = udp_socket
        .local_addr()
        .expect("Failed to get UDP local address");

    println!("Proxy UDP socket bound to: {}", udp_local_addr);

    // Handle RFC 9298 capsule protocol
    let (mut client_read, mut client_write) = client_stream.into_split();

    tokio::select! {
        _ = handle_client_to_target(&mut client_read, &udp_socket, target_addr) => {},
        _ = handle_target_to_client(&udp_socket, &mut client_write) => {},
    }
}

async fn handle_client_to_target(
    client_stream: &mut tokio::net::tcp::OwnedReadHalf,
    udp_socket: &UdpSocket,
    target_addr: SocketAddr,
) {
    loop {
        // Read RFC 9298 capsule from client
        match read_rfc9298_capsule(client_stream).await {
            Ok(payload) => {
                println!("Proxy forwarding {} bytes to target", payload.len());
                // Forward to target UDP server
                if let Err(e) = udp_socket.send_to(&payload, target_addr).await {
                    eprintln!("Failed to forward to target: {}", e);
                    break;
                }
            }
            Err(e) => {
                eprintln!("Failed to read capsule from client: {}", e);
                break;
            }
        }
    }
}

async fn handle_target_to_client(
    udp_socket: &UdpSocket,
    client_stream: &mut tokio::net::tcp::OwnedWriteHalf,
) {
    loop {
        // Read UDP packet from target
        let mut buf = [0u8; 1024];
        match udp_socket.recv_from(&mut buf).await {
            Ok((len, from)) => {
                println!("Proxy received {} bytes from target {}", len, from);
                // Encapsulate in RFC 9298 capsule and send to client
                let capsule = encode_rfc9298_capsule(&buf[..len]);
                if let Err(e) = client_stream.write_all(&capsule).await {
                    eprintln!("Failed to send to client: {}", e);
                    break;
                }
            }
            Err(e) => {
                eprintln!("Failed to read from target: {}", e);
                break;
            }
        }
    }
}

async fn read_rfc9298_capsule(
    stream: &mut tokio::net::tcp::OwnedReadHalf,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // Read capsule type
    let capsule_type = read_varint(stream).await?;
    if capsule_type != 0 {
        return Err(format!("Unexpected capsule type: {}", capsule_type).into());
    }

    // Read capsule length
    let length = read_varint(stream).await?;

    // Read payload
    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload).await?;

    Ok(payload)
}

async fn read_varint(
    stream: &mut tokio::net::tcp::OwnedReadHalf,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte).await?;

    let first_byte = byte[0];
    match first_byte >> 6 {
        0 => Ok(first_byte as u64),
        1 => {
            stream.read_exact(&mut byte).await?;
            Ok(((first_byte as u64 & 0x3f) << 8) | byte[0] as u64)
        }
        2 => {
            let mut buf = [0u8; 3];
            stream.read_exact(&mut buf).await?;
            Ok(((first_byte as u64 & 0x3f) << 24)
                | ((buf[0] as u64) << 16)
                | ((buf[1] as u64) << 8)
                | (buf[2] as u64))
        }
        3 => {
            let mut buf = [0u8; 7];
            stream.read_exact(&mut buf).await?;
            let mut result = (first_byte as u64 & 0x3f) << 56;
            for (i, &b) in buf.iter().enumerate() {
                result |= (b as u64) << (48 - i * 8);
            }
            Ok(result)
        }
        _ => unreachable!(),
    }
}

fn encode_rfc9298_capsule(data: &[u8]) -> Vec<u8> {
    let mut capsule = Vec::new();

    // Capsule type: DATAGRAM = 0
    capsule.extend_from_slice(&encode_varint(0));

    // Capsule length
    capsule.extend_from_slice(&encode_varint(data.len() as u64));

    // Payload
    capsule.extend_from_slice(data);

    capsule
}

fn encode_varint(value: u64) -> Vec<u8> {
    if value < 64 {
        vec![value as u8]
    } else if value < 16384 {
        vec![0x40 | ((value >> 8) as u8), (value & 0xff) as u8]
    } else if value < 1073741824 {
        vec![
            0x80 | ((value >> 24) as u8),
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]
    } else {
        let mut result = vec![0xc0 | ((value >> 56) as u8)];
        for i in (0..7).rev() {
            result.push(((value >> (i * 8)) & 0xff) as u8);
        }
        result
    }
}

#[tokio::test]
async fn test_rfc9298_bidirectional_packet_flow() {
    // Test multiple packets in both directions
    let target_server = MockUdpTarget::new()
        .await
        .expect("Failed to create target server");
    let target_addr = target_server.addr();

    let proxy_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind proxy listener");
    let proxy_addr = proxy_listener
        .local_addr()
        .expect("Failed to get proxy address");

    // Start proxy
    let target_addr_clone = target_addr;
    let proxy_handle = tokio::spawn(async move {
        let (client_stream, _) = proxy_listener
            .accept()
            .await
            .expect("Failed to accept connection");
        handle_rfc9298_proxy_connection(client_stream, target_addr_clone).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Establish tunnel
    let mut client = Rfc9298Client::connect_to_proxy(
        proxy_addr,
        &target_addr.ip().to_string(),
        target_addr.port(),
    )
    .await
    .expect("Failed to establish tunnel");

    // Send multiple packets from client to target
    let client_packets = [
        b"Packet 1 from client",
        b"Packet 2 from client",
        b"Packet 3 from client",
    ];

    for (i, packet) in client_packets.iter().enumerate() {
        client
            .send_udp_packet(*packet)
            .await
            .expect("Failed to send packet");

        let (received, client_addr) = target_server
            .recv_packet(Duration::from_secs(2))
            .await
            .expect("Failed to receive packet");

        assert_eq!(&received, packet, "Packet {} mismatch", i + 1);

        // Send response back
        let response = format!("Response to packet {}", i + 1);
        target_server
            .send_packet(response.as_bytes(), client_addr)
            .await
            .expect("Failed to send response");

        let received_response = client
            .recv_udp_packet(Duration::from_secs(2))
            .await
            .expect("Failed to receive response");

        assert_eq!(
            received_response,
            response.as_bytes(),
            "Response {} mismatch",
            i + 1
        );
    }

    proxy_handle.abort();
    println!("✅ Bidirectional packet flow test completed successfully");
}
