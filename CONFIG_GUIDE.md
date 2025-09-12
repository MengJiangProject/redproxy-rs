# Configuration Guide for config.yaml

This document provides a detailed explanation of the `config.yaml` file used by the proxy.

## 1. I/O Parameters (`ioParams`)

The `ioParams` section allows fine-tuning of input/output operations. These settings are optional, and the proxy will use default values if this section is omitted. It's recommended not to change these unless you have a clear understanding of their impact.

-   `bufferSize` (integer): Defines the size of the buffer (in bytes) used for I/O operations.
    -   *Default value*: `65536` (64KB)
-   `useSplice` (boolean): Toggles the use of the `splice()` system call on Linux for zero-copy data transfer between kernel buffers. This can improve performance by avoiding data copying between user space and kernel space.
    -   *Default value*: `true`
    -   *Note*: This setting is effective only on Linux systems that support `splice()`.

Example:
```yaml
ioParams:
  bufferSize: 65536
  useSplice: true
```

## 2. Metrics Configuration (`metrics`)

The entire `metrics` section is optional. The `metrics` section configures an HTTP endpoint for exposing Prometheus-compatible metrics and potentially a web UI.

-   `api_prefix` (string, optional): Specifies the URL prefix for the metrics API.
    -   *Default value*: `/api`
    -   If you change this, the metrics endpoint will be available at `http://<bind_address><api_prefix>/metrics`.
-   `ui` (string, optional): Defines the path to static files for a web UI. If the proxy is compiled with the `embedded-ui` feature, the default value is `"<embedded>"` to use the built-in UI. Otherwise, it defaults to being disabled (equivalent to `null`). You can specify a local directory path (e.g., `./ui`) to serve custom UI files.
-   `bind` (string): The IP address and port on which the metrics and UI server will listen.
    -   *Example*: `"0.0.0.0:8888"` will listen on port 8888 on all available network interfaces.
-   `history_size` (integer, optional): Specifies the maximum number of entries to keep in the connection history accessible via the API (e.g., `/api/history`).
    -   *Default value*: `100`
-   `cors` (string, optional): Configures the `Access-Control-Allow-Origin` header for the metrics and API endpoints.
    -   *Default value*: `"*"` (allows all origins)

Example:
```yaml
metrics:
  # api_prefix: /api
  # ui: ./ui # or "<embedded>" if compiled with embedded-ui feature
  # history_size: 100
  # cors: "*"
  bind: "0.0.0.0:8888"
```

## 3. Timeouts Configuration (`timeouts`)

The `timeouts` section allows you to define global timeout values for connections.

-   `idle` (integer): Specifies the timeout in seconds for idle connections. If a connection (e.g., TCP) remains inactive for this duration, it will be closed.
    -   *Default value*: `600` seconds (10 minutes), as indicated by comments in the example `config.yaml`. The example shows `10`.
-   `udp` (integer): Specifies the timeout in seconds for UDP associations. If a UDP session sees no traffic for this duration, it will be considered stale and resources may be cleaned up.
    -   *Default value*: `600` seconds (10 minutes), as indicated by comments in the example `config.yaml`. The example shows `10`.

*Note*: The example `config.yaml` shows these values set to `10`. Ensure you are using values appropriate for your environment. The default values mentioned in the comments (`600`) might be from the application's internal defaults if these fields are omitted, while the `10` in the example is an explicit override.

Example:
```yaml
timeouts:
  idle: 10 # unit: seconds, default value: 600
  udp: 10 # unit: seconds, default value: 600
```

## 4. Listeners Configuration (`listeners`)

The `listeners` section is a list that defines how the proxy listens for incoming connections. Each item in the list is a listener configuration object.

### Common Listener Parameters

Most listener types share some common parameters:

-   `name` (string): A descriptive name for the listener. If the `type` parameter is omitted, the proxy may attempt to infer the listener type from this `name` (e.g., a name like "http" might imply an HTTP listener).
-   `bind` (string): The IP address and port on which the listener will accept connections.
    -   *Example*: `"0.0.0.0:8080"` will listen on port 8080 on all available network interfaces.
-   `protocol` (string, optional): Specifies the transport protocol for the listener.
    -   *Common values*: `tcp` (default), `udp`.
    -   The default is usually `tcp` if not specified.
-   `type` (string, optional): Explicitly defines the type of the listener. If omitted, the type might be inferred from the `name` field. It's good practice to specify the `type` for clarity.

---

### Listener Types

#### 4.1. Transparent Proxy (`tproxy`)

*Availability: This listener type is only available when the proxy is compiled for Linux or Android systems.*

The `tproxy` listener allows the proxy to intercept traffic transparently, often used in gateway setups. This typically requires specific system configurations (e.g., iptables rules on Linux) to redirect traffic to this listener.

-   **`type: tproxy`** (or inferred from `name`)
-   **Common Parameters**: `bind`, `protocol` (can be `tcp` or `udp`).

##### `tproxy` specific for `protocol: udp`

When `protocol` is `udp`, `tproxy` has additional options:

-   `udpFullCone` (boolean):
    -   *Default value*: `false`.
    -   If `false` (restrictive NAT), the proxy maintains a mapping based on source IP/port and destination IP/port. This is generally faster and allows filtering by destination address.
    -   If `true` (full cone NAT), the proxy maintains a mapping based only on the source IP/port, allowing any external host to send packets to the client once the client has sent a packet out. This is slower and cannot filter by destination address.
    -   *Note*: The `config.yaml` comments state that SOCKS5 upstreams only support full cone NAT.
-   `udpMaxSocket` (integer):
    -   *Default value*: `128`.
    -   Only applicable when `udpFullCone` is `true`.
    -   Controls the number of sockets cached for sending UDP replies. Increasing this might be necessary for high-traffic full cone NAT scenarios.

*System Requirements for UDP TProxy*:
The comments in `config.yaml` note that UDP tproxy listeners require `CAP_NET_ADMIN` capabilities (e.g., set with `setcap cap_net_admin+ep <your_proxy_binary>` or by running as root).

Examples:

```yaml
# TCP tproxy listener
listeners:
  - name: tproxy # type 'tproxy' is inferred
    bind: 0.0.0.0:8080
    protocol: tcp # default if not specified and type is tproxy

# UDP tproxy listener
  - name: tproxy-udp
    type: tproxy
    bind: 0.0.0.0:8080 # Can be the same bind as TCP if differentiated by protocol
    protocol: udp
    udpFullCone: false
    udpMaxSocket: 256
```

---
#### 4.2. Reverse Proxy (`reverse`)

The `reverse` listener acts as a reverse proxy, forwarding incoming connections to a predefined target server.

-   **`type: reverse`**
-   **Common Parameters**: `bind`, `protocol` (can be `tcp` or `udp`).
-   `target` (string): The address and port of the upstream server to which traffic should be forwarded.
    -   *Format*: `"host:port"` or `"domain_name:port"`.
    -   *Example*: `"1.1.1.1:53"` or `"one.one.one.one:53"`.

Example:

```yaml
listeners:
  - name: udp-reverse
    type: reverse
    bind: 0.0.0.0:8053
    target: one.one.one.one:53 # Forwards to Cloudflare DNS
    protocol: udp
```

---
#### 4.3. HTTP Proxy (`http`)

The `http` listener acts as an HTTP proxy. It can handle plain HTTP connections and can be configured for HTTPS by adding a `tls` section.

-   **`type: http`** (or inferred if `name` is "http" or "https")
-   **Common Parameters**: `bind`. The protocol is implicitly TCP for HTTP/S.

##### TLS Configuration for HTTPS

To enable HTTPS, add a `tls` object to the listener configuration.

-   `tls`: Container for TLS settings.
    -   `cert` (string): Path to the server's SSL/TLS certificate file (e.g., `test.crt`).
    -   `key` (string): Path to the server's private key file (e.g., `test.key`).
    -   `client` (object, optional): Configures client certificate authentication (mTLS). If this block is omitted, client certificates are not requested.
        -   `ca` (string): Path to the Certificate Authority (CA) certificate file used to verify client certificates (e.g., `ca.crt`).
        -   `required` (boolean, optional): If `true`, clients must present a valid certificate signed by the specified CA. If `false` or omitted, client certificates are requested but not strictly required for the connection.
            -   *Default value*: `false` (when the `client` block is present).
    -   `protocol` (object, optional, added in *v0.11.0*): TLS protocol version configuration.
        -   `tls_1_2` (boolean, optional): Enable TLS 1.2 support. *Default*: `true`
        -   `tls_1_3` (boolean, optional): Enable TLS 1.3 support. *Default*: `true`
    -   `security` (object, optional, added in *v0.11.0*): Advanced TLS security options.
        -   `sni` (object, optional): Server Name Indication configuration.
            -   `enable` (boolean, optional): Enable SNI support. *Default*: `false`
            -   `certificates` (object, optional): Map of hostnames to certificate configurations.
        -   `ocsp_stapling` (boolean, optional): Enable OCSP stapling for certificate validation. *Default*: `false`
        -   `require_sni` (boolean, optional): Require SNI extension from clients. *Default*: `false`

Examples:

```yaml
listeners:
  # Plain HTTP listener
  - name: http
    bind: 0.0.0.0:8081

  # HTTPS listener with client certificate authentication
  - name: https # type 'http' can be inferred
    type: http # Explicitly setting type
    bind: 0.0.0.0:8082
    tls:
      cert: test.crt
      key: test.key
      client:
        ca: ca.crt
        required: true # Example showing strict requirement

  # Advanced HTTPS listener with SNI support
  - name: https-sni
    type: http
    bind: 0.0.0.0:8443
    tls:
      cert: default.crt  # Default certificate
      key: default.key
      protocol:
        tls_1_3: true    # Enable only TLS 1.3
        tls_1_2: false   # Disable TLS 1.2
      security:
        sni:
          enable: true
          certificates:
            "example.com":
              cert: "example.com.crt"
              key: "example.com.key"
            "api.example.com":
              cert: "api.example.com.crt" 
              key: "api.example.com.key"
        ocsp_stapling: true
        require_sni: true
```

---
#### 4.4. SOCKS Proxy (`socks`)

The `socks` listener implements a SOCKS5 proxy server. This listener can be configured to use TLS for secure SOCKS5 connections (SOCKS over TLS) by including the `tls` section.

-   **`type: socks`** (or inferred if `name` contains "socks")
-   **Common Parameters**: `bind`. Protocol is implicitly TCP for SOCKS5 handshake, UDP can be enabled for associations.
-   `allowUdp` (boolean):
    -   *Default value*: `true`.
    -   Enables UDP associate command handling in SOCKS5, allowing UDP traffic to be proxied.
-   `enforceUdpClient` (boolean):
    -   *Default value*: `false`.
    -   Relevant when `allowUdp` is `true`.
    -   The SOCKS5 RFC1928 (page 6) states: "The server MAY use this information [client IP and port in UDP request] to limit access to the association." If `true`, the proxy might enforce that UDP packets come from the client IP/port that established the association. If `false`, it might be more permissive.
-   `overrideUdpAddress` (string, optional):
    -   *Example*: `"127.0.0.1"`.
    -   If set, this IP address will be returned to the SOCKS client in the BND.ADDR field for UDP associations, instead of the server's actual IP address. This is useful if the proxy server is behind a NAT and the external IP needs to be specified.
-   `allowBind` (boolean, optional): Enables or disables the SOCKS BIND command support.
    -   *Default value*: `false`.
    -   When `true`, clients can use the SOCKS BIND command to create listening sockets for incoming connections.
    -   When `false`, BIND requests are rejected with an appropriate SOCKS error response.
    -   The BIND command is commonly used by FTP clients and other protocols requiring reverse connections.
-   `enforceBindAddress` (boolean, optional): Controls whether the listener ignores client-requested bind addresses for security.
    -   *Default value*: `true`.
    -   Only effective when `allowBind` is `true`.
    -   When `false`, the proxy honors the client's requested bind address and port (normal SOCKS behavior).
    -   When `true`, the proxy ignores the client's request and forces system-allocated addresses (0.0.0.0:0 or :::0).
    -   Setting to `true` (default) provides additional security by preventing clients from binding to specific addresses or ports.
-   `auth` (object, optional): Configures SOCKS5 authentication.
    -   `required` (boolean):
        -   *Default value*: `false`.
        -   If `true`, the client MUST use Username/Password authentication (Method 0x02). The proxy will check credentials against the `users` list or `cmd`.
        -   If `false`, Username/Password authentication is still offered to the client, but the credentials are not necessarily validated against the list/cmd. The comment suggests this is "to satisfy some strange software that do not work with NoAuth option of SOCKS5."
    -   `users` (list of objects, optional): A list of predefined username/password credentials.
        -   Each object has `username` (string) and `password` (string).
    -   `cmd` (list of strings, optional): A command to execute for validating username/password. The proxy will substitute `#USER#` and `#PASS#` with the client's provided credentials. The command should exit with status 0 for success.
        -   *Example*: `["test", "#USER#", "==", "#PASS#"]`
    -   `cache` (object, optional): Configures caching for authentication results from `cmd`.
        -   `timeout` (integer): Time in seconds to cache the authentication result.
            -   *Default value*: `300` (seconds).
-   `tls` (object, optional): If present, configures TLS for the SOCKS listener (SOCKS over TLS). The structure is the same as the TLS configuration for HTTPS listeners (see Section 4.3), requiring `cert` and `key`, and optionally `client` for mTLS.

Example:
```yaml
listeners:
  - name: socks
    bind: 0.0.0.0:1080
    allowUdp: true # Default
    enforceUdpClient: false
    # overrideUdpAddress: 127.0.0.1
    allowBind: false # Default - enable to support SOCKS BIND command
    enforceBindAddress: true # Default - force system-allocated addresses (security mode)
    auth:
      required: false # Default
      users:
        - username: a
          password: a
      # cmd:
      #   - test
      #   - "#USER#"
      #   - ==
      #   - "#PASS#"
      cache:
        timeout: 300 # Default
    # tls: # Optional SOCKS over TLS
      # cert: server.crt
      # key: server.key
      # client:
        # ca: client_ca.crt
        # required: false
```

---
#### 4.5. QUIC Listener (`quic`)

*Availability: This listener type is only available when the proxy is compiled with the `quic` feature.*

The `quic` listener allows the proxy to accept connections over the QUIC protocol. QUIC is a modern transport protocol that offers multiplexing and security by default (TLS).

-   **`type: quic`**
-   **Common Parameters**: `bind`.
-   `bbr` (boolean, optional): Enables or disables the BBR congestion control algorithm for QUIC connections.
    -   *Default value*: `true`.
-   `tls` (object): QUIC inherently uses TLS, so this configuration is mandatory.
    -   `cert` (string): Path to the server's SSL/TLS certificate file (e.g., `test.crt`).
    -   `key` (string): Path to the server's private key file (e.g., `test.key`).
    -   *Note*: Unlike HTTP listeners, client certificate authentication options are not shown in the example for QUIC listeners but might be supported if the underlying TLS library allows.

Example:
```yaml
listeners:
  - name: quic
    bind: 0.0.0.0:4433
    # bbr: true
    tls:
      cert: test.crt
      key: test.key
```

---

#### 4.6. SSH Listener (`ssh`)

*Availability: This listener type is only available when the proxy is compiled with the `ssh` feature.*

The `ssh` listener accepts SSH connections and forwards tunneled traffic through the proxy chain using SSH's direct-tcpip channel forwarding mechanism.

-   **`type: ssh`**
-   **Common Parameters**: `bind`.
-   `hostKeyPath` (string): Path to the SSH server's private host key file (e.g., `/etc/ssh/ssh_host_ed25519_key`).
-   `authorizedKeysPath` (string, optional): Path to the authorized_keys file for public key authentication (e.g., `/home/user/.ssh/authorized_keys`).
-   `allowPassword` (boolean, optional): Enables password authentication.
    -   *Default value*: `false`.
-   `passwordUsers` (object, optional): Map of username to password for password authentication. Only effective when `allowPassword` is `true`.
    -   *Example*: `{"alice": "secret123", "bob": "pass456"}`
-   `inactivityTimeoutSecs` (integer, optional): SSH session inactivity timeout in seconds.
    -   *Default value*: `300` (5 minutes).

*Note: At least one authentication method (`authorizedKeysPath` or `allowPassword` with `passwordUsers`) must be configured.*

Example:
```yaml
listeners:
  - name: ssh-tunnel
    type: ssh
    bind: 0.0.0.0:2222
    hostKeyPath: /etc/ssh/ssh_host_ed25519_key
    # Public key authentication
    authorizedKeysPath: /home/user/.ssh/authorized_keys
    # Password authentication (optional)
    allowPassword: true
    passwordUsers:
      alice: secret123
      bob: pass456
    inactivityTimeoutSecs: 300
```

---

#### 4.7. HttpX Listener (`httpx`)

The `httpx` listener is a unified HTTP listener that supports multiple HTTP protocol versions (HTTP/1.1, HTTP/2, HTTP/3) with automatic protocol negotiation via ALPN (Application-Layer Protocol Negotiation). This is an advanced listener type designed for modern HTTP proxy scenarios.

-   **`type: httpx`**
-   **Common Parameters**: `name`, `bind`.
-   `protocols` (object): HTTP protocol configuration section that controls which HTTP versions are enabled.
    -   `http1` (object, optional): HTTP/1.1 configuration.
        -   `enable` (boolean, optional): Enable HTTP/1.1 support.
            -   *Default value*: `true`.
    -   `http2` (object, optional): HTTP/2 configuration.
        -   `enable` (boolean, optional): Enable HTTP/2 support.
            -   *Default value*: `false`.
        -   `max_concurrent_streams` (integer, optional): Maximum concurrent streams per HTTP/2 connection.
        -   `initial_window_size` (integer, optional): Initial window size for HTTP/2 flow control.
    -   `http3` (object, optional): HTTP/3 configuration.
        -   `enable` (boolean, optional): Enable HTTP/3 support.
            -   *Default value*: `false`.
        -   `bind` (string, optional): UDP bind address for HTTP/3 (must differ from TCP port).
            -   *Example*: `"0.0.0.0:8443"`
        -   `max_concurrent_streams` (integer, optional): Maximum concurrent streams per HTTP/3 connection.
        -   `max_idle_timeout` (string, optional): Maximum idle timeout for HTTP/3 connections.
            -   *Example*: `"30s"`
-   `tls` (object, optional): TLS configuration for HTTPS support. Structure is the same as HTTP listener TLS configuration (see Section 4.3). Required for HTTP/2 and HTTP/3 protocols.
    -   ALPN protocols are automatically configured based on enabled protocol versions.
    -   Protocol preference order: HTTP/3 → HTTP/2 → HTTP/1.1
-   `udp` (object, optional): UDP support configuration.
    -   `enable` (boolean, optional): Enable UDP support (required for HTTP/3).
        -   *Default value*: `true`.
-   `loop_detect` (object, optional): Loop detection configuration to prevent proxy loops.
    -   `enable` (boolean, optional): Enable loop detection.
        -   *Default value*: `false`.
    -   `max_hops` (integer, optional): Maximum allowed proxy hops before rejecting request.
        -   *Default value*: `5`.
-   `auth` (object, optional): Authentication configuration. Structure is similar to SOCKS authentication (see Section 4.4).

**Protocol Requirements**:
- At least one HTTP protocol (http1, http2, or http3) must be enabled.
- HTTP/3 requires TLS configuration.
- HTTP/3 requires UDP support to be enabled.
- HTTP/3 UDP port must differ from the TCP port.

**ALPN Negotiation**:
The listener automatically configures ALPN protocols based on enabled versions:
- HTTP/3: `h3`, `h3-29`
- HTTP/2: `h2`
- HTTP/1.1: `http/1.1`, `http/1.0`

Examples:

```yaml
listeners:
  # Basic HttpX listener with HTTP/1.1 only
  - name: httpx-basic
    type: httpx
    bind: "0.0.0.0:8800"
    protocols:
      http1:
        enable: true
      http2:
        enable: false
      http3:
        enable: false

  # Advanced HttpX listener with multiple protocols and TLS
  - name: httpx-advanced
    type: httpx
    bind: "0.0.0.0:8801"
    protocols:
      http1:
        enable: true
      http2:
        enable: true
        max_concurrent_streams: 100
        initial_window_size: 65536
      http3:
        enable: true
        bind: "0.0.0.0:8443"  # UDP port for HTTP/3
        max_concurrent_streams: 50
        max_idle_timeout: "30s"
    tls:
      cert: server.crt
      key: server.key
      client:
        ca: client_ca.crt
        required: false
    udp:
      enable: true
    loop_detect:
      enable: true
      max_hops: 10
    auth:
      required: false
      users:
        - username: proxy_user
          password: secure_pass
```

With this, the documentation for all listener types in the example `config.yaml` is complete.

---

## 5. Connectors Configuration (`connectors`)

The `connectors` section is a list that defines how the proxy makes outgoing connections to destination servers or other proxies. These are used by rules to determine the outbound path for a request.

### Common Connector Parameters

Similar to listeners, some parameters are common across different connector types:

-   `name` (string): A descriptive name for the connector. This name is used in the `rules` section to specify which connector to use.
-   `type` (string, optional): Explicitly defines the type of the connector. If omitted, the type might be inferred from the `name` field (e.g., "direct" might imply a direct connection). It's good practice to specify `type` for clarity.

---

### Connector Types

#### 5.1. Load Balance (`loadbalance`)

The `loadbalance` connector distributes outgoing connections across a list of other configured connectors based on a specified algorithm.

-   **`type: loadbalance`** (or inferred if `name` is "loadbalance")
-   `connectors` (list of strings): A list of names of other connectors defined in the `connectors` section that this load balancer will use.
    -   *Example*: `["direct", "http"]`
-   `algorithm` (object or string): Defines the load balancing algorithm. This can be a predefined string or an object for more complex configurations.
    -   *Default value*: `roundRobin`
    -   *Possible string values*:
        -   `random`: Chooses a connector randomly from the list.
        -   `roundRobin` (or `rr`): Chooses connectors in a round-robin sequence.
    -   *Object value (for hash-based balancing)*:
        -   `{hashBy: "script_string"}`: Uses a Milu script to generate a string, which is then hashed to select a connector. The script has access to the `request` object.
            -   *Example*: `algorithm: {hashBy: "request.source.host"}`

Example:
```yaml
connectors:
  - name: loadbalance
    connectors:
      - direct
      - http # These should be names of other connectors defined elsewhere
    algorithm: {hashBy: "request.source.host"} # or algorithm: roundRobin
```

---

#### 5.2. Direct Connection (`direct`)

The `direct` connector makes a direct connection to the target host.

-   **`type: direct`** (or inferred if `name` is "direct")
-   `bind` (string, optional): Specifies a source IP address to bind to for outgoing connections and BIND operations.
    -   *Example*: `"192.168.100.1"`
    -   This setting affects all connection types: TCP forward, UDP forward/bind, and TCP BIND operations.
    -   For BIND operations, if specified, creates the listening socket on this interface; otherwise uses the target address.
-   `overrideBindAddress` (string, optional): Override the bind address reported to SOCKS clients for NAT scenarios.
    -   *Example*: `"203.0.113.1"`
    -   Only affects the address reported in SOCKS BIND responses, not the actual bind interface.
    -   Useful when the proxy is behind NAT and clients need to connect to the external IP address.
    -   The actual listener still uses the address determined by the `bind` field or target address.
-   `dns` (object, optional): Configures DNS resolution for this connector.
    -   `servers` (string): A comma-separated list of DNS server IP addresses, optionally with port numbers (e.g., `8.8.8.8:53`). Special values like `system`, `google`, `cloudflare` might also be supported to use system resolvers or predefined public DNS servers.
        -   *Default value*: `"system"` (uses the system's configured DNS resolvers). Other special string values `"google"` and `"cloudflare"` can also be used.
        -   *Example*: `"system"` or `"192.168.100.1:5353,1.1.1.1,8.8.8.8:53"`
    -   `family` (string): Specifies the preferred IP address family for DNS resolution.
        -   *Possible values*: `V4Only`, `V6Only`, `V4First`, `V6First` (default).
        -   `V4Only`: Resolve only A records.
        -   `V6Only`: Resolve only AAAA records.
        -   `V4First`: Try A records first, then AAAA records.
        -   `V6First`: Try AAAA records first, then A records (this is the default).
-   `fwmark` (integer, optional): If supported by the OS (Linux-specific), sets the `fwmark` (firewall mark) on outgoing packets from this connector. This can be used for advanced routing policies.
    -   *Availability*: Linux only.
-   `keepalive` (boolean, optional): Enables or disables TCP keepalive probes for connections made by this connector.
    -   *Default value*: `true`.

Example:
```yaml
connectors:
  - name: direct
    # bind: 192.168.100.1 # Optional source IP for all connections and BIND operations
    # overrideBindAddress: 203.0.113.1 # Optional NAT override for SOCKS BIND responses
    dns:
      servers: system
      # servers: 192.168.100.1:5353,1.1.1.1,8.8.8.8:53
      family: V4Only
    # fwmark: 123
    # keepalive: true
```

---

#### 5.3. HTTP/HTTPS Connector (`http`)

The `http` connector forwards traffic to an upstream HTTP or HTTPS proxy.

-   **`type: http`** (or inferred if `name` is "http" or "https")
-   `server` (string): The hostname or IP address of the upstream proxy server.
    -   *Example*: `"192.168.100.1"`
-   `port` (integer): The port number of the upstream proxy server.
    -   *Example*: `7081` (for HTTP) or `3333` (for HTTPS in the example)
-   `forceConnect` (boolean, optional): Forces all requests to use HTTP CONNECT tunneling instead of HTTP forward proxy.
    -   *Default value*: `false`.
    -   When `false`, GET/POST/PUT/DELETE requests are forwarded directly as HTTP requests.
    -   When `true`, all requests (including GET/POST/PUT/DELETE) are tunneled through HTTP CONNECT.
    -   This option is useful for compatibility with upstream proxies that only support CONNECT method.
-   `tls` (object, optional): If present, this section configures TLS for connecting to an HTTPS proxy.
    -   `insecure` (boolean):
        -   *Default value*: `false`.
        -   If `true`, the proxy will not verify the upstream proxy's TLS certificate. This is useful for proxies with self-signed certificates but introduces security risks (man-in-the-middle attacks).
    -   `ca` (string, optional): Path to a CA certificate file used to verify the upstream proxy's certificate. If not provided, system CAs might be used.
    -   `auth` (object, optional): Configures client certificate authentication (mTLS) for connecting to the upstream proxy. This block is optional.
        -   `cert` (string): Path to the client certificate file.
        -   `key` (string): Path to the client private key file.
    -   `disableEarlyData` (boolean, optional): Disables 0-RTT data in TLS 1.3 for connections to the upstream proxy.
        -   *Default value*: `false`.

Examples:

```yaml
connectors:
  # HTTP Connector
  - name: http
    server: 192.168.100.1
    port: 7081
    # forceConnect: false # Default: use HTTP forward proxy when possible

  # HTTPS Connector with CONNECT-only mode
  - name: https # 'type: http' is inferred
    type: http # Can be explicitly set
    server: 192.168.100.1
    port: 3333
    forceConnect: true # Force all requests to use CONNECT tunneling
    tls:
      insecure: true # Example allows self-signed certs for the upstream proxy
      ca: ca.crt # Optional custom CA for upstream proxy
      auth: # Optional mTLS to upstream proxy
        cert: proxy.crt
        key: proxy.key
      # disableEarlyData: false
```

---

#### 5.4. SOCKS5 Connector (`socks`)

The `socks` connector forwards traffic to an upstream SOCKS5 proxy. This can optionally be secured with TLS.

-   **`type: socks`** (or inferred if `name` contains "socks")
-   `version` (integer, optional): Specifies the SOCKS protocol version.
    -   *Supported values*: `4`, `5`.
    -   *Default value*: `5`.
-   `server` (string): The hostname or IP address of the upstream SOCKS5 proxy server.
    -   *Example*: `"192.168.100.1"`
-   `port` (integer): The port number of the upstream SOCKS5 proxy server.
    -   *Example*: `1080` (for plain SOCKS5) or `9123` (for SOCKS5 over TLS in the example)
-   `auth` (object, optional): Configures username/password authentication for the upstream SOCKS5 proxy.
    -   `username` (string): The username for the SOCKS5 proxy.
    -   `password` (string): The password for the SOCKS5 proxy.
-   `tls` (object, optional): If present, this section configures TLS for connecting to a SOCKS5 proxy that supports TLS encryption (SOCKS over TLS).
    -   `insecure` (boolean):
        -   *Default value*: `false`.
        -   If `true`, the proxy will not verify the upstream SOCKS5 server's TLS certificate.
        -   *Note*: The example shows `insecure: true` for the `socks-tls` connector.
    -   `auth` (object, optional): Configures client certificate authentication (mTLS) for the TLS connection to the upstream SOCKS proxy. This block is optional.
        -   `cert` (string): Path to the client certificate file.
        -   `key` (string): Path to the client private key file.
    -   `disableEarlyData` (boolean, optional): Disables 0-RTT data in TLS 1.3 for the TLS connection to the upstream SOCKS proxy.
        -   *Default value*: `false`.

Examples:

```yaml
connectors:
  # Plain SOCKS5 Connector
  - name: socks5-example
    type: socks
    version: 5
    server: 192.168.100.1
    port: 1080
    # auth: # Optional authentication
    #   username: proxy
    #   password: somepassword

  # SOCKS5 over TLS Connector
  - name: socks-tls-example
    type: socks
    version: 5
    server: 192.168.100.1
    port: 9123
    auth:
      username: proxy
      password: fuckgfw # Example credentials
    tls:
      insecure: true # Example allows self-signed certs for the upstream SOCKS-TLS server
      # auth: # Optional mTLS for the TLS layer
        # cert: client.crt
        # key: client.key
      # disableEarlyData: false
```

---

#### 5.5. QUIC Connector (`quic`)

*Availability: This connector type is only available when the proxy is compiled with the `quic` feature.*

The `quic` connector forwards traffic to an upstream server using the QUIC protocol. This is typically used when the upstream server is also a QUIC-enabled proxy or endpoint.

-   **`type: quic`**
-   `server` (string): The hostname or IP address of the upstream QUIC server.
    -   *Example*: `"192.168.100.1"`
-   `port` (integer): The port number of the upstream QUIC server.
    -   *Example*: `7081`
-   `bind` (string, optional): Specifies the local IP address and port to bind to for outgoing QUIC connections.
    -   *Default value*: `"[::]:0"` (any available IPv6 address, any port).
-   `bbr` (boolean, optional): Enables or disables the BBR congestion control algorithm for outgoing QUIC connections.
    -   *Default value*: `true`.
-   `inline_udp` (boolean, optional):
    -   *Default value*: `false`.
    -   If `true`, UDP traffic being forwarded over this QUIC connection will use reliable QUIC streams instead of QUIC datagrams. This can be useful if QUIC datagrams are unreliable or blocked, but it changes the nature of UDP transport (adds reliability and ordering).
    -   If `false` (default), UDP traffic is typically forwarded using QUIC datagrams, preserving the unreliable nature of UDP.
-   `tls` (object): QUIC connections are inherently secured with TLS.
    -   `insecure` (boolean):
        -   *Default value*: `false`.
        -   If `true`, the proxy will not verify the upstream QUIC server's TLS certificate. This is useful for servers with self-signed certificates but carries security risks.
        -   *Note*: The example shows `insecure: true`.
    -   `disableEarlyData` (boolean, optional): Disables 0-RTT data in TLS 1.3 for connections to the upstream QUIC server.
        -   *Default value*: `false`.
    -   *Client certificate authentication (mTLS) options are not shown in the example but might be configurable depending on the proxy's capabilities.*

Example:
```yaml
connectors:
  - name: quic-example
    type: quic
    server: 192.168.100.1
    port: 7081
    # bind: "[::]:0"
    # bbr: true
    inline_udp: false
    tls:
      insecure: true
      # disableEarlyData: false
```

---

#### 5.6. SSH Connector (`ssh`)

*Availability: This connector type is only available when the proxy is compiled with the `ssh` feature.*

The `ssh` connector tunnels traffic to upstream servers through an SSH connection using direct-tcpip channel forwarding. Each connection creates a new SSH session to avoid head-of-line blocking issues inherent in SSH's TCP-based transport.

-   **`type: ssh`**
-   `server` (string): The hostname or IP address of the SSH server.
    -   *Example*: `"ssh.example.com"`
-   `port` (integer): The SSH server port.
    -   *Default value*: `22`.
-   `username` (string): SSH username for authentication.
-   `auth` (object): SSH authentication configuration.
    -   **Password Authentication**:
        -   `type: password`
        -   `password` (string): The password for authentication.
    -   **Private Key Authentication**:
        -   `type: privateKey`
        -   `path` (string): Path to the private key file (e.g., `~/.ssh/id_ed25519`).
        -   `passphrase` (string, optional): Passphrase for encrypted private keys.
-   `serverKeyVerification` (object): Server key verification configuration.
    -   **Fingerprint Verification** (recommended for production):
        -   `type: fingerprint`
        -   `fingerprint` (string): Expected SHA256 fingerprint of the server's host key (e.g., `"SHA256:xUnNap5CE8FOAAr6+lhzLgkXBgYRoUexlLotEOhDgr4"`).
    -   **Insecure Mode** (development only):
        -   `type: insecureAcceptAny`
        -   ⚠️ **Warning**: This disables host key verification and should ONLY be used in development environments.
-   `inactivityTimeoutSecs` (integer, optional): SSH session inactivity timeout in seconds.
    -   *Default value*: `60`.

**Getting SSH Server Fingerprints:**

Use `ssh-keyscan` to get the server's fingerprint:
```bash
# Get SHA256 fingerprint
ssh-keyscan -H example.com 2>/dev/null | ssh-keygen -lf - -E sha256
# Output: 256 SHA256:xUnNap5CE8FOAAr6+lhzLgkXBgYRoUexlLotEOhDgr4 example.com (ED25519)
```

Example:
```yaml
connectors:
  # Password authentication
  - name: ssh-password
    type: ssh
    server: ssh.example.com
    port: 22
    username: proxyuser
    auth:
      type: password
      password: secretpass123
    serverKeyVerification:
      type: fingerprint
      fingerprint: "SHA256:xUnNap5CE8FOAAr6+lhzLgkXBgYRoUexlLotEOhDgr4"
    inactivityTimeoutSecs: 60

  # Private key authentication
  - name: ssh-key
    type: ssh  
    server: ssh.example.com
    port: 22
    username: proxyuser
    auth:
      type: privateKey
      path: ~/.ssh/id_ed25519
      # passphrase: optional_passphrase
    serverKeyVerification:
      type: fingerprint  
      fingerprint: "SHA256:xUnNap5CE8FOAAr6+lhzLgkXBgYRoUexlLotEOhDgr4"

  # Development mode (INSECURE - do not use in production!)
  - name: ssh-dev
    type: ssh
    server: test-server.local
    port: 22
    username: testuser
    auth:
      type: password
      password: testpass
    serverKeyVerification:
      type: insecureAcceptAny  # ⚠️ Development only!
```

---

#### 5.7. HttpX Connector (`httpx`)

The `httpx` connector is an advanced HTTP proxy connector that supports modern HTTP protocols (HTTP/1.1, HTTP/2, HTTP/3) with connection pooling, advanced configuration options, and WebSocket upgrade handling.

-   **`type: httpx`**
-   `server` (string): The hostname or IP address of the upstream HTTP proxy server.
    -   *Example*: `"http-proxy"`
-   `port` (integer): The port number of the upstream HTTP proxy server.
    -   *Example*: `3128`
-   `protocol` (object): HTTP protocol configuration with embedded protocol-specific settings.
    -   **HTTP/1.1 Configuration**:
        -   `type: "http/1.1"`
        -   `keep_alive` (boolean, optional): Enable Connection: keep-alive for connection reuse.
            -   *Default value*: `true`.
    -   **HTTP/2 Configuration**:
        -   `type: "h2"`
        -   `max_concurrent_streams` (integer, optional): Maximum concurrent streams per connection.
        -   `settings` (object, optional): HTTP/2 settings frame parameters.
    -   **HTTP/3 Configuration**:
        -   `type: "h3"`
        -   `quic` (object, optional): QUIC connection settings.
    -   **HTTP/1.1 over QUIC Configuration** (legacy):
        -   `type: "http1-over-quic"`
        -   `keep_alive` (boolean, optional): Enable Connection: keep-alive for connection reuse.
            -   *Default value*: `true`.
        -   `quic` (object, optional): QUIC connection settings.
-   `enable_forward_proxy` (boolean, optional): Enable HTTP forward proxy mode for GET/POST/PUT/DELETE requests.
    -   *Default value*: `false`.
    -   When `true`, supports both HTTP CONNECT tunneling and HTTP forward proxy requests.
    -   When `false`, only supports HTTP CONNECT tunneling.
-   `intercept_websocket_upgrades` (boolean, optional): Intercepts WebSocket upgrade requests and routes them through HTTP CONNECT tunneling.
    -   *Default value*: `false`.
    -   When `true`, requests containing WebSocket upgrade headers (`Upgrade: websocket`) are automatically tunneled through HTTP CONNECT instead of being forwarded as regular HTTP requests.
    -   When `false`, WebSocket upgrade requests are forwarded as regular HTTP requests, which may cause issues with HTTP proxies that strip hop-by-hop headers like `Upgrade` and `Connection`.
    -   This option prevents HTTP proxies (like Squid) from removing WebSocket upgrade headers, ensuring proper WebSocket handshake completion.
    -   Recommended to set to `true` when using upstream HTTP proxies that don't properly handle WebSocket upgrades.
-   `pool` (object, optional): Connection pool configuration for performance optimization.
    -   `enable` (boolean, optional): Enable connection pooling.
        -   *Default value*: `true`.
    -   `max_connections` (integer, optional): Maximum connections per target host.
        -   *Default value*: `50`.
    -   `idle_timeout_secs` (integer, optional): Idle timeout for pooled connections in seconds.
        -   *Default value*: `30`.
-   `tls` (object, optional): TLS configuration for HTTPS proxy connections. Structure is similar to other TLS configurations with `insecure`, `ca`, `auth`, etc.
-   `connect_timeout_secs` (integer, optional): Connection timeout in seconds.
    -   *Default value*: `10`.
-   `resolve_timeout_secs` (integer, optional): DNS resolution timeout in seconds.
    -   *Default value*: `5`.

Example:
```yaml
connectors:
  - name: httpx-advanced
    type: httpx
    server: "http-proxy"
    port: 3128
    protocol:
      type: "http/1.1"
      keep_alive: true
    enable_forward_proxy: true
    intercept_websocket_upgrades: true
    pool:
      enable: true
      max_connections: 50
      idle_timeout_secs: 30
    connect_timeout_secs: 10
    resolve_timeout_secs: 5
    # tls: # Optional for HTTPS proxy
    #   insecure: false
    #   ca: proxy_ca.crt
```

With this, the documentation for all connector types in the example `config.yaml` is complete.

---

## 6. Rules Configuration (`rules`)

The `rules` section is a list that defines how incoming requests are processed and routed to different connectors. Rules are evaluated in the order they are defined. The first rule that matches a request determines its fate.

Each rule object in the list consists of a `filter` (optional) and a `target`.

-   `filter` (string, optional): An expression that is evaluated against the request's properties. If the expression evaluates to true, the rule matches. If `filter` is omitted, the rule matches all requests (acting as a default or fallback rule).
    -   **Filter Expressions**: The expressions can use variables related to the request and various functions.
        -   **Available Variables (based on example comments)**:
            -   `request.source`: Likely a string representing the source IP and port (e.g., "192.168.1.100:12345").
            -   `request.target.host`: The requested hostname or IP address.
            -   `request.target.port`: The requested port number (as an integer).
            -   `request.target.type`: The type of the target, e.g., "domain", "ipv4", "ipv6".
            -   `request.listener`: The name of the listener that received the request.
            -   `request.feature`: Special features associated with the request, e.g., "UdpForward" for SOCKS5 UDP associations.
        -   **Operators**:
            -   `==` (equality)
            -   `!=` (inequality)
            -   `=~` (regex match, e.g., `request.source =~ "127.0.0.1"`)
            -   `||` (logical OR)
            -   `and` (logical AND) - Note: example uses `and`, typical YAML/ scripting might also support `&&`.
        -   **Available Functions (based on example comments)**:
            -   `cidr_match(request.target.host, "127.0.0.0/8")`: Matches if the host IP falls within the given CIDR range.
            -   `split(str, delimiter) -> [str]`: Splits a string into a list of strings.
            -   `to_string(any) -> str`: Converts a value to a string.
            -   `to_integer(str) -> int`: Converts a string to an integer.
    -   *Note*: The exact syntax and available properties/functions should be verified from the proxy's core logic or more detailed developer documentation if available.
-   `target` (string): Specifies the action to take if the filter matches.
    -   This is usually the `name` of a connector defined in the `connectors` section. The request will be forwarded using that connector.
    -   **Special Target `deny`**: If `target` is set to `"deny"`, the request is explicitly blocked.

**Rule Evaluation Logic**:
-   Rules are processed from top to bottom.
-   The first rule where the `filter` evaluates to `true` (or if the filter is absent) is applied.
-   If a request does not match any rule in the list, access is denied by default. Therefore, it's common to have a final "catch-all" rule (e.g., one with no filter or `filter: true`) that specifies a default connector.

Examples from `config.yaml`:
```yaml
rules:
  # Deny requests to loopback CIDR or localhost domain
  # - filter: cidr_match(request.target.host,"127.0.0.0/8") || request.target.host == "localhost"
  #   target: deny

  # Route requests for domain type targets to 'loadbalance' connector
  # - filter: request.target.type == "domain"
  #   target: loadbalance

  # Route SOCKS5 UDP forwarding requests to 'quic' connector
  - filter: request.feature == "UdpForward"
    target: quic

  # Route requests from localhost to 'direct' connector
  - filter: request.source.host == "127.0.0.1"
    target: direct

  # Route requests from 127.0.0.1 to google.com via 'direct' connector
  - filter: request.source =~ "127.0.0.1" and request.target =~ "google.com"
    target: direct

  # Route IPv6 targets to 'https' connector
  - filter: request.target.type == "ipv6"
    target: https

  # Deny requests to "deny-me.com"
  - filter: request.target =~ "deny-me.com"
    target: deny

  # Default rule: all other requests go to 'direct' connector
  - target: direct
```

---

## 7. SOCKS BIND Configuration Examples

The SOCKS BIND command allows clients to create listening sockets for incoming connections, commonly used by FTP clients and other protocols requiring reverse connections. This section provides practical configuration examples for different BIND scenarios.

### 7.1. Basic BIND Configuration

```yaml
listeners:
  - name: socks-with-bind
    type: socks
    bind: "0.0.0.0:1080"
    allowBind: true              # Enable BIND command support
    enforceBindAddress: false    # Allow client bind requests (less secure, but normal SOCKS behavior)
    allowUdp: true               # Standard UDP associate support

connectors:
  - name: direct
    type: direct
    # Uses target address for BIND operations by default

rules:
  - target: direct               # Default rule for all requests
```

### 7.2. BIND with Interface Control

```yaml
listeners:
  - name: socks-bind-controlled
    type: socks
    bind: "0.0.0.0:1081"
    allowBind: true
    enforceBindAddress: false

connectors:
  - name: direct-with-bind
    type: direct
    bind: "192.168.1.100"        # BIND operations will use this interface
    dns:
      servers: system

rules:
  - target: direct-with-bind
```

### 7.3. BIND with NAT Override (Recommended for NAT scenarios)

```yaml
listeners:
  - name: socks-nat-bind
    type: socks
    bind: "0.0.0.0:1082"
    allowBind: true
    enforceBindAddress: false

connectors:
  - name: direct-nat
    type: direct
    bind: "192.168.1.100"                    # Internal interface for actual binding
    overrideBindAddress: "203.0.113.50"     # External IP reported to clients

rules:
  - target: direct-nat
```

### 7.4. Multiple BIND Configurations

```yaml
listeners:
  # Standard BIND for internal clients
  - name: socks-internal-bind
    type: socks
    bind: "192.168.1.1:1080"
    allowBind: true
    enforceBindAddress: false
    
  # Strict BIND for external clients
  - name: socks-external-bind
    type: socks
    bind: "0.0.0.0:1081"
    allowBind: true
    enforceBindAddress: true    # Force system-allocated addresses (security mode)
    auth:
      required: true
      users:
        - username: external_user
          password: secure_pass

connectors:
  - name: direct-internal
    type: direct
    bind: "192.168.1.1"
    
  - name: direct-external
    type: direct
    bind: "203.0.113.50"
    overrideBindAddress: "203.0.113.50"

rules:
  # Route internal network to internal connector
  - filter: 'request.listener == "socks-internal-bind"'
    target: direct-internal
    
  # Route external clients to external connector
  - filter: 'request.listener == "socks-external-bind"'
    target: direct-external
```

### 7.5. BIND with Authentication and TLS

```yaml
listeners:
  - name: socks-secure-bind
    type: socks
    bind: "0.0.0.0:1443"
    allowBind: true
    enforceBindAddress: false
    auth:
      required: true
      users:
        - username: bind_user
          password: bind_pass
      cache:
        timeout: 600
    tls:
      cert: socks_server.crt
      key: socks_server.key
      client:
        ca: client_ca.crt
        required: true

connectors:
  - name: direct-secure
    type: direct
    bind: "10.0.0.100"

rules:
  - target: direct-secure
```

### 7.6. BIND Disabled (Default Behavior)

```yaml
listeners:
  - name: socks-no-bind
    type: socks
    bind: "0.0.0.0:1080"
    allowBind: false             # BIND requests will be rejected (default)
    allowUdp: true               # UDP associate still works

connectors:
  - name: direct
    type: direct

rules:
  - target: direct
```

### 7.7. Advanced BIND with Load Balancing

```yaml
listeners:
  - name: socks-lb-bind
    type: socks
    bind: "0.0.0.0:1080"
    allowBind: true
    enforceBindAddress: false

connectors:
  - name: direct-primary
    type: direct
    bind: "192.168.1.10"
    
  - name: direct-secondary
    type: direct
    bind: "192.168.1.20"
    
  - name: bind-loadbalancer
    type: loadbalance
    connectors: ["direct-primary", "direct-secondary"]
    algorithm: roundRobin

rules:
  # Use load balancer for BIND operations
  - filter: 'request.feature == "TcpBind"'
    target: bind-loadbalancer
    
  # Regular connections use primary
  - target: direct-primary
```

**Configuration Notes:**

1. **Security**: Always use authentication (`auth.required: true`) for BIND-enabled listeners exposed to untrusted networks.

2. **NAT Scenarios**: Use `overrideBindAddress` when the proxy is behind NAT to ensure clients connect to the correct external address.

3. **Interface Selection**: The `bind` field in DirectConnector now consistently affects all operations including TCP BIND.

4. **Address Control**: Setting `enforceBindAddress: true` (default) forces system-allocated addresses for security. Setting to `false` honors client bind requests.

5. **Protocol Support**: BIND currently supports TCP connections. UDP BIND operations depend on the connector's UDP capabilities.

---

## 8. Access Log Configuration (`accessLog`)

The entire `accessLog` section is optional. The `accessLog` section configures how and where access logs are written.

-   `path` (string): Specifies the file path where access logs will be written.
    -   *Example*: `access.log` (writes to a file named `access.log` in the proxy's working directory).
-   `format` (string or object): Defines the format of the log entries. This can be a simple string or a structured object depending on the desired format.
    -   **JSON Format**: To output logs in JSON.
        -   *Example*: `format: json`
    -   **Script Format**: To use a custom Milu script template for formatting. The script should evaluate to a string.
        -   *Example*:
            ```yaml
            format:
              script: "`src=${request.source} dst=${request.target} listener=${request.listener} connector=${request.connector}`"
            ```
        -   *Note*: The Milu script has access to the same `request` object available in rule filters.

Example:
```yaml
accessLog:
  path: access.log
  # Example for JSON format
  format: json
  # Example for Script format
  # format:
  #   script: "`src=${request.source} dst=${request.target} listener=${request.listener} connector=${request.connector}`"
```

---

[end of CONFIG_GUIDE.md]
