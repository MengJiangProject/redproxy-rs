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
-   `bind` (string, optional): Specifies a source IP address to bind to for outgoing connections.
    -   *Example*: `"192.168.100.1"`
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
    # bind: 192.168.100.1 # Optional source IP for outgoing connections
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
    -   `always_use_connect` (boolean, optional):
        -   *Default value*: `false`.
        -   *Behavior*:
            -   If `true`, and the incoming request to the proxy is a standard HTTP request (e.g., GET, POST), this connector will first establish an HTTP CONNECT tunnel to the configured proxy server (`server:port`). After the tunnel is established, the original HTTP request (e.g., GET /path) is sent through this tunnel to the target server.
            -   If `false` (or omitted), the connector behaves as standard: for HTTPS traffic to a target, it uses CONNECT. For HTTP traffic to a target, it typically forwards the HTTP request directly to the proxy (which then forwards it to the target).
            -   This option is useful when you want all traffic, including plain HTTP, to be tunneled through a CONNECT request to the upstream proxy, which can be required by some proxy server configurations or for specific routing policies.

Examples:

```yaml
connectors:
  # HTTP Connector
  - name: http-standard
    server: 192.168.100.1
    port: 7081

  # HTTP Connector that always uses CONNECT
  - name: http-always-connect
    type: http
    server: proxy.example.com
    port: 8080
    always_use_connect: true # New option

  # HTTPS Connector
  - name: https-standard # 'type: http' is inferred
    type: http # Can be explicitly set
    server: 192.168.100.1
    port: 3333
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

## 7. Access Log Configuration (`accessLog`)

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
