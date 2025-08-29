use anyhow::{Result, bail};
use h2::RecvStream;
use hyper::http::{Method, Request, Response, Uri};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace, warn};

use crate::protocols::http::{HttpMethod, HttpVersion};
use crate::{
    context::{ContextRef, IOBufStream},
    protocols::http::{HttpRequest, HttpResponse},
};

/// HTTP/2 protocol handler
///
/// Note: This is a simplified implementation that handles HTTP/2 protocol negotiation
/// and basic request/response patterns. Full HTTP/2 multiplexing, stream management,
/// and flow control would require deeper integration with the h2 crate.
#[derive(Debug)]
pub struct Http2Handler;

/// HTTP/2 stream wrapper to make IOBufStream compatible with h2 crate
struct H2StreamWrapper<'a> {
    inner: &'a mut IOBufStream,
}

impl<'a> H2StreamWrapper<'a> {
    fn new(stream: &'a mut IOBufStream) -> Self {
        Self { inner: stream }
    }
}

impl<'a> AsyncRead for H2StreamWrapper<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<'a> AsyncWrite for H2StreamWrapper<'a> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Http2Handler {
    pub fn new() -> Self {
        Self
    }

    /// Send HTTP/2 connection preface and initial SETTINGS frame
    async fn send_connection_preface(&self, stream: &mut IOBufStream) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        // HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        stream.write_all(CONNECTION_PREFACE).await?;

        // Send empty SETTINGS frame (0x4 type, 0x0 flags, stream 0, empty payload)
        let settings_frame = [
            0x00, 0x00, 0x00, // Length: 0
            0x04, // Type: SETTINGS
            0x00, // Flags: none
            0x00, 0x00, 0x00, 0x00, // Stream ID: 0
        ];
        stream.write_all(&settings_frame).await?;
        stream.flush().await?;

        trace!("HTTP/2: Sent connection preface and SETTINGS frame");
        Ok(())
    }

    /// Read and validate HTTP/2 connection preface
    async fn read_connection_preface(&self, stream: &mut IOBufStream) -> Result<()> {
        use tokio::io::AsyncReadExt;

        // Read connection preface
        const PREFACE_LEN: usize = 24;
        let mut preface = [0u8; PREFACE_LEN];
        stream.read_exact(&mut preface).await?;

        const EXPECTED_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        if preface != EXPECTED_PREFACE {
            bail!("Invalid HTTP/2 connection preface");
        }

        trace!("HTTP/2: Validated connection preface");
        Ok(())
    }

    /// Read a basic HTTP/2 frame header
    async fn read_frame_header(&self, stream: &mut IOBufStream) -> Result<(u32, u8, u8, u32)> {
        use tokio::io::AsyncReadExt;

        let mut header = [0u8; 9];
        stream.read_exact(&mut header).await?;

        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]);
        let frame_type = header[3];
        let flags = header[4];
        let stream_id =
            u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7FFFFFFF;

        Ok((length, frame_type, flags, stream_id))
    }

    /// Send a simple HTTP/2 frame
    async fn send_frame(
        &self,
        stream: &mut IOBufStream,
        frame_type: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let length = payload.len() as u32;
        let header = [
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8, // Length
            frame_type,   // Type
            flags,        // Flags
            (stream_id >> 24) as u8,
            (stream_id >> 16) as u8, // Stream ID
            (stream_id >> 8) as u8,
            stream_id as u8,
        ];

        stream.write_all(&header).await?;
        stream.write_all(payload).await?;
        stream.flush().await?;

        Ok(())
    }

    /// Convert from h2::Request to our HttpRequest
    fn convert_from_h2_request(&self, request: Request<RecvStream>) -> Result<HttpRequest> {
        let method = match *request.method() {
            Method::CONNECT => HttpMethod::Connect,
            Method::GET => HttpMethod::Get,
            Method::POST => HttpMethod::Post,
            Method::PUT => HttpMethod::Put,
            Method::DELETE => HttpMethod::Delete,
            Method::HEAD => HttpMethod::Head,
            Method::OPTIONS => HttpMethod::Options,
            Method::PATCH => HttpMethod::Patch,
            Method::TRACE => HttpMethod::Trace,
            _ => HttpMethod::Other(request.method().to_string()),
        };

        let uri = request.uri().to_string();
        let version = HttpVersion::Http2;

        let mut http_request = HttpRequest::new(method, uri, version);

        // Convert headers
        for (name, value) in request.headers() {
            let name_str = name.to_string();
            let value_str = String::from_utf8_lossy(value.as_bytes()).to_string();
            http_request.add_header(name_str, value_str);
        }

        Ok(http_request)
    }

    /// Convert from our HttpRequest to h2::Request
    fn convert_to_h2_request(&self, request: &HttpRequest) -> Result<Request<()>> {
        let method = match request.method {
            HttpMethod::Connect => Method::CONNECT,
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
            HttpMethod::Put => Method::PUT,
            HttpMethod::Delete => Method::DELETE,
            HttpMethod::Head => Method::HEAD,
            HttpMethod::Options => Method::OPTIONS,
            HttpMethod::Patch => Method::PATCH,
            HttpMethod::Trace => Method::TRACE,
            HttpMethod::Other(ref s) => Method::from_bytes(s.as_bytes())?,
        };

        let uri: Uri = request.uri.parse()?;
        let mut builder = Request::builder().method(method).uri(uri);

        // Add headers
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }

        Ok(builder.body(())?)
    }

    /// Convert from h2::Response to our HttpResponse
    fn convert_from_h2_response(&self, response: Response<RecvStream>) -> HttpResponse {
        let version = HttpVersion::Http2;
        let status_code = response.status().as_u16();
        let reason_phrase = response
            .status()
            .canonical_reason()
            .unwrap_or("")
            .to_string();

        let mut http_response = HttpResponse::new(version, status_code, reason_phrase);

        // Convert headers
        for (name, value) in response.headers() {
            let name_str = name.to_string();
            let value_str = String::from_utf8_lossy(value.as_bytes()).to_string();
            http_response.add_header(name_str, value_str);
        }

        http_response
    }

    /// Convert from our HttpResponse to h2::Response
    fn convert_to_h2_response(&self, response: &HttpResponse) -> Result<Response<()>> {
        let mut builder = Response::builder().status(response.status_code);

        // Add headers
        for (name, value) in &response.headers {
            builder = builder.header(name, value);
        }

        Ok(builder.body(())?)
    }
}

impl Http2Handler {
    pub fn version(&self) -> HttpVersion {
        HttpVersion::Http2
    }

    pub async fn handle_listener_connection(
        &self,
        stream: Box<dyn crate::context::IOStream>,
        contexts: std::sync::Arc<crate::context::ContextManager>,
        queue: tokio::sync::mpsc::Sender<crate::context::ContextRef>,
        listener_name: String,
        source: std::net::SocketAddr,
    ) -> Result<()> {
        debug!("HTTP/2: Starting connection handling for {}", source);

        // Create buffered stream for H2 usage
        let mut buffered_stream = crate::context::make_buffered_stream(stream);

        // 1. Establish H2 server connection
        let stream_wrapper = H2StreamWrapper::new(&mut buffered_stream);
        let mut h2_conn = h2::server::handshake(stream_wrapper).await?;

        debug!("HTTP/2: Handshake completed for {}", source);

        // 2. Accept multiple streams concurrently on same connection
        while let Some(result) = h2_conn.accept().await {
            let (request, respond) = result?;

            let contexts = contexts.clone();
            let queue = queue.clone();
            let listener_name = listener_name.clone();

            debug!("HTTP/2: New stream accepted for {}", source);

            // 3. Handle each H2 stream in parallel
            tokio::spawn(async move {
                if let Err(e) =
                    Self::handle_h2_stream(request, respond, contexts, queue, listener_name, source)
                        .await
                {
                    warn!("HTTP/2: Stream handling failed for {}: {}", source, e);
                }
            });
        }

        debug!("HTTP/2: Connection closed for {}", source);
        Ok(())
    }

    /// Handle a single HTTP/2 stream
    async fn handle_h2_stream(
        request: Request<RecvStream>,
        respond: h2::server::SendResponse<bytes::Bytes>,
        contexts: std::sync::Arc<crate::context::ContextManager>,
        queue: tokio::sync::mpsc::Sender<crate::context::ContextRef>,
        listener_name: String,
        source: std::net::SocketAddr,
    ) -> Result<()> {
        // 1. Create context for THIS stream (not connection!)
        let ctx = contexts.create_context(listener_name, source).await;

        // 2. Convert h2 request to unified format
        let handler = Http2Handler::new();
        let http_request = handler.convert_from_h2_request(request)?;

        debug!(
            "HTTP/2: Processing stream request: {} {}",
            http_request.method, http_request.uri
        );

        // 3. Store request in context
        // TODO: Create Http2StreamWrapper for the respond handle
        {
            let mut ctx_guard = ctx.write().await;
            ctx_guard.set_http_request(http_request);
            // TODO: Set up stream wrapper with respond handle
            // ctx_guard.set_client_stream(Box::new(Http2StreamWrapper::new(respond)));
        }

        // 4. Queue for processing
        if let Err(e) = queue.send(ctx).await {
            warn!("HTTP/2: Failed to queue stream context: {}", e);
        }

        // TODO: The response will be handled through the stream wrapper
        // For now, we need to handle the respond to avoid dropping it
        drop(respond);

        Ok(())
    }

    pub async fn read_request(&self, _stream: &mut IOBufStream) -> Result<Option<HttpRequest>> {
        // HTTP/2 uses h2 crate for request parsing, but we need to integrate with IOBufStream
        // For now, implement a basic approach that converts from h2's Request
        bail!(
            "HTTP/2 request reading requires h2 integration - implement connection handshake first"
        )
    }

    pub async fn send_request(
        &self,
        stream: &mut IOBufStream,
        request: &HttpRequest,
    ) -> Result<()> {
        // HTTP/2 request sending through h2 client
        // TODO: Implement HTTP/2 client request sending with h2 crate
        bail!("HTTP/2 client request sending not yet implemented")
    }

    pub async fn read_response(&self, _stream: &mut IOBufStream) -> Result<HttpResponse> {
        // HTTP/2 response reading through h2 client
        bail!("HTTP/2 response reading requires h2 client integration")
    }

    pub async fn send_response(
        &self,
        _stream: &mut IOBufStream,
        _response: &HttpResponse,
    ) -> Result<()> {
        // HTTP/2 response sending through h2 server
        bail!("HTTP/2 response sending requires h2 server integration")
    }

    pub async fn handle_listener(
        &self,
        stream: &mut IOBufStream,
        _ctx: ContextRef,
    ) -> Result<HttpRequest> {
        // For HTTP/2, we need to wrap the stream to work with h2 crate
        // This is a simplified implementation that handles the first request

        // Create h2 server connection from the stream
        let stream_wrapper = H2StreamWrapper::new(stream);
        let mut connection = h2::server::handshake(stream_wrapper).await?;

        // Accept the first request from the connection
        if let Some(request_result) = connection.accept().await {
            let (request, respond) = request_result?;

            // Convert h2::Request to our HttpRequest
            let http_request = self.convert_from_h2_request(request)?;

            // For now, we'll accept the request and let the connector handle the response
            // In a full implementation, we'd need to keep the `respond` handle for later
            trace!("HTTP/2 server received request: {:?}", http_request);

            Ok(http_request)
        } else {
            bail!("No HTTP/2 request received from client")
        }
    }

    pub async fn handle_connector(&self, stream: &mut IOBufStream, ctx: ContextRef) -> Result<()> {
        let ctx_read = ctx.read().await;
        let request = if let Some(http_request) = ctx_read.http_request() {
            http_request.as_ref().clone()
        } else {
            let target = ctx_read.target();
            HttpRequest::new(HttpMethod::Connect, target.to_string(), HttpVersion::Http2)
        };
        drop(ctx_read);

        // TODO: Implement HTTP/2 client connection and request sending
        bail!("HTTP/2 connector not yet implemented")
    }
}

impl Default for Http2Handler {
    fn default() -> Self {
        Self::new()
    }
}
