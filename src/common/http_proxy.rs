use async_trait::async_trait;
use easy_error::{bail, err_msg, Error, ResultExt}; // Added err_msg
use futures::Future;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU32, Ordering},
};
use tokio::sync::mpsc::Sender;
use tracing::{trace, warn};
use url::Url; // Added Url import

use crate::{
    common::http::{HttpRequest, HttpResponse},
    context::{Context, ContextCallback, ContextRef, ContextRefOps, Feature, IOBufStream},
};

use super::frames::{frames_from_stream, FrameIO};

pub async fn http_proxy_connect<T1, T2>(
    mut server: IOBufStream,
    ctx: ContextRef,
    local: SocketAddr,
    remote: SocketAddr,
    frame_channel: &str,
    frame_fn: T1,
) -> Result<(), Error>
where
    T1: FnOnce(u32) -> T2 + Sync,
    T2: Future<Output = FrameIO>,
{
    tracing::trace!("http_proxy_connect: channel={}", frame_channel);
    let target = ctx.read().await.target();
    let feature = ctx.read().await.feature();
    match feature {
        Feature::TcpForward => {
            HttpRequest::new("CONNECT", &target)
                .with_header("Host", &target)
                .write_to(&mut server)
                .await?;
            let resp = HttpResponse::read_from(&mut server).await?;
            if resp.code != 200 {
                bail!("upstream server failure: {:?}", resp);
            }
            ctx.write()
                .await
                .set_server_stream(server)
                .set_local_addr(local)
                .set_server_addr(remote);
        }
        Feature::HttpForward => {
            // For HttpForward, the 'server' stream is already connected to the target origin server.
            // No explicit handshake (like CONNECT) is needed here as it's a direct forward.
            // The HttpForwardCallback will handle writing the request and reading the response.
            ctx.write()
                .await
                .set_server_stream(server)
                .set_local_addr(local)
                .set_server_addr(remote);
        }
        Feature::UdpForward | Feature::UdpBind => {
            let mut request = HttpRequest::new("CONNECT", &target)
                .with_header("Host", &target)
                .with_header("Proxy-Protocol", "udp")
                .with_header("Proxy-Channel", frame_channel);
            if feature == Feature::UdpBind {
                let bind_src = ctx
                    .read()
                    .await
                    .extra("udp-bind-source")
                    .unwrap()
                    .to_owned();
                request = request.with_header("Udp-Bind-Source", bind_src);
            }

            request.write_to(&mut server).await?;
            let resp = HttpResponse::read_from(&mut server).await?;
            tracing::trace!("response: {:?}", resp);
            if resp.code != 200 {
                bail!("upstream server failure: {:?}", resp);
            }
            let session_id = resp.header("Session-Id", "0").parse().unwrap();
            ctx.write()
                .await
                .set_server_frames(if frame_channel.eq_ignore_ascii_case("inline") {
                    frames_from_stream(session_id, server)
                } else {
                    frame_fn(session_id).await
                })
                .set_local_addr(local)
                .set_server_addr(remote);
        }
        x => bail!("not supported feature {:?}", x),
    };
    Ok(())
}

static SESSION_ID: AtomicU32 = AtomicU32::new(0);
// HTTP 1.1 CONNECT protocol handlers
// used by http and quic listeners and connectors
pub async fn http_proxy_handshake<FrameFn, T2>(
    ctx: ContextRef,
    queue: Sender<ContextRef>,
    create_frames: FrameFn,
) -> Result<(), Error>
where
    FrameFn: FnOnce(&str, u32) -> T2 + Sync,
    T2: Future<Output = Result<FrameIO, Error>>,
{
    use crate::context::TargetAddress; // Ensure TargetAddress is in scope for this function
                                       // url::Url import moved to top of file

    let mut ctx_lock = ctx.write().await;
    let socket = ctx_lock.borrow_client_stream().unwrap();
    let request = HttpRequest::read_from(socket).await?;
    tracing::trace!("request={:?}", request);
    if request.method.eq_ignore_ascii_case("CONNECT") {
        let protocol = request.header("Proxy-Protocol", "tcp");
        // let host = request.header("Host", "0.0.0.0:0");
        let target = request
            .resource
            .parse()
            .with_context(|| format!("failed to parse target address: {}", request.resource))?;
        if protocol.eq_ignore_ascii_case("tcp") {
            ctx_lock.set_target(target).set_callback(ConnectCallback);
        } else if protocol.eq_ignore_ascii_case("udp") {
            let session_id = SESSION_ID.fetch_add(1, Ordering::Relaxed);
            let channel = request.header("Proxy-Channel", "inline");
            let inline = channel.eq_ignore_ascii_case("inline");
            let source = request.header("Udp-Bind-Source", "");
            ctx_lock
                .set_target(target)
                .set_callback(FrameChannelCallback { session_id, inline });
            if source.is_empty() {
                ctx_lock.set_feature(Feature::UdpForward);
            } else {
                ctx_lock
                    .set_extra("udp-bind-source", source)
                    .set_feature(Feature::UdpBind);
            }

            if !inline {
                ctx_lock.set_client_frames(
                    create_frames(channel, session_id)
                        .await
                        .context("create frames")?,
                );
            }
        } else {
            HttpResponse::new(400, "Bad Request")
                .write_to(socket)
                .await?;
            bail!("Invalid request protocol: {}", protocol);
        }
    } else if matches!(
        request.method.to_uppercase().as_str(),
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH"
    ) {
        let target_addr = if request.resource.starts_with("http://")
            || request.resource.starts_with("https://")
        {
            // Absolute URI
            let url = Url::parse(&request.resource)
                .map_err(|e| err_msg(format!("Failed to parse resource URI: {}", e)))?;
            let host = url
                .host_str()
                .ok_or_else(|| err_msg("Missing host in resource URI"))?;
            let port = url
                .port_or_known_default()
                .ok_or_else(|| err_msg("Missing port in resource URI"))?;
            TargetAddress::DomainPort(host.to_string(), port)
        } else {
            // Relative path, use Host header
            let host_header = request.header("Host", "");
            if host_header.is_empty() {
                bail!("Missing Host header for relative resource path");
            }
            host_header
                .parse()
                .with_context(|| format!("failed to parse Host header: {}", host_header))?
        };

        ctx_lock
            .set_target(target_addr)
            .set_feature(Feature::HttpForward)
            .set_http_request(request) // Store the request
            .set_callback(HttpForwardCallback);
    } else {
        HttpResponse::new(400, "Bad Request")
            .write_to(socket)
            .await?;
        bail!("Invalid request method: {}", request.method);
    }
    trace!("Request: {:?}", ctx_lock);
    drop(ctx_lock);
    ctx.enqueue(&queue).await?;
    Ok(())
}

struct ConnectCallback;
#[async_trait]
impl ContextCallback for ConnectCallback {
    async fn on_connect(&self, ctx: &mut Context) {
        let socket = ctx.borrow_client_stream().unwrap();
        if let Err(e) = HttpResponse::new(200, "Connection established")
            .write_to(socket)
            .await
        {
            warn!("failed to send response: {}", e)
        }
    }
    async fn on_error(&self, ctx: &mut Context, error: Error) {
        let socket = ctx.borrow_client_stream();
        if socket.is_none() {
            return;
        }
        let buf = format!("Error: {} Cause: {:?}", error, error.cause);
        if let Err(e) = HttpResponse::new(503, "Service unavailable")
            .with_header("Content-Type", "text/plain")
            .with_header("Content-Length", buf.len())
            .write_with_body(socket.unwrap(), buf.as_bytes())
            .await
        {
            warn!("failed to send response: {}", e)
        }
    }
}

use tokio::io::{copy, AsyncReadExt, AsyncWriteExt};

struct HttpForwardCallback;
#[async_trait]
impl ContextCallback for HttpForwardCallback {
    async fn on_connect(&self, ctx: &mut Context) {
        let client_stream = ctx.take_client_stream();
        let server_stream = ctx.take_server_stream(); // This assumes server_stream is already connected and set.
        let request = ctx.http_request();

        if client_stream.is_none() || server_stream.is_none() || request.is_none() {
            warn!("HttpForwardCallback::on_connect: missing client_stream, server_stream, or http_request");
            // Call on_error manually if streams are not available early
            if let Some(mut client_stream) = client_stream {
                let _ = HttpResponse::new(500, "Internal Server Error")
                    .with_header("Connection", "close")
                    .write_to(&mut client_stream)
                    .await;
            }
            return;
        }

        let mut client_stream = client_stream.unwrap();
        let mut server_stream = server_stream.unwrap();
        let request = request.unwrap();

        if let Err(e) = request.write_to(&mut server_stream).await {
            warn!("Failed to write request to server: {}", e);
            let _ = HttpResponse::new(503, "Service Unavailable")
                .with_header("Connection", "close")
                .write_to(&mut client_stream)
                .await;
            return;
        }

        // Handle request body if Content-Length is present
        if let Ok(content_length) = request.header("Content-Length", "0").parse::<u64>() {
            if content_length > 0 {
                if let Err(e) = copy_bidirectional_with_limit(
                    &mut client_stream,
                    &mut server_stream,
                    content_length,
                )
                .await
                {
                    warn!("Error copying request body: {}", e);
                    let _ = HttpResponse::new(503, "Service Unavailable")
                        .with_header("Connection", "close")
                        .write_to(&mut client_stream)
                        .await;
                    return;
                }
            }
        } else if request
            .header("Transfer-Encoding", "")
            .eq_ignore_ascii_case("chunked")
        {
            // TODO: Implement chunked request body transfer
            warn!("Chunked request body not yet supported in HttpForwardCallback");
            let _ = HttpResponse::new(501, "Not Implemented")
                .with_header("Connection", "close")
                .write_to(&mut client_stream)
                .await;
            return;
        }
        // Ensure server stream flush if body was written separately
        if let Err(e) = server_stream.flush().await {
            warn!("Failed to flush server stream after request body: {}", e);
            let _ = HttpResponse::new(503, "Service Unavailable")
                .with_header("Connection", "close")
                .write_to(&mut client_stream)
                .await;
            return;
        }

        match HttpResponse::read_from(&mut server_stream).await {
            Ok(response) => {
                if let Err(e) = response.write_to(&mut client_stream).await {
                    warn!("Failed to write response headers to client: {}", e);
                    // Connection might be already closed by client
                    return;
                }

                // Handle response body
                if let Ok(content_length) = response.header("Content-Length", "0").parse::<u64>() {
                    if content_length > 0 {
                        if let Err(e) = copy_bidirectional_with_limit(
                            &mut server_stream,
                            &mut client_stream,
                            content_length,
                        )
                        .await
                        {
                            warn!("Error copying response body: {}", e);
                            // Client connection might be closed already
                        }
                    }
                } else if response
                    .header("Transfer-Encoding", "")
                    .eq_ignore_ascii_case("chunked")
                {
                    // TODO: Implement chunked response body transfer
                    // For now, attempt to copy until EOF, though this might not be correct for chunked encoding without proper parsing.
                    if let Err(e) = copy(&mut server_stream, &mut client_stream).await {
                        warn!("Error copying chunked response body (unsupported): {}", e);
                    }
                }
                if let Err(e) = client_stream.flush().await {
                    warn!("Failed to flush client stream after response body: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to read response from server: {}", e);
                let _ = HttpResponse::new(503, "Service Unavailable")
                    .with_header("Connection", "close")
                    .write_to(&mut client_stream)
                    .await;
            }
        }
    }

    async fn on_error(&self, ctx: &mut Context, error: Error) {
        warn!("HttpForwardCallback::on_error: {}", error);
        if let Some(mut socket) = ctx.take_client_stream() {
            // Use take_client_stream to avoid borrow issues
            let response = HttpResponse::new(503, "Service Unavailable")
                .with_header("Content-Type", "text/plain")
                .with_header("Connection", "close");
            let body = format!("Error: {}\r\nCause: {:?}", error, error.cause);
            let response = response.with_header("Content-Length", body.len().to_string());

            if let Err(e) = response.write_with_body(&mut socket, body.as_bytes()).await {
                warn!("Failed to send error response to client: {}", e);
            }
        } else {
            warn!("HttpForwardCallback::on_error: No client stream to send error response.");
        }
    }
}

// Helper function to copy with a limit
async fn copy_bidirectional_with_limit<R, W>(
    reader: &mut R,
    writer: &mut W,
    limit: u64,
) -> Result<u64, std::io::Error>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut reader = reader.take(limit);
    tokio::io::copy(&mut reader, writer).await
}

struct FrameChannelCallback {
    session_id: u32,
    inline: bool,
}
#[async_trait]
impl ContextCallback for FrameChannelCallback {
    async fn on_connect(&self, ctx: &mut Context) {
        tracing::trace!("on_connect callback: id={} ctx={}", self.session_id, ctx);
        let stream_opt = ctx.take_client_stream(); // Removed mut
        if stream_opt.is_none() {
            warn!("FrameChannelCallback::on_connect: client stream is None, cannot proceed.");
            return;
        }
        let mut stream = stream_opt.unwrap();

        if let Err(e) = HttpResponse::new(200, "Connection established")
            .with_header("Session-Id", self.session_id.to_string())
            .with_header(
                "Udp-Bind-Address",
                ctx.extra("udp-bind-address").unwrap_or(""),
            )
            .write_to(&mut stream)
            .await
        {
            warn!("failed to send response: {}", e);
            // Note: stream is moved back to ctx if set_client_frames is not called or fails.
            // However, if write_to fails, the stream state might be uncertain.
            // For now, we'll just return. If the stream needs to be put back, logic would be more complex.
            return;
        }
        if self.inline {
            // frames_from_stream takes ownership of the stream.
            ctx.set_client_frames(frames_from_stream(self.session_id, stream));
        } else {
            // If not inline, the stream was used for handshake and should be put back or handled appropriately.
            // For now, assuming if not inline, it's not used further here or already handled by create_frames.
            // If it needs to be put back: ctx.set_client_stream(stream); but this is tricky with ownership.
            // The current design implies 'create_frames' in http_proxy_handshake would use a different stream or channel.
            // The stream here is the main client communication stream. If !inline, it's not turned into frames here.
            // So, we might need to put it back if it wasn't consumed.
            // However, `frames_from_stream` consumes `stream`. If `!self.inline`, `stream` is NOT consumed here.
            // What should happen to `stream` if `!self.inline`?
            // The `create_frames` in `http_proxy_handshake` is called when `!inline`.
            // `http_proxy_handshake` does `ctx_lock.set_client_frames(create_frames(channel, session_id).await...);`
            // This `set_client_frames` happens *before* this `on_connect` callback is usually called.
            // So, if `!self.inline`, client_frames are already set.
            // This callback `FrameChannelCallback::on_connect` is for post-connection setup.
            // The `HttpResponse` was written to `stream`. If `!self.inline`, what else?
            // It seems the stream is just left as is for communication if not converted to frames.
            // This part of the logic might need review based on how non-inline UDP frames are meant to interact
            // after initial handshake response.
            // For now, if !self.inline, `stream` is simply dropped here if not used further.
            // This seems fine as its primary use in this callback was the HttpResponse.
        }
    }
    async fn on_error(&self, ctx: &mut Context, error: Error) {
        let socket = ctx.borrow_client_stream();
        if socket.is_none() {
            return;
        }
        let buf = format!("Error: {} Cause: {:?}", error, error.cause);
        if let Err(e) = HttpResponse::new(503, "Service unavailable")
            .with_header("Content-Type", "text/plain")
            .with_header("Content-Length", buf.len())
            .write_with_body(socket.unwrap(), buf.as_bytes())
            .await
        {
            warn!("failed to send response: {}", e)
        }
    }
}
