use anyhow::{Context as AnyhowContext, Error, Result, anyhow, bail};
use async_trait::async_trait;
use futures::Future;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU32, Ordering},
};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::Sender;
use tracing::{trace, warn};
use url::Url;

use crate::{
    common::http::{HttpRequest, HttpResponse},
    context::{
        Context, ContextCallback, ContextRef, ContextRefOps, Feature, IOBufStream, TargetAddress,
    },
};

use super::frames::{FrameIO, frames_from_stream};

pub async fn http_proxy_connect<T1, T2>(
    mut server: IOBufStream,
    ctx: ContextRef,
    local: SocketAddr,
    remote: SocketAddr,
    frame_channel: &str,
    frame_fn: T1,
) -> Result<()>
where
    T1: FnOnce(u32) -> T2 + Sync,
    T2: Future<Output = FrameIO>,
{
    tracing::trace!("http_proxy_connect: channel={}", frame_channel);
    let target = ctx.read().await.target();
    let feature = ctx.read().await.feature();
    match feature {
        Feature::TcpForward => {
            // Check if we have a stored HTTP request (GET, POST, etc.)
            let has_http_request = ctx.read().await.http_request().is_some();

            if has_http_request {
                // HTTP forwarding - no CONNECT handshake needed
                // The server stream is already connected to the target origin server
                // HttpForwardCallback will handle writing the request and reading the response
                ctx.write()
                    .await
                    .set_server_stream(server)
                    .set_local_addr(local)
                    .set_server_addr(remote);
            } else {
                // Traditional CONNECT tunneling
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

// HTTP 1.1 proxy protocol handlers
// used by http and quic listeners and connectors
pub async fn http_proxy_handshake<FrameFn, T2>(
    ctx: ContextRef,
    queue: Sender<ContextRef>,
    create_frames: FrameFn,
) -> Result<()>
where
    FrameFn: FnOnce(&str, u32) -> T2 + Sync,
    T2: Future<Output = Result<FrameIO>>,
{
    let mut ctx_lock = ctx.write().await;
    let socket = ctx_lock.borrow_client_stream().unwrap();
    let request = HttpRequest::read_from(socket).await?;
    tracing::trace!("request={:?}", request);

    if request.method.eq_ignore_ascii_case("CONNECT") {
        let protocol = request.header("Proxy-Protocol", "tcp");
        let target = request
            .resource
            .parse()
            .with_context(|| format!("failed to parse target address: {}", request.resource))?;

        if protocol.eq_ignore_ascii_case("tcp") {
            ctx_lock
                .set_target(target)
                .set_callback(HttpConnectCallback);
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
                .map_err(|e| anyhow!("Failed to parse resource URI: {}", e))?;
            let host = url
                .host_str()
                .ok_or_else(|| anyhow!("Missing host in resource URI"))?;
            let port = url
                .port_or_known_default()
                .ok_or_else(|| anyhow!("Missing port in resource URI"))?;
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
            .set_feature(Feature::TcpForward)
            .set_http_request(request)
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

struct HttpConnectCallback;
#[async_trait]
impl ContextCallback for HttpConnectCallback {
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
        let buf = format!("Error: {} Cause: {:?}", error, error.source());
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

struct HttpForwardCallback;
#[async_trait]
impl ContextCallback for HttpForwardCallback {
    async fn on_connect(&self, ctx: &mut Context) {
        let client_stream = ctx.take_client_stream();
        let server_stream = ctx.take_server_stream();
        let request = ctx.http_request();

        if client_stream.is_none() || server_stream.is_none() || request.is_none() {
            warn!(
                "HttpForwardCallback::on_connect: missing client_stream, server_stream, or http_request"
            );
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
        let mut request = request.unwrap().as_ref().clone();

        // Only add Connection: close for regular HTTP requests, not WebSocket upgrades
        let is_websocket_upgrade = request
            .header("Connection", "")
            .to_lowercase()
            .contains("upgrade")
            && request
                .header("Upgrade", "")
                .to_lowercase()
                .contains("websocket");

        if !is_websocket_upgrade {
            request = request.with_header("Connection", "close");
        }

        if let Err(e) = request.write_to(&mut server_stream).await {
            warn!("Failed to write request to server: {}", e);
            let _ = HttpResponse::new(503, "Service Unavailable")
                .with_header("Connection", "close")
                .write_to(&mut client_stream)
                .await;
            return;
        }

        // Flush the server stream to ensure request is sent
        if let Err(e) = server_stream.flush().await {
            warn!("Failed to flush server stream after writing request: {}", e);
            let _ = HttpResponse::new(503, "Service Unavailable")
                .with_header("Connection", "close")
                .write_to(&mut client_stream)
                .await;
            return;
        }

        // Put streams back and let copy_bidi handle everything else
        ctx.set_client_stream(client_stream);
        ctx.set_server_stream(server_stream);
    }

    async fn on_error(&self, ctx: &mut Context, error: Error) {
        warn!("HttpForwardCallback::on_error: {}", error);
        if let Some(mut socket) = ctx.take_client_stream() {
            let response = HttpResponse::new(503, "Service Unavailable")
                .with_header("Content-Type", "text/plain")
                .with_header("Connection", "close");
            let body = format!("Error: {}\r\nCause: {:?}", error, error.source());
            let response = response.with_header("Content-Length", body.len().to_string());

            if let Err(e) = response.write_with_body(&mut socket, body.as_bytes()).await {
                warn!("Failed to send error response to client: {}", e);
            }
        } else {
            warn!("HttpForwardCallback::on_error: No client stream to send error response.");
        }
    }
}

struct FrameChannelCallback {
    session_id: u32,
    inline: bool,
}

#[async_trait]
impl ContextCallback for FrameChannelCallback {
    async fn on_connect(&self, ctx: &mut Context) {
        tracing::trace!("on_connect callback: id={} ctx={}", self.session_id, ctx);
        let stream_opt = ctx.take_client_stream();
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
            return;
        }

        if self.inline {
            ctx.set_client_frames(frames_from_stream(self.session_id, stream));
        }
    }

    async fn on_error(&self, ctx: &mut Context, error: Error) {
        let socket = ctx.borrow_client_stream();
        if socket.is_none() {
            return;
        }
        let buf = format!("Error: {} Cause: {:?}", error, error.source());
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
