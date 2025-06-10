use async_trait::async_trait;
use easy_error::{Error, ResultExt, bail};
use futures::Future;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU32, Ordering},
};
use tokio::sync::mpsc::Sender;
use tracing::{trace, warn};

use crate::{
    common::http::{HttpRequest, HttpResponse},
    context::{Context, ContextCallback, ContextRef, ContextRefOps, Feature, IOBufStream},
};

use super::frames::{FrameIO, frames_from_stream};

pub async fn h11c_connect<T1, T2>(
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
    tracing::trace!("h11c_connect: channel={}", frame_channel);
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
pub async fn h11c_handshake<FrameFn, T2>(
    ctx: ContextRef,
    queue: Sender<ContextRef>,
    create_frames: FrameFn,
) -> Result<(), Error>
where
    FrameFn: FnOnce(&str, u32) -> T2 + Sync,
    T2: Future<Output = Result<FrameIO, Error>>,
{
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

struct FrameChannelCallback {
    session_id: u32,
    inline: bool,
}
#[async_trait]
impl ContextCallback for FrameChannelCallback {
    async fn on_connect(&self, ctx: &mut Context) {
        tracing::trace!("on_connect callback: id={} ctx={}", self.session_id, ctx);
        let mut stream = ctx.take_client_stream();
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
