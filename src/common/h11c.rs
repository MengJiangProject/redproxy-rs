use async_trait::async_trait;
use easy_error::{bail, Error, ResultExt};
use log::{debug, warn};
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::mpsc::Sender;

use crate::{
    common::http::{HttpRequest, HttpResponse},
    context::{Context, ContextCallback, ContextRef, ContextRefOps, Feature},
};

use super::frames::{frames_from_stream, Frames};

static SESSION_ID: AtomicU32 = AtomicU32::new(0);
// HTTP 1.1 CONNECT protocol handlers
// used by http and quic listeners and connectors
pub async fn h11c_handshake<FrameFn>(
    ctx: ContextRef,
    queue: Sender<ContextRef>,
    create_frames: FrameFn,
) -> Result<(), Error>
where
    FrameFn: FnOnce(&str, u32) -> Result<Frames, Error> + Sync,
{
    let mut ctx_lock = ctx.write().await;
    let socket = ctx_lock.borrow_client_stream();
    let request = HttpRequest::read_from(socket).await?;
    if request.method.eq_ignore_ascii_case("CONNECT") {
        ctx_lock
            .set_target(
                request.resource.parse().with_context(|| {
                    format!("failed to parse target address: {}", request.resource)
                })?,
            )
            .set_callback(ConnectCallback);
    } else if request.method.eq_ignore_ascii_case("POST")
        && request.resource.eq_ignore_ascii_case("/udp_channel")
    {
        let session_id = SESSION_ID.fetch_add(1, Ordering::Relaxed);
        let channel = request
            .headers
            .iter()
            .find(|x| x.0.eq_ignore_ascii_case("Proxy-Channel"))
            .map_or("inline", |x| x.1.as_str());
        let host = request
            .headers
            .iter()
            .find(|x| x.0.eq_ignore_ascii_case("Host"))
            .map_or("0.0.0.0:0", |x| x.1.as_str());
        ctx_lock
            .set_target(host.parse().with_context(|| {
                format!("failed to parse target address: {}", request.resource)
            })?);
        let inline = if channel.eq_ignore_ascii_case("inline") {
            true
        } else {
            ctx_lock
                .set_client_frames(create_frames(channel, session_id).context("create frames")?);
            false
        };
        ctx_lock
            .set_callback(FrameChannelCallback { session_id, inline })
            .set_feature(Feature::UdpForward);
    } else {
        HttpResponse::new(400, "Bad Request")
            .write_to(socket)
            .await?;
        bail!("Invalid request method: {}", request.method);
    }
    debug!("Request: {:?}", ctx_lock);
    drop(ctx_lock);
    ctx.enqueue(&queue).await?;
    Ok(())
}

struct ConnectCallback;
#[async_trait]
impl ContextCallback for ConnectCallback {
    async fn on_connect(&self, ctx: &mut Context) {
        let socket = ctx.borrow_client_stream();
        if let Err(e) = HttpResponse::new(200, "Connection established")
            .write_to(socket)
            .await
        {
            warn!("failed to send response: {}", e)
        }
    }
    async fn on_error(&self, ctx: &mut Context, error: Error) {
        let socket = ctx.borrow_client_stream();
        let buf = format!("Error: {} Cause: {:?}", error, error.cause);
        if let Err(e) = HttpResponse::new(503, "Service unavailable")
            .with_header("Content-Type", "text/plain")
            .with_header("Content-Length", buf.as_bytes().len())
            .write_with_body(socket, buf.as_bytes())
            .await
        {
            warn!("failed to send response: {}", e)
        }
    }
}

#[allow(dead_code)]
struct FrameChannelCallback {
    session_id: u32,
    inline: bool,
}
#[async_trait]
impl ContextCallback for FrameChannelCallback {
    async fn on_connect(&self, ctx: &mut Context) {
        log::trace!("on_connect callback: id={}", self.session_id);
        let mut stream = ctx.take_client_stream();
        if let Err(e) = HttpResponse::new(200, "Connection established")
            .with_header("Session-Id", self.session_id.to_string())
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
        let buf = format!("Error: {} Cause: {:?}", error, error.cause);
        if let Err(e) = HttpResponse::new(503, "Service unavailable")
            .with_header("Content-Type", "text/plain")
            .with_header("Content-Length", buf.as_bytes().len())
            .write_with_body(socket, buf.as_bytes())
            .await
        {
            warn!("failed to send response: {}", e)
        }
    }
}
