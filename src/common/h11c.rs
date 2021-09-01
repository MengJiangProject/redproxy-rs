use easy_error::{bail, Error, ResultExt};
use log::warn;
use std::{future::Future, ops::DerefMut, pin::Pin};
use tokio::sync::mpsc::Sender;

use crate::{
    common::http::HttpRequest,
    context::{ContextCallback, ContextRef, ContextRefOps},
};

use super::http::HttpResponse;

// HTTP 1.1 CONNECT protocol handlers
// used by http and quic listeners and connectors
pub async fn h11c_handshake(ctx: ContextRef, queue: Sender<ContextRef>) -> Result<(), Error> {
    let request = {
        let ctx = ctx.read().await;
        let mut socket = ctx.get_client_stream().await;
        let request = HttpRequest::read_from(socket.deref_mut()).await?;
        if !request.method.eq_ignore_ascii_case("CONNECT") {
            HttpResponse::new(400, "Bad Request")
                .write_to(socket.deref_mut())
                .await?;
            bail!("Invalid request method: {}", request.method)
        }
        request
    };
    ctx.write()
        .await
        .set_target(
            request
                .resource
                .parse()
                .with_context(|| format!("failed to parse target address: {}", request.resource))?,
        )
        .set_callback(Callback);
    ctx.enqueue(&queue).await?;
    Ok(())
}

struct Callback;
impl ContextCallback for Callback {
    fn on_connect(&self, ctx: ContextRef) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            let ctx = ctx.read().await;
            let mut socket = ctx.get_client_stream().await;
            let s = socket.deref_mut();
            if let Err(e) = HttpResponse::new(200, "Connection established")
                .write_to(s)
                .await
            {
                warn!("failed to send response: {}", e)
            }
        })
    }
    fn on_error(&self, ctx: ContextRef, error: Error) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            let ctx = ctx.read().await;
            let mut socket = ctx.get_client_stream().await;
            let s = socket.deref_mut();
            let buf = format!("Error: {} Cause: {:?}", error, error.cause);
            if let Err(e) = HttpResponse::new(503, "Service unavailable")
                .with_header("Content-Type", "text/plain")
                .with_header("Content-Length", buf.as_bytes().len())
                .write_with_body(s, buf.as_bytes())
                .await
            {
                warn!("failed to send response: {}", e)
            }
        })
    }
}
