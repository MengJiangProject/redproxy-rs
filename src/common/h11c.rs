use easy_error::{bail, err_msg, Error};
use log::{debug, warn};
use std::{future::Future, net::SocketAddr, ops::DerefMut, pin::Pin, sync::Arc};
use tokio::sync::mpsc::Sender;

use crate::{
    common::http::HttpRequest,
    context::{Context, ContextCallback, IOBufStream},
};

use super::http::HttpResponse;

// HTTP 1.1 CONNECT protocol handlers
// used by http and quic listeners and connectors
pub async fn h11c_handshake(
    name: String,
    socket: IOBufStream,
    source: SocketAddr,
    queue: Sender<Arc<Context>>,
) -> Result<(), Error> {
    debug!("connected from {:?}", source);
    let mut ctx = Context::new(name, socket, source);
    let request = {
        let mut socket = ctx.lock_socket().await;
        let request = HttpRequest::read_from(socket.deref_mut()).await?;
        if !request.method.eq_ignore_ascii_case("CONNECT") {
            HttpResponse::new(400, "Bad Request")
                .write_to(socket.deref_mut())
                .await?;
            bail!("Invalid request method: {}", request.method)
        }
        request
    };
    ctx.target = request.resource.parse().map_err(|_e| {
        err_msg(format!(
            "failed to parse target address: {}",
            request.resource
        ))
    })?;
    ctx.set_callback(Callback);
    ctx.enqueue(&queue).await?;
    Ok(())
}

struct Callback;
impl ContextCallback for Callback {
    fn on_connect(&self, ctx: Arc<Context>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            let mut socket = ctx.lock_socket().await;
            let s = socket.deref_mut();
            if let Err(e) = HttpResponse::new(200, "Connection established")
                .write_to(s)
                .await
            {
                warn!("failed to send response: {}", e)
            }
        })
    }
    fn on_error(
        &self,
        ctx: Arc<Context>,
        error: Error,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            let mut socket = ctx.lock_socket().await;
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
