use easy_error::{bail, err_msg, Error, ResultExt};
use log::{debug, warn};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};
use tokio::{io::AsyncWriteExt, sync::mpsc::Sender};

use crate::{
    common::http::HttpRequest,
    context::{Context, ContextCallback, IOBufStream},
};

use super::http::HttpResponse;

// HTTP 1.1 CONNECT protocol handlers
// used by http and quic listeners and connectors
pub async fn h11c_handshake(
    name: String,
    mut socket: IOBufStream,
    source: SocketAddr,
    queue: Sender<Context>,
) -> Result<(), Error> {
    debug!("connected from {:?}", source);
    let request = HttpRequest::read_from(&mut socket).await?;
    if !request.method.eq_ignore_ascii_case("CONNECT") {
        bail!("Invalid request method: {}", request.method)
    }
    let target = request.resource.parse().map_err(|_e| {
        err_msg(format!(
            "failed to parse target address: {}",
            request.resource
        ))
    })?;

    queue
        .send(Context {
            socket,
            target,
            source,
            listener: name,
            callback: Some(Arc::new(Callback)),
        })
        .await
        .context("enqueue")?;
    Ok(())
}

struct Callback;
impl ContextCallback for Callback {
    fn on_connect<'a>(
        &self,
        ctx: &'a mut Context,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let s = &mut ctx.socket;
            if let Some(e) = HttpResponse::new(200, "Connection established")
                .write_to(s)
                .await
                .and(s.flush().await.context("flush"))
                .err()
            {
                warn!("failed to send response: {}", e)
            }
        })
    }
    fn on_error<'a>(
        &self,
        ctx: &'a mut Context,
        error: Error,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let s = &mut ctx.socket;
            if let Some(e) = HttpResponse::new(503, "Service unavailable")
                .with_header("Error", error)
                .write_to(s)
                .await
                .and(s.flush().await.context("flush"))
                .err()
            {
                warn!("failed to send response: {}", e)
            }
        })
    }
}
