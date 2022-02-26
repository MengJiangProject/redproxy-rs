use crate::context::{ContextRef, ContextState, ContextStatistics};
use easy_error::{err_msg, Error, ResultExt};
use futures::Future;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

#[cfg(feature = "metrics")]
lazy_static::lazy_static! {
    static ref IO_BYTES_CLIENT: prometheus::IntCounterVec = prometheus::register_int_counter_vec!(
        "io_client_bytes",
        "Number of bytes sent from client to server.",
        &["listener"]
    )
    .unwrap();
    static ref IO_BYTES_SERVER: prometheus::IntCounterVec = prometheus::register_int_counter_vec!(
        "io_server_bytes",
        "Number of bytes sent from server to client.",
        &["connector"]
    )
    .unwrap();
}

async fn copy_stream<C, T, F>(
    mut r: ReadHalf<T>,
    rn: &str,
    mut w: WriteHalf<T>,
    wn: &str,
    stat: Arc<ContextStatistics>,
    #[cfg(feature = "metrics")] counter: prometheus::core::GenericCounter<
        prometheus::core::AtomicU64,
    >,
    cb: C,
) -> Result<(), Error>
where
    T: AsyncRead + AsyncWrite,
    C: FnOnce() -> F,
    F: Future<Output = ()>,
{
    let mut buf = [0u8; 65536];
    loop {
        let len = r
            .read(&mut buf)
            .await
            .with_context(|| format!("read from {}", rn))?;
        if len > 0 {
            let mut pos = 0;
            while pos < len {
                let n = w
                    .write(&buf[pos..len])
                    .await
                    .with_context(|| format!("write to {}", wn))?;
                pos += n;
            }
            w.flush()
                .await
                .with_context(|| format!("flush {} buffer", wn))?;
            stat.incr_sent_bytes(len);
            #[cfg(feature = "metrics")]
            counter.inc_by(len as u64);
        } else {
            break;
        }
    }
    cb().await;
    w.shutdown()
        .await
        .with_context(|| format!("shutdown {})", wn)) //.or(Ok(())) // Ignore "Transport endpoint is not connected"
}
pub async fn copy_bidi(ctx: ContextRef, idle_timeout: Duration) -> Result<(), Error> {
    let ctx_lock = ctx.read().await;
    let (client, server) = ctx_lock.get_streams();
    let mut client = client.lock().await;
    let mut server = server.lock().await;
    let client_stat = ctx_lock.props().client_stat.clone();
    let client_label = ctx_lock.props().listener.clone();
    let server_stat = ctx_lock.props().server_stat.clone();
    let server_label = ctx_lock.props().connector.as_ref().unwrap().clone();
    drop(ctx_lock);

    let (cread, cwrite) = tokio::io::split(client.get_mut());
    let (sread, swrite) = tokio::io::split(server.get_mut());
    let copy_c2s = copy_stream(
        cread,
        "client",
        swrite,
        "server",
        client_stat.clone(),
        #[cfg(feature = "metrics")]
        IO_BYTES_CLIENT.with_label_values(&[client_label.as_str()]),
        || async {},
    );
    let copy_s2c = copy_stream(
        sread,
        "server",
        cwrite,
        "client",
        server_stat.clone(),
        #[cfg(feature = "metrics")]
        IO_BYTES_SERVER.with_label_values(&[server_label.as_str()]),
        || async {},
    );
    let interval = tokio::time::interval(Duration::from_secs(1));
    tokio::pin!(copy_c2s);
    tokio::pin!(copy_s2c);
    tokio::pin!(interval);

    let mut c2s = None;
    let mut s2c = None;

    while c2s.is_none() || s2c.is_none() {
        tokio::select! {
            biased;
            ret = (&mut copy_c2s), if c2s.is_none() => {
                ctx.write().await.set_state(ContextState::ClientShutdown);
                c2s = Some(ret?)
            },
            ret = (&mut copy_s2c), if s2c.is_none() => {
                ctx.write().await.set_state(ContextState::ServerShutdown);
                s2c = Some(ret?)
            },
            _ = interval.tick() => if server_stat.is_timeout(idle_timeout) && client_stat.is_timeout(idle_timeout){
                return Err(err_msg("idle timeout"))
            }
        }
    }
    Ok(())
}
