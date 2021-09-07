use crate::context::{ContextRef, ContextStatistics};
use easy_error::{Error, ResultExt};
use std::sync::Arc;
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

async fn copy_stream<T: AsyncRead + AsyncWrite>(
    mut r: ReadHalf<T>,
    rn: &str,
    mut w: WriteHalf<T>,
    wn: &str,
    stat: Arc<ContextStatistics>,
    #[cfg(feature = "metrics")] counter: prometheus::core::GenericCounter<
        prometheus::core::AtomicU64,
    >,
) -> Result<(), Error> {
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
    w.shutdown().await.or(Ok(())) // Ignore "Transport endpoint is not connected"
}
pub async fn copy_bidi(ctx: ContextRef) -> Result<(), Error> {
    let ctx = ctx.read().await;
    let mut client = ctx.get_client_stream().await;
    let mut server = ctx.get_server_stream().await;
    let (cread, cwrite) = tokio::io::split(client.get_mut());
    let (sread, swrite) = tokio::io::split(server.get_mut());
    let copy_a_to_b = copy_stream(
        cread,
        "client",
        swrite,
        "server",
        ctx.props().client_stat.clone(),
        #[cfg(feature = "metrics")]
        IO_BYTES_CLIENT.with_label_values(&[ctx.props().listener.as_str()]),
    );
    let copy_b_to_a = copy_stream(
        sread,
        "server",
        cwrite,
        "client",
        ctx.props().server_stat.clone(),
        #[cfg(feature = "metrics")]
        IO_BYTES_SERVER.with_label_values(&[ctx.props().connector.as_deref().unwrap()]),
    );
    tokio::try_join!(copy_a_to_b, copy_b_to_a)?;
    Ok(())
}
