use crate::{
    common::frames::{Frame, FrameReader, FrameWriter, Frames},
    context::{make_buffered_stream, ContextRef, ContextState, ContextStatistics, IOBufStream},
};
use async_trait::async_trait;
use easy_error::{err_msg, Error, ResultExt};
use futures::{Future, FutureExt};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

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

async fn copy_stream<T>(
    (mut rs, mut rf, rn): (ReadHalf<T>, Box<dyn FrameReader>, &'static str),
    (mut ws, mut wf, wn): (WriteHalf<T>, Box<dyn FrameWriter>, &'static str),
    stat: Arc<ContextStatistics>,
    #[cfg(feature = "metrics")] counter: prometheus::core::GenericCounter<
        prometheus::core::AtomicU64,
    >,
) -> Result<(), Error>
where
    T: AsyncRead + AsyncWrite,
{
    let mut sbuf = [0u8; 65536];
    loop {
        tokio::select! {
            ret = rs.read(&mut sbuf) => {
                let len = ret.with_context(|| format!("read from {}", rn))?;
                if len > 0 {
                    ws.write_all(&sbuf[..len]).await.with_context(|| format!("write to {}", wn))?;
                    ws.flush().await.with_context(|| format!("flush {} buffer", wn))?;
                    stat.incr_sent_bytes(len);
                    #[cfg(feature = "metrics")]
                    counter.inc_by(len as u64);
                } else {
                    break;
                }
            }
            ret = rf.read() => {
                let fbuf = ret.with_context(|| format!("read frame from {}", rn))?;
                if let Some(fbuf) = fbuf {
                    let len = wf.write(fbuf).await.with_context(|| format!("write frame to {}", wn))?;
                    stat.incr_sent_bytes(len);
                    stat.incr_sent_frames(1);
                    #[cfg(feature = "metrics")]
                    counter.inc_by(len as u64);
                }else{
                    break;
                }

            }
        }
    }

    ws.shutdown()
        .await
        .with_context(|| format!("shutdown {})", wn))?;
    wf.shutdown()
        .await
        .with_context(|| format!("shutdown frame {})", wn))?;
    Ok(())
}
pub async fn copy_bidi(ctx: ContextRef) -> Result<(), Error> {
    let mut ctx_lock = ctx.write().await;
    let idle_timeout = ctx_lock.idle_timeout();
    let (client, server) = ctx_lock.take_streams().unwrap_or_else(null_stream);
    let frames = ctx_lock.take_frames().unwrap_or_else(null_frames);
    let client_stat = ctx_lock.props().client_stat.clone();
    let server_stat = ctx_lock.props().server_stat.clone();
    #[cfg(feature = "metrics")]
    let client_label = ctx_lock.props().listener.clone();
    #[cfg(feature = "metrics")]
    let server_label = ctx_lock.props().connector.as_ref().unwrap().clone();
    drop(ctx_lock);

    let (csr, csw) = tokio::io::split(client);
    let (ssr, ssw) = tokio::io::split(server);
    let (cfr, cfw) = frames.0;
    let (sfr, sfw) = frames.1;
    let copy_c2s = copy_stream(
        (csr, cfr, "client"),
        (ssw, sfw, "server"),
        client_stat.clone(),
        #[cfg(feature = "metrics")]
        IO_BYTES_CLIENT.with_label_values(&[client_label.as_str()]),
    );
    let copy_s2c = copy_stream(
        (ssr, sfr, "server"),
        (csw, cfw, "client"),
        server_stat.clone(),
        #[cfg(feature = "metrics")]
        IO_BYTES_SERVER.with_label_values(&[server_label.as_str()]),
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
                c2s = Some(ret?);
                ctx.write().await.set_state(ContextState::ClientShutdown);
            },
            ret = (&mut copy_s2c), if s2c.is_none() => {
                s2c = Some(ret?);
                ctx.write().await.set_state(ContextState::ServerShutdown);
            },
            _ = interval.tick() => if server_stat.is_timeout(idle_timeout) && client_stat.is_timeout(idle_timeout){
                return Err(err_msg("idle timeout"))
            }
        }
    }
    Ok(())
}

use std::io::Result as IoResult;
fn null_frames() -> (Frames, Frames) {
    (
        (Box::new(NullFrames), Box::new(NullFrames)),
        (Box::new(NullFrames), Box::new(NullFrames)),
    )
}

fn null_stream() -> (IOBufStream, IOBufStream) {
    let (a, b) = duplex(1);
    (make_buffered_stream(a), make_buffered_stream(b))
}

struct NullFrames;
impl FrameReader for NullFrames {
    fn read<'life0, 'async_trait>(
        &'life0 mut self,
    ) -> Pin<Box<(dyn futures::Future<Output = IoResult<Option<Frame>>> + Send + 'async_trait)>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        struct Never;
        impl Future for Never {
            type Output = IoResult<Option<Frame>>;

            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
                Poll::Pending
            }
        }
        Never.boxed()
    }
}
#[async_trait]
impl FrameWriter for NullFrames {
    async fn write(&mut self, _frame: Frame) -> IoResult<usize> {
        Ok(0)
    }

    async fn shutdown(&mut self) -> IoResult<()> {
        Ok(())
    }
}
