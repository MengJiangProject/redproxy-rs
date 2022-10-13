use crate::{
    common::frames::{FrameReader, FrameWriter},
    context::{ContextRef, ContextState, ContextStatistics, IOBufStream},
};
use easy_error::{err_msg, Error, ResultExt};
use std::{io::Result as IoResult, sync::Arc, time::Duration};
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

struct SrcHalf<T> {
    name: &'static str,
    stream: Option<ReadHalf<T>>,
    frames: Option<Box<dyn FrameReader>>,
}

impl<T> SrcHalf<T> {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            stream: None,
            frames: None,
        }
    }
}

struct DstHalf<T> {
    stream: Option<WriteHalf<T>>,
    frames: Option<Box<dyn FrameWriter>>,
    name: &'static str,
}

impl<T> DstHalf<T> {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            stream: None,
            frames: None,
        }
    }
}

async fn copy_half<S, D>(
    mut src: SrcHalf<S>,
    mut dst: DstHalf<D>,
    stat: Arc<ContextStatistics>,
    #[cfg(feature = "metrics")] counter: prometheus::core::GenericCounter<
        prometheus::core::AtomicU64,
    >,
) -> Result<(), Error>
where
    S: AsyncRead,
    D: AsyncWrite,
{
    let mut sbuf = [0u8; 65536];
    let have_stream = src.stream.is_some() && dst.stream.is_some();
    let have_frames = src.frames.is_some() && dst.frames.is_some();
    loop {
        tokio::select! {
            ret = src.stream.as_mut().unwrap().read(&mut sbuf), if have_stream => {
                let len = ret.with_context(|| format!("read from {}", src.name))?;
                if len > 0 {
                    dst.stream.as_mut().unwrap().write_all(&sbuf[..len]).await.with_context(|| format!("write to {}", dst.name))?;
                    dst.stream.as_mut().unwrap().flush().await.with_context(|| format!("flush {} buffer", dst.name))?;
                    stat.incr_sent_bytes(len);
                    #[cfg(feature = "metrics")]
                    counter.inc_by(len as u64);
                } else {
                    break;
                }
            }
            ret = src.frames.as_mut().unwrap().read(), if have_frames => {
                let fbuf = ret.with_context(|| format!("read frame from {}", src.name))?;
                if let Some(fbuf) = fbuf {
                    let len = dst.frames.as_mut().unwrap().write(fbuf).await.with_context(|| format!("write frame to {}", dst.name))?;
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

    dst.stream
        .as_mut()
        .unwrap()
        .shutdown()
        .await
        .with_context(|| format!("shutdown {})", dst.name))?;
    dst.frames
        .as_mut()
        .unwrap()
        .shutdown()
        .await
        .with_context(|| format!("shutdown frame {})", dst.name))?;
    Ok(())
}

async fn drain_buffers(from: &mut IOBufStream, to: &mut IOBufStream) -> IoResult<()> {
    let left_over = from.buffer();
    if !left_over.is_empty() {
        to.write_all(left_over).await?;
    }
    to.flush().await
}
pub async fn copy_bidi(ctx: ContextRef) -> Result<(), Error> {
    let mut ctx_lock = ctx.write().await;
    let idle_timeout = ctx_lock.idle_timeout();
    let streams = ctx_lock.take_streams();
    let frames = ctx_lock.take_frames();
    let client_stat = ctx_lock.props().client_stat.clone();
    let server_stat = ctx_lock.props().server_stat.clone();
    #[cfg(feature = "metrics")]
    let client_label = ctx_lock.props().listener.clone();
    #[cfg(feature = "metrics")]
    let server_label = ctx_lock.props().connector.as_ref().unwrap().clone();
    drop(ctx_lock);

    let mut csrc = SrcHalf::new("client");
    let mut ssrc = SrcHalf::new("server");
    let mut cdst = DstHalf::new("client");
    let mut sdst = DstHalf::new("server");
    if let Some((mut client, mut server)) = streams {
        // Drain any buffers that may haven't been consumed or flushed.
        drain_buffers(&mut client, &mut server)
            .await
            .context("failed to drain client buffers")?;
        drain_buffers(&mut server, &mut client)
            .await
            .context("failed to drain server buffers")?;

        // Get the naked streams without buffers.
        let client = client.into_inner().into_inner();
        let server = server.into_inner().into_inner();

        let (csr, csw) = tokio::io::split(client);
        csrc.stream = Some(csr);
        cdst.stream = Some(csw);
        let (ssr, ssw) = tokio::io::split(server);
        ssrc.stream = Some(ssr);
        sdst.stream = Some(ssw);
    }

    if let Some((client, server)) = frames {
        let (cfr, cfw) = client;
        csrc.frames = Some(cfr);
        cdst.frames = Some(cfw);
        let (sfr, sfw) = server;
        ssrc.frames = Some(sfr);
        sdst.frames = Some(sfw);
    }

    let copy_c2s = copy_half(
        csrc,
        sdst,
        client_stat.clone(),
        #[cfg(feature = "metrics")]
        IO_BYTES_CLIENT.with_label_values(&[client_label.as_str()]),
    );
    let copy_s2c = copy_half(
        ssrc,
        cdst,
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
