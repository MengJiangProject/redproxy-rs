use crate::{
    common::frames::{FrameReader, FrameWriter},
    config::IoParams,
    context::{ContextRef, ContextState, ContextStatistics, IOBufStream},
};
use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use futures::future::BoxFuture;
use std::{io::Result as IoResult, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

#[cfg(feature = "metrics")]
lazy_static::lazy_static! {
    static ref IO_BYTES_CLIENT: prometheus::IntCounterVec = prometheus::register_int_counter_vec!(
        "io_client_bytes",
        "Number of bytes sent from client to server.",
        &["listener"]
    )
    .expect("Failed to register IO client bytes counter metric");
    static ref IO_BYTES_SERVER: prometheus::IntCounterVec = prometheus::register_int_counter_vec!(
        "io_server_bytes",
        "Number of bytes sent from server to client.",
        &["connector"]
    )
    .expect("Failed to register IO server bytes counter metric");
}

#[cfg(target_os = "linux")]
use std::os::unix::prelude::OwnedFd;
#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;
#[cfg(target_os = "linux")]
fn has_raw_fd(stream: &dyn crate::context::IOStream) -> bool {
    use tokio::net::TcpStream;
    stream.as_any().is::<TcpStream>()
}
#[cfg(target_os = "linux")]
fn into_owned_fd(stream: Box<dyn crate::context::IOStream>) -> OwnedFd {
    use tokio::net::TcpStream;
    let stream = stream.into_any().downcast::<TcpStream>().unwrap();
    let std_fd = stream.into_std().unwrap();
    std_fd.into()
}

#[cfg(not(target_os = "linux"))]
type OwnedFd = i32;
#[cfg(not(target_os = "linux"))]
type AsyncFd<T> = Option<T>;
#[cfg(not(target_os = "linux"))]
fn has_raw_fd(_stream: &dyn crate::context::IOStream) -> bool {
    false
}

struct SrcHalf<T> {
    name: &'static str,
    stream: Option<ReadHalf<T>>,
    frames: Option<Box<dyn FrameReader>>,
    rawfd: Option<AsyncFd<OwnedFd>>,
}

impl<T> SrcHalf<T> {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            stream: None,
            frames: None,
            rawfd: None,
        }
    }
}

struct DstHalf<T> {
    name: &'static str,
    stream: Option<WriteHalf<T>>,
    frames: Option<Box<dyn FrameWriter>>,
    rawfd: Option<AsyncFd<OwnedFd>>,
}

impl<T> DstHalf<T> {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            stream: None,
            frames: None,
            rawfd: None,
        }
    }
}

async fn copy_half<S, D>(
    params: &IoParams,
    mut src: SrcHalf<S>,
    mut dst: DstHalf<D>,
    stat: Arc<ContextStatistics>,
    #[cfg(feature = "metrics")] counter: prometheus::core::GenericCounter<
        prometheus::core::AtomicU64,
    >,
) -> Result<()>
where
    S: AsyncRead,
    D: AsyncWrite,
{
    let mut sbuf = BytesMut::zeroed(params.buffer_size);
    let have_stream = src.stream.is_some() && dst.stream.is_some();
    let have_frames = src.frames.is_some() && dst.frames.is_some();
    let have_rawfd = src.rawfd.is_some() && dst.rawfd.is_some();

    trait SpliceFn {
        fn read(&mut self) -> BoxFuture<'_, IoResult<usize>>;
        fn write(&mut self, more: bool) -> BoxFuture<'_, IoResult<usize>>;
    }
    //type BoxSpliceFn = Box<dyn SpliceFn + Send>;
    struct NullFn;
    impl SpliceFn for NullFn {
        fn read(&mut self) -> BoxFuture<'_, IoResult<usize>> {
            unreachable!()
        }
        fn write(&mut self, _more: bool) -> BoxFuture<'_, IoResult<usize>> {
            unreachable!()
        }
    }
    #[cfg(target_os = "linux")]
    let mut pipe_fn: Box<dyn SpliceFn + Send> = if have_rawfd {
        use crate::common::splice::{async_splice, pipe};
        use futures::FutureExt;

        struct PipeFn {
            sfd: AsyncFd<OwnedFd>,
            dfd: AsyncFd<OwnedFd>,
            pipe: (AsyncFd<OwnedFd>, AsyncFd<OwnedFd>),
            bufsz: usize,
        }
        impl SpliceFn for PipeFn {
            fn read(&mut self) -> BoxFuture<'_, IoResult<usize>> {
                async_splice(&mut self.sfd, &self.pipe.1, self.bufsz, false).boxed()
            }
            fn write(&mut self, more: bool) -> BoxFuture<'_, IoResult<usize>> {
                async_splice(&mut self.pipe.0, &self.dfd, self.bufsz, more).boxed()
            }
        }

        Box::new(PipeFn {
            sfd: src.rawfd.unwrap(),
            dfd: dst.rawfd.unwrap(),
            pipe: pipe().context("pipe")?,
            bufsz: params.buffer_size,
        })
    } else {
        Box::new(NullFn)
    };
    #[cfg(not(target_os = "linux"))]
    let mut pipe_fn = Box::new(NullFn);
    loop {
        tokio::select! {
            ret = async {src.stream.as_mut().unwrap().read(&mut sbuf).await}, if have_stream => {
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
            ret = async {src.frames.as_mut().unwrap().read().await}, if have_frames => {
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
            ret = async {pipe_fn.read().await}, if have_rawfd => {
                let len = ret.with_context(|| format!("pipe_read from {}", src.name))?;
                if len > 0 {
                    pipe_fn.write(len >= params.buffer_size).await.with_context(|| format!("pipe_write to {}", dst.name))?;
                    stat.incr_sent_bytes(len);
                    #[cfg(feature = "metrics")]
                    counter.inc_by(len as u64);
                } else {
                    break;
                }
            }
            else => {
                break;
            }
        }
    }

    if let Some(mut s) = dst.stream {
        s.shutdown()
            .await
            .with_context(|| format!("shutdown {})", dst.name))?;
    }

    if let Some(mut s) = dst.frames {
        s.shutdown()
            .await
            .with_context(|| format!("shutdown frame {})", dst.name))?;
    }

    Ok(())
}

async fn drain_buffers(from: &mut IOBufStream, to: &mut IOBufStream) -> IoResult<()> {
    let left_over = from.buffer();
    if !left_over.is_empty() {
        to.write_all(left_over).await?;
    }
    to.flush().await
}
pub async fn copy_bidi(ctx: ContextRef, params: &IoParams) -> Result<()> {
    let mut ctx_lock = ctx.write().await;
    let idle_timeout = ctx_lock.idle_timeout();
    let streams = ctx_lock.take_streams();
    let frames = ctx_lock.take_frames();
    let client_stat = ctx_lock.props().client_stat.clone();
    let server_stat = ctx_lock.props().server_stat.clone();
    #[cfg(feature = "metrics")]
    let client_label = ctx_lock.props().listener.clone();
    #[cfg(feature = "metrics")]
    let server_label = ctx_lock
        .props()
        .connector
        .as_ref()
        .ok_or_else(|| anyhow!("No connector information available"))?
        .clone();
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

        if has_raw_fd(&*client) && has_raw_fd(&*server) && params.use_splice {
            #[cfg(target_os = "linux")]
            {
                let craw = into_owned_fd(client);
                let sraw = into_owned_fd(server);
                csrc.rawfd = Some(AsyncFd::new(craw.try_clone().unwrap()).unwrap());
                cdst.rawfd = Some(AsyncFd::new(craw).unwrap());
                ssrc.rawfd = Some(AsyncFd::new(sraw.try_clone().unwrap()).unwrap());
                sdst.rawfd = Some(AsyncFd::new(sraw).unwrap());
            }
        } else {
            let (csr, csw) = tokio::io::split(client);
            csrc.stream = Some(csr);
            cdst.stream = Some(csw);
            let (ssr, ssw) = tokio::io::split(server);
            ssrc.stream = Some(ssr);
            sdst.stream = Some(ssw);
        }
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
        params,
        csrc,
        sdst,
        client_stat.clone(),
        #[cfg(feature = "metrics")]
        IO_BYTES_CLIENT.with_label_values(&[client_label.as_str()]),
    );
    let copy_s2c = copy_half(
        params,
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
                return Err(anyhow::anyhow!("idle timeout"))
            }
        }
    }
    Ok(())
}
