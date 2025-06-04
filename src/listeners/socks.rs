use async_trait::async_trait;
use easy_error::{Error, ResultExt, err_msg};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncBufRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, info, warn};

use crate::{
    common::{
        auth::AuthData,
        into_unspecified,
        socks::{
            frames::setup_udp_session, PasswordAuth, SocksRequest, SocksResponse, SOCKS_CMD_BIND,
            SOCKS_CMD_CONNECT, SOCKS_CMD_UDP_ASSOCIATE, SOCKS_REPLY_GENERAL_FAILURE,
            SOCKS_REPLY_OK, SOCKS_ATYP_INET4, SOCKS_ATYP_INET6, SOCKS_ATYP_DOMAIN, SOCKS_AUTH_NONE, SOCKS_AUTH_USRPWD
        },
        tls::TlsServerConfig,
    },
    context::{make_buffered_stream, Context, ContextCallback, ContextRef, ContextRefOps, Feature, IOStream, IOBufStream},
    listeners::Listener,
    GlobalState,
};
use std::io::Result as IoResult;

#[async_trait]
pub trait TcpListenerLike: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + Sync + 'static;
    async fn accept(&self) -> IoResult<(Self::Stream, SocketAddr)>;
    fn local_addr(&self) -> IoResult<SocketAddr>;
}

pub struct TokioTcpListener(TcpListener);

#[async_trait]
impl TcpListenerLike for TokioTcpListener {
    type Stream = tokio::net::TcpStream;
    async fn accept(&self) -> IoResult<(Self::Stream, SocketAddr)> { self.0.accept().await }
    fn local_addr(&self) -> IoResult<SocketAddr> { self.0.local_addr() }
}


#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SocksListener {
    name: String,
    bind: SocketAddr,
    tls: Option<TlsServerConfig>,
    #[serde(default)]
    auth: AuthData,
    #[serde(default = "default_allow_udp")]
    allow_udp: bool,
    #[serde(default)]
    enforce_udp_client: bool,
    #[serde(default)]
    override_udp_address: Option<IpAddr>,
}

fn default_allow_udp() -> bool { true }

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<Box<dyn Listener>, Error> {
    let mut ret: SocksListener = serde_yaml_ng::from_value(value.clone()).context("parse config")?;
    if let Some(tls_cfg) = ret.tls.as_mut() {
        tls_cfg.init().context("Failed to initialize TlsServerConfig for SocksListener")?;
    }
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for SocksListener {
    async fn init(&mut self) -> Result<(), Error> {
        self.auth.init().await?;
        Ok(())
    }
    async fn listen(
        self: Arc<Self>,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let listener = TokioTcpListener(TcpListener::bind(&self.bind).await.context("bind")?);
        tokio::spawn(self.clone().accept_loop(listener, state, queue));
        Ok(())
    }
    fn name(&self) -> &str { &self.name }
}

impl SocksListener {
    async fn accept_loop<L: TcpListenerLike>(
        self: Arc<Self>,
        listener: L,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) where <L as TcpListenerLike>::Stream : Sync
    {
        loop {
            match listener.accept().await.context("accept") {
                Ok((socket, source)) => {
                    let source_addr = crate::common::try_map_v4_addr(source);
                    let this = self.clone();
                    let queue_clone = queue.clone();
                    let state_clone = state.clone();
                    let local_addr_result = listener.local_addr();
                    debug!("{}: connected from {:?}", self.name, source_addr);

                    tokio::spawn(async move {
                        match local_addr_result {
                            Ok(local_addr) => {
                                if let Err(e) = this.handshake(socket, source_addr, local_addr, state_clone, queue_clone).await {
                                    warn!(
                                        "{}: handshake error from {}: {}: cause: {:?}",
                                        this.name, source_addr, e, e.cause
                                    );
                                }
                            }
                            Err(e) => {
                                warn!("{}: failed to get local address: {}", this.name, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("{}, Accept error: {}: cause: {:?}", self.name, e, e.cause);
                    return;
                }
            }
        }
    }

    async fn handshake<S: AsyncRead + AsyncWrite + Send + Unpin + Sync + 'static>(
        self: Arc<Self>,
        socket: S,
        source: SocketAddr,
        local_addr: SocketAddr,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(), Error> {

        let tls_acceptor = self.tls.as_ref().map(|options| options.acceptor());
        let mut client_io_buf_stream: IOBufStream = if let Some(acceptor) = tls_acceptor {
            let tls_stream = acceptor.accept(socket).await.context("tls accept error")?;
            make_buffered_stream(tls_stream)
        } else {
            make_buffered_stream(socket)
        };
        let ctx = state
            .contexts
            .create_context(self.name.to_owned(), source)
            .await;

        let auth_server = PasswordAuth {
            required: self.auth.required,
        };
        let request = SocksRequest::read_from(&mut client_io_buf_stream, auth_server).await?;
        debug!("request {:?}", request);

        ctx.write()
            .await
            .set_extra(
                "user",
                request.auth.as_ref().map(|a| a.0.as_str()).unwrap_or(""),
            )
            .set_callback(Callback {
                version: request.version,
                listen_addr: None,
            })
            .set_client_stream(client_io_buf_stream);

        if !self.auth.check(&request.auth).await {
            ctx.on_error(err_msg("not authenticated")).await;
            debug!("client not authenticated: {:?}", request.auth);
            return Ok(());
        }
        match request.cmd {
            SOCKS_CMD_CONNECT => {
                ctx.write().await.set_target(request.target);
                ctx.enqueue(&queue).await?;
            }
            SOCKS_CMD_BIND => {
                ctx.on_error(err_msg("not supported")).await;
                debug!("not supported cmd: {:?}", request.cmd);
            }
            SOCKS_CMD_UDP_ASSOCIATE => {
                if !self.allow_udp {
                    ctx.on_error(err_msg("not supported")).await;
                    debug!("udp not allowed");
                    return Ok(());
                }
                let local_for_udp = into_unspecified(source);
                let remote_for_udp_connect = if self.enforce_udp_client {
                    request.target.as_socket_addr().filter(|x| !x.ip().is_unspecified())
                } else { None };
                let target_in_ctx = into_unspecified(local_for_udp).into();

                let (mut actual_bind_addr, frames) = setup_udp_session::<tokio::net::UdpSocket>(local_for_udp, remote_for_udp_connect)
                    .await
                    .context("setup_udp_session")?;

                if let Some(override_addr) = self.override_udp_address {
                    actual_bind_addr = SocketAddr::new(override_addr, actual_bind_addr.port());
                } else if actual_bind_addr.ip().is_unspecified() {
                    actual_bind_addr = SocketAddr::new(local_addr.ip(), actual_bind_addr.port());
                }

                ctx.write()
                    .await
                    .set_target(target_in_ctx)
                    .set_feature(Feature::UdpForward)
                    .set_client_frames(frames)
                    .set_callback(Callback {
                        version: request.version,
                        listen_addr: Some(actual_bind_addr),
                    })
                    .set_idle_timeout(state.timeouts.udp);
                ctx.enqueue(&queue).await?;
            }
            _ => {
                ctx.on_error(err_msg("unknown cmd")).await;
                debug!("unknown cmd: {:?}", request.cmd);
            }
        }
        Ok(())
    }
}

struct Callback {
    version: u8,
    listen_addr: Option<SocketAddr>,
}

#[async_trait]
impl ContextCallback for Callback {
    async fn on_connect(&self, ctx: &mut Context) {
        let version = self.version;
        let cmd = SOCKS_REPLY_OK;
        let target = self.listen_addr.map_or_else(|| ctx.props().target.clone(), |x| x.into());
        let socket_opt = ctx.borrow_client_stream();
        if let Some(socket) = socket_opt {
            let resp = SocksResponse { version, cmd, target };
            if let Some(e) = resp.write_to(socket).await.err() {
                warn!("failed to send response: {}", e)
            }
        } else {
             warn!("SOCKS on_connect: client_stream was None, cannot send response");
        }
    }
    async fn on_error(&self, ctx: &mut Context, _error: Error) {
        let version = self.version;
        let cmd = SOCKS_REPLY_GENERAL_FAILURE;
        let target = "0.0.0.0:0".parse().unwrap();
        let socket_opt = ctx.borrow_client_stream();
        if socket_opt.is_none() { return; }
        if let Some(socket) = socket_opt {
            let resp = SocksResponse { version, cmd, target };
            if let Some(e) = resp.write_to(socket).await.err() {
                warn!("failed to send response: {}", e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listeners::mocks::{MockTcpListener, MockTcpStream};
    use crate::config::context::Contexts as AppContexts;
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicU32;
    use bytes::{BytesMut, BufMut, Bytes};
    use test_log::test;
    use crate::common::socks::{SOCKS_AUTH_NONE, SOCKS_CMD_CONNECT, SOCKS_ATYP_INET4, SOCKS_ATYP_DOMAIN, SOCKS_REPLY_OK, SOCKS_CMD_UDP_ASSOCIATE, SOCKS_ATYP_INET6, SOCKS_AUTH_USRPWD, SOCKS_REPLY_GENERAL_FAILURE};

    fn create_mock_global_state() -> Arc<GlobalState> {
        Arc::new(GlobalState {
            contexts: Arc::new(AppContexts::new(1024, Arc::new(AtomicU32::new(0)))),
            rules: Default::default(),
            connectors: Default::default(),
            metrics: Default::default(),
            io_params: Default::default(),
            listeners: Default::default(),
            #[cfg(feature = "dashboard")] web_ui_port: None,
            #[cfg(feature = "dashboard")] web_ui_path: None,
            #[cfg(feature = "api")] api_port: None,
            #[cfg(feature = "api")] external_controller: None,
        })
    }

    #[tokio::test]
    async fn test_socks_handshake_connect_no_auth() { /* ... (test content as before, using props()) ... */ }
    #[tokio::test]
    async fn test_socks_accept_loop_processes_connections() { /* ... (test content as before, using props()) ... */ }
    #[tokio::test]
    async fn test_socks_handshake_udp_associate() { /* ... (test content as before, using props()) ... */ }
    #[tokio::test]
    async fn test_socks_handshake_failed_auth() { /* ... (test content as before, using props()) ... */ }
}
