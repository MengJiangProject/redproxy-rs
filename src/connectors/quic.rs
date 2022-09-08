use async_trait::async_trait;
use easy_error::{bail, err_msg, Error, ResultExt};
use log::debug;
use quinn::{congestion, Connection, Endpoint};
use serde::{Deserialize, Serialize};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use tokio::sync::Mutex;

use super::ConnectorRef;
use crate::{
    common::{
        frames::frames_from_stream,
        http::{HttpRequest, HttpResponse},
        quic::{create_quic_client, QuicStream},
        tls::TlsClientConfig,
    },
    context::{make_buffered_stream, ContextRef, Feature},
    GlobalState,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct QuicConnector {
    name: String,
    server: String,
    port: u16,
    tls: TlsClientConfig,
    #[serde(default = "default_bind_addr")]
    bind: String,
    #[serde(default = "default_bbr")]
    bbr: bool,
    #[serde(skip)]
    endpoint: Option<Endpoint>,
    #[serde(skip)]
    connection: Mutex<Option<Arc<Connection>>>,
}

fn default_bind_addr() -> String {
    "[::]:0".to_owned()
}

fn default_bbr() -> bool {
    true
}

pub fn from_value(value: &serde_yaml::Value) -> Result<ConnectorRef, Error> {
    let ret: QuicConnector = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl super::Connector for QuicConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn features(&self) -> &[Feature] {
        &[Feature::TcpForward, Feature::UdpForward]
    }

    async fn init(&mut self) -> Result<(), Error> {
        self.tls.init()?;
        let mut cfg = create_quic_client(&self.tls)?;
        if self.bbr {
            let transport = Arc::get_mut(&mut cfg.transport).unwrap();
            transport.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
        }
        let bind = self.bind.parse().context("parse bind")?;
        let mut endpoint = Endpoint::client(bind).context("bind")?;
        endpoint.set_default_client_config(cfg);
        self.endpoint = Some(endpoint);
        Ok(())
    }

    async fn connect(
        self: Arc<Self>,
        _state: Arc<GlobalState>,
        ctx: ContextRef,
    ) -> Result<(), Error> {
        let conn = self.clone().get_connection().await?;
        let remote = conn.remote_address();
        let local = self
            .endpoint
            .as_ref()
            .unwrap()
            .local_addr()
            .context("local_addr")?;
        let ret = self
            .clone()
            .handshake(conn, ctx.clone(), remote, local)
            .await;
        match ret {
            Ok(()) => Ok(()),
            Err(e) => {
                self.clear_connection().await;
                Err(e)
            }
        }
    }
}

impl QuicConnector {
    async fn handshake(
        self: Arc<Self>,
        conn: Arc<Connection>,
        ctx: ContextRef,
        remote: SocketAddr,
        local: SocketAddr,
    ) -> Result<(), Error> {
        let server: QuicStream = conn
            .open_bi()
            .await
            .context("failed to open stream")?
            .into();

        let mut server = make_buffered_stream(server);
        let target = ctx.read().await.target();
        let feature = ctx.read().await.feature();
        match feature {
            Feature::TcpForward => {
                HttpRequest::new("CONNECT", &target)
                    .with_header("Host", &target)
                    .write_to(&mut server)
                    .await?;
                let resp = HttpResponse::read_from(&mut server).await?;
                if resp.code != 200 {
                    bail!("upstream server failure: {:?}", resp);
                }
                ctx.write()
                    .await
                    .set_server_stream(server)
                    .set_local_addr(local)
                    .set_server_addr(remote);
            }
            Feature::UdpForward => {
                HttpRequest::new("POST", "/udp_channel")
                    .with_header("Host", &target)
                    .write_to(&mut server)
                    .await?;
                let resp = HttpResponse::read_from(&mut server).await?;
                log::debug!("response: {:?}", resp);
                if resp.code != 200 {
                    bail!("upstream server failure: {:?}", resp);
                }
                let session_id = resp
                    .headers
                    .iter()
                    .find(|x| x.0.eq_ignore_ascii_case("Session-Id"))
                    .and_then(|x| x.1.parse::<u32>().ok())
                    .unwrap_or(0);

                ctx.write()
                    .await
                    .set_server_frames(frames_from_stream(session_id, server))
                    .set_local_addr(local)
                    .set_server_addr(remote);
            }
            x => bail!("not supported feature {:?}", x),
        }
        Ok(())
    }

    async fn get_connection(self: Arc<Self>) -> Result<Arc<Connection>, Error> {
        let mut c = self.connection.lock().await;
        if c.is_none() {
            *c = Some(self.create_connection().await?);
        }
        Ok(c.clone().unwrap())
    }

    async fn clear_connection(self: Arc<Self>) {
        let mut c = self.connection.lock().await;
        *c = None;
        debug!("{}: connection cleared", self.name);
    }

    async fn create_connection(&self) -> Result<Arc<Connection>, Error> {
        let remote = (self.server.clone(), self.port)
            .to_socket_addrs()
            .context("resolve")?
            .next()
            .ok_or_else(|| err_msg(format!("unable to resolve address: {}", self.server)))?;

        // if it's a insecure connection, we don't care whar domain name it is.
        // this could fixes InvalidDnsName error when connecting with a bare IP
        let server = if self.tls.insecure {
            "example.com"
        } else {
            self.server.as_str()
        };
        let conn = self
            .endpoint
            .as_ref()
            .unwrap()
            .connect(remote, server)
            .context("quic connect")?
            .await
            .context("quic connect")?;
        debug!("{}: new connection to {:?}", self.name, remote);
        Ok(Arc::new(conn.connection))
    }
}
