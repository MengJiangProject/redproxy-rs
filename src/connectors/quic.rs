use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use chashmap_async::CHashMap;
use quinn::{Connection, Endpoint};
use serde::{Deserialize, Serialize};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    ops::{Deref, DerefMut},
    sync::Arc,
};
use tokio::sync::Mutex;
use tracing::debug;

use super::ConnectorRef;
use crate::{
    common::{
        http_proxy::http_forward_proxy_connect,
        quic::{
            QuicFrameSessions, QuicStream, create_quic_client, create_quic_frames,
            quic_frames_thread,
        },
        tls::TlsClientConfig,
    },
    context::{ContextRef, Feature, make_buffered_stream},
};

type QuicConn = (Connection, QuicFrameSessions);

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct QuicConnectorConfig {
    name: String,
    server: String,
    port: u16,
    tls: TlsClientConfig,
    #[serde(default = "default_bind_addr")]
    bind: String,
    #[serde(default = "default_bbr")]
    bbr: bool,
    #[serde(default = "default_inline_udp")]
    inline_udp: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct QuicConnector {
    #[serde(flatten)]
    config: QuicConnectorConfig,
    #[serde(skip)]
    endpoint: Option<Endpoint>,
    #[serde(skip)]
    connection: Arc<Mutex<Option<QuicConn>>>,
}

impl Deref for QuicConnector {
    type Target = QuicConnectorConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl DerefMut for QuicConnector {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

fn default_bind_addr() -> String {
    "[::]:0".to_owned()
}

fn default_bbr() -> bool {
    true
}

fn default_inline_udp() -> bool {
    false
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef> {
    let config: QuicConnectorConfig =
        serde_yaml_ng::from_value(value.clone()).context("parse config")?;
    let ret = QuicConnector {
        config,
        endpoint: None,
        connection: Arc::new(Mutex::new(None)),
    };
    Ok(Box::new(ret))
}

#[async_trait]
impl super::Connector for QuicConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn features(&self) -> &[Feature] {
        &[Feature::TcpForward, Feature::UdpForward, Feature::UdpBind]
    }

    async fn init(&mut self) -> Result<()> {
        self.tls.init()?;
        let cfg = create_quic_client(&self.tls, self.bbr)?;
        let bind = self.bind.parse().context("parse bind")?;
        let mut endpoint = Endpoint::client(bind).context("bind")?;
        endpoint.set_default_client_config(cfg);
        self.endpoint = Some(endpoint);
        Ok(())
    }

    async fn connect(self: Arc<Self>, ctx: ContextRef) -> Result<()> {
        let (conn, sessions) = self.get_connection().await?;
        let remote = conn.remote_address();
        let local = self
            .endpoint
            .as_ref()
            .unwrap()
            .local_addr()
            .context("local_addr")?;
        let ret = self
            .clone()
            .handshake(conn, sessions, ctx.clone(), remote, local)
            .await;
        match ret {
            Ok(()) => Ok(()),
            Err(e) => {
                if e.to_string().starts_with("quic:") {
                    self.clear_connection().await;
                }
                Err(e)
            }
        }
    }
}

impl QuicConnector {
    async fn handshake(
        self: Arc<Self>,
        conn: Connection,
        sessions: QuicFrameSessions,
        ctx: ContextRef,
        remote: SocketAddr,
        local: SocketAddr,
    ) -> Result<()> {
        let server: QuicStream = conn
            .open_bi()
            .await
            .context("quic: failed to open bi-stream")?
            .into();

        let server = make_buffered_stream(server);
        let channel = if self.inline_udp {
            "inline"
        } else {
            "quic-datagrams"
        };
        let frames = |id| create_quic_frames(conn, id, sessions);
        http_forward_proxy_connect(server, ctx, local, remote, channel, frames, false, None).await?;
        Ok(())
    }

    async fn get_connection(self: &Arc<Self>) -> Result<QuicConn> {
        let mut c = self.connection.lock().await;
        if c.is_none() {
            *c = Some(self.create_connection().await?);
        }
        Ok(c.clone().unwrap())
    }

    async fn clear_connection(&self) {
        let mut c = self.connection.lock().await;
        *c = None;
        debug!("{}: connection cleared", self.name);
    }

    async fn create_connection(self: &Arc<Self>) -> Result<QuicConn> {
        let remote = (self.server.clone(), self.port)
            .to_socket_addrs()
            .context("resolve")?
            .next()
            .ok_or_else(|| anyhow!("unable to resolve address: {}", self.server))?;

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
        let sessions = Arc::new(CHashMap::new());
        tokio::spawn(quic_frames_thread(
            self.name.to_owned(),
            sessions.clone(),
            conn.clone(),
        ));
        Ok((conn, sessions))
    }
}
