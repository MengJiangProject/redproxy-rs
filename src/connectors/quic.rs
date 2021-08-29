use async_trait::async_trait;
use easy_error::{bail, err_msg, Error, ResultExt};
use log::debug;
use quinn::{Connection, Endpoint};
use serde::{Deserialize, Serialize};
use std::{net::ToSocketAddrs, sync::Arc};
use tokio::sync::Mutex;

use super::ConnectorRef;
use crate::{
    common::{
        http::{HttpRequest, HttpResponse},
        quic::{create_quic_client, QuicStream},
        tls::TlsClientConfig,
    },
    context::{make_buffered_stream, Context, IOBufStream},
};

#[derive(Serialize, Deserialize, Debug)]
pub struct QuicConnector {
    name: String,
    server: String,
    port: u16,
    tls: TlsClientConfig,
    #[serde(default = "default_bind_addr")]
    bind: String,

    #[serde(skip)]
    endpoint: Option<Endpoint>,
    #[serde(skip)]
    connection: Mutex<Option<Arc<Connection>>>,
}

fn default_bind_addr() -> String {
    "[::]:0".to_owned()
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

    async fn init(&mut self) -> Result<(), Error> {
        self.tls.init()?;
        let epb = create_quic_client(&self.tls)?;
        let bind = self.bind.parse().context("parse bind")?;
        let (endpoint, _) = epb.bind(&bind).context("bind")?;
        self.endpoint = Some(endpoint);
        Ok(())
    }

    async fn connect(self: Arc<Self>, ctx: &Context) -> Result<IOBufStream, Error> {
        let conn = self.clone().get_connection().await?;
        let ret = self.clone().handshake(conn, ctx).await;
        if ret.is_err() {
            self.clear_connection().await;
        }
        ret
    }
}

impl QuicConnector {
    async fn handshake(
        self: Arc<Self>,
        conn: Arc<Connection>,
        ctx: &Context,
    ) -> Result<IOBufStream, Error> {
        let server: QuicStream = conn
            .open_bi()
            .await
            .map_err(|e| err_msg(format!("failed to open stream: {}", e)))?
            .into();

        let mut server = make_buffered_stream(server);
        HttpRequest::new("CONNECT", &ctx.target)
            .with_header("Host", &ctx.target)
            .write_to(&mut server)
            .await?;
        let resp = HttpResponse::read_from(&mut server).await?;
        if resp.code != 200 {
            bail!("upstream server failure: {:?}", resp);
        }
        Ok(server)
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
            .connect(&remote, server)
            .context("quic connect")?
            .await
            .context("quic connect")?;
        debug!("{}: new connection to {:?}", self.name, remote);
        Ok(Arc::new(conn.connection))
    }
}
