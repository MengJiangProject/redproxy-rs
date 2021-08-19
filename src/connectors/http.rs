use async_trait::async_trait;
use easy_error::{bail, Error, ResultExt};
use log::{trace, warn};
use tokio::{
    io::{AsyncWriteExt, BufStream},
    net::TcpStream,
};

use crate::common::copy::copy_bidi;
use crate::common::http::HttpResponse;
use crate::context::Context;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpConnector {
    name: String,
    server: String,
    port: u16,
}

pub fn from_value(value: &serde_yaml::Value) -> Result<Box<dyn super::Connector>, Error> {
    let ret: HttpConnector = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl super::Connector for HttpConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }

    async fn connect(&self, ctx: Context) -> Result<(), Error> {
        let server_addr = (self.server.to_owned(), self.port);
        let mut client = ctx.socket;
        let target = ctx.target;
        tokio::spawn(async move {
            if let Err(err) = async {
                trace!("connecting to server {:?}", server_addr);
                let server = TcpStream::connect(server_addr).await.context("connect")?;
                let mut server = BufStream::new(server);
                let request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", target, target);
                trace!("request={:?}", request);
                server
                    .write_all(request.as_bytes())
                    .await
                    .context("sending request")?;
                server.flush().await.context("flush")?;
                let resp = HttpResponse::new(&mut server).await?;
                if resp.code != 200 {
                    bail!("server failure {:?}", resp);
                }
                // let mut client = client.into_inner();
                copy_bidi(&mut client, &mut server)
                    .await
                    .context("copy_bidirectional")
            }
            .await
            {
                warn!("connection failed {:?} {:?}", target, err);
            }
        });
        Ok(())
    }
}
