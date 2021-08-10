use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::{trace, warn};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpSocket,
};

use super::copy::copy_bidirectional;
use crate::context::Context;
pub struct DirectConnector {}

#[async_trait]
impl super::Connector for DirectConnector {
    async fn create(_block: &str) -> Result<Box<Self>, Box<dyn std::error::Error>> {
        Ok(Box::new(DirectConnector {}))
    }

    async fn connect(&self, ctx: Context) -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(async move {
            let mut client = ctx.socket;
            let target = ctx.target;
            if let Err(err) = async {
                trace!("connecting to {:?}", target);
                let mut server = target.connect_tcp().await.context("connect")?;
                trace!("connected to {:?}", target);

                copy_bidirectional(&mut client, &mut server)
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
