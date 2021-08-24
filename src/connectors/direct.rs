use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::{trace, warn};
use tokio::io::BufStream;

use crate::{common::copy::copy_bidi, context::Context};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct DirectConnector {
    name: String,
}

pub fn from_value(value: &serde_yaml::Value) -> Result<Box<dyn super::Connector>, Error> {
    let ret: DirectConnector = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl super::Connector for DirectConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }

    async fn connect(&self, mut ctx: Context) -> Result<(), Error> {
        tokio::spawn(async move {
            if let Err(err) = async {
                let target = &ctx.target;
                trace!("connecting to {:?}", target);
                let server = target.connect_tcp().await.context("connect")?;
                let mut server = BufStream::new(server);
                trace!("connected to {:?}", target);
                // let mut client = client.into_inner();
                ctx.on_connect().await;
                let client = &mut ctx.socket;
                copy_bidi(client, &mut server)
                    .await
                    .context("copy_bidirectional")
            }
            .await
            {
                warn!("connection failed {:?} {:?}", ctx.target, err);
                ctx.on_error(err).await;
            }
        });
        Ok(())
    }
}
