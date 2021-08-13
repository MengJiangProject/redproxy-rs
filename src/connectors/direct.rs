use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::{trace, warn};
use tokio::io::BufStream;

use super::copy::copy_bidirectional;
use crate::context::Context;
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

    async fn connect(&self, ctx: Context) -> Result<(), Error> {
        tokio::spawn(async move {
            let mut client = ctx.socket;
            let target = ctx.target;
            if let Err(err) = async {
                trace!("connecting to {:?}", target);
                let server = target.connect_tcp().await.context("connect")?;
                let mut server = BufStream::new(server);
                trace!("connected to {:?}", target);
                // let mut client = client.into_inner();
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
