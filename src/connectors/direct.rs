use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::context::Context;
pub struct DirectConnector {}

#[async_trait]
impl super::Connector for DirectConnector {
    async fn create(_block: &str) -> Result<Box<Self>, Box<dyn std::error::Error>> {
        Ok(Box::new(DirectConnector {}))
    }

    async fn connect(&self, ctx: Context) -> Result<(), Box<dyn std::error::Error>> {
        let mut socket = ctx.socket;
        tokio::spawn(async move {
            let mut buf = [0; 1024];

            // In a loop, read data from the socket and write the data back.
            loop {
                let n = match socket.read(&mut buf).await {
                    // socket closed
                    Ok(n) if n == 0 => return,
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("failed to read from socket; err = {:?}", e);
                        return;
                    }
                };

                // Write the data back
                if let Err(e) = socket.write_all(&buf[0..n]).await {
                    eprintln!("failed to write to socket; err = {:?}", e);
                    return;
                }
            }
        });
        Ok(())
    }
}
