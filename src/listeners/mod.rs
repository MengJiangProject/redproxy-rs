use async_trait::async_trait;
use easy_error::Error;
use tokio::sync::mpsc::Sender;

use crate::context::Context;
pub mod http;
pub mod tproxy;

#[async_trait]
pub trait Listener {
    async fn create(block: &str) -> Result<Box<Self>, Error>;
    async fn listen(&self, queue: Sender<Context>) -> Result<(), Error>;
}
