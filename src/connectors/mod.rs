use crate::context::Context;
use async_trait::async_trait;
use easy_error::Error;

mod copy;
pub mod direct;
#[async_trait]
pub trait Connector {
    async fn create(block: &str) -> Result<Box<Self>, Error>;
    async fn connect(&self, ctx: Context) -> Result<(), Error>;
}
