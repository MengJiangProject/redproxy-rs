use crate::context::Context;
use async_trait::async_trait;

pub mod direct;
#[async_trait]
pub trait Connector {
    async fn create(block: &str) -> Result<Box<Self>, Box<dyn std::error::Error>>;
    async fn connect(&self, ctx: Context) -> Result<(), Box<dyn std::error::Error>>;
}
