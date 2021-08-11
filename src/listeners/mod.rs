use async_trait::async_trait;
use easy_error::{err_msg, Error};
use serde_yaml::{Sequence, Value};
use tokio::sync::mpsc::Sender;

use crate::context::Context;

pub mod http;
pub mod tproxy;

mod tls;
#[async_trait]
pub trait Listener {
    fn name(&self) -> &str;
    async fn init(&mut self) -> Result<(), Error>;
    async fn listen(&self, queue: Sender<Context>) -> Result<(), Error>;
}

pub fn config(listeners: &Sequence) -> Result<Vec<Box<dyn Listener>>, Error> {
    let mut ret = Vec::with_capacity(listeners.len());
    for l in listeners {
        let ll = from_value(l)?;
        ret.push(ll);
    }
    Ok(ret)
}

pub fn from_value(value: &Value) -> Result<Box<dyn Listener>, Error> {
    let name = value.get("name").ok_or(err_msg("missing name"))?;
    let tname = value.get("type").or(Some(name)).unwrap();
    match tname.as_str() {
        Some("tproxy") => tproxy::from_value(value),
        Some("http") => http::from_value(value),
        _ => Err(err_msg("not implemented")),
    }
}
