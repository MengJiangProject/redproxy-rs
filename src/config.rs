use super::rules::Rule;
use easy_error::{Error, ResultExt};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub listeners: serde_yaml::Sequence,
    pub connectors: serde_yaml::Sequence,
    pub rules: Vec<Rule>,
}

impl Config {
    pub async fn load(path: &str) -> Result<Self, Error> {
        let s = tokio::fs::read(path).await.context("read file")?;
        let s = String::from_utf8(s).context("parse utf8")?;
        serde_yaml::from_str(&s).context("parse yaml")
    }
}
