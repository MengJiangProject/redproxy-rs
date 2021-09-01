use crate::metrics::MetricsConfig;

use super::rules::Rule;
use easy_error::{Error, ResultExt};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub api_version: String,
    pub kind: String,
    pub listeners: serde_yaml::Sequence,
    pub connectors: serde_yaml::Sequence,
    pub rules: Vec<Rule>,
    pub metrics: Option<MetricsConfig>,
}

impl Config {
    pub async fn load(path: &str) -> Result<Self, Error> {
        let s = tokio::fs::read(path).await.context("read file")?;
        let s = String::from_utf8(s).context("parse utf8")?;
        serde_yaml::from_str(&s).context("parse yaml")
    }
}
