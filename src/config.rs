use easy_error::{Error, ResultExt};
use serde::{Deserialize, Serialize};

use crate::{access_log::AccessLog, metrics::MetricsServer};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub api_version: String,
    pub kind: String,
    pub listeners: serde_yaml::Sequence,
    pub connectors: serde_yaml::Sequence,
    pub rules: serde_yaml::Sequence,
    #[cfg(feature = "metrics")]
    pub metrics: Option<MetricsServer>,
    pub access_log: Option<AccessLog>,
    #[serde(default)]
    pub timeouts: Timeouts,
}

impl Config {
    pub async fn load(path: &str) -> Result<Self, Error> {
        let s = tokio::fs::read(path).await.context("read file")?;
        let s = String::from_utf8(s).context("parse utf8")?;
        serde_yaml::from_str(&s).context("parse yaml")
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Timeouts {
    pub idle: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts { idle: 600 }
    }
}
