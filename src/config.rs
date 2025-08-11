use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::access_log::AccessLog;
use serde_yaml_ng::Sequence;

#[cfg(feature = "metrics")]
use crate::metrics::MetricsServer;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub listeners: Sequence,
    pub connectors: Sequence,
    pub rules: Sequence,
    #[cfg(feature = "metrics")]
    pub metrics: Option<MetricsServer>,
    pub access_log: Option<AccessLog>,
    #[serde(default)]
    pub timeouts: Timeouts,
    #[serde(default)]
    pub io_params: IoParams,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct IoParams {
    pub buffer_size: usize,
    pub use_splice: bool,
}

impl Default for IoParams {
    fn default() -> Self {
        Self {
            buffer_size: 65536,
            use_splice: true,
        }
    }
}

impl Config {
    pub async fn load(path: &str) -> Result<Self> {
        let s = tokio::fs::read(path).await.with_context(|| "read file")?;
        let s = String::from_utf8(s).with_context(|| "parse utf8")?;
        serde_yaml_ng::from_str(&s).with_context(|| "parse yaml")
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Timeouts {
    #[serde(default = "default_timeout")]
    pub idle: u64,
    #[serde(default = "default_timeout")]
    pub udp: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            idle: default_timeout(),
            udp: default_timeout(),
        }
    }
}

fn default_timeout() -> u64 {
    600
}

#[cfg(test)]
mod tests {
    use crate::{connectors, listeners, rules};

    #[tokio::test]
    async fn test_load() {
        use super::*;
        let cfg = Config::load("config.yaml").await.unwrap();
        let _listeners = listeners::from_config(&cfg.listeners).unwrap();
        let _connectors = connectors::from_config(&cfg.connectors).unwrap();
        let _rules = rules::from_config(&cfg.rules).unwrap();
    }
}
