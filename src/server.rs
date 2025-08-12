use anyhow::{Context, Result, anyhow};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc::channel;
use tracing::{info, warn};

#[cfg(feature = "metrics")]
use crate::metrics::MetricsServer;

use crate::{
    access_log,
    config::{self, IoParams, Timeouts},
    connectors::{self, ConnectorRegistry},
    context::{ContextManager, ContextRef, ContextRefOps, ContextState},
    copy::copy_bidi,
    listeners::{self, Listener},
    rules::{self, RulesManager},
};

pub struct ProxyServer {
    pub rules_manager: RulesManager,
    pub listeners: HashMap<String, Arc<dyn Listener>>,
    pub connectors: ConnectorRegistry,
    pub contexts: Arc<ContextManager>,
    pub timeouts: Timeouts,
    #[cfg(feature = "metrics")]
    pub metrics: Option<Arc<MetricsServer>>,
    pub io_params: IoParams,
    // Store what we need for initialization
    rules_config: serde_yaml_ng::Sequence,
    access_log_config: Option<access_log::AccessLog>,
}

impl ProxyServer {
    pub async fn from_config_file(config_path: &str) -> Result<Self> {
        let mut cfg = config::Config::load(config_path).await?;

        // Just construct components, don't initialize them
        let contexts = Arc::new(ContextManager::default());
        let listeners = listeners::from_config(&cfg.listeners)?;
        let connectors = connectors::from_config(&cfg.connectors)?;
        let rules_manager = RulesManager::new();

        #[cfg(feature = "metrics")]
        let metrics = cfg.metrics.take().map(Arc::new);

        Ok(ProxyServer {
            rules_manager,
            listeners,
            connectors,
            contexts,
            timeouts: cfg.timeouts.clone(),
            #[cfg(feature = "metrics")]
            metrics,
            io_params: cfg.io_params.clone(),
            rules_config: cfg.rules.clone(),
            access_log_config: cfg.access_log.take(),
        })
    }

    pub async fn init(&mut self) -> Result<()> {
        self.init_contexts().await?;
        self.init_listeners().await?;
        self.init_connectors().await?;
        self.setup_connector_registry()?;
        self.init_metrics()?;
        self.init_rules().await?;
        self.verify().await?;
        Ok(())
    }

    async fn init_contexts(&mut self) -> Result<()> {
        // Initialize contexts with timeout
        if let Some(ctx_mut) = Arc::get_mut(&mut self.contexts) {
            ctx_mut.default_timeout = self.timeouts.idle;

            // Initialize access log if configured
            if let Some(mut access_log) = self.access_log_config.take() {
                access_log.init().await?;
                ctx_mut.access_log = Some(access_log);
            }
        } else {
            return Err(anyhow!("Cannot initialize context state"));
        }
        Ok(())
    }

    async fn init_listeners(&mut self) -> Result<()> {
        // Initialize listeners
        for l in self.listeners.values_mut() {
            if let Some(listener_mut) = Arc::get_mut(l) {
                listener_mut.init().await.with_context(|| {
                    format!("Failed to initialize listener {}", listener_mut.name())
                })?;
            } else {
                return Err(anyhow!(
                    "Cannot get mutable reference to listener during initialization"
                ));
            }
        }
        Ok(())
    }

    async fn init_connectors(&mut self) -> Result<()> {
        // Initialize connectors
        for c in self.connectors.values_mut() {
            if let Some(connector_mut) = Arc::get_mut(c) {
                connector_mut.init().await.context(format!(
                    "Failed to initialize connector {}",
                    connector_mut.name()
                ))?;
            } else {
                return Err(anyhow!(
                    "Cannot get mutable reference to connector during initialization"
                ));
            }
        }
        Ok(())
    }

    fn setup_connector_registry(&self) -> Result<()> {
        for connector in self.connectors.values() {
            if let Some(lb_connector) = (connector.as_ref() as &dyn std::any::Any)
                .downcast_ref::<crate::connectors::loadbalance::LoadBalanceConnector>(
            ) {
                lb_connector
                    .registry
                    .set(self.connectors.clone())
                    .map_err(|_| anyhow!("LoadBalance connector registry already initialized"))?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "metrics")]
    fn init_metrics(&mut self) -> Result<()> {
        if let Some(metrics) = &self.metrics {
            if let Ok(mut metrics_mut) = Arc::try_unwrap(metrics.clone()) {
                metrics_mut.init()?;
                if let Some(ctx_mut) = Arc::get_mut(&mut self.contexts) {
                    ctx_mut.history_size = metrics_mut.history_size;
                }
                self.metrics = Some(Arc::new(metrics_mut));
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "metrics"))]
    fn init_metrics(&self) -> Result<()> {
        Ok(())
    }

    async fn init_rules(&self) -> Result<()> {
        self.rules_manager
            .set_rules(rules::from_config(&self.rules_config)?, &self.connectors)
            .await?;
        Ok(())
    }

    async fn verify(&self) -> Result<()> {
        // Verify all components
        for l in self.listeners.values() {
            l.verify().await?;
        }

        for c in self.connectors.values() {
            c.verify().await?;
        }

        Ok(())
    }

    pub async fn run(mut self) -> Result<()> {
        // Initialize all components before running
        self.init().await?;

        self.start().await
    }

    async fn start(self) -> Result<()> {
        let (tx, mut rx) = channel(100);
        let server = Arc::new(self);

        // Start listeners
        for l in server.listeners.values().cloned() {
            l.listen(server.contexts.clone(), server.timeouts.clone(), tx.clone())
                .await?;
        }

        // Start metrics server if enabled
        #[cfg(feature = "metrics")]
        if let Some(metrics) = server.metrics.clone() {
            metrics.listen(server.clone()).await?;
        }

        // Start garbage collection thread
        server.contexts.clone().gc_thread();

        // Main request processing loop
        loop {
            let ctx = rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("Channel closed unexpectedly"))?;

            let server = server.clone();
            tokio::spawn(async move {
                server.process_request(ctx).await;
            });
        }
    }

    async fn process_request(self: &Arc<Self>, ctx: ContextRef) {
        let connector = match self.rules_manager.eval_rules(&ctx).await {
            Some(connector) => connector,
            None => {
                info!("denied: {}", ctx.to_string().await);
                ctx.on_error(anyhow!("access denied")).await;
                return;
            }
        };

        // Check if connector has requested feature
        let props = ctx.read().await.props().clone();
        let feature = props.request_feature;
        if !connector.has_feature(feature) {
            let e = anyhow!("unsupported connector feature: {:?}", feature);
            warn!(
                "failed to connect to upstream: {} \ncause: {:?} \nctx: {}",
                e,
                e.source(),
                props.to_string()
            );
            ctx.on_error(anyhow!("{}", e)).await;
            return;
        }

        ctx.write()
            .await
            .set_state(ContextState::ServerConnecting)
            .set_connector(connector.name().to_owned());
        let props = ctx.read().await.props().clone();
        if let Err(e) = connector.connect(ctx.clone()).await {
            warn!(
                "failed to connect to upstream: {} cause: {:?} \nctx: {}",
                e,
                e.source(),
                props.to_string()
            );
            ctx.on_error(anyhow!("{}", e)).await;
            return;
        }

        ctx.on_connect().await;
        match copy_bidi(ctx.clone(), &self.io_params).await {
            Err(e) => {
                warn!(
                    "error in io thread: {} \ncause: {:?} \nctx: {}",
                    e,
                    e.source(),
                    props.to_string()
                );
                ctx.on_error(anyhow!("{}", e)).await;
            }
            Ok(_) => {
                ctx.write().await.set_state(ContextState::Terminated);
                ctx.on_finish().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_config() -> String {
        r#"
listeners:
  - name: "test_http"
    type: "http"
    bind: "127.0.0.1:0"

connectors:
  - name: "test_direct"
    type: "direct"

rules:
  - filter: "true"
    target: "test_direct"

timeouts:
  idle: 300
  udp: 300

ioParams:
  bufferSize: 8192
  useSplice: false
"#
        .to_string()
    }

    #[tokio::test]
    async fn test_proxy_server_construction() -> Result<()> {
        // Create a temporary config file
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(create_test_config().as_bytes())?;
        let config_path = temp_file.path().to_str().unwrap();

        // Test construction
        let server = ProxyServer::from_config_file(config_path).await?;

        // Verify basic structure
        assert_eq!(server.timeouts.idle, 300);
        assert_eq!(server.io_params.buffer_size, 8192);
        assert!(!server.io_params.use_splice);
        assert!(!server.listeners.is_empty());
        assert!(!server.connectors.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_server_init_contexts() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(create_test_config().as_bytes())?;
        let config_path = temp_file.path().to_str().unwrap();

        let mut server = ProxyServer::from_config_file(config_path).await?;

        // Test context initialization
        server.init_contexts().await?;

        // Verify contexts are initialized
        assert!(server.contexts.default_timeout > 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_server_init_listeners() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(create_test_config().as_bytes())?;
        let config_path = temp_file.path().to_str().unwrap();

        let mut server = ProxyServer::from_config_file(config_path).await?;

        // Test listener initialization
        server.init_listeners().await?;

        // Verify listeners exist
        assert!(!server.listeners.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_server_init_connectors() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(create_test_config().as_bytes())?;
        let config_path = temp_file.path().to_str().unwrap();

        let mut server = ProxyServer::from_config_file(config_path).await?;

        // Test connector initialization
        server.init_connectors().await?;

        // Verify connectors exist
        assert!(!server.connectors.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_server_setup_connector_registry() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(create_test_config().as_bytes())?;
        let config_path = temp_file.path().to_str().unwrap();

        let server = ProxyServer::from_config_file(config_path).await?;

        // Test connector registry setup (should not fail)
        server.setup_connector_registry()?;

        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_server_init_rules() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(create_test_config().as_bytes())?;
        let config_path = temp_file.path().to_str().unwrap();

        let server = ProxyServer::from_config_file(config_path).await?;

        // Test rules initialization
        server.init_rules().await?;

        // Verify rules are set
        let rules = server.rules_manager.rules().await;
        assert!(!rules.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_server_full_init() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(create_test_config().as_bytes())?;
        let config_path = temp_file.path().to_str().unwrap();

        let mut server = ProxyServer::from_config_file(config_path).await?;

        // Test full initialization sequence
        server.init().await?;

        // Verify all components are initialized
        let rules = server.rules_manager.rules().await;
        assert!(!rules.is_empty());
        assert!(!server.listeners.is_empty());
        assert!(!server.connectors.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_server_verify() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(create_test_config().as_bytes())?;
        let config_path = temp_file.path().to_str().unwrap();

        let mut server = ProxyServer::from_config_file(config_path).await?;
        server.init().await?;

        // Test component verification
        server.verify().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_config_file() {
        let result = ProxyServer::from_config_file("nonexistent_file.yaml").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_malformed_config() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"invalid: yaml: content:").unwrap();
        let config_path = temp_file.path().to_str().unwrap();

        let result = ProxyServer::from_config_file(config_path).await;
        assert!(result.is_err());
    }
}
