use std::{
    hash::Hash,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::{Context, Error, Result, anyhow, bail, ensure};
use async_trait::async_trait;
use milu::{
    parser::parse,
    script::{ScriptContext, Type, Value},
};
use rand::{rng, seq::IndexedRandom};
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::{Connector, ConnectorRef, ConnectorRegistry};
use crate::{context::ContextRef, rules::script_ext::create_context};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalanceConnector {
    name: String,
    connectors: Vec<String>,

    #[serde(
        alias = "algo",
        default,
        with = "serde_yaml_ng::with::singleton_map_recursive"
    )]
    algorithm: Algorithm,

    // for RoundRobin selection,
    #[serde(skip)]
    idx: AtomicUsize,

    #[serde(skip)]
    hash_by: Option<Value>,

    #[serde(skip)]
    pub registry: OnceLock<ConnectorRegistry>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum Algorithm {
    Random,
    #[serde(alias = "rr")]
    RoundRobin,
    #[serde(alias = "hash")]
    HashBy(String),
    // TODO: Those Algorithms are not yet ready as i had to find a good way to collect data.
    // LeastConnection,
    // LeastRTT,
}

impl Default for Algorithm {
    fn default() -> Algorithm {
        Self::RoundRobin
    }
}

impl Default for LoadBalanceConnector {
    fn default() -> Self {
        Self {
            name: String::new(),
            connectors: Vec::new(),
            algorithm: Algorithm::default(),
            idx: AtomicUsize::new(0),
            hash_by: None,
            registry: OnceLock::new(),
        }
    }
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef> {
    let ret: LoadBalanceConnector =
        serde_yaml_ng::from_value(value.clone()).context("parse loadbalance connector config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Connector for LoadBalanceConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn init(&mut self) -> Result<()> {
        // Basic initialization without resolver
        Ok(())
    }

    async fn verify(&self) -> Result<()> {
        ensure!(!self.connectors.is_empty(), "connectors must not be empty");

        if let Some(registry) = self.registry.get() {
            for n in &self.connectors {
                ensure!(registry.contains_key(n), "connector not defined: {}", n);

                // Disallow LoadBalance connectors as targets to prevent recursion
                if let Some(target_connector) = registry.get(n)
                    && (target_connector.as_ref() as &dyn std::any::Any)
                        .downcast_ref::<LoadBalanceConnector>()
                        .is_some()
                {
                    bail!(
                        "LoadBalance connector '{}' cannot use another LoadBalance connector '{}' as target",
                        self.name,
                        n
                    );
                }
            }
        }
        Ok(())
    }

    async fn connect(self: Arc<Self>, ctx: ContextRef) -> Result<(), Error> {
        let registry = self
            .registry
            .get()
            .ok_or_else(|| anyhow!("Connector registry not initialized"))?;
        let conn = match self.algorithm {
            Algorithm::RoundRobin => self.round_robin(registry)?,
            Algorithm::Random => self.random(registry)?,
            Algorithm::HashBy(_) => self.hash_by(registry, &ctx).await?,
        };
        let next = conn.name().to_owned();
        debug!("{}: selected connector: {}", self.name, next);
        ctx.write().await.set_connector(next);
        conn.connect(ctx).await
    }
}

impl std::fmt::Debug for LoadBalanceConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadBalanceConnector")
            .field("name", &self.name)
            .field("connectors", &self.connectors)
            .field("algorithm", &self.algorithm)
            .field("idx", &self.idx)
            .field("hash_by", &self.hash_by.as_ref().map(|_| "Some(Value)"))
            .field(
                "registry",
                &self
                    .registry
                    .get()
                    .map(|_| "ConnectorRegistry")
                    .unwrap_or("None"),
            )
            .finish()
    }
}

impl LoadBalanceConnector {
    fn random(self: &Arc<Self>, registry: &ConnectorRegistry) -> Result<Arc<dyn Connector>> {
        let next = self
            .connectors
            .choose(&mut rng())
            .ok_or_else(|| anyhow!("No connectors available for random selection"))?;
        registry
            .get(next)
            .cloned()
            .ok_or_else(|| anyhow!("Connector '{}' not found in registry", next))
    }

    fn round_robin(
        self: &Arc<Self>,
        registry: &ConnectorRegistry,
    ) -> Result<Arc<dyn Connector>, Error> {
        if self.connectors.is_empty() {
            return Err(anyhow!("No connectors available for round robin selection"));
        }
        let next = self.idx.fetch_add(1, Ordering::Relaxed);
        let next = &self.connectors[next % self.connectors.len()];
        registry
            .get(next)
            .cloned()
            .ok_or_else(|| anyhow!("Connector '{}' not found in registry", next))
    }

    async fn hash_by(
        self: &Arc<Self>,
        registry: &ConnectorRegistry,
        ctx: &ContextRef,
    ) -> Result<Arc<dyn Connector>, Error> {
        let script_ctx = create_context(ctx.read().await.props().clone());

        // Handle lazy compilation if hash_by is not set
        let result = if let Some(ref hash_func) = self.hash_by {
            hash_func.real_value_of(script_ctx.into()).await?
        } else if let Algorithm::HashBy(ref script) = self.algorithm {
            // Compile on-demand
            let value = parse(script).context("unable to compile hash script")?;
            let type_ctx: Arc<ScriptContext> = create_context(Default::default()).into();
            let rtype = value
                .real_type_of(type_ctx)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            ensure!(
                rtype == Type::String,
                "hash script type mismatch: required string, got {}\nsnippet: {}",
                rtype,
                script
            );
            value.real_value_of(script_ctx.into()).await?
        } else {
            return Err(anyhow!("Hash function not available"));
        };
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::Hasher;
        result.hash(&mut hasher);
        let hash = hasher.finish() as usize;
        debug!("result: {:?} hash: {:?}", result, hash);
        if self.connectors.is_empty() {
            return Err(anyhow!("No connectors available for hash selection"));
        }
        let next = &self.connectors[hash % self.connectors.len()];
        registry
            .get(next)
            .cloned()
            .ok_or_else(|| anyhow!("Connector '{}' not found in registry", next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{ContextManager, TargetAddress};
    use std::collections::HashMap;
    use std::net::SocketAddr;

    // Mock connector for testing
    #[derive(Debug)]
    struct MockConnector {
        name: String,
        connect_count: Arc<AtomicUsize>,
    }

    impl MockConnector {
        fn new(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                connect_count: Arc::new(AtomicUsize::new(0)),
            })
        }
    }

    #[async_trait]
    impl Connector for MockConnector {
        fn name(&self) -> &str {
            &self.name
        }

        async fn connect(self: Arc<Self>, _ctx: ContextRef) -> Result<()> {
            self.connect_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn create_test_registry() -> ConnectorRegistry {
        let mut registry = HashMap::new();
        registry.insert(
            "conn1".to_string(),
            MockConnector::new("conn1") as Arc<dyn Connector>,
        );
        registry.insert(
            "conn2".to_string(),
            MockConnector::new("conn2") as Arc<dyn Connector>,
        );
        registry.insert(
            "conn3".to_string(),
            MockConnector::new("conn3") as Arc<dyn Connector>,
        );
        registry
    }

    async fn create_test_context() -> ContextRef {
        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();
        let ctx = manager
            .create_context("test-listener".to_string(), source)
            .await;

        // Set target for testing
        ctx.write()
            .await
            .set_target(TargetAddress::DomainPort("example.com".to_string(), 80));
        ctx
    }

    #[tokio::test]
    async fn test_round_robin_selection() {
        let lb = LoadBalanceConnector {
            name: "test-lb".to_string(),
            connectors: vec![
                "conn1".to_string(),
                "conn2".to_string(),
                "conn3".to_string(),
            ],
            algorithm: Algorithm::RoundRobin,
            ..Default::default()
        };

        let registry = create_test_registry();
        lb.registry
            .set(registry.clone())
            .map_err(|_| "Already set")
            .unwrap();

        let lb = Arc::new(lb);

        // Test round robin order
        let selected1 = lb.round_robin(&registry).unwrap();
        assert_eq!(selected1.name(), "conn1");

        let selected2 = lb.round_robin(&registry).unwrap();
        assert_eq!(selected2.name(), "conn2");

        let selected3 = lb.round_robin(&registry).unwrap();
        assert_eq!(selected3.name(), "conn3");

        // Should wrap around
        let selected4 = lb.round_robin(&registry).unwrap();
        assert_eq!(selected4.name(), "conn1");
    }

    #[tokio::test]
    async fn test_random_selection() {
        let lb = LoadBalanceConnector {
            name: "test-lb".to_string(),
            connectors: vec![
                "conn1".to_string(),
                "conn2".to_string(),
                "conn3".to_string(),
            ],
            algorithm: Algorithm::Random,
            ..Default::default()
        };

        let registry = create_test_registry();
        lb.registry
            .set(registry.clone())
            .map_err(|_| "Already set")
            .unwrap();

        let lb = Arc::new(lb);

        // Test multiple random selections to ensure they're from our connector list
        for _ in 0..10 {
            let selected = lb.random(&registry).unwrap();
            let name = selected.name();
            assert!(name == "conn1" || name == "conn2" || name == "conn3");
        }
    }

    #[tokio::test]
    async fn test_hash_by_selection() {
        let lb = LoadBalanceConnector {
            name: "test-lb".to_string(),
            connectors: vec![
                "conn1".to_string(),
                "conn2".to_string(),
                "conn3".to_string(),
            ],
            algorithm: Algorithm::HashBy("request.target.host".to_string()),
            ..Default::default()
        };

        let registry = create_test_registry();
        lb.registry
            .set(registry.clone())
            .map_err(|_| "Already set")
            .unwrap();

        let lb = Arc::new(lb);
        let ctx = create_test_context().await;

        // Same context should always select the same connector
        let selected1 = lb.hash_by(&registry, &ctx).await.unwrap();
        let selected2 = lb.hash_by(&registry, &ctx).await.unwrap();
        assert_eq!(selected1.name(), selected2.name());
    }

    #[tokio::test]
    async fn test_verify_empty_connectors() {
        let lb = LoadBalanceConnector {
            name: "test-lb".to_string(),
            connectors: vec![],
            ..Default::default()
        };

        let result = lb.verify().await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("connectors must not be empty")
        );
    }

    #[tokio::test]
    async fn test_verify_unknown_connector() {
        let lb = LoadBalanceConnector {
            name: "test-lb".to_string(),
            connectors: vec!["unknown".to_string()],
            ..Default::default()
        };

        let registry = create_test_registry();
        lb.registry
            .set(registry)
            .map_err(|_| "Already set")
            .unwrap();

        let result = lb.verify().await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("connector not defined: unknown")
        );
    }

    #[tokio::test]
    async fn test_verify_recursion_prevention() {
        let mut registry = HashMap::new();

        // Create a LoadBalance connector
        let inner_lb = Arc::new(LoadBalanceConnector {
            name: "inner-lb".to_string(),
            connectors: vec!["conn1".to_string()],
            ..Default::default()
        }) as Arc<dyn Connector>;

        registry.insert("inner-lb".to_string(), inner_lb);
        registry.insert(
            "conn1".to_string(),
            MockConnector::new("conn1") as Arc<dyn Connector>,
        );

        let outer_lb = LoadBalanceConnector {
            name: "outer-lb".to_string(),
            connectors: vec!["inner-lb".to_string()],
            ..Default::default()
        };

        outer_lb
            .registry
            .set(registry)
            .map_err(|_| "Already set")
            .unwrap();

        let result = outer_lb.verify().await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("cannot use another LoadBalance connector")
        );
    }

    #[tokio::test]
    async fn test_connect_integration() {
        let lb = LoadBalanceConnector {
            name: "test-lb".to_string(),
            connectors: vec!["conn1".to_string(), "conn2".to_string()],
            algorithm: Algorithm::RoundRobin,
            ..Default::default()
        };

        let registry = create_test_registry();
        lb.registry
            .set(registry)
            .map_err(|_| "Already set")
            .unwrap();

        let lb = Arc::new(lb);
        let ctx = create_test_context().await;

        // Test successful connection
        let result = lb.connect(ctx.clone()).await;
        assert!(result.is_ok());

        // Verify context was updated with connector name
        let context_read = ctx.read().await;
        assert!(context_read.props().connector.is_some());
    }

    #[tokio::test]
    async fn test_connect_uninitialized_registry() {
        let lb = Arc::new(LoadBalanceConnector {
            name: "test-lb".to_string(),
            connectors: vec!["conn1".to_string()],
            algorithm: Algorithm::RoundRobin,
            ..Default::default()
        });

        let ctx = create_test_context().await;
        let result = lb.connect(ctx).await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Connector registry not initialized")
        );
    }

    #[tokio::test]
    async fn test_empty_connectors_error_handling() {
        let lb = LoadBalanceConnector {
            name: "test-lb".to_string(),
            connectors: vec![],
            algorithm: Algorithm::RoundRobin,
            ..Default::default()
        };

        let registry = create_test_registry();
        lb.registry
            .set(registry.clone())
            .map_err(|_| "Already set")
            .unwrap();
        let lb = Arc::new(lb);

        // Test round robin with empty connectors
        let result = lb.round_robin(&registry);
        assert!(result.is_err());
        match result {
            Ok(_) => panic!("Expected error but got success"),
            Err(e) => assert!(e.to_string().contains("No connectors available")),
        }

        // Test random with empty connectors
        let result = lb.random(&registry);
        assert!(result.is_err());
        match result {
            Ok(_) => panic!("Expected error but got success"),
            Err(e) => assert!(e.to_string().contains("No connectors available")),
        }
    }
}
