use anyhow::{Context, Error, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, RwLockReadGuard};

use crate::connectors::Connector;
use crate::context::ContextRef;
use crate::rules::Rule;

/// Manages rules and their evaluation
pub struct RulesManager {
    rules: RwLock<Vec<Arc<Rule>>>,
}

impl RulesManager {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
        }
    }

    /// Set rules after initializing them with connectors
    pub async fn set_rules(
        &self,
        mut rules: Vec<Arc<Rule>>,
        connectors: &HashMap<String, Arc<dyn Connector>>,
    ) -> Result<(), Error> {
        // Initialize rules before putting them in Arc
        for r in rules.iter_mut() {
            if let Some(rule_mut) = Arc::get_mut(r) {
                rule_mut
                    .init()
                    .await
                    .with_context(|| "Failed to initialize rule")?;
            } else {
                return Err(anyhow!(
                    "Cannot get mutable reference to rule during initialization"
                ));
            }
        }

        // Assign connector targets to rules
        for r in rules.iter_mut() {
            if r.target_name() == "deny" {
                continue;
            } else if let Some(t) = connectors.get(r.target_name()) {
                if let Some(rule_mut) = Arc::get_mut(r) {
                    rule_mut.target = Some(t.clone());
                } else {
                    return Err(anyhow!(
                        "Cannot get mutable reference to rule during target assignment"
                    ));
                }
            } else {
                return Err(anyhow!("target not found: {}", r.target_name()));
            }
        }

        *self.rules.write().await = rules;
        Ok(())
    }

    /// Get read access to rules
    pub async fn rules(&self) -> RwLockReadGuard<'_, Vec<Arc<Rule>>> {
        self.rules.read().await
    }

    /// Evaluate rules against context to find matching connector
    pub async fn eval_rules(&self, ctx: &ContextRef) -> Option<Arc<dyn Connector>> {
        let ctx = &ctx.clone().read_owned().await;
        let rules = self.rules().await;
        for rule in rules.iter() {
            if rule.evaluate(ctx).await {
                return rule.target.clone();
            }
        }
        None
    }
}

impl Default for RulesManager {
    fn default() -> Self {
        Self::new()
    }
}
