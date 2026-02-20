// Any sufficiently complicated C or Fortran program contains an ad hoc, informally-specified, bug-ridden, slow implementation of half of Common Lisp.  --Greenspun's tenth rule

mod filter;
mod rules_manager;
pub(crate) mod script_ext;
pub use rules_manager::RulesManager;

use anyhow::{Context as AnyhowContext, Result};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tracing::trace;

use crate::{connectors::Connector, context::Context};

pub fn from_config(cfg: &[Value]) -> Result<Vec<Arc<Rule>>> {
    let mut ret = Vec::with_capacity(cfg.len());
    for val in cfg {
        ret.push(serde_yaml_ng::from_value(val.clone()).with_context(|| "parse rule")?);
    }
    Ok(ret)
}

#[derive(Serialize, Deserialize)]
pub struct Rule {
    #[serde(rename = "target")]
    target_name: String,
    #[serde(skip)]
    pub target: Option<Arc<dyn Connector>>,
    #[serde(rename = "filter")]
    filter_str: Option<String>,
    #[serde(skip)]
    filter: Option<filter::Filter>,
    #[serde(skip_deserializing)]
    stats: RuleStatistics,
}

#[derive(Serialize, Default)]
pub struct RuleStatistics {
    // Total execution count
    exec: AtomicU64,
    // Total execution time in nanoseconds
    time: AtomicU64,
    // How many time rule hits (is true)
    hits: AtomicU64,
}

#[cfg(feature = "metrics")]
use std::sync::OnceLock;

#[cfg(feature = "metrics")]
struct RulesMetrics {
    execute_count: prometheus::IntCounter,
    hit_count: prometheus::IntCounter,
    execute_time: prometheus::Histogram,
}

#[cfg(feature = "metrics")]
impl RulesMetrics {
    fn new() -> Self {
        Self {
            execute_count: prometheus::register_int_counter!(
                "rules_exec_count",
                "Number of all rules executions."
            )
            .unwrap(),
            hit_count: prometheus::register_int_counter!(
                "rules_hit_count",
                "Number of rules executions hits."
            )
            .unwrap(),
            execute_time: prometheus::register_histogram!(
                "rules_exec_time",
                "Rules execution time in seconds.",
                vec![
                    0.000_100, 0.000_250, 0.000_500, 0.000_750, 0.001_000, 0.002_500, 0.005_000,
                    0.007_500, 0.010_000, 0.025_000, 0.050_000, 0.075_000, 0.100_000, 0.250_000,
                    0.500_000, 0.750_000,
                ]
            )
            .unwrap(),
        }
    }
}

#[cfg(feature = "metrics")]
static RULES_METRICS: OnceLock<RulesMetrics> = OnceLock::new();

#[cfg(feature = "metrics")]
fn rules_metrics() -> &'static RulesMetrics {
    RULES_METRICS.get_or_init(RulesMetrics::new)
}

impl Rule {
    pub async fn init(&mut self) -> Result<()> {
        if let Some(s) = &self.filter_str {
            trace!("compiling filter: {:?}", s);
            let filter: filter::Filter = s.parse().with_context(|| "parse filter")?;
            filter.validate().await?;
            self.filter = Some(filter);
        }
        Ok(())
    }

    pub async fn evaluate(&self, request: &Context) -> bool {
        trace!(
            "evaluate filter={:?} target={}",
            self.filter_str, self.target_name
        );
        self.stats.exec.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "metrics")]
        let timer = {
            rules_metrics().execute_count.inc();
            rules_metrics().execute_time.start_timer()
        };
        let t = Instant::now();
        let ret = if let Some(filter) = &self.filter {
            match filter.evaluate(request).await {
                Ok(b) => b,
                Err(e) => {
                    trace!("error evaluating filter: {:?}", e);
                    false
                }
            }
        } else {
            true
        };
        let t = t.elapsed().as_nanos() as u64;
        #[cfg(feature = "metrics")]
        timer.stop_and_record();
        self.stats.time.fetch_add(t, Ordering::Relaxed);
        if ret {
            #[cfg(feature = "metrics")]
            rules_metrics().hit_count.inc();
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
        }
        trace!("evaluation finished in {} ns", t);
        ret
    }

    /// Get a reference to the rule's target name.
    pub fn target_name(&self) -> &str {
        self.target_name.as_str()
    }
}

impl std::fmt::Debug for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rule")
            .field("target_name", &self.target_name)
            .field(
                "target",
                if self.target.is_some() {
                    &"Some"
                } else {
                    &"None"
                },
            )
            .field("filter_str", &self.filter_str)
            .field("filter", &self.filter)
            .finish()
    }
}
