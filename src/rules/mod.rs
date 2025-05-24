// Any sufficiently complicated C or Fortran program contains an ad hoc, informally-specified, bug-ridden, slow implementation of half of Common Lisp.  --Greenspun's tenth rule

mod filter;
pub(crate) mod script_ext;
use easy_error::{Error, ResultExt};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};
use tracing::trace;

use crate::{connectors::Connector, context::Context};

pub fn from_config(cfg: &[Value]) -> Result<Vec<Arc<Rule>>, Error> {
    let mut ret = Vec::with_capacity(cfg.len());
    for val in cfg {
        ret.push(serde_yaml_ng::from_value(val.clone()).context("parse rule")?);
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
lazy_static::lazy_static! {
    static ref RULES_EXECUTE_COUNT: prometheus::IntCounter = prometheus::register_int_counter!(
        "rules_exec_count",
        "Number of all rules executions."
    )
    .unwrap();
    static ref RULES_HIT_COUNT: prometheus::IntCounter = prometheus::register_int_counter!(
        "rules_hit_count",
        "Number of rules executions hits."
    )
    .unwrap();
    static ref RULES_EXECUTE_TIME: prometheus::Histogram = prometheus::register_histogram!(
        "rules_exec_time",
        "Rules execution time in seconds.",
        vec![
            0.000_100, 0.000_250, 0.000_500, 0.000_750,
            0.001_000, 0.002_500, 0.005_000, 0.007_500,
            0.010_000, 0.025_000, 0.050_000, 0.075_000,
            0.100_000, 0.250_000, 0.500_000, 0.750_000,
        ]
    )
    .unwrap();
}

impl Rule {
    pub fn init(&mut self) -> Result<(), Error> {
        if let Some(s) = &self.filter_str {
            trace!("compiling filter: {:?}", s);
            let filter: filter::Filter = s.parse().context("parse filter")?;
            filter.validate()?;
            self.filter = Some(filter);
        }
        Ok(())
    }

    pub fn evaluate(&self, request: &Context) -> bool {
        trace!(
            "evaluate filter={:?} target={}",
            self.filter_str,
            self.target_name
        );
        self.stats.exec.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "metrics")]
        let timer = {
            RULES_EXECUTE_COUNT.inc();
            RULES_EXECUTE_TIME.start_timer()
        };
        let t = Instant::now();
        let ret = if self.filter.is_none() {
            true
        } else {
            match self.filter.as_ref().unwrap().evaluate(request) {
                Ok(b) => b,
                Err(e) => {
                    trace!("error evaluating filter: {:?}", e);
                    false
                }
            }
        };
        let t = t.elapsed().as_nanos() as u64;
        #[cfg(feature = "metrics")]
        timer.stop_and_record();
        self.stats.time.fetch_add(t, Ordering::Relaxed);
        if ret {
            #[cfg(feature = "metrics")]
            RULES_EXECUTE_COUNT.inc();
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
