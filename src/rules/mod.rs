// Any sufficiently complicated C or Fortran program contains an ad hoc, informally-specified, bug-ridden, slow implementation of half of Common Lisp.  --Greenspun's tenth rule

mod filter;
mod script_ext;
use easy_error::{Error, ResultExt};
use log::trace;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use crate::{connectors::Connector, context::Context};

pub fn from_config(cfg: &[Value]) -> Result<Vec<Rule>, Error> {
    let mut ret = Vec::with_capacity(cfg.len());
    for val in cfg {
        ret.push(serde_yaml::from_value(val.clone()).context("parse rule")?);
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
        self.stats.time.fetch_add(t, Ordering::Relaxed);
        if ret {
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
