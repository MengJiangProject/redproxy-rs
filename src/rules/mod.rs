// Any sufficiently complicated C or Fortran program contains an ad hoc, informally-specified, bug-ridden, slow implementation of half of Common Lisp.  --Greenspun's tenth rule

mod filter;
use easy_error::{Error, ResultExt};
use log::trace;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{connectors::ConnectorRef, context::Context};

#[derive(Serialize, Deserialize)]
pub struct Rule {
    #[serde(rename = "target")]
    target_name: String,
    #[serde(skip)]
    target: Option<Arc<ConnectorRef>>,
    #[serde(rename = "filter")]
    filter_str: Option<String>,
    #[serde(skip)]
    filter: Option<filter::Filter>,
}

impl Rule {
    pub fn init(&mut self) -> Result<(), Error> {
        if let Some(s) = &self.filter_str {
            trace!("compiling filter: {:?}", s);
            self.filter = Some(s.parse().context("parse filter")?);
        }
        Ok(())
    }

    pub fn evaluate(&self, context: &Context) -> bool {
        if self.filter.is_none() {
            true
        } else {
            match self.filter.as_ref().unwrap().evaluate(context) {
                Ok(b) => b,
                Err(e) => {
                    trace!("error evaluating filter: {:?}", e);
                    false
                }
            }
        }
    }

    pub fn target(&self) -> Arc<ConnectorRef> {
        self.target.clone().unwrap()
    }

    pub fn set_target(&mut self, target: Arc<ConnectorRef>) {
        self.target = Some(target);
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
