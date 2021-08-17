mod filter;
mod parser;
mod script;

use easy_error::{Error, ResultExt};
use log::trace;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::connectors::Connector;

#[derive(Serialize, Deserialize, Debug)]
pub struct Rule {
    #[serde(rename = "target")]
    target_name: String,
    #[serde(skip)]
    target: Option<Arc<Box<dyn Connector>>>,
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

    pub fn evaluate(&self, context: &super::context::Context) -> bool {
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

    pub fn target(&self) -> Arc<Box<dyn Connector>> {
        self.target.clone().unwrap()
    }

    pub fn set_target(&mut self, target: Arc<Box<dyn Connector>>) {
        self.target = Some(target);
    }

    /// Get a reference to the rule's target name.
    pub fn target_name(&self) -> &str {
        self.target_name.as_str()
    }
}
