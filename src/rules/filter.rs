use anyhow::{Result, ensure};
use milu::parser::{SyntaxError, parse};
use milu::script::{Evaluatable, Type, Value};
use std::convert::TryInto;
use std::str::FromStr;
use tracing::trace;

use crate::context::Context;
use crate::rules::script_ext::create_context;

#[derive(Debug)]
pub struct Filter {
    root: Value,
}

impl Filter {
    pub async fn validate(&self) -> Result<()> {
        let ctx = create_context(Default::default());
        let rtype = self.root.type_of(ctx.into()).await?;
        ensure!(
            rtype == Type::Boolean,
            "filter return type mismatch: required boolean, got {}",
            rtype
        );
        Ok(())
    }
    pub async fn evaluate(&self, request: &Context) -> Result<bool> {
        let ctx = create_context(request.props().clone());
        let ret = self.root.value_of(ctx.into()).await?.try_into()?;
        trace!("filter eval: {:?} => {}", request, ret);
        Ok(ret)
    }
}

impl FromStr for Filter {
    type Err = SyntaxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse(s).map(|root| Filter { root })
    }
}
