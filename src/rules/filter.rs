use easy_error::{bail, ensure, Error};
use log::trace;
use milu::parser::{parse, SyntaxError};
use milu::script::{
    Accessible, Evaluatable, NativeObject, ScriptContext, ScriptContextRef, Type, Value,
};
use std::convert::TryInto;
use std::str::FromStr;

use crate::context::{Context, ContextProps};

#[derive(Debug)]
pub struct Filter {
    root: Value<'static>,
}

impl Filter {
    fn create_context(props: &ContextProps) -> ScriptContext {
        let mut ctx = ScriptContext::new(Some(Default::default()));
        let adapter = ContextAdaptor::new(props);
        ctx.set("request".to_string(), adapter.into());
        ctx
    }
    pub fn validate(&self) -> Result<(), Error> {
        let request = Default::default();
        let ctx = Self::create_context(&request);
        let rtype = self.root.type_of(ctx.into())?;
        ensure!(
            rtype == Type::Boolean,
            "filter return type mismatch: required boolean, got {}",
            rtype
        );
        Ok(())
    }
    pub fn evaluate(&self, request: &Context) -> Result<bool, Error> {
        let ctx = Self::create_context(request.props());
        let ret = self.root.value_of(ctx.into())?.try_into()?;
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

// #[derive(Debug)]

#[derive(Clone, Hash, Debug)]
struct ContextAdaptor<'a> {
    req: &'a ContextProps,
}

impl<'a> ContextAdaptor<'a> {
    fn new(req: &'a ContextProps) -> Self {
        Self { req }
    }
}

impl<'a> Accessible<'a> for ContextAdaptor<'a> {
    fn names(&self) -> Vec<&str> {
        vec!["listener", "source", "target"]
    }

    fn get(&self, name: &str) -> Result<Value<'a>, Error> {
        match name {
            "listener" => Ok(self.req.listener.clone().into()),
            "target" => Ok(self.req.target.to_string().into()),
            "source" => Ok(self.req.source.to_string().into()),
            _ => bail!("property undefined: {}", name),
        }
    }

    fn type_of<'b>(&self, name: &str, _ctx: ScriptContextRef<'b>) -> Result<Type, Error>
    where
        'a: 'b,
    {
        match name {
            "listener" | "source" | "target" => Ok(Type::String),
            _ => bail!("undefined"),
        }
    }
}

impl<'a> NativeObject<'a> for ContextAdaptor<'a> {
    fn as_accessible(&self) -> Option<&dyn Accessible<'a>> {
        Some(self)
    }
}

impl std::fmt::Display for ContextAdaptor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
