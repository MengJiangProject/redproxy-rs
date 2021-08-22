use std::convert::TryInto;
use std::rc::Rc;
use std::{fmt, str::FromStr};

use easy_error::{bail, Error};
use log::trace;
use nom::error::{convert_error, VerboseError};

use crate::context::Context;

use milu::parser::root;
use milu::script::{
    Accessible, Callable, Evaluatable, Indexable, NativeObject, ScriptContext, Type, Value,
};

#[derive(Debug)]
pub struct Filter {
    root: Value<'static>,
}

impl Filter {
    pub fn evaluate(&self, request: &Context) -> Result<bool, Error> {
        let ctx = Default::default();
        let mut ctx = ScriptContext::new(Some(ctx));
        let adapter = ContextAdaptor::new(request);
        let value = Value::NativeObject(Rc::new(adapter));
        ctx.set("request".to_string(), value);
        let ret = self.root.value_of(ctx.into())?.try_into()?;
        trace!("filter eval: {:?} => {}", request, ret);
        Ok(ret)
    }
}

impl FromStr for Filter {
    type Err = SyntaxError;

    fn from_str<'a>(s: &'a str) -> Result<Self, Self::Err> {
        root::<VerboseError<&str>>(s)
            .map(|(rest, root)| {
                assert!(
                    rest.is_empty(),
                    "parser not complete: val={:?} left={:}",
                    root,
                    rest,
                );
                Filter { root }
            })
            .map_err(|e| SyntaxError::new(e, s))
    }
}

// #[derive(Debug)]
pub struct SyntaxError {
    msg: String,
}

impl SyntaxError {
    fn new(e: nom::Err<VerboseError<&str>>, input: &str) -> Self {
        let msg = match e {
            nom::Err::Error(e) | nom::Err::Failure(e) => convert_error(input, e),
            _ => e.to_string(),
        };
        SyntaxError { msg }
    }
}

impl std::error::Error for SyntaxError {}
impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SyntaxError: {}", self.msg)
    }
}

impl fmt::Debug for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SyntaxError: {}", self.msg)
    }
}
#[derive(Clone, Hash, Debug)]
struct ContextAdaptor<'a> {
    req: &'a Context,
}

impl<'a> ContextAdaptor<'a> {
    fn new(req: &'a Context) -> Self {
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

    fn type_of<'b>(&self, name: &str, _ctx: Rc<ScriptContext<'b>>) -> Result<Type, Error>
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
    fn as_evaluatable(&self) -> Option<&dyn Evaluatable> {
        None
    }
    fn as_accessible(&self) -> Option<&dyn Accessible<'a>> {
        Some(self)
    }
    fn as_indexable(&self) -> Option<&dyn Indexable<'a>> {
        None
    }
    fn as_callable(&self) -> Option<&dyn Callable> {
        None
    }
    // fn as_any(&self) -> &dyn std::any::Any {
    //     self
    // }
    // fn equals(&self, other: &dyn NativeObject) -> bool {
    //     // other.as_any().downcast_ref::<Self>().is_some()
    //     false
    // }
}

impl std::fmt::Display for ContextAdaptor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
