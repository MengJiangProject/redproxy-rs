use std::convert::TryInto;
use std::{fmt, str::FromStr};

use easy_error::{bail, Error};
use log::trace;
use nom::error::{convert_error, VerboseError};

use crate::context::Context;

use crate::milu::parser::root;
use crate::milu::script::{
    Accessible, Callable, Indexable, NativeObject, ScriptContext, Type, Value,
};

#[derive(Debug)]
pub struct Filter {
    root: Value,
}

impl Filter {
    pub fn evaluate(&self, request: &Context) -> Result<bool, Error> {
        let ctx = Default::default();
        let mut ctx = ScriptContext::new(Some(&ctx));
        let adapter = ContextAdaptor::new(request);
        ctx.set("request".to_string(), adapter.into());
        let ret = self.root.value_of(&ctx)?.try_into()?;
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
#[derive(Debug, Clone)]
struct ContextAdaptor {
    listener: Value,
    source: Value,
    target: Value,
}
impl ContextAdaptor {
    fn new(c: &Context) -> Self {
        let listener = c.listener.clone().into();
        let source = c.source.to_string().into();
        let target = c.target.to_string().into();
        Self {
            listener,
            source,
            target,
        }
    }
}
impl Accessible for ContextAdaptor {
    fn names(&self) -> Vec<&str> {
        vec!["listener", "source", "target"]
    }

    fn get(&self, name: &str) -> Result<&Value, Error> {
        match name {
            "listener" => Ok(&self.listener),
            "target" => Ok(&self.target),
            "source" => Ok(&self.source),
            _ => bail!("property undefined: {}", name),
        }
    }

    fn type_of(&self, name: &str, _ctx: &ScriptContext) -> Result<Type, Error> {
        match name {
            "listener" | "source" | "target" => Ok(Type::String),
            _ => bail!("undefined"),
        }
    }
}

impl From<ContextAdaptor> for Value {
    fn from(c: ContextAdaptor) -> Self {
        #[derive(Clone)]
        pub struct Stub(ContextAdaptor);
        impl NativeObject for Stub {
            fn name(&self) -> &str {
                "request"
            }
            fn type_of(&self, _ctx: &ScriptContext) -> Result<Type, Error> {
                Ok(Type::NativeObject)
            }
            fn value_of(&self, _ctx: &ScriptContext) -> Result<Value, Error> {
                bail!("not a value")
            }
            fn as_accessible(&self) -> Option<&dyn Accessible> {
                Some(&self.0)
            }
            fn as_indexable(&self) -> Option<&dyn Indexable> {
                None
            }
            fn as_callable(&self) -> Option<&dyn Callable> {
                None
            }
        }
        impl std::fmt::Display for Stub {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", stringify!($name))
            }
        }
        impl std::fmt::Debug for Stub {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", stringify!($name))
            }
        }
        Value::NativeObject(Box::new(Stub(c)))
    }
}
