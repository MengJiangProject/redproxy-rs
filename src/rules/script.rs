use easy_error::{Error, ResultExt};
use std::convert::TryFrom;
pub mod stdlib;

#[derive(Debug, Eq, Clone)]
pub enum Type {
    String,
    Integer,
    Boolean,
    Array(Box<Type>),
    Tuple(Box<Vec<Type>>),
    NativeObject,
    Null,
    Any, //native only
}

impl PartialEq for Type {
    fn eq(&self, other: &Type) -> bool {
        use Type::*;
        match (self, other) {
            (Any, _) => true,
            (_, Any) => true,
            (String, String) => true,
            (Integer, Integer) => true,
            (Boolean, Boolean) => true,
            (Array(a), Array(b)) => a == b,
            (Tuple(a), Tuple(b)) => a == b,
            (NativeObject, NativeObject) => true,
            (Null, Null) => true,
            _ => false,
        }
    }
}
pub trait Indexable {
    fn length(&self) -> usize;
    fn get(&self, index: usize) -> Result<Value, Error>;
}

pub trait Accessible {
    fn names(&self) -> Vec<&str>;
    fn get(&self, name: &str) -> Result<Value, Error>;
}

pub trait Callable: std::fmt::Debug + dyn_clone::DynClone {
    // fn new(args: Vec<Value>) -> Box<dyn Callable>;
    // should not return Any
    fn signature(&self) -> Result<Type, Error>;
    fn call(self) -> Result<Value, Error>;
    // fn clone(&self) -> Box<dyn Callable>;
    fn name(&self) -> &str;
    fn paramters(&self) -> Box<[&Value]>;
}

dyn_clone::clone_trait_object!(Callable);
impl Eq for dyn Callable {}
impl PartialEq for dyn Callable {
    fn eq(&self, other: &dyn Callable) -> bool {
        self.name() == other.name() && self.paramters() == other.paramters()
    }
}

#[derive(Debug, Eq, Clone)]
pub enum Value {
    Null,
    Array(Box<Vec<Value>>),
    Tuple(Box<Vec<Value>>),
    String(String),
    Integer(i64),
    Boolean(bool),
    Identifier(String),
    Lambda(Box<dyn Callable>),
}

impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        use Value::*;
        match (self, other) {
            (String(a), String(b)) => a == b,
            (Integer(a), Integer(b)) => a == b,
            (Boolean(a), Boolean(b)) => a == b,
            (Identifier(a), Identifier(b)) => a == b,
            (Array(a), Array(b)) => a == b,
            (Tuple(a), Tuple(b)) => a == b,
            (Lambda(a), Lambda(b)) => a == b,
            (Null, Null) => true,
            _ => false,
        }
    }
}

impl Value {
    fn type_of(&self) -> Result<Type, Error> {
        use Value::*;
        match self {
            Null => Ok(Type::Null),
            String(_) => Ok(Type::String),
            Boolean(_) => Ok(Type::Boolean),
            Integer(_) => Ok(Type::Integer),
            Identifier(_) => Ok(Type::NativeObject),
            Lambda(x) => x.signature(),
            Array(a) => {
                if a.is_empty() {
                    Ok(Type::Array(Box::new(Type::Null)))
                } else {
                    let t = a[0].type_of()?;
                    Ok(Type::Array(Box::new(t)))
                }
            }
            Tuple(t) => {
                let mut ret = Vec::with_capacity(t.len());
                for x in t.iter() {
                    ret.push(x.type_of()?)
                }
                Ok(Type::Tuple(Box::new(ret)))
            }
        }
    }
}

macro_rules! cast_value {
    ($ty:ty, $name:ident) => {
        cast_value!($ty, $name, v, v, v);
    };
    ($ty:ty, $name:ident, boxed) => {
        cast_value!($ty, $name, v, *v, Box::new(v));
    };
    ($ty:ty, $name:ident, $v: ident, $from:expr, $to:expr) => {
        impl TryFrom<Value> for $ty {
            type Error = easy_error::Error;
            fn try_from(x: Value) -> Result<$ty, Self::Error> {
                if let Value::$name($v) = x {
                    Ok($from)
                } else {
                    easy_error::bail!("unable to cast {:?} into {}", x, stringify!($ty))
                }
            }
        }

        impl From<$ty> for Value {
            fn from($v: $ty) -> Self {
                Self::$name($to)
            }
        }
    };
}

cast_value!(String, String);
cast_value!(i64, Integer);
cast_value!(bool, Boolean);
cast_value!(Vec<Value>, Array, boxed);
// cast_value!(Lambda, dyn Callable, boxed);

impl From<&str> for Value {
    fn from(x: &str) -> Self {
        Self::String(x.into())
    }
}

impl<T> From<T> for Value
where
    T: Callable + 'static,
{
    fn from(x: T) -> Self {
        Value::Lambda(Box::new(x))
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => write!(f, "null"),
            Self::String(s) => write!(f, "{}", s),
            Self::Integer(i) => write!(f, "{}", i),
            Self::Boolean(b) => write!(f, "{}", b),
            Self::Identifier(id) => write!(f, "<{}>", id),
            Self::Lambda(x) => write!(f, "{:?}", x),
            Self::Array(x) => write!(f, "{:?}", x),
            Self::Tuple(x) => write!(f, "{:?}", x),
            // _ => panic!("not implemented"),
        }
    }
}
