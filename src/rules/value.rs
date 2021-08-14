use super::parser::Expr;
use std::convert::TryFrom;
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Value {
    Null,
    Array(Box<Vec<Value>>),
    Tuple(Box<Vec<Value>>),
    String(String),
    Integer(i64),
    Boolean(bool),
    Identifier(String),
    Expression(Box<Expr>),
}

impl Value {}

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
cast_value!(Expr, Expression, boxed);

impl From<&str> for Value {
    fn from(x: &str) -> Self {
        Self::String(x.into())
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
            Self::Expression(x) => write!(f, "{:?}", x),
            Self::Array(x) => write!(f, "{:?}", x),
            Self::Tuple(x) => write!(f, "{:?}", x),
            // _ => panic!("not implemented"),
        }
    }
}
