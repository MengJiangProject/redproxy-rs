use super::parser::Expr;

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

impl From<Vec<Value>> for Value {
    fn from(x: Vec<Value>) -> Self {
        Self::Array(x.into())
    }
}

impl From<&str> for Value {
    fn from(x: &str) -> Self {
        Self::String(x.into())
    }
}

impl From<String> for Value {
    fn from(x: String) -> Self {
        Self::String(x)
    }
}

impl From<i64> for Value {
    fn from(x: i64) -> Self {
        Self::Integer(x)
    }
}

impl From<bool> for Value {
    fn from(x: bool) -> Self {
        Self::Boolean(x)
    }
}

impl From<Expr> for Value {
    fn from(x: Expr) -> Self {
        Self::Expression(x.into())
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
