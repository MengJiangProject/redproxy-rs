use easy_error::{Error, ResultExt};
// use super::parser::Expr;
use super::value::Value;

mod stdlib;

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Type {
    String,
    Integer,
    Boolean,
    Array(Box<Type>),
    Tuple(Box<Vec<Type>>),
    Function,
    Null,
    Any,
}

pub trait Indexable {
    fn length(&self) -> usize;
    fn get(&self, index: usize) -> Result<Value, Error>;
}

pub trait Accessible {
    fn names(&self) -> Vec<&str>;
    fn get(&self, name: &str) -> Result<Value, Error>;
}

pub trait Callable {
    fn signature(&self) -> (Type, Box<[Type]>);
    fn call(&self, args: Vec<Value>) -> Result<Value, Error>;
}
