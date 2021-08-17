use easy_error::{bail, err_msg, Error, ResultExt};
use std::{
    any::Any,
    collections::HashMap,
    convert::{TryFrom, TryInto},
};
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

impl Type {
    pub fn array_of(t: Self) -> Self {
        Self::Array(Box::new(t))
    }
    pub fn tuple_of(t: Vec<Self>) -> Self {
        Self::Tuple(Box::new(t))
    }
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
    fn get(&self, index: i64) -> Result<&Value, Error>;
}

pub trait Accessible {
    fn names(&self) -> Vec<&str>;
    fn get(&self, name: &str) -> Result<&Value, Error>;
}

pub trait Callable: std::fmt::Debug + dyn_clone::DynClone {
    // fn new(args: Vec<Value>) -> Box<dyn Callable>;
    // should not return Any
    fn signature(
        &self,
        ctx: &ScriptContext,
        args: Vec<Type>,
        vals: &Vec<Value>,
    ) -> Result<Type, Error>;
    fn call(&self, ctx: &ScriptContext, args: &Vec<Value>) -> Result<Value, Error>;

    // fn clone(&self) -> Box<dyn Callable>;
    fn name(&self) -> &str;
    // fn paramters(&self) -> Box<[&Value]>;
}

dyn_clone::clone_trait_object!(Callable);
impl Eq for dyn Callable {}
impl PartialEq for dyn Callable {
    fn eq(&self, other: &dyn Callable) -> bool {
        self.name() == other.name() //&& self.paramters() == other.paramters()
    }
}

pub trait NativeObject: std::fmt::Debug + dyn_clone::DynClone {
    fn type_of(&self, ctx: &ScriptContext) -> Result<Type, Error>;
    fn value_of(&self, ctx: &ScriptContext) -> Result<Value, Error>;
    fn as_accessible(&self) -> Option<Box<dyn Accessible>>;
    fn as_indexable(&self) -> Option<Box<dyn Indexable>>;
    fn as_callable(&self) -> Option<Box<dyn Callable>>;
    fn as_any(&self) -> &dyn Any;
    fn equals(&self, other: &dyn NativeObject) -> bool;
}
dyn_clone::clone_trait_object!(NativeObject);

impl Eq for dyn NativeObject {}
impl PartialEq for dyn NativeObject {
    fn eq(&self, other: &dyn NativeObject) -> bool {
        self.equals(other)
    }
}

pub struct ScriptContext {
    globals: HashMap<String, Value>,
}

impl ScriptContext {
    fn lookup(&self, id: &str) -> Result<Value, Error> {
        self.globals
            .get(id)
            .ok_or(err_msg(format!("\"{}\" is undefined", id)))
            .map(Clone::clone)
    }
}
impl Default for ScriptContext {
    fn default() -> Self {
        let mut globals = HashMap::default();
        globals.insert("to_string".to_string(), stdlib::ToString::stub());
        globals.insert("to_integer".to_string(), stdlib::ToInteger::stub());
        globals.insert("split".to_string(), stdlib::Split::stub());
        Self { globals }
    }
}

impl Accessible for HashMap<String, Value> {
    fn names(&self) -> Vec<&str> {
        self.keys().map(String::as_str).collect()
    }

    fn get(&self, name: &str) -> Result<&Value, Error> {
        self.get(name)
            .ok_or(err_msg(format!("undefined: {}", name)))
    }
}

impl Indexable for Vec<Value> {
    fn length(&self) -> usize {
        self.len()
    }

    fn get(&self, index: i64) -> Result<&Value, Error> {
        let index: Result<usize, std::num::TryFromIntError> = if index >= 0 {
            index.try_into()
        } else {
            (-index).try_into().map(|i: usize| self.len() - i)
        };
        let i: usize = index.context("failed to cast index from i64")?;
        if i >= self.len() {
            bail!("index out of bounds: {}", i)
        }
        Ok(&self[i])
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
    NativeObject(Box<dyn NativeObject>),
    OpCall(Box<Call>),
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
            (OpCall(a), OpCall(b)) => a == b,
            (NativeObject(a), NativeObject(b)) => a == b,
            (Null, Null) => true,
            _ => false,
        }
    }
}

impl Value {
    fn type_of(&self, ctx: &ScriptContext) -> Result<Type, Error> {
        use Value::*;
        match self {
            Null => Ok(Type::Null),
            String(_) => Ok(Type::String),
            Boolean(_) => Ok(Type::Boolean),
            Integer(_) => Ok(Type::Integer),
            Identifier(_) => Ok(Type::NativeObject),
            OpCall(x) => x.signature(ctx),
            Array(a) => {
                if a.is_empty() {
                    Ok(Type::Array(Box::new(Type::Any)))
                } else {
                    let t = a[0].type_of(ctx)?;
                    a.iter().try_for_each(|x| {
                        let xt = x.type_of(ctx)?;
                        if xt != t {
                            bail!("array member must have same type: required type={:?}, mismatch item={:?}", t, x)
                        } else {
                            Ok(())
                        }
                    })?;
                    Ok(Type::Array(Box::new(t)))
                }
            }
            Tuple(t) => {
                let mut ret = Vec::with_capacity(t.len());
                for x in t.iter() {
                    ret.push(x.type_of(ctx)?)
                }
                Ok(Type::Tuple(Box::new(ret)))
            }
            NativeObject(o) => o.type_of(ctx),
        }
    }

    //evaluate to the final value
    pub fn value_of(&self, ctx: &ScriptContext) -> Result<Self, Error> {
        use Value::*;
        match self {
            Identifier(id) => ctx.lookup(id),
            OpCall(f) => f.call(ctx),
            NativeObject(f) => f.value_of(ctx),
            _ => Ok(self.clone()),
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
cast_value!(Call, OpCall, boxed);

impl From<&str> for Value {
    fn from(x: &str) -> Self {
        Self::String(x.into())
    }
}

// impl<T> From<T> for Value
// where
//     T: Callable + 'static,
// {
//     fn from(x: T) -> Self {
//         Value::OpCall(Box::new(x))
//     }
// }

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Value::*;
        match self {
            Null => write!(f, "null"),
            String(s) => write!(f, "{}", s),
            Integer(i) => write!(f, "{}", i),
            Boolean(b) => write!(f, "{}", b),
            Identifier(id) => write!(f, "<{}>", id),
            OpCall(x) => write!(f, "{:?}", x),
            Array(x) => write!(f, "{:?}", x),
            Tuple(x) => write!(f, "{:?}", x),
            NativeObject(x) => write!(f, "{:?}", x),
            // _ => panic!("not implemented"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    func: Value,
    args: Vec<Value>,
}

impl Call {
    pub fn new(mut args: Vec<Value>) -> Self {
        let func = args.remove(0);
        Self { func, args }
    }
    fn signature(&self, ctx: &ScriptContext) -> Result<Type, Error> {
        let func = self.func(ctx)?;
        let mut args = Vec::with_capacity(self.args.len());
        for x in &self.args {
            args.push(x.type_of(ctx)?);
        }
        func.signature(ctx, args, &self.args)
    }
    fn call(&self, ctx: &ScriptContext) -> Result<Value, Error> {
        let func = self.func(ctx)?;
        func.call(ctx, &self.args)
    }
    fn func(&self, ctx: &ScriptContext) -> Result<Box<dyn Callable>, Error> {
        let func = if let Value::Identifier(_) = &self.func {
            self.func.value_of(ctx)?
        } else {
            self.func.clone()
        };
        if let Value::NativeObject(x) = func {
            x.as_callable()
                .ok_or(err_msg("NativeObject does not implement Callable"))
        } else {
            bail!("func does not implement Callable: {:?}", func)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::parser::root;
    use super::*;
    #[test]
    fn one_plus_one() {
        type_test("1+1", Type::Integer);
        eval_test("1+1", 2.into());
    }

    #[test]
    fn to_string() {
        type_test("to_string(100*2)", Type::String);
        eval_test("to_string(100*2)", "200".into())
    }

    #[test]
    fn arrays() {
        type_test("[1,2,3]", Type::array_of(Type::Integer));
        eval_test("[1,2,3][0]", 1.into())
    }

    #[test]
    fn array_type() {
        let input = "[1,\"true\",false]";
        let ctx = &Default::default();
        let value = root::<nom::error::VerboseError<&str>>(input)
            .unwrap()
            .1
            .type_of(ctx);
        println!("t={:?}", value);
        assert!(value.is_err());
    }
    fn eval_test(input: &str, output: Value) {
        let ctx = &Default::default();
        let value = root::<nom::error::VerboseError<&str>>(input)
            .unwrap()
            .1
            .value_of(ctx)
            .unwrap();
        assert_eq!(value, output);
    }
    fn type_test(input: &str, output: Type) {
        let ctx = &Default::default();
        let value = root::<nom::error::VerboseError<&str>>(input)
            .unwrap()
            .1
            .type_of(ctx)
            .unwrap();
        assert_eq!(value, output);
    }
}
