use easy_error::{bail, err_msg, Error, ResultExt};
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fmt::Display,
    rc::Rc,
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

impl Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::String => write!(f, "string"),
            &Self::Integer => write!(f, "integer"),
            &Self::Boolean => write!(f, "boolean"),
            Self::Array(a) => write!(f, "[{}]", a),
            Self::Tuple(t) => write!(
                f,
                "({})",
                t.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            &Self::NativeObject => write!(f, "native"),
            &Self::Null => write!(f, "null"),
            &Self::Any => write!(f, "any"),
        }
    }
}

pub trait Evaluatable<'a> {
    fn type_of(&self, ctx: &ScriptContext) -> Result<Type, Error>;
    fn value_of<'b>(&self, ctx: &ScriptContext<'b>) -> Result<Value<'b>, Error>
    where
        'a: 'b;
}

pub trait Indexable<'a> {
    fn length(&self) -> usize;
    fn type_of<'b>(&self, index: i64, ctx: &'b ScriptContext<'b>) -> Result<Type, Error>
    where
        'a: 'b;
    fn get(&self, index: i64) -> Result<&Value<'a>, Error>;
}

pub trait Accessible<'a> {
    fn names(&self) -> Vec<&str>;
    fn type_of<'b>(&self, name: &str, ctx: &'b ScriptContext<'b>) -> Result<Type, Error>
    where
        'a: 'b;
    fn get(&self, name: &str) -> Result<&Value<'a>, Error>;
}

pub trait Callable<'a> {
    // should not return Any
    fn signature<'b>(
        &self,
        ctx: &'b ScriptContext<'b>,
        args: &Vec<Value<'a>>,
    ) -> Result<Type, Error>
    where
        'a: 'b;
    fn call<'b>(
        &self,
        ctx: &'b ScriptContext<'b>,
        args: &Vec<Value<'a>>,
    ) -> Result<Value<'b>, Error>
    where
        'a: 'b;
}

impl<'a> Accessible<'a> for HashMap<String, Value<'a>> {
    fn names(&self) -> Vec<&str> {
        self.keys().map(String::as_str).collect()
    }

    fn type_of<'b>(&self, name: &str, ctx: &'b ScriptContext<'b>) -> Result<Type, Error>
    where
        'a: 'b,
    {
        Accessible::get(self, name).and_then(|x| x.type_of(ctx))
    }

    fn get(&self, name: &str) -> Result<&Value<'a>, Error> {
        self.get(name)
            .ok_or(err_msg(format!("undefined: {}", name)))
    }
}

impl<'a> Indexable<'a> for Vec<Value<'a>> {
    fn length(&self) -> usize {
        self.len()
    }

    fn type_of<'b>(&self, index: i64, ctx: &'b ScriptContext<'b>) -> Result<Type, Error>
    where
        'a: 'b,
    {
        Indexable::get(self, index).and_then(|x| x.type_of(ctx))
    }

    fn get(&self, index: i64) -> Result<&Value<'a>, Error> {
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

pub trait NativeObject<'a>: std::fmt::Debug + std::any::Any + 'a {
    fn as_evaluatable(&self) -> Option<&dyn Evaluatable<'a>>;
    fn as_accessible(&self) -> Option<&dyn Accessible<'a>>;
    fn as_indexable(&self) -> Option<&dyn Indexable<'a>>;
    fn as_callable(&self) -> Option<&dyn Callable<'a>>;
    fn as_any(&self) -> &dyn std::any::Any;
    fn equals(&self, other: &dyn NativeObject) -> bool;
}
// dyn_clone::clone_trait_object!(NativeObject<'_>);
impl Eq for dyn NativeObject<'_> {}
impl PartialEq for dyn NativeObject<'_> {
    fn eq(&self, other: &dyn NativeObject) -> bool {
        self.equals(other)
    }
}

pub struct ScriptContext<'a> {
    parent: Option<&'a ScriptContext<'a>>,
    varibles: HashMap<String, Value<'a>>,
}

impl<'a> ScriptContext<'a> {
    pub fn new(parent: Option<&'a ScriptContext<'a>>) -> Self {
        Self {
            parent,
            varibles: Default::default(),
        }
    }
    pub fn lookup(&self, id: &str) -> Result<Value<'a>, Error> {
        if let Some(r) = self.varibles.get(id) {
            Ok(r.clone())
        } else {
            if let Some(p) = &self.parent {
                p.lookup(id)
            } else {
                bail!("\"{}\" is undefined", id)
            }
        }
    }
    pub fn set(&mut self, id: String, value: Value<'a>) {
        self.varibles.insert(id, value);
    }
}

impl Default for ScriptContext<'static> {
    fn default() -> Self {
        let mut varibles = HashMap::default();
        varibles.insert("to_string".to_string(), stdlib::ToString.into());
        varibles.insert("to_integer".to_string(), stdlib::ToInteger.into());
        varibles.insert("split".to_string(), stdlib::Split.into());
        Self {
            parent: None,
            varibles,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Value<'a> {
    Null,
    Array(Box<Vec<Value<'a>>>),
    Tuple(Box<Vec<Value<'a>>>),
    String(String),
    Integer(i64),
    Boolean(bool),
    Identifier(String),
    NativeObject(Rc<dyn NativeObject<'a> + 'static>),
    OpCall(Box<Call<'a>>),
}

impl<'a> Eq for Value<'a> {}
impl<'a> PartialEq for Value<'a> {
    fn eq(&self, other: &Value<'a>) -> bool {
        use Value::*;
        match (self, other) {
            (String(a), String(b)) => a == b,
            (Integer(a), Integer(b)) => a == b,
            (Boolean(a), Boolean(b)) => a == b,
            (Identifier(a), Identifier(b)) => a == b,
            (Array(a), Array(b)) => a == b,
            (Tuple(a), Tuple(b)) => a == b,
            (OpCall(a), OpCall(b)) => a == b,
            (NativeObject(a), NativeObject(b)) => Rc::ptr_eq(a, b),
            (Null, Null) => true,
            _ => false,
        }
    }
}

#[allow(dead_code)]
impl<'a> Value<'a> {
    fn as_vec(&self) -> &Vec<Value<'a>> {
        match self {
            Self::Array(a) => &a,
            Self::Tuple(a) => &a,
            _ => panic!("as_vec: type mismatch, possible bug in parse"),
        }
    }
    fn as_str(&self) -> &str {
        match self {
            Self::String(a) => &a,
            Self::Identifier(a) => &a,
            _ => panic!("as_str: type mismatch, possible bug in parse"),
        }
    }
    fn as_i64(&self) -> i64 {
        match self {
            Self::Integer(a) => *a,
            _ => panic!("as_i64: type mismatch"),
        }
    }

    pub fn type_of<'b>(&self, ctx: &'b ScriptContext<'b>) -> Result<Type, Error>
    where
        'a: 'b,
    {
        use Value::*;
        match self {
            Null => Ok(Type::Null),
            String(_) => Ok(Type::String),
            Boolean(_) => Ok(Type::Boolean),
            Integer(_) => Ok(Type::Integer),
            Identifier(id) => ctx.lookup(id).and_then(|x| x.type_of(ctx)),
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
            NativeObject(o) => o
                .as_evaluatable()
                .map_or_else(|| Ok(Type::NativeObject), |x| x.type_of(ctx)),
        }
    }

    pub fn value_of<'b>(&self, ctx: &'b ScriptContext<'b>) -> Result<Value<'b>, Error>
    where
        'a: 'b,
    {
        match self {
            Self::Identifier(id) => ctx.lookup(id),
            Self::OpCall(f) => f.call(ctx),
            Self::NativeObject(f) => {
                let e = f.as_evaluatable();
                if e.is_some() {
                    e.unwrap().value_of(ctx)
                } else {
                    // Ok(self.clone())
                    todo!()
                }
            }
            _ => todo!(), //Ok(self.clone()),
        }
    }
}

macro_rules! cast_value {
    ($ty:ty, $name:ident) => {
        cast_value!($ty, $name, 'a, v, v, v);
    };
    ($ty:ty, $name:ident, $a:lifetime, boxed) => {
        cast_value!($ty, $name, $a, v, *v, Box::new(v));
    };
    ($ty:ty, $name:ident, boxed) => {
        cast_value!($ty, $name, 'a, v, *v, Box::new(v));
    };
    ($ty:ty, $name:ident, $a:lifetime, $v: ident, $from:expr, $to:expr) => {
        impl<$a> TryFrom<Value<$a>> for $ty {
            type Error = easy_error::Error;
            fn try_from(x: Value<$a>) -> Result<$ty, Self::Error> {
                if let Value::$name($v) = x {
                    Ok($from)
                } else {
                    easy_error::bail!("unable to cast {:?} into {}", x, stringify!($ty))
                }
            }
        }

        impl<$a> From<$ty> for Value<$a> {
            fn from($v: $ty) -> Self {
                Self::$name($to)
            }
        }
    };
}

cast_value!(String, String);
cast_value!(i64, Integer);
cast_value!(bool, Boolean);
cast_value!(Vec<Value<'a>>, Array, 'a, boxed);
cast_value!(Call<'a>, OpCall, 'a, boxed);

impl From<&str> for Value<'_> {
    fn from(x: &str) -> Self {
        Self::String(x.into())
    }
}

impl<'a, T> From<T> for Value<'a>
where
    T: NativeObject<'a> + 'a,
{
    fn from(x: T) -> Self {
        Value::NativeObject(Rc::new(x))
    }
}

impl std::fmt::Display for Value<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Value::*;
        match self {
            Null => write!(f, "null"),
            String(s) => write!(f, "{}", s),
            Integer(i) => write!(f, "{}", i),
            Boolean(b) => write!(f, "{}", b),
            Identifier(id) => write!(f, "<{}>", id),
            OpCall(x) => write!(f, "{:?}", x),
            Array(x) => write!(
                f,
                "[{}]",
                x.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Tuple(x) => write!(
                f,
                "({})",
                x.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            NativeObject(x) => write!(f, "{:?}", x),
            // _ => panic!("not implemented"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call<'a> {
    func: Value<'a>,
    args: Vec<Value<'a>>,
}

impl<'a> Call<'a> {
    pub fn new(mut args: Vec<Value<'a>>) -> Self {
        let func = args.remove(0);
        Self { func, args }
    }
    fn signature<'b>(&self, ctx: &'b ScriptContext<'b>) -> Result<Type, Error>
    where
        'a: 'b,
    {
        let func = self.func(ctx)?;
        let func = func.as_callable().unwrap();
        func.signature(ctx, &self.args)
    }
    fn call<'b>(&self, ctx: &'b ScriptContext<'b>) -> Result<Value<'b>, Error>
    where
        'a: 'b,
    {
        let func = self.func(ctx)?;
        let func = func.as_callable().unwrap();
        func.call(ctx, &self.args)
    }
    fn func<'b>(&self, ctx: &'b ScriptContext<'b>) -> Result<Rc<dyn NativeObject<'b>>, Error>
    where
        'a: 'b,
    {
        let func = if let Value::Identifier(_) = &self.func {
            self.func.value_of(ctx)?
        } else {
            self.func.clone()
        };
        if let Value::NativeObject(x) = func {
            if x.as_callable().is_some() {
                Ok(x)
            } else {
                Err(err_msg("NativeObject does not implement Callable"))
            }
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

    #[test]
    fn ctx_chain() {
        let ctx = &Default::default();
        let mut ctx2 = ScriptContext::new(Some(ctx));
        ctx2.set("a".into(), 1.into());
        let value = root::<nom::error::VerboseError<&str>>("a+1")
            .unwrap()
            .1
            .value_of(&ctx2)
            .unwrap();
        assert_eq!(value, 2.into());
    }

    #[test]
    fn scope() {
        type_test("let a=1;b=2 in a+b", Type::Integer);
        eval_test("let a=1;b=2 in a+b", 3.into());
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
        let value = root::<nom::error::VerboseError<&str>>(input).unwrap().1;
        let value = value.type_of(ctx).unwrap();
        assert_eq!(value, output);
    }
}
