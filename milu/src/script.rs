use easy_error::{bail, err_msg, Error, ResultExt};
use std::{
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    fmt::Display,
    sync::Arc,
};
pub mod stdlib;

#[derive(Debug, Eq, Clone)]
pub enum Type {
    String,
    Integer,
    Boolean,
    Array(Box<Type>),
    Tuple(Vec<Type>),
    NativeObject(Arc<NativeObjectRef>),
    Null,
    Any, //native only
}

impl Type {
    pub fn array_of(t: Self) -> Self {
        Self::Array(Box::new(t))
    }
    pub fn tuple_of(t: Vec<Self>) -> Self {
        Self::Tuple(t)
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
            (NativeObject(a), NativeObject(b)) => a == b,
            (Null, Null) => true,
            _ => false,
        }
    }
}

impl Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String => write!(f, "string"),
            Self::Integer => write!(f, "integer"),
            Self::Boolean => write!(f, "boolean"),
            Self::Array(a) => write!(f, "[{}]", a),
            Self::Tuple(t) => write!(
                f,
                "({})",
                t.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Self::NativeObject(x) => write!(f, "native@{:x}", x.gen_hash()),
            Self::Null => write!(f, "null"),
            Self::Any => write!(f, "any"),
        }
    }
}

pub trait Evaluatable {
    fn type_of(&self, ctx: ScriptContextRef) -> Result<Type, Error>;
    fn value_of(&self, ctx: ScriptContextRef) -> Result<Value, Error>;
}

pub trait Indexable {
    fn length(&self) -> usize;
    fn type_of(&self, ctx: ScriptContextRef) -> Result<Type, Error>;
    fn get(&self, index: i64) -> Result<Value, Error>;
}

pub trait Accessible {
    fn names(&self) -> Vec<&str>;
    fn type_of(&self, name: &str, ctx: ScriptContextRef) -> Result<Type, Error>;
    fn get(&self, name: &str) -> Result<Value, Error>;
}

pub trait Callable {
    // should not return Any
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error>;
    fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error>;
    fn unresovled_ids<'s: 'o, 'o>(&self, args: &'s [Value], ids: &mut HashSet<&'o Value>) {
        args.iter().for_each(|v| v.unresovled_ids(ids))
    }
}

impl Accessible for HashMap<String, Value> {
    fn names(&self) -> Vec<&str> {
        self.keys().map(String::as_str).collect()
    }

    fn type_of(&self, name: &str, ctx: ScriptContextRef) -> Result<Type, Error> {
        Accessible::get(self, name).and_then(|x| x.type_of(ctx))
    }

    fn get(&self, name: &str) -> Result<Value, Error> {
        self.get(name)
            .cloned()
            .ok_or_else(|| err_msg(format!("undefined: {}", name)))
    }
}

impl Indexable for Vec<Value> {
    fn length(&self) -> usize {
        self.len()
    }

    fn type_of(&self, ctx: ScriptContextRef) -> Result<Type, Error> {
        Indexable::get(self, 0).and_then(|x| x.type_of(ctx))
    }

    fn get(&self, index: i64) -> Result<Value, Error> {
        let index: Result<usize, std::num::TryFromIntError> = if index >= 0 {
            index.try_into()
        } else {
            (-index).try_into().map(|i: usize| self.len() - i)
        };
        let i: usize = index.context("failed to cast index from i64")?;
        if i >= self.len() {
            bail!("index out of bounds: {}", i)
        }
        Ok(self[i].clone())
    }
}

pub trait NativeObjectHash {
    fn gen_hash(&self) -> u64;
    fn hash_with_state(&self, st: &mut dyn std::hash::Hasher);
}

impl<T> NativeObjectHash for T
where
    T: std::hash::Hash + ?Sized + NativeObject,
{
    fn gen_hash(&self) -> u64 {
        use std::hash::Hasher;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
    fn hash_with_state(&self, mut st: &mut dyn std::hash::Hasher) {
        self.hash(&mut st);
    }
}

pub trait NativeObject: std::fmt::Debug + NativeObjectHash {
    fn as_evaluatable(&self) -> Option<&dyn Evaluatable> {
        None
    }
    fn as_accessible(&self) -> Option<&dyn Accessible> {
        None
    }
    fn as_indexable(&self) -> Option<&dyn Indexable> {
        None
    }
    fn as_callable(&self) -> Option<&dyn Callable> {
        None
    }
}

type NativeObjectRef = Box<dyn NativeObject + Send + Sync>;
impl Eq for NativeObjectRef {}
impl PartialEq for NativeObjectRef {
    fn eq(&self, other: &NativeObjectRef) -> bool {
        // println!("self={:?} hash={}", self, self.hash());
        // println!("other={:?} hash={}", other, other.hash());
        self.gen_hash() == other.gen_hash()
    }
}

impl std::hash::Hash for NativeObjectRef {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash_with_state(state)
    }
}

pub struct ScriptContext {
    parent: Option<ScriptContextRef>,
    varibles: HashMap<String, Value>,
}

pub type ScriptContextRef = Arc<ScriptContext>;

impl ScriptContext {
    pub fn new(parent: Option<ScriptContextRef>) -> Self {
        let parent = unsafe { std::mem::transmute(parent) };
        Self {
            parent,
            varibles: Default::default(),
        }
    }
    pub fn lookup(&self, id: &str) -> Result<Value, Error> {
        if let Some(r) = self.varibles.get(id) {
            log::trace!("lookup({})={}", id, r);
            Ok(r.clone())
        } else if let Some(p) = &self.parent {
            p.lookup(id)
        } else {
            bail!("\"{}\" is undefined", id)
        }
    }
    pub fn set(&mut self, id: String, value: Value) {
        self.varibles.insert(id, value);
    }
}

impl Default for ScriptContext {
    fn default() -> Self {
        let mut varibles = HashMap::default();
        varibles.insert("to_string".to_string(), stdlib::ToString::stub().into());
        varibles.insert("to_integer".to_string(), stdlib::ToInteger::stub().into());
        varibles.insert("split".to_string(), stdlib::Split::stub().into());
        Self {
            parent: None,
            varibles,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum Value {
    Null,
    Integer(i64),
    Boolean(bool),
    String(String),
    Identifier(String),
    Array(Arc<Vec<Value>>),
    Tuple(Arc<Vec<Value>>),
    OpCall(Arc<Call>),
    NativeObject(Arc<NativeObjectRef>),
}

impl Value {
    // fn unsafe_clone(&self) -> Value {
    //     unsafe { std::mem::transmute(self.clone()) }
    // }
    fn as_vec(&self) -> &Vec<Value> {
        match self {
            Self::Array(a) => a,
            Self::Tuple(a) => a,
            _ => panic!("as_vec: type mismatch, possible bug in parse"),
        }
    }
    fn as_str(&self) -> &str {
        match self {
            Self::String(a) => a,
            Self::Identifier(a) => a,
            _ => panic!("as_str: type mismatch, possible bug in parse"),
        }
    }
    #[allow(dead_code)]
    fn as_i64(&self) -> i64 {
        match self {
            Self::Integer(a) => *a,
            _ => panic!("as_i64: type mismatch, possible bug in parse"),
        }
    }
    fn unresovled_ids<'s: 'o, 'o>(&'s self, ids: &mut HashSet<&'o Value>) {
        match self {
            Self::Identifier(_) => {
                ids.insert(self);
            }
            Self::Array(a) => a.iter().for_each(|v| v.unresovled_ids(ids)),
            Self::Tuple(a) => a.iter().for_each(|v| v.unresovled_ids(ids)),
            Self::OpCall(a) => a.unresovled_ids(ids),
            _ => (),
        }
    }

    /// Returns `true` if the value is [`Identifier`].
    ///
    /// [`Identifier`]: Value::Identifier
    pub fn is_identifier(&self) -> bool {
        matches!(self, Self::Identifier(..))
    }
}

impl Evaluatable for Value {
    fn type_of(&self, ctx: ScriptContextRef) -> Result<Type, Error> {
        log::trace!("type_of={}", self);
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
                    let t = a[0].type_of(ctx.clone())?;
                    a.iter().try_for_each(|x| {
                        let xt = x.type_of(ctx.clone())?;
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
                    ret.push(x.type_of(ctx.clone())?)
                }
                Ok(Type::Tuple(ret))
            }
            NativeObject(o) => Ok(Type::NativeObject(o.clone())),
        }
    }

    fn value_of(&self, ctx: ScriptContextRef) -> Result<Value, Error> {
        log::trace!("value_of={}", self);
        match self {
            Self::Identifier(id) => ctx.lookup(id).and_then(|x| x.value_of(ctx)),
            Self::OpCall(f) => f.call(ctx),
            Self::NativeObject(f) => {
                let e = f.as_evaluatable();
                if let Some(e) = e {
                    e.value_of(ctx)
                } else {
                    Ok(self.clone())
                }
            }
            _ => Ok(self.clone()),
        }
    }
}

macro_rules! cast_value {
    ($ty:ty, $name:ident) => {
        cast_value_from!($ty, $name, |v| v);
        cast_value_to!($ty, $name, |v| v);
    };
    ($ty:ty as $tx:ty, $name:ident) => {
        cast_value_from!($ty, $name, |v| v as $tx);
        cast_value_to!($ty, $name, |v| v as $ty);
    };
    ($ty:ty, $name:ident, boxed) => {
        cast_value_from!($ty, $name, |v| Box::new(v));
        cast_value_to!($ty, $name, |v| *v);
    };
    ($ty:ty, $name:ident, arc) => {
        cast_value_from!($ty, $name, |v| Arc::new(v));
        cast_value_to!(Arc<$ty>, $name, |v| v);
    };
}
macro_rules! cast_value_to {
    ($ty:ty, $name:ident, | $v: ident | $transfrom:expr) => {
        impl TryFrom<Value> for $ty {
            type Error = easy_error::Error;
            fn try_from(x: Value) -> Result<$ty, Self::Error> {
                if let Value::$name($v) = x {
                    Ok($transfrom)
                } else {
                    easy_error::bail!("unable to cast {:?} into {}", x, stringify!($ty))
                }
            }
        }
    };
}
macro_rules! cast_value_from {
    ($ty:ty, $name:ident, | $v: ident | $transfrom:expr) => {
        impl From<$ty> for Value {
            fn from($v: $ty) -> Self {
                Self::$name($transfrom)
            }
        }
    };
}

cast_value!(String, String);
cast_value!(i64, Integer);
cast_value!(i32 as i64, Integer);
cast_value!(i16 as i64, Integer);
cast_value!(i8 as i64, Integer);
cast_value!(u32 as i64, Integer);
cast_value!(u16 as i64, Integer);
cast_value!(u8 as i64, Integer);
cast_value!(bool, Boolean);
cast_value!(Vec<Value>, Array, arc);
cast_value!(Call, OpCall, arc);

impl From<&str> for Value {
    fn from(x: &str) -> Self {
        Self::String(x.into())
    }
}

impl<T> From<T> for Value
where
    T: NativeObject + Send + Sync + 'static,
{
    fn from(x: T) -> Self {
        Value::NativeObject(Arc::new(Box::new(x)))
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Value::*;
        match self {
            Null => write!(f, "null"),
            String(s) => write!(f, "{:?}", s),
            Integer(i) => write!(f, "{}", i),
            Boolean(b) => write!(f, "{}", b),
            Identifier(id) => write!(f, "<{}>", id),
            OpCall(x) => write!(f, "{}", x),
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Call {
    func: Value,
    args: Vec<Value>,
}
impl std::fmt::Display for Call {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}({})",
            self.func,
            self.args
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

impl Call {
    pub fn new(mut args: Vec<Value>) -> Self {
        let func = args.remove(0);
        Self { func, args }
    }
    fn signature(&self, ctx: ScriptContextRef) -> Result<Type, Error> {
        let func = self.func(ctx.clone())?;
        let func = func.as_callable().unwrap();
        func.signature(ctx, &self.args)
    }
    fn call(&self, ctx: ScriptContextRef) -> Result<Value, Error> {
        let func = self.func(ctx.clone())?;
        let func = func.as_callable().unwrap();
        func.call(ctx, &self.args)
    }
    fn func(&self, ctx: ScriptContextRef) -> Result<Arc<NativeObjectRef>, Error> {
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
    fn unresovled_ids<'s: 'o, 'o>(&'s self, list: &mut HashSet<&'o Value>) {
        if self.func.is_identifier() {
            list.insert(&self.func);
        } else if let Value::NativeObject(x) = &self.func {
            if let Some(c) = x.as_callable() {
                c.unresovled_ids(&self.args, list)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::parser::parse;
    use super::*;
    macro_rules! eval_test {
        ($input: expr, $output: expr) => {{
            let ctx = Default::default();
            let value = parse($input).unwrap();
            println!("ast={}", value);
            let value = value.value_of(ctx).unwrap();
            assert_eq!(value, $output);
        }};
    }

    fn type_test(input: &str, output: Type) {
        let ctx = Default::default();
        let value = parse(input).unwrap();
        let value = value.type_of(ctx).unwrap();
        assert_eq!(value, output);
    }

    #[test]
    fn one_plus_one() {
        type_test("1+1", Type::Integer);
        eval_test!("1+1", 2.into());
    }

    #[test]
    fn to_string() {
        type_test("to_string(100*2)", Type::String);
        eval_test!("to_string(100*2)", "200".into())
    }

    #[test]
    fn unresovled_ids() {
        let value = parse("let a=1;b=2 in a+b").unwrap();
        let mut unresovled_ids = HashSet::new();
        value.unresovled_ids(&mut unresovled_ids);
        assert!(unresovled_ids.is_empty());

        let value = parse("let a=1;b=a+1 in a+b+c").unwrap();
        let mut unresovled_ids = HashSet::new();
        value.unresovled_ids(&mut unresovled_ids);
        assert!(unresovled_ids.contains(&Value::Identifier("a".into())));
        assert!(unresovled_ids.contains(&Value::Identifier("c".into())))
    }

    #[test]
    fn arrays() {
        type_test("[1,2,3]", Type::array_of(Type::Integer));
        eval_test!(
            "[if 1>2||1==1 then 1*1 else 99,2*2,3*3,to_integer(\"4\")][0]",
            1.into()
        )
    }

    #[test]
    fn array_type() {
        let input = "[1,\"true\",false]";
        let ctx = Default::default();
        let value = parse(input).unwrap().type_of(ctx);
        println!("t={:?}", value);
        assert!(value.is_err());
    }

    #[test]
    fn ctx_chain() {
        let ctx = Default::default();
        let mut ctx2 = ScriptContext::new(Some(ctx));
        ctx2.set("a".into(), 1.into());
        let value = parse("a+1").unwrap().value_of(ctx2.into()).unwrap();
        assert_eq!(value, 2.into());
    }

    #[test]
    fn scope() {
        type_test("let a=1;b=2 in a+b", Type::Integer);
        eval_test!("let a=1;b=2 in a+b", 3.into());
    }

    #[test]
    fn access_tuple() {
        type_test("(1,\"2\",false).1", Type::String);
        eval_test!("(1,\"2\",false).1", "2".into());
    }
}
