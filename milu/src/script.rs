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
    NativeObject,
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
    fn type_of<'b>(&self, ctx: ScriptContextRef<'b>) -> Result<Type, Error>
    where
        'a: 'b;
    fn value_of<'b>(&self, ctx: ScriptContextRef<'b>) -> Result<Value<'b>, Error>
    where
        'a: 'b;
}

pub trait Indexable<'a> {
    fn length(&self) -> usize;
    fn type_of<'b>(&self, ctx: ScriptContextRef<'b>) -> Result<Type, Error>
    where
        'a: 'b;
    fn get(&self, index: i64) -> Result<Value<'a>, Error>;
}

pub trait Accessible<'a> {
    fn names(&self) -> Vec<&str>;
    fn type_of<'b>(&self, name: &str, ctx: ScriptContextRef<'b>) -> Result<Type, Error>
    where
        'a: 'b;
    fn get(&self, name: &str) -> Result<Value<'a>, Error>;
}

pub trait Callable {
    // should not return Any
    fn signature<'a: 'b, 'b>(
        &self,
        ctx: ScriptContextRef<'b>,
        args: &[Value<'a>],
    ) -> Result<Type, Error>;
    fn call<'a: 'b, 'b>(
        &self,
        ctx: ScriptContextRef<'b>,
        args: &[Value<'a>],
    ) -> Result<Value<'b>, Error>;
    fn unresovled_ids<'a, 'b>(&self, args: &'a [Value<'b>], ids: &mut HashSet<&'a Value<'b>>) {
        args.iter().for_each(|v| v.unresovled_ids(ids))
    }
}

impl<'a> Accessible<'a> for HashMap<String, Value<'a>> {
    fn names(&self) -> Vec<&str> {
        self.keys().map(String::as_str).collect()
    }

    fn type_of<'b>(&self, name: &str, ctx: ScriptContextRef<'b>) -> Result<Type, Error>
    where
        'a: 'b,
    {
        Accessible::get(self, name).and_then(|x| x.type_of(ctx))
    }

    fn get(&self, name: &str) -> Result<Value<'a>, Error> {
        self.get(name)
            .cloned()
            .ok_or_else(|| err_msg(format!("undefined: {}", name)))
    }
}

impl<'a> Indexable<'a> for Vec<Value<'a>> {
    fn length(&self) -> usize {
        self.len()
    }

    fn type_of<'b>(&self, ctx: ScriptContextRef<'b>) -> Result<Type, Error>
    where
        'a: 'b,
    {
        Indexable::get(self, 0).and_then(|x| x.type_of(ctx))
    }

    fn get(&self, index: i64) -> Result<Value<'a>, Error> {
        let index: Result<usize, std::num::TryFromIntError> = if index >= 0 {
            index.try_into()
        } else {
            (-index).try_into().map(|i: usize| self.len() - i)
        };
        let i: usize = index.context("failed to cast index from i64")?;
        if i >= self.len() {
            bail!("index out of bounds: {}", i)
        }
        Ok(self[i].unsafe_clone())
    }
}

pub trait NativeObjectHash {
    fn gen_hash(&self) -> u64;
    fn hash_with_state(&self, st: &mut dyn std::hash::Hasher);
}

impl<'a, T> NativeObjectHash for T
where
    T: std::hash::Hash + ?Sized + NativeObject<'a>,
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

pub trait NativeObject<'a>: std::fmt::Debug + NativeObjectHash {
    fn as_evaluatable(&self) -> Option<&dyn Evaluatable<'a>> {
        None
    }
    fn as_accessible(&self) -> Option<&dyn Accessible<'a>> {
        None
    }
    fn as_indexable(&self) -> Option<&dyn Indexable<'a>> {
        None
    }
    fn as_callable(&self) -> Option<&dyn Callable> {
        None
    }
}

type NativeObjectRef<'a> = Box<dyn NativeObject<'a> + Send + Sync + 'a>;
impl<'a> Eq for NativeObjectRef<'a> {}
impl<'a> PartialEq for NativeObjectRef<'a> {
    fn eq(&self, other: &NativeObjectRef<'a>) -> bool {
        // println!("self={:?} hash={}", self, self.hash());
        // println!("other={:?} hash={}", other, other.hash());
        self.gen_hash() == other.gen_hash()
    }
}

impl<'a> std::hash::Hash for NativeObjectRef<'a> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash_with_state(state)
    }
}

pub struct ScriptContext<'a> {
    parent: Option<ScriptContextRef<'a>>,
    varibles: HashMap<String, Value<'a>>,
}

pub type ScriptContextRef<'a> = Arc<ScriptContext<'a>>;

impl<'a> ScriptContext<'a> {
    pub fn new<'b>(parent: Option<ScriptContextRef<'b>>) -> Self
    where
        'b: 'a,
    {
        let parent = unsafe { std::mem::transmute(parent) };
        Self {
            parent,
            varibles: Default::default(),
        }
    }
    pub fn lookup(&self, id: &str) -> Result<Value<'a>, Error> {
        if let Some(r) = self.varibles.get(id) {
            log::trace!("lookup({})={}", id, r);
            Ok(r.clone())
        } else if let Some(p) = &self.parent {
            p.lookup(id)
        } else {
            bail!("\"{}\" is undefined", id)
        }
    }
    pub fn set(&mut self, id: String, value: Value<'a>) {
        self.varibles.insert(id, value);
    }
}

impl Default for ScriptContext<'_> {
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
pub enum Value<'a> {
    Null,
    Integer(i64),
    Boolean(bool),
    String(String),
    Identifier(String),
    Array(Arc<Vec<Value<'a>>>),
    Tuple(Arc<Vec<Value<'a>>>),
    OpCall(Arc<Call<'a>>),
    NativeObject(Arc<NativeObjectRef<'a>>),
}

impl<'a> Value<'a> {
    fn unsafe_clone<'b>(&self) -> Value<'b>
    where
        'a: 'b,
    {
        unsafe { std::mem::transmute(self.clone()) }
    }
    fn as_vec(&self) -> &Vec<Value<'a>> {
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
    fn unresovled_ids<'b>(&'b self, ids: &mut HashSet<&'b Value<'a>>)
    where
        'a: 'b,
    {
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

impl<'a> Evaluatable<'a> for Value<'a> {
    fn type_of<'b>(&self, ctx: ScriptContextRef<'b>) -> Result<Type, Error>
    where
        'a: 'b,
    {
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
            NativeObject(o) => o
                .as_evaluatable()
                .map_or_else(|| Ok(Type::NativeObject), |x| x.type_of(ctx)),
        }
    }

    fn value_of<'b>(&self, ctx: ScriptContextRef<'b>) -> Result<Value<'b>, Error>
    where
        'a: 'b,
    {
        log::trace!("value_of={}", self);
        match self {
            Self::Identifier(id) => ctx.lookup(id).and_then(|x| x.value_of(ctx)),
            Self::OpCall(f) => f.call(ctx),
            Self::NativeObject(f) => {
                let e = f.as_evaluatable();
                if let Some(e) = e {
                    e.value_of(ctx)
                } else {
                    Ok(self.unsafe_clone())
                }
            }
            _ => Ok(self.unsafe_clone()),
        }
    }
}

macro_rules! cast_value {
    ($ty:ty, $name:ident) => {
        cast_value_from!($ty, $name, 'a, |v| v);
        cast_value_to!($ty, $name, 'a, |v| v);
    };
    ($ty:ty as $tx:ty, $name:ident) => {
        cast_value_from!($ty, $name, 'a, |v| v as $tx);
        cast_value_to!($ty, $name, 'a, |v| v as $ty);
    };
    ($ty:ty, $name:ident <$a:lifetime> , boxed) => {
        cast_value_from!($ty, $name, $a, |v| Box::new(v));
        cast_value_to!($ty, $name, $a, |v| *v);
    };
    ($ty:ty, $name:ident <$a:lifetime> , arc) => {
        cast_value_from!($ty, $name, $a, |v| Arc::new(v));
        cast_value_to!(Arc<$ty>, $name, $a, |v| v);
    };
}
macro_rules! cast_value_to {
    ($ty:ty, $name:ident, $a:lifetime, | $v: ident | $transfrom:expr) => {
        impl<$a> TryFrom<Value<$a>> for $ty {
            type Error = easy_error::Error;
            fn try_from(x: Value<$a>) -> Result<$ty, Self::Error> {
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
    ($ty:ty, $name:ident, $a:lifetime, | $v: ident | $transfrom:expr) => {
        impl<$a> From<$ty> for Value<$a> {
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
cast_value!(Vec<Value<'a>>, Array<'a>, arc);
cast_value!(Call<'a>, OpCall<'a>, arc);

impl From<&str> for Value<'_> {
    fn from(x: &str) -> Self {
        Self::String(x.into())
    }
}

impl<'a, T> From<T> for Value<'a>
where
    T: NativeObject<'a> + Send + Sync + 'a,
{
    fn from(x: T) -> Self {
        Value::NativeObject(Arc::new(Box::new(x)))
    }
}

impl std::fmt::Display for Value<'_> {
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
pub struct Call<'a> {
    func: Value<'a>,
    args: Vec<Value<'a>>,
}
impl std::fmt::Display for Call<'_> {
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

impl<'a> Call<'a> {
    pub fn new(mut args: Vec<Value<'a>>) -> Self {
        let func = args.remove(0);
        Self { func, args }
    }
    fn signature<'b>(&self, ctx: ScriptContextRef<'b>) -> Result<Type, Error>
    where
        'a: 'b,
    {
        let func = self.func(ctx.clone())?;
        let func = func.as_callable().unwrap();
        func.signature(ctx, &self.args)
    }
    fn call<'b>(&self, ctx: ScriptContextRef<'b>) -> Result<Value<'b>, Error>
    where
        'a: 'b,
    {
        let func = self.func(ctx.clone())?;
        let func = func.as_callable().unwrap();
        func.call(ctx, &self.args)
    }
    fn func<'b>(&self, ctx: ScriptContextRef<'b>) -> Result<Arc<NativeObjectRef<'b>>, Error>
    where
        'a: 'b,
    {
        let func = if let Value::Identifier(_) = &self.func {
            self.func.value_of(ctx)?
        } else {
            self.func.unsafe_clone()
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
    fn unresovled_ids<'b>(&'b self, list: &mut HashSet<&'b Value<'a>>) {
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
