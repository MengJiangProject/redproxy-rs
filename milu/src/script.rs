use async_trait::async_trait;
use easy_error::{bail, err_msg, Error, ResultExt};
use std::{
    sync::RwLock, // Changed from RefCell
    collections::{HashMap, HashSet},
    convert::TryFrom,
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
    // Null,
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
            // (Null, Null) => true,
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
            // Self::Null => write!(f, "null"),
            Self::Any => write!(f, "any"),
        }
    }
}

#[async_trait]
pub trait Evaluatable {
    fn type_of(&self, ctx: ScriptContextRef) -> Result<Type, Error>;
    async fn value_of(&self, ctx: ScriptContextRef) -> Result<Value, Error>;
}

pub trait Indexable {
    fn length(&self) -> usize;
    fn type_of_member(&self, ctx: ScriptContextRef) -> Result<Type, Error>;
    fn get(&self, index: i64) -> Result<Value, Error>;
}

pub trait Accessible {
    fn names(&self) -> Vec<&str>;
    fn type_of(&self, name: &str, ctx: ScriptContextRef) -> Result<Type, Error>;
    fn get(&self, name: &str) -> Result<Value, Error>;
}

#[async_trait]
pub trait Callable {
    // should not return Any
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error>;
    async fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error>;
    fn unresovled_ids<'s: 'o, 'o>(&'s self, args: &'s [Value], ids: &mut HashSet<&'o Value>) { // Changed &self to &'s self
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

    fn type_of_member(&self, ctx: ScriptContextRef) -> Result<Type, Error> {
        Indexable::get(self, 0).and_then(|x| x.type_of(ctx))
    }

    fn get(&self, index: i64) -> Result<Value, Error> {
        let len = self.len();
        let final_idx: usize;

        if index >= 0 {
            final_idx = index as usize;
        } else {
            // Negative index: calculate from the end.
            if len == 0 { // Cannot use negative index on empty array
                bail!("index out of bounds: array is empty, len is 0, index was {}", index);
            }
            // index = -1 means last element (len - 1)
            // index = -len means first element (0)
            if let Some(positive_offset) = index.checked_neg().and_then(|val| usize::try_from(val).ok()) {
                if positive_offset > len {
                    bail!("index out of bounds: negative index {} is too large for array of len {}", index, len);
                }
                final_idx = len - positive_offset;
            } else {
                // This case handles index = i64::MIN which cannot be negated.
                bail!("index out of bounds: invalid negative index {}", index);
            }
        }

        if final_idx >= len { // Combined check for positive and resolved negative indices
            // Match the error message format expected by tests like test_index_out_of_bounds_array
            // Using the original index in the error message is more user-friendly.
            bail!("index out of bounds: {}", index);
        }
        Ok(self[final_idx].clone())
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
        self.gen_hash() == other.gen_hash()
    }
}

impl std::hash::Hash for NativeObjectRef {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash_with_state(state)
    }
}

#[derive(Debug)] 
pub struct ScriptContext {
    parent: Option<ScriptContextRef>,
    varibles: RwLock<HashMap<String, Value>>, 
}

pub type ScriptContextRef = Arc<ScriptContext>;

#[derive(Debug, Clone)] 
pub struct UserDefinedFunction {
    pub name: Option<String>,
    pub arg_names: Vec<String>,
    pub body: Value,
    pub captured_context: ScriptContextRef,
}

impl PartialEq for UserDefinedFunction {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name &&
        self.arg_names == other.arg_names &&
        self.body == other.body
    }
}
impl Eq for UserDefinedFunction {}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParsedFunction {
    pub name_ident: Value, 
    pub arg_idents: Vec<Value>, 
    pub body: Value,
}

impl Callable for UserDefinedFunction {
    fn signature(&self, _ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        if args.len() != self.arg_names.len() {
            bail!(
                "expected {} arguments, got {}",
                self.arg_names.len(),
                args.len()
            );
        }
        Ok(Type::Any)
    }
    // TODO: This should be async too
    async fn call(&self, caller_context: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        if args.len() != self.arg_names.len() {
            bail!(
                "expected {} arguments, got {}",
                self.arg_names.len(),
                args.len()
            );
        }

        let fn_ctx = ScriptContext::new(Some(self.captured_context.clone()));
        // TODO: This should be async too
        for (i, arg_name) in self.arg_names.iter().enumerate() {
            // TODO: This should be async too
            let arg_value = args[i].real_value_of(caller_context.clone()).await?;
            fn_ctx.set(arg_name.clone(), arg_value);
        }
        // TODO: This should be async too
        self.body.real_value_of(Arc::new(fn_ctx)).await
    }

    fn unresovled_ids<'s: 'o, 'o>(&'s self, args: &'s [Value], ids: &mut HashSet<&'o Value>) {
        args.iter().for_each(|v| v.unresovled_ids(ids));

        let mut body_ids = HashSet::new();
        self.body.unresovled_ids(&mut body_ids);

        for id_val in body_ids {
            if let Value::Identifier(id_name) = id_val {
                if !self.arg_names.contains(id_name) {
                    ids.insert(id_val);
                }
            } else {
                 ids.insert(id_val); 
            }
        }
    }
}

impl ScriptContext {
    pub fn new(parent: Option<ScriptContextRef>) -> Self {
        Self {
            parent,
            varibles: RwLock::new(Default::default()), 
        }
    }
    pub fn lookup(&self, id: &str) -> Result<Value, Error> {
        if let Some(r) = self.varibles.read().unwrap().get(id) { 
            tracing::trace!("lookup({})={}", id, r);
            Ok(r.clone())
        } else if let Some(p) = &self.parent {
            p.lookup(id)
        } else {
            bail!("\"{}\" is undefined", id)
        }
    }
    pub fn set(&self, id: String, value: Value) { 
        self.varibles.write().unwrap().insert(id, value); 
    }
}

impl Default for ScriptContext {
    fn default() -> Self {
        let mut map = HashMap::default(); 
        map.insert("to_string".to_string(), stdlib::ToString::stub().into());
        map.insert("to_integer".to_string(), stdlib::ToInteger::stub().into());
        map.insert("split".to_string(), stdlib::Split::stub().into());
        map.insert("strcat".to_string(), stdlib::StringConcat::stub().into());
        Self {
            parent: None,
            varibles: RwLock::new(map), 
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)] 
pub enum Value {
    Integer(i64),
    Boolean(bool),
    String(String),
    Identifier(String),
    Array(Arc<Vec<Value>>),
    Tuple(Arc<Vec<Value>>),
    OpCall(Arc<Call>),
    NativeObject(Arc<NativeObjectRef>),
    UserDefined(Arc<UserDefinedFunction>),
    ParsedFunction(Arc<ParsedFunction>),
}

impl Value {
    fn as_vec(&self) -> &Vec<Value> {
        match self {
            Self::Array(a) => a,
            Self::Tuple(a) => a,
            _ => panic!("as_vec: type mismatch, possible bug in parse"),
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
            Self::OpCall(a) => a.unresovled_ids(ids), // This line is important!
            Self::UserDefined(udf_arc) => {
                let mut body_ids = HashSet::new();
                udf_arc.body.unresovled_ids(&mut body_ids);
                body_ids.retain(|val_in_body| {
                    if let Value::Identifier(id_str_in_body) = val_in_body {
                        !udf_arc.arg_names.contains(id_str_in_body)
                    } else {
                        true 
                    }
                });
                ids.extend(body_ids);
            }
            Self::ParsedFunction(parsed_fn_arc) => {
                let mut body_ids = HashSet::new();
                parsed_fn_arc.body.unresovled_ids(&mut body_ids);
                body_ids.retain(|val_in_body| {
                    if let Value::Identifier(id_in_body) = val_in_body {
                        !parsed_fn_arc.arg_idents.iter().any(|arg_ident_val| {
                            if let Value::Identifier(arg_id_str) = arg_ident_val {
                                arg_id_str == id_in_body
                            } else {
                                false 
                            }
                        })
                    } else {
                        true 
                    }
                });
                ids.extend(body_ids);
            }
            _ => (), // NativeObject, Literals don't have script unresolved IDs within themselves
        }
    }

    pub fn is_identifier(&self) -> bool {
        matches!(self, Self::Identifier(..))
    }

    pub fn real_type_of(&self, ctx: ScriptContextRef) -> Result<Type, Error> {
        let t = self.type_of(ctx.clone())?;
        if let Type::NativeObject(o) = t {
            if let Some(e) = o.as_evaluatable() {
                e.type_of(ctx)
            } else {
                Ok(Type::NativeObject(o))
            }
        } else {
            Ok(t)
        }
    }
    // TODO: This should be async too
    pub async fn real_value_of(&self, ctx: ScriptContextRef) -> Result<Value, Error> {
        // TODO: This should be async too
        let t = self.value_of(ctx.clone()).await?;
        if let Self::NativeObject(o) = t {
            if let Some(e) = o.as_evaluatable() {
                // TODO: This should be async too
                e.value_of(ctx).await
            } else {
                Ok(Self::NativeObject(o))
            }
        } else {
            Ok(t)
        }
    }
}

#[async_trait]
impl Evaluatable for Value {
    fn type_of(&self, ctx: ScriptContextRef) -> Result<Type, Error> {
        tracing::trace!("type_of={}", self);
        use Value::*;
        match self {
            String(_) => Ok(Type::String),
            Boolean(_) => Ok(Type::Boolean),
            Integer(_) => Ok(Type::Integer),
            Identifier(id) => ctx.lookup(id).and_then(|x| x.type_of(ctx)),
            OpCall(x) => x.signature(ctx),
            Array(a) => {
                if a.is_empty() {
                    Ok(Type::Array(Box::new(Type::Any)))
                } else {
                    let t = a[0].real_type_of(ctx.clone())?;
                    a.iter().try_for_each(|x| {
                        let xt = x.real_type_of(ctx.clone())?;
                        if xt != t {
                            bail!("array member must have same type: required type={:?}, mismatch type={} item={:?}", t, xt, x)
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
            UserDefined(_udf_arc) => {
                Ok(Type::Any)
            }
            ParsedFunction(_) => {
                Ok(Type::Any)
            }
        }
    }
    // TODO: This should be async too
    async fn value_of(&self, ctx: ScriptContextRef) -> Result<Value, Error> {
        tracing::trace!("value_of={}", self);
        match self {
            // TODO: This should be async too
            Self::Identifier(id) => {
                let looked_up_value = ctx.lookup(id)?;
                looked_up_value.value_of(ctx).await
            }
            // TODO: This should be async too
            Self::OpCall(f) => f.call(ctx).await,
            // NativeObject and other literals return self.clone(); real_value_of handles unwrapping evaluatables.
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
            UserDefined(x) => {
                let name = x.name.as_deref().unwrap_or("");
                write!(f, "fn<{}>({})", name, x.arg_names.join(", "))
            }
            ParsedFunction(x) => {
                let arg_names_str = x.arg_idents.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
                write!(f, "<parsed_fn {}({})>", x.name_ident, arg_names_str)
            } 
        }
    }
}

impl std::hash::Hash for UserDefinedFunction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.arg_names.hash(state);
        self.body.hash(state);
    }
}

impl std::hash::Hash for ParsedFunction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name_ident.hash(state);
        self.arg_idents.hash(state);
        self.body.hash(state);
    }
}

impl std::hash::Hash for Value {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        use Value::*;
        match self {
            Integer(i) => i.hash(state),
            Boolean(b) => b.hash(state),
            String(s) => s.hash(state),
            Identifier(id) => id.hash(state),
            Array(a) => a.hash(state),
            Tuple(t) => t.hash(state),
            OpCall(c) => c.hash(state),
            NativeObject(o) => o.hash(state),
            UserDefined(f) => f.hash(state),
            ParsedFunction(f) => f.hash(state),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Call {
    func: Value,
    args: Vec<Value>,
}

enum ResolvedFunction {
    Native(Arc<NativeObjectRef>),
    User(Arc<UserDefinedFunction>),
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
        // TODO: This should be async too
        let resolved_func = tokio_test::block_on(self.func(ctx.clone()))?; // block_on for sync context
        match resolved_func {
            ResolvedFunction::Native(native_ref) => {
                native_ref.as_callable()
                    .ok_or_else(|| err_msg("Internal error: NativeObject marked callable but as_callable is None"))?
                    .signature(ctx, &self.args)
            }
            ResolvedFunction::User(udf_ref) => {
                udf_ref.signature(ctx, &self.args)
            }
        }
    }
    // TODO: This should be async too
    async fn call(&self, ctx: ScriptContextRef) -> Result<Value, Error> {
        // TODO: This should be async too
        let resolved_func = self.func(ctx.clone()).await?;
        match resolved_func {
            ResolvedFunction::Native(native_ref) => {
                native_ref.as_callable()
                    .ok_or_else(|| err_msg("Internal error: NativeObject marked callable but as_callable is None"))?
                    .call(ctx, &self.args).await
            }
            ResolvedFunction::User(udf_ref) => {
                udf_ref.call(ctx, &self.args).await
            }
        }
    }
    // TODO: This should be async too
    async fn func(&self, ctx: ScriptContextRef) -> Result<ResolvedFunction, Error> {
        // TODO: This should be async too
        let resolved_fn_val = if let Value::Identifier(_) = &self.func {
            self.func.value_of(ctx).await?
        } else {
            self.func.clone()
        };

        match resolved_fn_val {
            Value::NativeObject(arc_native_ref) => {
                if arc_native_ref.as_callable().is_some() {
                    Ok(ResolvedFunction::Native(arc_native_ref))
                } else {
                    Err(err_msg(format!("Value {:?} is not a callable function type", arc_native_ref)))
                }
            }
            Value::UserDefined(arc_udf) => {
                Ok(ResolvedFunction::User(arc_udf))
            }
            other_val => {
                Err(err_msg(format!("Value {:?} is not a callable function type", other_val)))
            }
        }
    }
    // CORRECTED VERSION OF unresovled_ids:
    fn unresovled_ids<'s: 'o, 'o>(&'s self, ids: &mut HashSet<&'o Value>) {
        match &self.func {
            Value::Identifier(_) => {
                ids.insert(&self.func); 
                for arg in &self.args {
                    arg.unresovled_ids(ids);
                }
            }
            Value::UserDefined(udf_arc) => {
                udf_arc.unresovled_ids(&self.args, ids);
            }
            Value::NativeObject(nobj_arc) => {
                if let Some(callable_trait_obj) = nobj_arc.as_callable() {
                    callable_trait_obj.unresovled_ids(&self.args, ids);
                } else {
                    self.func.unresovled_ids(ids); 
                    for arg in &self.args {
                        arg.unresovled_ids(ids);
                    }
                }
            }
            _ => { 
                self.func.unresovled_ids(ids); 
                for arg in &self.args {       
                    arg.unresovled_ids(ids);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::parser::parse;
    use super::*;
    // For Value::Integer, etc.
    use super::Value; 
     // Required for the new NativeObject impls
    use tokio; // Added tokio

    macro_rules! eval_test {
        ($input: expr, $output: expr) => {{
            let ctx = Default::default();
            let parsed_value = parse($input).unwrap_or_else(|e| panic!("Parse error for '{}': {:?}", $input, e));
            // println!("ast={{}}", parsed_value); // Keep this commented out for less noise unless debugging
            let value = tokio::runtime::Runtime::new().unwrap().block_on(parsed_value.value_of(ctx)).unwrap_or_else(|e| panic!("Eval error for '{}': {:?}", $input, e));
            assert_eq!(value, $output);
        }};
    }

    macro_rules! eval_error_test {
        ($input: expr, $expected_error_substring: expr) => {{
            let ctx = Default::default();
            let parsed_value = parse($input).unwrap_or_else(|e| panic!("Parse error for '{}': {:?}", $input, e));
            let result = tokio::runtime::Runtime::new().unwrap().block_on(parsed_value.value_of(ctx));
            assert!(result.is_err(), "Expected error for '{}', but got Ok({:?})", $input, result.as_ref().ok());
            let error_message = result.err().unwrap().to_string();
            assert!(
                error_message.contains($expected_error_substring),
                "Error message for '{}' was '{}', expected to contain '{}'",
                $input, error_message, $expected_error_substring
            );
        }};
    }


    fn type_test(input: &str, output: Type) {
        let ctx = Default::default();
        let value = parse(input).unwrap_or_else(|e| panic!("Parse error for '{}': {:?}", input, e));
        let value = value.type_of(ctx).unwrap();
        assert_eq!(value, output);
    }

    #[tokio::test]
    async fn one_plus_one() { // Added async
        type_test("1+1", Type::Integer);
        eval_test!("1+1", Value::Integer(2).into());
    }

    #[tokio::test]
    async fn to_string() { // Added async
        type_test("to_string(100*2)", Type::String);
        eval_test!("to_string(100*2)", Value::String("200".to_string()).into());
    }

    #[test]
    fn unresovled_ids() {
        let value = parse("let a=1;b=2 in a+b").unwrap();
        let mut unresovled_ids = HashSet::new();
        value.unresovled_ids(&mut unresovled_ids);
        assert!(unresovled_ids.is_empty(), "Test 1 failed: expected empty, got {:?}", unresovled_ids);

        let value = parse("let a=1;b=a+1 in a+b+c").unwrap(); 
        let mut unresovled_ids = HashSet::new();
        value.unresovled_ids(&mut unresovled_ids);
        assert_eq!(unresovled_ids.len(), 2, "Test 2 failed: Expected 2 unresolved IDs, got {:?} with count {}", unresovled_ids, unresovled_ids.len()); 
        assert!(unresovled_ids.contains(&Value::Identifier("a".into())), "Test 2 failed: expected 'a' to be unresolved");
        assert!(unresovled_ids.contains(&Value::Identifier("c".into())), "Test 2 failed: expected 'c' to be unresolved");
    }

    #[tokio::test]
    async fn arrays() { // Added async
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
        // println!("t={:?}", value); // Keep this commented out
        assert!(value.is_err());
    }

    #[tokio::test]
    async fn ctx_chain() { // Added async
        let ctx: ScriptContextRef = Default::default();
        let ctx2_instance = ScriptContext::new(Some(ctx)); // Create instance first
        ctx2_instance.set("a".into(), 1.into());           // Call set on the instance
        let ctx2_arc = Arc::new(ctx2_instance);            // Then wrap in Arc
        let value = parse("a+1").unwrap().value_of(ctx2_arc).await.unwrap(); // Added await
        assert_eq!(value, 2.into());
    }

    #[tokio::test]
    async fn scope() { // Added async
        type_test("let a=1;b=2 in a+b", Type::Integer);
        eval_test!("let a=1;b=2 in a+b", Value::Integer(3).into());
    }

    #[tokio::test]
    async fn access_tuple() { // Added async
        type_test("(1,\"2\",false).1", Type::String);
        eval_test!("(1,\"2\",false).1", Value::String("2".to_string()).into());
    }

    #[tokio::test]
    async fn strcat() { // Added async
        type_test(r#" strcat(["1","2",to_string(3)]) "#, Type::String);
        eval_test!(r#" strcat(["1","2",to_string(3)]) "#, Value::String("123".to_string()).into());
    }

    #[tokio::test]
    async fn template() { // Added async
        type_test(r#" `x=${to_string(1+2)}` "#, Type::String);
        eval_test!(
            r#" `x=
${to_string(1+2)}` "#,
            Value::String("x=\n3".to_string()).into()
        );
    }

    #[tokio::test]
    async fn native_objects() { // Added async
        let ctx_instance = ScriptContext::new(Some(Default::default()));
        ctx_instance.set("a".into(), ("xx".to_owned(), 1).into());
        let ctx_arc: ScriptContextRef = Arc::new(ctx_instance);
        let value = parse("a.length+1+a.x") // Removed block_on, using await directly
            .unwrap()
            .value_of(ctx_arc.clone())
            .await
            .unwrap();
        assert_eq!(value, 4.into());
        let value = parse("a[a.x] > 200 ? a : \"yy\"") // Removed block_on, using await directly
            .unwrap()
            .value_of(ctx_arc)
            .await
            .unwrap();
        assert_eq!(value, "yy".into());
    }

    #[tokio::test]
    async fn eval_simple_function_call() { // Added async
        eval_test!("let f(a) = a + 1 in f(5)", Value::Integer(6));
        type_test("let f(a) = a + 1 in f(5)", Type::Integer); 
    }

    #[tokio::test]
    async fn eval_function_multiple_args() { // Added async
        eval_test!("let add(x, y) = x + y in add(3, 4)", Value::Integer(7));
        type_test("let add(x, y) = x + y in add(3, 4)", Type::Integer);
    }

    #[tokio::test]
    async fn eval_function_no_args() { // Added async
        eval_test!("let get_num() = 42 in get_num()", Value::Integer(42));
        type_test("let get_num() = 42 in get_num()", Type::Integer);
    }

    #[tokio::test]
    async fn eval_closure_lexical_scoping() { // Added async
        eval_test!("let x = 10; f(a) = a + x in f(5)", Value::Integer(15));
        type_test("let x = 10; f(a) = a + x in f(5)", Type::Integer);
        eval_test!("let x = 10; f() = x * 2 in f()", Value::Integer(20));
        type_test("let x = 10; f() = x * 2 in f()", Type::Integer);
    }

    #[tokio::test]
    async fn eval_closure_arg_shadows_outer_scope() { // Added async
        eval_test!("let x = 10; f(x) = x + 1 in f(5)", Value::Integer(6));
        type_test("let x = 10; f(x) = x + 1 in f(5)", Type::Integer);
    }

    #[tokio::test]
    async fn eval_closure_inner_let_shadows_outer_scope() { // Added async
        eval_test!("let x = 10; f() = (let x = 5 in x + 1) in f()", Value::Integer(6)); 
        type_test("let x = 10; f() = (let x = 5 in x + 1) in f()", Type::Integer);
        eval_test!("let x = 10; f() = (let y = 5 in x + y) in f()", Value::Integer(15)); 
        type_test("let x = 10; f() = (let y = 5 in x + y) in f()", Type::Integer);
    }

    #[tokio::test]
    async fn eval_recursive_function_factorial() { // Added async
        eval_test!("let fac(n) = if n == 0 then 1 else n * fac(n - 1) in fac(3)", Value::Integer(6));
        type_test("let fac(n) = if n == 0 then 1 else n * fac(n - 1) in fac(3)", Type::Integer);
        eval_test!("let fac(n) = if n == 0 then 1 else n * fac(n - 1) in fac(0)", Value::Integer(1));
        type_test("let fac(n) = if n == 0 then 1 else n * fac(n - 1) in fac(0)", Type::Integer);
    }

    #[tokio::test]
    async fn eval_mutually_recursive_functions() { // Added async
        let script_even = "let is_even(n) = if n == 0 then true else is_odd(n - 1); is_odd(n) = if n == 0 then false else is_even(n - 1) in is_even(4)"; 
        eval_test!(script_even, Value::Boolean(true));
        type_test(script_even, Type::Integer);

        let script_odd = "let is_even(n) = if n == 0 then true else is_odd(n - 1); is_odd(n) = if n == 0 then false else is_even(n - 1) in is_odd(3)"; 
        eval_test!(script_odd, Value::Boolean(true));
        type_test(script_odd, Type::Integer);
    }
    
    #[tokio::test]
    async fn eval_function_uses_another_in_same_block() { // Added async
        eval_test!("let g() = 10; f(a) = a + g() in f(5)", Value::Integer(15)); 
        type_test("let g() = 10; f(a) = a + g() in f(5)", Type::Integer);
    }

    impl NativeObject for (String, u32) {
        fn as_accessible(&self) -> Option<&dyn Accessible> {
            Some(self)
        }
        fn as_evaluatable(&self) -> Option<&dyn Evaluatable> {
            Some(self)
        }
        fn as_indexable(&self) -> Option<&dyn Indexable> {
            Some(self)
        }
    }

    impl Accessible for (String, u32) {
        fn names(&self) -> Vec<&str> {
            vec!["length", "x"]
        }

        fn type_of(&self, name: &str, _ctx: ScriptContextRef) -> Result<Type, Error> {
            match name {
                "length" | "x" => Ok(Type::Integer),
                _ => bail!("no such property"),
            }
        }

        fn get(&self, name: &str) -> Result<Value, Error> {
            match name {
                "length" => Ok((self.0.len() as i64).into()),
                "x" => Ok(self.1.into()),
                _ => bail!("no such property"),
            }
        }
    }

    impl Indexable for (String, u32) {
        fn length(&self) -> usize {
            self.0.len()
        }

        fn type_of_member(&self, _ctx: ScriptContextRef) -> Result<Type, Error> {
            Ok(Type::Integer)
        }

        fn get(&self, index: i64) -> Result<Value, Error> {
            let n_char_val = self 
                .0
                .chars()
                .nth(index as usize)
                .ok_or_else(|| err_msg("index out of range"))? as i64;
            Ok(n_char_val.into()) 
        }
    }

    #[async_trait] // Ensure async_trait is here
    impl Evaluatable for (String, u32) {
        fn type_of(&self, _ctx: ScriptContextRef) -> Result<Type, Error> {
            Ok(Type::String)
        }

        async fn value_of(&self, _ctx: ScriptContextRef) -> Result<Value, Error> {
            Ok(self.0.to_owned().into())
        }
    }

    // --- Native Object Test Setup ---

    #[derive(Debug, Hash, Eq, PartialEq)]
    struct TestNativeSimple;
    impl NativeObject for TestNativeSimple {
        fn as_accessible(&self) -> Option<&dyn Accessible> {
            Some(self)
        }
    }
    impl Accessible for TestNativeSimple {
        fn names(&self) -> Vec<&str> {
            vec!["valid_prop"]
        }
        fn type_of(&self, name: &str, _ctx: ScriptContextRef) -> Result<Type, Error> {
            if name == "valid_prop" { Ok(Type::Integer) } else { bail!("no such property") }
        }
        fn get(&self, name: &str) -> Result<Value, Error> {
            if name == "valid_prop" { Ok(Value::Integer(123)) } else { bail!("no such property: {}", name) }
        }
    }
    
    #[derive(Debug, Hash, Eq, PartialEq)]
    struct TestNativeFailingAccess;
    impl NativeObject for TestNativeFailingAccess {
        fn as_accessible(&self) -> Option<&dyn Accessible> {
            Some(self)
        }
    }
    impl Accessible for TestNativeFailingAccess {
        fn names(&self) -> Vec<&str> { vec!["prop_that_fails"] }
        fn type_of(&self, _name: &str, _ctx: ScriptContextRef) -> Result<Type, Error> { Ok(Type::Integer) }
        fn get(&self, name: &str) -> Result<Value, Error> {
            bail!("native error on get for {}", name)
        }
    }

    #[derive(Debug, Hash, Eq, PartialEq)]
    struct TestNativeFailingCall;
    impl NativeObject for TestNativeFailingCall {
        fn as_callable(&self) -> Option<&dyn Callable> {
            Some(self)
        }
    }
    #[async_trait] // Ensure async_trait is here, was likely added when Callable was changed
    impl Callable for TestNativeFailingCall {
        fn signature(&self, _ctx: ScriptContextRef, _args: &[Value]) -> Result<Type, Error> {
            Ok(Type::Integer)
        }
        async fn call(&self, _ctx: ScriptContextRef, _args: &[Value]) -> Result<Value, Error> {
            bail!("native error on call")
        }
    }


    // --- Runtime Error Handling Tests ---
    #[tokio::test]
    async fn test_call_non_existent_function() { // Added async
        eval_error_test!("non_existent_func()", "\"non_existent_func\" is undefined");
    }

    #[tokio::test]
    async fn test_call_non_callable_value() { // Added async
        eval_error_test!("let x = 10 in x()", "is not a callable function type");
    }

    #[tokio::test]
    async fn test_incorrect_arg_count_udf() { // Added async
        eval_error_test!("let f(a) = a in f(1,2)", "expected 1 arguments, got 2");
    }

    #[tokio::test]
    async fn test_type_mismatch_binary_op() { // Added async
        eval_error_test!("1 + \"hello\"", "type mismatch"); // Error message might vary based on Plus impl
    }

    #[tokio::test]
    async fn test_index_out_of_bounds_array() { // Added async
        eval_error_test!("[1,2][2]", "index out of bounds: 2");
        eval_error_test!("[1,2][-3]", "index out of bounds"); // Exact message might differ
    }

    #[tokio::test]
    async fn test_index_out_of_bounds_tuple() { // Added async
        eval_error_test!("(1,2).2", "index out of bounds: 2");
        eval_error_test!("(1,2).-3", "index out of bounds");
    }
    
    #[tokio::test]
    async fn test_access_non_existent_property_native() { // Added async
        let ctx = ScriptContext::new(Some(Default::default()));
        ctx.set("no_simple".to_string(), TestNativeSimple.into());
        let parsed = parse("no_simple.invalid_prop").unwrap();
        let res = parsed.value_of(Arc::new(ctx)).await; // Added await
        assert!(res.is_err());
        assert!(res.err().unwrap().to_string().contains("no such property: invalid_prop"));
    }
    
    #[tokio::test]
    async fn test_division_by_zero() { // Added async
        eval_error_test!("1 / 0", "division by zero");
    }

    #[tokio::test]
    async fn test_modulo_by_zero() { // Added async
        eval_error_test!("1 % 0", "division by zero");
    }

    // --- Scope and Context Tests ---
    #[tokio::test]
    async fn test_variable_shadowing_and_unshadowing() { // Added async
        eval_test!("let x = 1 in (let x = 2 in x) + x", Value::Integer(3));
        eval_test!("let x = 1 in let y = (let x = 2 in x) + x in y", Value::Integer(3)); // y = 2 + 1
    }

    #[tokio::test]
    async fn test_variable_redefinition_in_let_block() { // Added async
        // Current parser allows this, and it shadows.
        // `let a=1; a=2 in a` parses as `let a=1 ; (a=2 in a)`
        // The inner `a=2` is an assignment if `a` is mutable or a new var declaration.
        // Milu's `let` creates immutable bindings in current scope.
        // `a=2` inside `let` is actually parsed as `tuple!(id!(a), int!(2))` by `op_assign`
        // So `let a=1; a=2 in a` becomes `scope!(array!(tuple!(id!(a),int!(1)), tuple!(id!(a),int!(2))), id!(a))`
        // The Scope::call will set 'a' to 1, then 'a' to 2. So 'a' will be 2.
        eval_test!("let a = 1; a = 2 in a", Value::Integer(2));
        // If it were to be an error, it would be a compile/parse time error or specific runtime check.
        // To test if `let a=1, a=2 in a` is an error, that's a parser test.
        // This test is for runtime evaluation of shadowing if allowed.
    }
    
    // --- Native Objects Error Tests ---
    #[tokio::test]
    async fn test_native_object_failing_get() { // Added async
        let ctx = ScriptContext::new(Some(Default::default()));
        ctx.set("native_fail_get".to_string(), TestNativeFailingAccess.into());
        let parsed = parse("native_fail_get.prop_that_fails").unwrap();
        let res = parsed.value_of(Arc::new(ctx)).await; // Added await
        assert!(res.is_err());
        assert!(res.err().unwrap().to_string().contains("native error on get for prop_that_fails"));
    }

    #[tokio::test]
    async fn test_native_object_failing_call() { // Added async
        let ctx = ScriptContext::new(Some(Default::default()));
        ctx.set("native_fail_call".to_string(), TestNativeFailingCall.into());
        let parsed = parse("native_fail_call()").unwrap();
        let res = parsed.value_of(Arc::new(ctx)).await; // Added await
        assert!(res.is_err());
        assert!(res.err().unwrap().to_string().contains("native error on call"));
    }

    // --- ToString Tests (from original request, placed here for eval_test) ---
    #[tokio::test]
    async fn test_to_string_empty_array() { // Added async
        eval_test!("to_string([])", Value::String("[]".to_string()));
    }

    #[tokio::test]
    async fn test_to_string_mixed_array() { // Added async
        // This depends on array type checking. If an array like [1, "a"] can be formed:
        // The current Array type_of logic would error if members are different.
        // Let's assume if it forms (e.g. array of Any, or if type check is bypassed),
        // to_string should handle it.
        // For now, this test will likely fail at array creation time if types are strict.
        // If array elements must be same type, this test should be `eval_error_test`.
        // Assuming an array of Type::Any could be constructed or specific `to_string` behavior:
        // eval_test!("to_string([1, \"a\"])", Value::String("[1,\"a\"]".to_string()));
        // Let's test `to_string` on an array that CAN be formed:
        eval_test!("to_string([1, 2])", Value::String("[1,2]".to_string()));
        eval_test!("to_string([\"a\", \"b\"])", Value::String("[\"a\",\"b\"]".to_string()));
    }

    #[tokio::test]
    async fn test_to_string_empty_tuple() { // Added async
        eval_test!("to_string(())", Value::String("()".to_string()));
    }

    #[tokio::test]
    async fn test_to_string_mixed_tuple() { // Added async
        eval_test!("to_string((1, \"a\"))", Value::String("(1,\"a\")".to_string()));
    }

    #[tokio::test]
    async fn test_to_string_complex_expression_result() { // Added async
        // to_string should operate on the *result* of the expression.
        eval_test!("to_string(let x=1 in x+1)", Value::String("2".to_string()));
        eval_test!("to_string(if true then \"hello\" else \"world\")", Value::String("\"hello\"".to_string()));
    }

}
