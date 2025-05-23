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

pub trait Evaluatable {
    fn type_of(&self, ctx: ScriptContextRef) -> Result<Type, Error>;
    fn value_of(&self, ctx: ScriptContextRef) -> Result<Value, Error>;
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

pub trait Callable {
    // should not return Any
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error>;
    fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error>;
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

#[derive(Debug)] // Added Debug for ScriptContext
pub struct ScriptContext {
    parent: Option<ScriptContextRef>,
    varibles: HashMap<String, Value>,
}

pub type ScriptContextRef = Arc<ScriptContext>;

#[derive(Debug, Clone)] // Removed PartialEq, Eq from derive for UserDefinedFunction
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
        // captured_context is intentionally excluded from comparison
    }
}
impl Eq for UserDefinedFunction {}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParsedFunction {
    pub name_ident: Value, // Expected to be Value::Identifier
    pub arg_idents: Vec<Value>, // Expected to be Vec<Value::Identifier>
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

    fn call(&self, caller_context: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        if args.len() != self.arg_names.len() {
            bail!(
                "expected {} arguments, got {}",
                self.arg_names.len(),
                args.len()
            );
        }

        let mut fn_ctx = ScriptContext::new(Some(self.captured_context.clone()));
        for (i, arg_name) in self.arg_names.iter().enumerate() {
            let arg_value = args[i].real_value_of(caller_context.clone())?;
            fn_ctx.set(arg_name.clone(), arg_value);
        }

        self.body.real_value_of(Arc::new(fn_ctx))
    }

    fn unresovled_ids<'s: 'o, 'o>(&'s self, args: &'s [Value], ids: &mut HashSet<&'o Value>) { // Changed &self to &'s self
        args.iter().for_each(|v| v.unresovled_ids(ids));

        let mut body_ids = HashSet::new();
        self.body.unresovled_ids(&mut body_ids);

        for id_val in body_ids {
            if let Value::Identifier(id_name) = id_val {
                if !self.arg_names.contains(id_name) {
                    ids.insert(id_val);
                }
            } else {
                // If it's not an identifier, it could be a complex expression
                // that needs its own unresolved ids checked, but Value::unresovled_ids
                // should handle nesting. However, direct insertion if not an identifier
                // might be needed if other Value types can be 'unresolved' in a special way.
                // For now, only add if it's an identifier not masked by args.
                // Consider if other Value types (like OpCall within the body) need specific handling here.
                 ids.insert(id_val); // Or potentially recurse/delegate if id_val itself can contain unresolved ids
            }
        }
    }
}

impl ScriptContext {
    pub fn new(parent: Option<ScriptContextRef>) -> Self {
        //let parent = unsafe { std::mem::transmute(parent) };
        Self {
            parent,
            varibles: Default::default(),
        }
    }
    pub fn lookup(&self, id: &str) -> Result<Value, Error> {
        if let Some(r) = self.varibles.get(id) {
            tracing::trace!("lookup({})={}", id, r);
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
        varibles.insert("strcat".to_string(), stdlib::StringConcat::stub().into());
        Self {
            parent: None,
            varibles,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)] // Removed Hash from derive
pub enum Value {
    // Null,
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
            Self::UserDefined(udf_arc) => {
                let mut body_ids = HashSet::new();
                udf_arc.body.unresovled_ids(&mut body_ids);

                // Filter out argument names (udf_arc.arg_names are Vec<String>)
                body_ids.retain(|val_in_body| {
                    if let Value::Identifier(id_str_in_body) = val_in_body {
                        !udf_arc.arg_names.contains(id_str_in_body)
                    } else {
                        true // Keep non-identifiers (e.g., nested OpCalls that might resolve to functions)
                    }
                });
                ids.extend(body_ids);
            }
            Self::ParsedFunction(parsed_fn_arc) => {
                // The name_ident of ParsedFunction (e.g., 'f' in 'let f(x) = ...') is handled
                // by the Identifier case if 'f' is used later.
                // Here, we are interested in unresolved IDs within the body of the ParsedFunction,
                // excluding its own arguments.

                let mut body_ids = HashSet::new();
                parsed_fn_arc.body.unresovled_ids(&mut body_ids);

                // Filter out argument names (arg_idents are Value::Identifier)
                body_ids.retain(|val_in_body| {
                    // val_in_body is &Value. We only care if it's an Identifier.
                    if let Value::Identifier(id_in_body) = val_in_body {
                        // Check if this identifier matches any of the argument names.
                        // parsed_fn_arc.arg_idents contains Value::Identifier items.
                        !parsed_fn_arc.arg_idents.iter().any(|arg_ident_val| {
                            if let Value::Identifier(arg_id_str) = arg_ident_val {
                                arg_id_str == id_in_body
                            } else {
                                false // Should not happen as parser ensures arg_idents are Value::Identifier
                            }
                        })
                    } else {
                        true // Keep non-identifiers (e.g., nested OpCalls, Literals that resolve to functions)
                    }
                });
                ids.extend(body_ids);

                // Arg_idents themselves are Value::Identifier. They are not expressions that can have unresolved IDs.
                // Their "unresolved" status is determined when the function is defined or called,
                // not when the ParsedFunction value itself is traversed.
            }
            // NativeObject, String, Integer, Boolean do not contain script sub-expressions with identifiers.
            _ => (),
        }
    }

    /// Returns `true` if the value is [`Identifier`].
    ///
    /// [`Identifier`]: Value::Identifier
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
    pub fn real_value_of(&self, ctx: ScriptContextRef) -> Result<Value, Error> {
        let t = self.value_of(ctx.clone())?;
        if let Self::NativeObject(o) = t {
            if let Some(e) = o.as_evaluatable() {
                e.value_of(ctx)
            } else {
                Ok(Self::NativeObject(o))
            }
        } else {
            Ok(t)
        }
    }
}

impl Evaluatable for Value {
    fn type_of(&self, ctx: ScriptContextRef) -> Result<Type, Error> {
        tracing::trace!("type_of={}", self);
        use Value::*;
        match self {
            // Null => Ok(Type::Null),
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
                // A UserDefinedFunction's type when treated as a value is not directly its signature's return type.
                // Its signature's return type is for when it's *called*.
                // For now, we'll treat the "type of a function value" as Type::Any.
                // A more sophisticated type system might have a Type::Function variant.
                // If we wanted to get the return type of its signature:
                // udf_arc.signature(ctx, &[]) // This would require ctx, and might not be what's intended here.
                Ok(Type::Any)
            }
            ParsedFunction(_) => {
                // ParsedFunction is an intermediate representation and ideally should not be directly evaluated for type
                // in a fully resolved AST. If it occurs, it implies an incomplete processing step.
                // However, to make the match exhaustive, we return Type::Any.
                // Consider if an internal error or a more specific "untyped" or "function definition" type is better.
                Ok(Type::Any)
            }
        }
    }

    fn value_of(&self, ctx: ScriptContextRef) -> Result<Value, Error> {
        tracing::trace!("value_of={}", self);
        match self {
            Self::Identifier(id) => ctx.lookup(id).and_then(|x| x.value_of(ctx)),
            Self::OpCall(f) => f.call(ctx),
            // Self::NativeObject(f) => {
            //     let e = f.as_evaluatable();
            //     if let Some(e) = e {
            //         e.value_of(ctx)
            //     } else {
            //         Ok(self.clone())
            //     }
            // }
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
            // Null => write!(f, "null"),
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
            } // _ => panic!("not implemented"),
        }
    }
}

impl std::hash::Hash for UserDefinedFunction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.arg_names.hash(state);
        self.body.hash(state);
        // We cannot hash captured_context as it would lead to infinite recursion
        // if the context captures a function that captures the context.
        // Arc::as_ptr(&self.captured_context).hash(state);
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
            // Null => 0.hash(state),
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
        let resolved_func = self.func(ctx.clone())?;
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
    fn call(&self, ctx: ScriptContextRef) -> Result<Value, Error> {
        let resolved_func = self.func(ctx.clone())?;
        match resolved_func {
            ResolvedFunction::Native(native_ref) => {
                native_ref.as_callable()
                    .ok_or_else(|| err_msg("Internal error: NativeObject marked callable but as_callable is None"))?
                    .call(ctx, &self.args)
            }
            ResolvedFunction::User(udf_ref) => {
                udf_ref.call(ctx, &self.args)
            }
        }
    }
    fn func(&self, ctx: ScriptContextRef) -> Result<ResolvedFunction, Error> {
        let resolved_fn_val = if let Value::Identifier(_) = &self.func {
            self.func.value_of(ctx)?
        } else {
            self.func.clone()
        };

        match resolved_fn_val {
            Value::NativeObject(arc_native_ref) => {
                if arc_native_ref.as_callable().is_some() {
                    Ok(ResolvedFunction::Native(arc_native_ref))
                } else {
                    Err(err_msg(format!("Value {:?} is a NativeObject but not callable", arc_native_ref)))
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
    fn unresovled_ids<'s: 'o, 'o>(&'s self, list: &mut HashSet<&'o Value>) {
        // If self.func is an identifier, it's an unresolved ID.
        if self.func.is_identifier() {
            list.insert(&self.func);
        } else {
            // If self.func is not an identifier, it's some other Value.
            // This Value might itself contain unresolved identifiers (e.g., if it's an OpCall, Array, UserDefined, etc.).
            // So, we call its unresovled_ids method.
            self.func.unresovled_ids(list);
        }

        // Process all arguments for unresolved identifiers.
        // This is the default behavior from the Callable trait, but we are overriding, so we must do it explicitly.
        for arg in &self.args {
            arg.unresovled_ids(list);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::parser::parse;
    use super::*;
    // For Value::Integer, etc.
    use crate::script::Value::{Integer as int, Boolean as bool_val, String as str_val};


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

    #[test]
    fn strcat() {
        type_test(r#" strcat(["1","2",to_string(3)]) "#, Type::String);
        eval_test!(r#" strcat(["1","2",to_string(3)]) "#, "123".into());
    }

    #[test]
    fn template() {
        type_test(r#" `x=${to_string(1+2)}` "#, Type::String);
        eval_test!(
            r#" `x=
${to_string(1+2)}` "#,
            "x=\n3".into()
        );
    }

    #[test]
    fn native_objects() {
        let mut ctx = ScriptContext::new(Some(Default::default()));
        ctx.set("a".into(), ("xx".to_owned(), 1).into());
        let ctx: ScriptContextRef = ctx.into();
        let value = parse("a.length+1+a.x")
            .unwrap()
            .value_of(ctx.clone())
            .unwrap();
        assert_eq!(value, 4.into());
        // this test if "a" could be used as Indexable, Accessible, Evaluatable at sametime
        let value = parse("a[a.x] > 200 ? a : \"yy\"")
            .unwrap()
            .value_of(ctx)
            .unwrap();
        assert_eq!(value, "yy".into());
    }

    #[test]
    fn eval_simple_function_call() {
        eval_test!("let f(a) = a + 1 in f(5)", int!(6));
        type_test!("let f(a) = a + 1 in f(5)", Type::Any); // UDF returns Type::Any
    }

    #[test]
    fn eval_function_multiple_args() {
        eval_test!("let add(x, y) = x + y in add(3, 4)", int!(7));
        type_test!("let add(x, y) = x + y in add(3, 4)", Type::Any);
    }

    #[test]
    fn eval_function_no_args() {
        eval_test!("let get_num() = 42 in get_num()", int!(42));
        type_test!("let get_num() = 42 in get_num()", Type::Any);
    }

    #[test]
    fn eval_closure_lexical_scoping() {
        eval_test!("let x = 10; let f(a) = a + x in f(5)", int!(15));
        type_test!("let x = 10; let f(a) = a + x in f(5)", Type::Any);
        eval_test!("let x = 10; let f() = x * 2 in f()", int!(20));
        type_test!("let x = 10; let f() = x * 2 in f()", Type::Any);
    }

    #[test]
    fn eval_closure_arg_shadows_outer_scope() {
        eval_test!("let x = 10; let f(x) = x + 1 in f(5)", int!(6));
        type_test!("let x = 10; let f(x) = x + 1 in f(5)", Type::Any);
    }

    #[test]
    fn eval_closure_inner_let_shadows_outer_scope() {
        eval_test!("let x = 10; let f() = (let x = 5 in x + 1); f()", int!(6));
        type_test!("let x = 10; let f() = (let x = 5 in x + 1); f()", Type::Any);
        eval_test!("let x = 10; let f() = (let y = 5 in x + y); f()", int!(15));
        type_test!("let x = 10; let f() = (let y = 5 in x + y); f()", Type::Any);
    }

    #[test]
    fn eval_recursive_function_factorial() {
        eval_test!("let fac(n) = if n == 0 then 1 else n * fac(n - 1) in fac(3)", int!(6));
        type_test!("let fac(n) = if n == 0 then 1 else n * fac(n - 1) in fac(3)", Type::Any);
        eval_test!("let fac(n) = if n == 0 then 1 else n * fac(n - 1) in fac(0)", int!(1));
        type_test!("let fac(n) = if n == 0 then 1 else n * fac(n - 1) in fac(0)", Type::Any);
    }

    #[test]
    fn eval_mutually_recursive_functions() {
        let script_even = "let is_even(n) = if n == 0 then true else is_odd(n - 1); let is_odd(n) = if n == 0 then false else is_even(n - 1) in is_even(4)";
        eval_test!(script_even, bool_val!(true));
        type_test!(script_even, Type::Any);

        let script_odd = "let is_even(n) = if n == 0 then true else is_odd(n - 1); let is_odd(n) = if n == 0 then false else is_even(n - 1) in is_odd(3)";
        eval_test!(script_odd, bool_val!(true));
        type_test!(script_odd, Type::Any);
    }
    
    #[test]
    fn eval_function_uses_another_in_same_block() {
        eval_test!("let g() = 10; let f(a) = a + g() in f(5)", int!(15));
        type_test!("let g() = 10; let f(a) = a + g() in f(5)", Type::Any);
    }

    // Optional: Type of function itself.
    // `UserDefinedFunction::signature` returns Type::Any for the *call result*.
    // The type of the function *value* itself, when looked up or passed around, is not explicitly `Type::Function`.
    // It's `Value::UserDefined`, and its `type_of` method in `impl Evaluatable for Value` would need
    // a specific branch for `UserDefined` returning a distinct `Type::Function` or similar.
    // Currently, `Value::UserDefined(_).type_of(ctx)` is not implemented in `Evaluatable for Value`.
    // It would fall into the `Identifier(id) => ctx.lookup(id).and_then(|x| x.type_of(ctx))` if it's an identifier,
    // or not directly handled if it's a raw UDF value.
    // Let's test what `type_of` on an identifier bound to a function returns.
    // Based on current `Value::type_of` and `UserDefinedFunction::signature`, this will try to *call* it.
    // `type_test!("let f()=1 in f", Type::Any);` // This implies calling f, which is correct for type_test as is.
    // If we wanted a `Type::Function`, `Value::type_of` would need a new arm for `UserDefined`.

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
            let n = self
                .0
                .chars()
                .nth(index as usize)
                .ok_or_else(|| err_msg("index out of range"))? as i64;
            Ok(n.into())
        }
    }

    impl Evaluatable for (String, u32) {
        fn type_of(&self, _ctx: ScriptContextRef) -> Result<Type, Error> {
            Ok(Type::String)
        }

        fn value_of(&self, _ctx: ScriptContextRef) -> Result<Value, Error> {
            Ok(self.0.to_owned().into())
        }
    }
}
