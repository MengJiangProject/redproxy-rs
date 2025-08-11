use anyhow::{Result, bail};
use async_trait::async_trait;
use std::{collections::HashSet, convert::TryFrom, fmt::Display, sync::Arc};

// Assuming other modules are correctly set up in `super` or `crate::script`
use super::context::ScriptContextRef;
use super::functions::{Call, ParsedFunction, UserDefinedFunction};
use super::traits::{Evaluatable, NativeObject, NativeObjectRef}; // Added NativeObject
use super::types::Type; // Assuming these are in functions.rs

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
    Function(Arc<UserDefinedFunction>),
    ParsedFunction(Arc<ParsedFunction>),
}

impl Value {
    pub fn type_of_simple(&self) -> &'static str {
        match self {
            Value::Integer(_) => "Integer",
            Value::Boolean(_) => "Boolean",
            Value::String(_) => "String",
            Value::Identifier(_) => "Identifier",
            Value::Array(_) => "Array",
            Value::Tuple(_) => "Tuple",
            Value::OpCall(_) => "OpCall",
            Value::NativeObject(_) => "NativeObject",
            Value::Function(_) => "Function",
            Value::ParsedFunction(_) => "ParsedFunction",
        }
    }

    pub fn as_vec(&self) -> Result<&Vec<Value>> {
        // Made pub
        match self {
            Self::Array(a) => Ok(a),
            Self::Tuple(a) => Ok(a),
            _ => bail!(
                "as_vec: type mismatch, expected Array or Tuple, got {}",
                self.type_of_simple()
            ),
        }
    }
    #[allow(dead_code)]
    pub fn as_i64(&self) -> Result<i64> {
        // Made pub
        match self {
            Self::Integer(a) => Ok(*a),
            _ => bail!(
                "as_i64: type mismatch, expected Integer, got {}",
                self.type_of_simple()
            ),
        }
    }
    pub fn unresovled_ids<'s: 'o, 'o>(&'s self, ids: &mut HashSet<&'o Value>) {
        // Made pub
        match self {
            Self::Identifier(_) => {
                ids.insert(self);
            }
            Self::Array(a) => a.iter().for_each(|v| v.unresovled_ids(ids)),
            Self::Tuple(a) => a.iter().for_each(|v| v.unresovled_ids(ids)),
            Self::OpCall(a) => a.unresovled_ids(ids),
            Self::Function(udf_arc) => {
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
            _ => (),
        }
    }

    pub fn is_identifier(&self) -> bool {
        matches!(self, Self::Identifier(..))
    }

    pub async fn real_type_of(&self, ctx: ScriptContextRef) -> Result<Type> {
        let t = self.type_of(ctx.clone()).await?;
        if let Type::NativeObject(o) = t {
            if let Some(e) = o.as_evaluatable() {
                e.type_of(ctx).await
            } else {
                Ok(Type::NativeObject(o))
            }
        } else {
            Ok(t)
        }
    }
    pub async fn real_value_of(&self, ctx: ScriptContextRef) -> Result<Value> {
        let t = self.value_of(ctx.clone()).await?;
        if let Self::NativeObject(o) = t {
            if let Some(e) = o.as_evaluatable() {
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
    async fn type_of(&self, ctx: ScriptContextRef) -> Result<Type> {
        tracing::trace!("type_of={}", self);
        use Value::*;
        match self {
            String(_) => Ok(Type::String),
            Boolean(_) => Ok(Type::Boolean),
            Integer(_) => Ok(Type::Integer),
            Identifier(id) => {
                let val = ctx.lookup(id)?;
                val.type_of(ctx).await
            }
            OpCall(x) => x.signature(ctx).await,
            Array(a) => {
                if a.is_empty() {
                    Ok(Type::Array(Box::new(Type::Any)))
                } else {
                    let t = a[0].real_type_of(ctx.clone()).await?;
                    for x_val in a.iter().skip(1) {
                        let xt = x_val.real_type_of(ctx.clone()).await?;
                        if xt != t {
                            bail!(
                                "array member must have same type: required type={:?}, mismatch type={} item={:?}",
                                t,
                                xt,
                                x_val
                            )
                        }
                    }
                    Ok(Type::Array(Box::new(t)))
                }
            }
            Tuple(t) => {
                let mut ret = Vec::with_capacity(t.len());
                for x_val in t.iter() {
                    ret.push(x_val.type_of(ctx.clone()).await?)
                }
                Ok(Type::Tuple(ret))
            }
            NativeObject(o) => Ok(Type::NativeObject(o.clone())),
            Function(_udf_arc) => Ok(Type::Any), // Function type is complex, Any for now
            ParsedFunction(_) => Ok(Type::Any),  // Similar to Function
        }
    }

    async fn value_of(&self, ctx: ScriptContextRef) -> Result<Value> {
        tracing::trace!("value_of={}", self);
        match self {
            Self::Identifier(id) => {
                let looked_up_value = ctx.lookup(id)?;
                looked_up_value.value_of(ctx).await
            }
            Self::OpCall(f) => f.call(ctx).await,
            _ => Ok(self.clone()),
        }
    }
}

impl Display for Value {
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
            Function(x) => {
                let name = x.name.as_deref().unwrap_or("");
                write!(f, "fn<{}>({})", name, x.arg_names.join(", "))
            }
            ParsedFunction(x) => {
                let arg_names_str = x
                    .arg_idents
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "<parsed_fn {}({})>", x.name_ident, arg_names_str)
            }
        }
    }
}

// Macros for From/TryFrom impls (kept local as they are only used for Value here)
macro_rules! cast_value_to {
    ($ty:ty, $name:ident, | $v: ident | $transfrom:expr) => {
        impl TryFrom<Value> for $ty {
            type Error = anyhow::Error;
            fn try_from(x: Value) -> Result<$ty, Self::Error> {
                if let Value::$name($v) = x {
                    Ok($transfrom)
                } else {
                    bail!(
                        "unable to cast {:?} into {}",
                        x.type_of_simple(),
                        stringify!($ty)
                    )
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
cast_value!(Call, OpCall, arc); // Assuming Call struct will be moved to functions.rs

impl From<&str> for Value {
    fn from(x: &str) -> Self {
        Self::String(x.into())
    }
}

impl<T> From<T> for Value
where
    T: NativeObject + Send + Sync + 'static, // Ensure NativeObject is in scope
{
    fn from(x: T) -> Self {
        Value::NativeObject(Arc::new(Box::new(x)))
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
            NativeObject(o) => o.hash(state), // Relies on NativeObjectRef's Hash impl
            Function(f) => f.hash(state),     // Relies on UserDefinedFunction's Hash impl
            ParsedFunction(f) => f.hash(state), // Relies on ParsedFunction's Hash impl
        }
    }
}
