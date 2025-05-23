use easy_error::{bail, err_msg, Error, ResultExt};
use std::{
    cell::RefCell, 
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    fmt::Display,
    hash::{Hash, Hasher},
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
    Any, 
    Generic(String), 
    Function {
        params: Vec<Type>,
        ret: Box<Type>,
    },
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
            (NativeObject(_a), NativeObject(_b)) => true, 
            (Generic(s1), Generic(s2)) => s1 == s2,
            (Function { params: p1, ret: r1 }, Function { params: p2, ret: r2 }) => {
                p1 == p2 && r1 == r2
            }
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
                t.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            ),
            Self::NativeObject(_x) => write!(f, "native_object"), 
            Self::Any => write!(f, "any"),
            Self::Generic(name) => write!(f, "{}", name),
            Self::Function { params, ret } => {
                let param_str = params.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
                write!(f, "({}) -> {}", param_str, ret)
            }
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
    fn type_of_member(&self, ctx: ScriptContextRef) -> Result<Type, Error> {
        if self.is_empty() {
            Ok(Type::Any) 
        } else {
            self[0].real_type_of(ctx)
        }
    }
    fn get(&self, index: i64) -> Result<Value, Error> {
        let i = if index >= 0 {
            index as usize
        } else {
            let positive_idx = index.abs() as usize;
            if positive_idx > self.len() {
                bail!("negative index out of bounds: {}", index)
            }
            self.len() - positive_idx
        };

        if i >= self.len() {
            bail!("index out of bounds: {} (len is {})", i, self.len())
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
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
    fn hash_with_state(&self, mut st: &mut dyn std::hash::Hasher) {
        self.hash(&mut st);
    }
}

pub trait NativeObject: std::fmt::Debug + NativeObjectHash {
    fn as_evaluatable(&self) -> Option<&dyn Evaluatable> { None }
    fn as_accessible(&self) -> Option<&dyn Accessible> { None }
    fn as_indexable(&self) -> Option<&dyn Indexable> { None }
    fn as_callable(&self) -> Option<&dyn Callable> { None }
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

pub struct ScriptContext {
    parent: Option<ScriptContextRef>,
    varibles: RefCell<HashMap<String, Value>>, 
}
pub type ScriptContextRef = Arc<ScriptContext>;

impl ScriptContext {
    pub fn new(parent: Option<ScriptContextRef>) -> Self {
        Self {
            parent,
            varibles: RefCell::new(Default::default()), 
        }
    }
    pub fn lookup(&self, id: &str) -> Result<Value, Error> {
        if let Some(r) = self.varibles.borrow().get(id) { 
            tracing::trace!("lookup({})={}", id, r);
            Ok(r.clone())
        } else if let Some(p) = &self.parent {
            p.lookup(id)
        } else {
            bail!("\"{}\" is undefined", id)
        }
    }
    pub fn set(&self, id: String, value: Value) {
        self.varibles.borrow_mut().insert(id, value); 
    }
}

impl Default for ScriptContext {
    fn default() -> Self {
        let varibles_map = HashMap::from([
            ("to_string".to_string(), stdlib::ToString::stub().into()),
            ("to_integer".to_string(), stdlib::ToInteger::stub().into()),
            ("split".to_string(), stdlib::Split::stub().into()),
            ("strcat".to_string(), stdlib::StringConcat::stub().into()),
            ("repeat".to_string(), stdlib::Repeat::stub().into()),
        ]);
        Self {
            parent: None,
            varibles: RefCell::new(varibles_map), 
        }
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Value {
    Integer(i64),
    Boolean(bool),
    String(String),
    Identifier(String),
    Array(Arc<Vec<Value>>),
    Tuple(Arc<Vec<Value>>),
    OpCall(Arc<Call>),
    NativeObject(Arc<NativeObjectRef>),
    FunctionDef {
        name: Option<String>, 
        params: Vec<Value>,   
        body: Arc<Value>,     
    },
    DoBlock {
        bindings: Vec<Value>, 
        final_expr: Arc<Value>,
    },
    ArrayPattern {
        elements: Vec<Value>, 
        rest: Option<Arc<Value>>, 
    },
    Binding { 
        pattern: Arc<Value>, 
        expr: Arc<Value>,
    },
}

#[derive(Debug, Clone)]
pub struct UserDefinedFunction {
    name: Option<String>,
    params: Vec<String>, 
    body: Arc<Value>,
    definition_context: ScriptContextRef,
}

impl PartialEq for UserDefinedFunction {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.params == other.params
            && Arc::ptr_eq(&self.body, &other.body) 
            && Arc::ptr_eq(&self.definition_context, &other.definition_context) 
    }
}
impl Eq for UserDefinedFunction {}

impl Hash for UserDefinedFunction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.params.hash(state);
        Arc::as_ptr(&self.body).hash(state); 
        Arc::as_ptr(&self.definition_context).hash(state); 
    }
}

impl NativeObject for UserDefinedFunction {
    fn as_callable(&self) -> Option<&dyn Callable> {
        Some(self)
    }
}

impl Callable for UserDefinedFunction {
    fn signature(&self, _ctx: ScriptContextRef, _args: &[Value]) -> Result<Type, Error> {
        let param_types = self.params.iter().map(|_| Type::Any).collect();
        Ok(Type::Function {
            params: param_types,
            ret: Box::new(Type::Any),
        })
    }

    fn call(&self, _calling_context: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        if args.len() != self.params.len() {
            bail!(
                "Argument count mismatch for function {:?}: expected {}, got {}",
                self.name.as_deref().unwrap_or("<anonymous>"),
                self.params.len(),
                args.len()
            );
        }
        let call_ctx_internal_ref = Arc::new(ScriptContext::new(Some(self.definition_context.clone())));
        for (param_name, arg_value) in self.params.iter().zip(args.iter()) {
            call_ctx_internal_ref.set(param_name.clone(), arg_value.clone());
        }
        self.body.value_of(call_ctx_internal_ref)
    }
}

impl Value {
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
            Self::FunctionDef { params, body, .. } => {
                params.iter().for_each(|p| p.unresovled_ids(ids)); 
                body.unresovled_ids(ids);
            }
            Self::DoBlock { bindings, final_expr } => {
                for binding_val in bindings { 
                    if let Value::Binding { pattern, expr } = binding_val {
                        pattern.unresovled_ids(ids); 
                        expr.unresovled_ids(ids);
                    } else { 
                        binding_val.unresovled_ids(ids);
                    }
                }
                final_expr.unresovled_ids(ids);
            }
            Self::ArrayPattern { elements, rest } => {
                elements.iter().for_each(|el| el.unresovled_ids(ids));
                if let Some(r) = rest {
                    r.unresovled_ids(ids);
                }
            }
            Self::Binding { pattern, expr } => {
                pattern.unresovled_ids(ids); 
                expr.unresovled_ids(ids);
            }
            _ => (),
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
                 if o.as_callable().is_some() {
                    Ok(Type::NativeObject(o)) 
                } else {
                    Ok(Type::NativeObject(o))
                }
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

    pub fn destructure_and_bind(
        pattern: &Value,
        value: Value, 
        ctx: ScriptContextRef, 
    ) -> Result<(), Error> {
        match (pattern, &value) { 
            (Value::Identifier(id_name), val_to_bind) => {
                ctx.set(id_name.clone(), val_to_bind.clone()); 
                Ok(())
            }
            (Value::ArrayPattern { elements: pattern_elements, rest: pattern_rest }, Value::Array(value_array)) => {
                let val_len = value_array.len();
                let pat_len = pattern_elements.len();

                if let Some(rest_pattern_arc) = pattern_rest { 
                    let rest_pattern_id_val = &**rest_pattern_arc;
                    if pat_len > val_len {
                        return Err(err_msg(format!(
                            "Array pattern [..., |rest] needs at least {} element(s) for fixed part, but array has only {} element(s). Pattern: {}, Value: {:?}",
                            pat_len, val_len, pattern, value_array
                        )));
                    }
                    for (i, pattern_el) in pattern_elements.iter().enumerate() {
                        Self::destructure_and_bind(pattern_el, value_array[i].clone(), ctx.clone())?;
                    }
                    let rest_values: Vec<Value> = value_array.iter().skip(pat_len).cloned().collect();
                    if let Value::Identifier(rest_id_name) = rest_pattern_id_val {
                         ctx.set(rest_id_name.clone(), Value::Array(Arc::new(rest_values)));
                    } else {
                        return Err(err_msg(format!("Rest pattern in array destructuring must be an identifier, found: {:?}", rest_pattern_id_val)));
                    }
                } else { 
                    if pat_len != val_len {
                        return Err(err_msg(format!(
                            "Array pattern expected exactly {} element(s), but array has {} element(s). Pattern: {}, Value: {:?}",
                            pat_len, val_len, pattern, value_array
                        )));
                    }
                    for (pattern_el, value_el) in pattern_elements.iter().zip(value_array.iter()) {
                        Self::destructure_and_bind(pattern_el, value_el.clone(), ctx.clone())?;
                    }
                }
                Ok(())
            }
             (Value::ArrayPattern { .. }, other_val) => {
                let type_of_other = other_val.type_of(ctx.clone()).unwrap_or(Type::Any); 
                Err(err_msg(format!("RHS of array destructuring must be an array, got type: {:?}", type_of_other)))
            }
            (Value::Tuple(_pattern_tuple), Value::Tuple(_value_tuple)) => {
                bail!("Tuple destructuring is not yet supported.")
            }
            _ => {
                Err(err_msg(format!("Unsupported pattern type {:?} for destructuring against value of type {:?}", pattern, value.type_of(ctx)? )))
            }
        }
    }

    pub fn bind_pattern_placeholders_for_type_check(
        pattern: &Value,
        rhs_type: Type, 
        ctx: ScriptContextRef,
    ) -> Result<(), Error> {
        match pattern {
            Value::Identifier(id_name) => {
                ctx.set(id_name.clone(), Value::String(format!("_placeholder_type_{:?}_", rhs_type)));
            }
            Value::ArrayPattern { elements, rest } => {
                let inner_type = match rhs_type {
                    Type::Array(it) => *it,
                    Type::Any => Type::Any, 
                    _ => return Err(err_msg(format!("RHS of array destructuring must be an array type for type checking, got {:?}, in pattern {}", rhs_type, pattern))),
                };

                for el_pattern in elements {
                    Self::bind_pattern_placeholders_for_type_check(el_pattern, inner_type.clone(), ctx.clone())?;
                }
                if let Some(rest_pattern_arc) = rest {
                    let rest_pattern = &**rest_pattern_arc;
                    if let Value::Identifier(rest_id_name) = rest_pattern {
                        let rest_type = Type::Array(Box::new(inner_type.clone()));
                         ctx.set(rest_id_name.clone(), Value::String(format!("_placeholder_type_{:?}_", rest_type)));
                    } else {
                        return Err(err_msg("Rest pattern in array destructuring must be an identifier for type checking"));
                    }
                }
            }
            _ => {} 
        }
        Ok(())
    }
}


impl Evaluatable for Value {
    fn type_of(&self, ctx: ScriptContextRef) -> Result<Type, Error> {
        tracing::trace!("type_of={}", self);
        use Value::*;
        match self {
            String(_) => Ok(Type::String),
            Boolean(_) => Ok(Type::Boolean),
            Integer(_) => Ok(Type::Integer),
            Identifier(id) => ctx.lookup(id).and_then(|x| x.type_of(ctx.clone())),
            OpCall(x) => x.signature(ctx),
            Array(a) => {
                if a.is_empty() {
                    Ok(Type::Array(Box::new(Type::Any)))
                } else {
                    let first_element_type = a[0].real_type_of(ctx.clone())?;
                    for item_value in a.iter().skip(1) {
                        let item_type = item_value.real_type_of(ctx.clone())?;
                        if item_type != first_element_type && first_element_type != Type::Any && item_type != Type::Any {
                            if first_element_type != Type::Any && item_type != Type::Any && item_type != first_element_type {
                                bail!(
                                    "Array elements must have consistent types. Expected {} based on first element, found {} in element {:?}",
                                    first_element_type, item_type, item_value
                                );
                            }
                        }
                    }
                    Ok(Type::Array(Box::new(first_element_type)))
                }
            }
            Tuple(t) => {
                let mut ret = Vec::with_capacity(t.len());
                for x in t.iter() {
                    ret.push(x.type_of(ctx.clone())?)
                }
                Ok(Type::Tuple(ret))
            }
            NativeObject(o) => {
                if let Some(callable) = o.as_callable() {
                    callable.signature(ctx, &[]) 
                } else if let Some(evaluatable) = o.as_evaluatable() {
                    evaluatable.type_of(ctx)
                } else {
                    Ok(Type::NativeObject(o.clone())) 
                }
            }
            FunctionDef { params, .. } => {
                let num_params = params.len();
                Ok(Type::Function {
                    params: vec![Type::Any; num_params],
                    ret: Box::new(Type::Any),
                })
            }
            DoBlock { bindings, final_expr } => {
                let eval_ctx = Arc::new(ScriptContext::new(Some(ctx)));
                for binding_val in bindings { 
                    if let Value::Binding{pattern, expr} = binding_val {
                        let rhs_type = expr.real_type_of(eval_ctx.clone())?;
                        Self::bind_pattern_placeholders_for_type_check(pattern, rhs_type, eval_ctx.clone())?;
                    } else {
                        return Err(err_msg(format!("Binding in 'do' block must be a Value::Binding, got {:?}", binding_val)));
                    }
                }
                final_expr.real_type_of(eval_ctx)
            }
            ArrayPattern { .. } => Err(err_msg("ArrayPattern is not directly evaluatable for type_of and should not be type-checked directly.")), 
            Binding { pattern: _pattern, expr } => {
                expr.real_type_of(ctx)
            }
        }
    }

    fn value_of(&self, ctx: ScriptContextRef) -> Result<Value, Error> {
        tracing::trace!("value_of={}", self);
        match self {
            Self::Identifier(id) => ctx.lookup(id).and_then(|x| x.value_of(ctx.clone())),
            Self::OpCall(f) => f.call(ctx),
            Self::FunctionDef { ref name, ref params, ref body } => {
                let param_names_res: Result<Vec<String>, Error> = params.iter().map(|p_val| {
                    if let Value::Identifier(id_name) = p_val {
                        Ok(id_name.clone())
                    } else {
                        bail!("Function definition parameters must be identifiers, got {:?}", p_val)
                    }
                }).collect();

                let param_names = param_names_res?;

                let udf = UserDefinedFunction {
                    name: name.clone(),
                    params: param_names,
                    body: body.clone(),
                    definition_context: ctx, 
                };
                Ok(Value::NativeObject(Arc::new(Box::new(udf))))
            }
            Self::DoBlock { bindings, final_expr } => {
                let eval_ctx = Arc::new(ScriptContext::new(Some(ctx)));
                for binding_val in bindings { 
                    if let Value::Binding{pattern, expr} = binding_val {
                        let value_to_destructure = expr.value_of(eval_ctx.clone())?;
                        Self::destructure_and_bind(pattern, value_to_destructure, eval_ctx.clone())?;
                    } else {
                        return Err(err_msg(format!("Binding in 'do' block must be a Value::Binding, got {:?}", binding_val)));
                    }
                }
                final_expr.value_of(eval_ctx)
            }
            ArrayPattern { .. } => Err(err_msg("ArrayPattern is not directly evaluatable to a value.")),
            Binding { .. } => Err(err_msg("Binding is not directly evaluatable to a value; it's a structural element.")),
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
                x.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            ),
            Tuple(x) => write!(
                f,
                "({})",
                x.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            ),
            NativeObject(x) => write!(f, "{:?}", x), 
            FunctionDef { name, params, body } => {
                let param_str = params.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" ");
                write!(f, "fun {:?} {} = {}", name.as_deref().unwrap_or(""), param_str, body)
            }
            DoBlock { bindings, final_expr } => {
                write!(f, "do {{ ")?;
                for binding_val in bindings { 
                    if let Value::Binding { pattern, expr } = binding_val { 
                         write!(f, "let {} = {}; ", pattern, expr)?;
                    } else {
                         write!(f, "<invalid_binding_structure_in_do_display>; ")?;
                    }
                }
                write!(f, "{} }}", final_expr)
            }
            ArrayPattern { elements, rest } => {
                write!(f, "[")?;
                for (i, el) in elements.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{}", el)?;
                }
                if let Some(r) = rest {
                    if !elements.is_empty() || elements.is_empty() { 
                         write!(f, " | ")?;
                    }
                    write!(f, "{}", r)?;
                }
                write!(f, "]")
            }
            Binding { pattern, expr } => {
                write!(f, "{} = {}", pattern, expr)
            }
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
            self.args.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
        )
    }
}

impl Call {
    pub fn new(mut args: Vec<Value>) -> Self {
        let func = args.remove(0);
        Self { func, args }
    }
    fn signature(&self, ctx: ScriptContextRef) -> Result<Type, Error> {
        let func_val = self.func.value_of(ctx.clone())?; 
        match func_val {
            Value::NativeObject(obj_ref) => {
                if let Some(callable) = obj_ref.as_callable() {
                    callable.signature(ctx, &self.args)
                } else {
                    bail!("Value {:?} is not callable", self.func)
                }
            }
            _ => bail!("Value {:?} is not a callable function object", self.func),
        }
    }
    fn call(&self, ctx: ScriptContextRef) -> Result<Value, Error> {
        let func_val = self.func.value_of(ctx.clone())?;

        match func_val {
            Value::NativeObject(obj_ref) => {
                if let Some(callable) = obj_ref.as_callable() {
                    let evaluated_args: Result<Vec<Value>, Error> = self
                        .args
                        .iter()
                        .map(|arg_expr| arg_expr.value_of(ctx.clone()))
                        .collect();
                    callable.call(ctx, &evaluated_args?)
                } else {
                    bail!("Value {:?} is not callable", self.func)
                }
            }
            _ => bail!("Value {:?} is not a callable function object", func_val),
        }
    }

    fn unresovled_ids<'s: 'o, 'o>(&'s self, list: &mut HashSet<&'o Value>) {
        self.func.unresovled_ids(list); 
        self.args.iter().for_each(|arg| arg.unresovled_ids(list));
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
        let value = parse($input).unwrap();
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
        let ctx: ScriptContextRef = Default::default(); // Arc<ScriptContext>
        // ScriptContext::new returns ScriptContext, not Arc. We need to wrap it.
        let ctx2 = Arc::new(ScriptContext::new(Some(ctx))); 
        ctx2.set("a".into(), 1.into()); // .set() takes &self, so it works on Arc via Deref.
        let value = parse("a+1").unwrap().value_of(ctx2.clone()).unwrap(); 
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
        // ScriptContext::new returns ScriptContext. Wrap in Arc for ScriptContextRef.
        let ctx = Arc::new(ScriptContext::new(Some(Default::default()))); 
        ctx.set("a".into(), ("xx".to_owned(), 1).into());
        // ctx is already ScriptContextRef (Arc<ScriptContext>)
        let value = parse("a.length+1+a.x")
            .unwrap()
            .value_of(ctx.clone())
            .unwrap();
        assert_eq!(value, 4.into());
        let value = parse("a[a.x] > 200 ? a : \"yy\"")
            .unwrap()
            .value_of(ctx)
            .unwrap();
        assert_eq!(value, "yy".into());
    }

    impl NativeObject for (String, u32) {
        fn as_accessible(&self) -> Option<&dyn Accessible> { Some(self) }
        fn as_evaluatable(&self) -> Option<&dyn Evaluatable> { Some(self) }
        fn as_indexable(&self) -> Option<&dyn Indexable> { Some(self) }
    }

    impl Accessible for (String, u32) {
        fn names(&self) -> Vec<&str> { vec!["length", "x"] }
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
        fn length(&self) -> usize { self.0.len() }
        fn type_of_member(&self, _ctx: ScriptContextRef) -> Result<Type, Error> { Ok(Type::Integer) }
        fn get(&self, index: i64) -> Result<Value, Error> {
            let n = self.0.chars().nth(index as usize)
                .ok_or_else(|| err_msg("index out of range"))? as i64;
            Ok(n.into())
        }
    }

    impl Evaluatable for (String, u32) {
        fn type_of(&self, _ctx: ScriptContextRef) -> Result<Type, Error> { Ok(Type::String) }
        fn value_of(&self, _ctx: ScriptContextRef) -> Result<Value, Error> { Ok(self.0.to_owned().into()) }
    }

    // --- Tests for new Type system features ---
    #[test]
    fn type_display_tests() {
        assert_eq!(Type::Generic("T".into()).to_string(), "T");
        assert_eq!(
            Type::Function {
                params: vec![Type::Integer, Type::String],
                ret: Box::new(Type::Boolean),
            }.to_string(),
            "(integer, string) -> boolean"
        );
        assert_eq!(
            Type::Function {
                params: vec![],
                ret: Box::new(Type::Integer),
            }.to_string(),
            "() -> integer"
        );
        assert_eq!(Type::NativeObject(Arc::new(Box::new(stdlib::ToString::stub()))).to_string(), "native_object");

    }

    #[test]
    fn type_partial_eq_tests() {
        assert_eq!(Type::Generic("T".into()), Type::Generic("T".into()));
        assert_ne!(Type::Generic("T".into()), Type::Generic("U".into()));

        let func_type1 = Type::Function {
            params: vec![Type::Integer],
            ret: Box::new(Type::String),
        };
        let func_type2 = Type::Function {
            params: vec![Type::Integer],
            ret: Box::new(Type::String),
        };
        let func_type3 = Type::Function {
            params: vec![Type::String], // Different param
            ret: Box::new(Type::String),
        };
        let func_type4 = Type::Function {
            params: vec![Type::Integer],
            ret: Box::new(Type::Boolean), // Different return
        };
        assert_eq!(func_type1, func_type2);
        assert_ne!(func_type1, func_type3);
        assert_ne!(func_type1, func_type4);

        assert_ne!(Type::Generic("T".into()), Type::Integer);
        
        // Any comparisons
        assert_eq!(Type::Any, Type::Generic("T".into()));
        assert_eq!(Type::Generic("T".into()), Type::Any);
        assert_eq!(Type::Any, func_type1.clone());
        assert_eq!(func_type1.clone(), Type::Any);
        assert_eq!(Type::Any, Type::Integer);
        assert_eq!(Type::Integer, Type::Any);
    }

    #[test]
    fn value_type_of_function_def_test() {
        let fun_def_val = Value::FunctionDef {
            name: None,
            params: vec![Value::Identifier("x".into()), Value::Identifier("y".into())],
            body: Arc::new(Value::Integer(1)), // Dummy body
        };
        let ctx: ScriptContextRef = Default::default();
        let type_of_fun = fun_def_val.type_of(ctx).unwrap();
        
        assert_eq!(
            type_of_fun,
            Type::Function {
                params: vec![Type::Any, Type::Any],
                ret: Box::new(Type::Any)
            }
        );
    }
    
    #[test]
    fn user_defined_function_signature_test() {
        let udf = UserDefinedFunction {
            name: Some("test_func".into()),
            params: vec!["a".into(), "b".into(), "c".into()],
            body: Arc::new(Value::Integer(1)), // Dummy body
            definition_context: Default::default(),
        };
        let dummy_ctx: ScriptContextRef = Default::default();
        let signature = udf.signature(dummy_ctx, &[]).unwrap(); // Args slice is not used by UDF.signature

        assert_eq!(
            signature,
            Type::Function {
                params: vec![Type::Any, Type::Any, Type::Any],
                ret: Box::new(Type::Any)
            }
        );
    }
     #[test]
    fn type_of_native_object_callable() {
        let to_string_stub = stdlib::ToString::stub(); // A struct that impl NativeObject + Callable
        let native_val = Value::NativeObject(Arc::new(Box::new(to_string_stub)));
        let ctx: ScriptContextRef = Default::default();
        let type_of_native = native_val.type_of(ctx).unwrap();

        // stdlib::ToString is function!(ToString(s: Any)=>String, ...);
        // So its signature should be (any) -> string
        assert_eq!(
            type_of_native,
            Type::Function {
                params: vec![Type::Any], // ToString takes one arg of Type::Any
                ret: Box::new(Type::String)
            }
        );
    }
}

[end of milu/src/script.rs]
