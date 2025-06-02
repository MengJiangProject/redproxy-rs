use async_trait::async_trait;
use easy_error::{bail, err_msg, Error};
use std::{collections::HashSet, fmt::Display, sync::Arc}; // Added err_msg back as it's used

use super::context::{ScriptContext, ScriptContextRef, ScriptContextWeakRef}; // For UDF context
use super::traits::{Callable, Evaluatable, NativeObjectRef};
use super::types::Type;
use super::value::Value; // Value is used extensively // Added Evaluatable, Callable for UDF, NativeObjectRef for ResolvedFunction

#[derive(Debug, Clone)]
pub struct UserDefinedFunction {
    pub name: Option<String>,
    pub arg_names: Vec<String>,
    pub body: Value,
    pub captured_context: ScriptContextWeakRef,
}

impl PartialEq for UserDefinedFunction {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.arg_names == other.arg_names && self.body == other.body
        // Note: captured_context comparison is tricky due to Weak pointers.
        // If true equality including context is needed, it's more complex.
        // For hashing and general purposes, comparing name, args, and body is often sufficient.
    }
}
impl Eq for UserDefinedFunction {}

impl std::hash::Hash for UserDefinedFunction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.arg_names.hash(state);
        self.body.hash(state);
        // Weak pointers (captured_context) cannot be directly hashed easily or meaningfully in most cases.
        // Hashing based on content that defines the function is typical.
    }
}

#[async_trait]
impl Callable for UserDefinedFunction {
    async fn signature(&self, _ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        if args.len() != self.arg_names.len() {
            bail!(
                "expected {} arguments, got {}",
                self.arg_names.len(),
                args.len()
            );
        }
        Ok(Type::Any) // UDFs are type-checked at runtime or more dynamically; Any for now
    }

    async fn call(&self, caller_context: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        if args.len() != self.arg_names.len() {
            bail!(
                "expected {} arguments, got {}",
                self.arg_names.len(),
                args.len()
            );
        }

        let captured_ctx_strong = self.captured_context.upgrade().ok_or_else(|| {
            err_msg(format!(
                "Captured context for function '{}' was dropped",
                self.name.as_deref().unwrap_or("<anonymous>")
            ))
        })?;

        let mut fn_ctx = ScriptContext::new(Some(captured_ctx_strong));
        for (i, arg_name) in self.arg_names.iter().enumerate() {
            let arg_value = args[i].real_value_of(caller_context.clone()).await?;
            fn_ctx.set(arg_name.clone(), arg_value);
        }
        self.body.real_value_of(Arc::new(fn_ctx)).await
    }

    fn unresovled_ids<'s: 'o, 'o>(&'s self, args: &'s [Value], ids: &mut HashSet<&'o Value>) {
        // Arguments to a UDF call are resolved in the caller's context
        args.iter().for_each(|v| v.unresovled_ids(ids));

        // For the body of the UDF, unresolved IDs are those not matching its own arguments
        let mut body_ids = HashSet::new();
        self.body.unresovled_ids(&mut body_ids);

        for id_val_from_body in body_ids {
            if let Value::Identifier(id_name_from_body) = id_val_from_body {
                if !self.arg_names.contains(id_name_from_body) {
                    ids.insert(id_val_from_body);
                }
            } else {
                // Non-identifier unresolved items from body (e.g. OpCall to undefined func)
                ids.insert(id_val_from_body);
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParsedFunction {
    pub name_ident: Value,      // Should be Value::Identifier
    pub arg_idents: Vec<Value>, // Should be Vec<Value::Identifier>
    pub body: Value,
}

impl std::hash::Hash for ParsedFunction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name_ident.hash(state);
        self.arg_idents.hash(state);
        self.body.hash(state);
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

impl Display for Call {
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

    pub async fn signature(&self, ctx: ScriptContextRef) -> Result<Type, Error> {
        let resolved_func = self.resolve_func(ctx.clone()).await?;
        match resolved_func {
            ResolvedFunction::Native(native_ref) => {
                native_ref
                    .as_callable()
                    .ok_or_else(|| {
                        err_msg(
                            "Internal error: NativeObject marked callable but as_callable is None",
                        )
                    })?
                    .signature(ctx, &self.args)
                    .await
            }
            ResolvedFunction::User(udf_ref) => udf_ref.signature(ctx, &self.args).await,
        }
    }

    pub async fn call(&self, ctx: ScriptContextRef) -> Result<Value, Error> {
        let resolved_func = self.resolve_func(ctx.clone()).await?;
        match resolved_func {
            ResolvedFunction::Native(native_ref) => {
                native_ref
                    .as_callable()
                    .ok_or_else(|| {
                        err_msg(
                            "Internal error: NativeObject marked callable but as_callable is None",
                        )
                    })?
                    .call(ctx, &self.args)
                    .await
            }
            ResolvedFunction::User(udf_ref) => udf_ref.call(ctx, &self.args).await,
        }
    }

    async fn resolve_func(&self, ctx: ScriptContextRef) -> Result<ResolvedFunction, Error> {
        // Renamed from `func` to avoid conflict
        let resolved_fn_val = if let Value::Identifier(_) = &self.func {
            self.func.value_of(ctx).await? // Assumes Value has value_of
        } else {
            self.func.clone()
        };

        match resolved_fn_val {
            Value::NativeObject(arc_native_ref) => {
                if arc_native_ref.as_callable().is_some() {
                    Ok(ResolvedFunction::Native(arc_native_ref))
                } else {
                    Err(err_msg(format!(
                        "Value {:?} is not a callable function type (NativeObject not callable)",
                        arc_native_ref
                    )))
                }
            }
            Value::Function(arc_udf) => Ok(ResolvedFunction::User(arc_udf)),
            other_val => Err(err_msg(format!(
                "Value {:?} is not a callable function type",
                other_val
            ))),
        }
    }

    pub fn unresovled_ids<'s: 'o, 'o>(&'s self, ids: &mut HashSet<&'o Value>) {
        // Made pub
        match &self.func {
            Value::Identifier(_) => {
                ids.insert(&self.func); // The function name itself is an ID
                for arg in &self.args {
                    // Arguments are expressions that might contain IDs
                    arg.unresovled_ids(ids);
                }
            }
            Value::Function(udf_arc) => {
                // If func is a direct UDF value (e.g. from a variable)
                udf_arc.unresovled_ids(&self.args, ids); // Check args against UDF params and body
            }
            Value::NativeObject(nobj_arc) => {
                // If func is a NativeObject that's callable
                if let Some(callable_trait_obj) = nobj_arc.as_callable() {
                    callable_trait_obj.unresovled_ids(&self.args, ids);
                } else {
                    // Should not happen if it's a valid call target
                    self.func.unresovled_ids(ids); // Fallback: check func value itself for IDs
                    for arg in &self.args {
                        arg.unresovled_ids(ids);
                    }
                }
            }
            _ => {
                // Other direct values used as functions (e.g. string, integer) - usually an error at runtime
                // but for static analysis, treat the func part as potentially having IDs if it's complex.
                self.func.unresovled_ids(ids);
                for arg in &self.args {
                    arg.unresovled_ids(ids);
                }
            }
        }
    }
}
