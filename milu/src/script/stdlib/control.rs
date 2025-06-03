use crate::{args, function_head}; // Added macro imports
use async_trait::async_trait;
use easy_error::{Error, bail, err_msg}; // ResultExt can be removed
use std::collections::HashSet; // For unresovled_ids in Access and Scope
use std::convert::TryInto;
use std::sync::Arc; // Added Weak for ScriptContextWeakRef
use tracing::trace;

// Adjust crate::script::* to specific imports
use crate::script::{
    Accessible, Callable, Evaluatable, Indexable, NativeObject, ScriptContext, ScriptContextRef,
    ScriptContextWeakRef, Type, UserDefinedFunction, Value,
};

// Note: The function! and function_head! macros are defined in stdlib/mod.rs

// --- Control Flow and Access Functions ---

function_head!(Index(obj: Any, index: Any) => Any);
#[async_trait]
impl Callable for Index {
    async fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        let obj_val = &args[0];
        let index_val = &args[1];
        if index_val.type_of(ctx.clone()).await? != Type::Integer {
            bail!("Index not a integer type")
        } else if let Value::NativeObject(nobj) = obj_val {
            if let Some(idx) = nobj.as_indexable() {
                idx.type_of_member(ctx).await
            } else {
                bail!("NativeObject not in indexable")
            }
        } else if let Type::Array(t) = obj_val.type_of(ctx).await? {
            Ok(*t)
        } else {
            bail!("Object does not implement Indexable: {:?}", obj_val)
        }
    }
    async fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        args!(args, obj, index);
        let index_val: i64 = index.value_of(ctx.clone()).await?.try_into()?;
        let obj_eval = obj.value_of(ctx.clone()).await?;
        let obj_indexable: &dyn Indexable = match &obj_eval {
            Value::Array(a) => a.as_ref(),
            Value::NativeObject(a) => a
                .as_indexable()
                .ok_or_else(|| err_msg("NativeObject does not implement Indexible"))?,
            _ => bail!(
                "type mismatch, expected Array or Indexable NativeObject, got {:?}",
                obj_eval.type_of_simple()
            ),
        };
        obj_indexable.get(index_val)?.value_of(ctx).await
    }
}

function_head!(Access(obj: Any, index: Any) => Any);
#[async_trait]
impl Callable for Access {
    async fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        async fn get_accessible_type(
            ctx: ScriptContextRef,
            obj: &dyn Accessible,
            index_val: &Value,
        ) -> Result<Type, Error> {
            let index_str = if let Value::Identifier(s) = index_val {
                s
            } else {
                bail!("Can not access a NativeObject with: {:?}", index_val)
            };
            obj.type_of(index_str, ctx).await
        }

        async fn get_tuple_type(
            _ctx: ScriptContextRef,
            obj_type: Type,
            index_val: &Value,
        ) -> Result<Type, Error> {
            let idx = if let Value::Integer(i) = index_val {
                *i
            } else {
                bail!("Can not access a tuple with: {}", index_val)
            };
            if let Type::Tuple(mut t) = obj_type {
                if idx < 0 || idx as usize >= t.len() {
                    bail!("Tuple index out of bounds: {}", idx);
                }
                Ok(t.remove(idx as usize))
            } else {
                bail!("Can not access type: {}", obj_type)
            }
        }

        let obj_arg = &args[0];
        let obj_type = obj_arg.type_of(ctx.clone()).await?;
        trace!("obj={:?} obj_type={:?}", obj_arg, obj_type);
        let index_arg = &args[1];

        if let Type::NativeObject(obj_arc) = obj_type {
            if let Some(acc_obj) = obj_arc.as_accessible() {
                get_accessible_type(ctx, acc_obj, index_arg).await
            } else if let Some(eval_obj) = obj_arc.as_evaluatable() {
                let inner_obj_type = eval_obj.type_of(ctx.clone()).await?;
                get_tuple_type(ctx, inner_obj_type, index_arg).await
            } else {
                bail!("NativeObject not accessible or tuple")
            }
        } else if let Type::Tuple(_) = obj_type {
            get_tuple_type(ctx, obj_type, index_arg).await
        } else {
            bail!("Object {:?} is not Tuple nor Accessible", obj_arg)
        }
    }

    async fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        async fn call_accessible(
            ctx: ScriptContextRef,
            obj: &dyn Accessible,
            index_val: &Value,
        ) -> Result<Value, Error> {
            let index_str = if let Value::Identifier(s) = index_val {
                s
            } else {
                bail!("Can not access a NativeObject with: {:?}", index_val)
            };
            let ret = obj.get(index_str)?;
            ret.value_of(ctx).await
        }

        async fn call_tuple(
            ctx: ScriptContextRef,
            obj_val: Value,
            index_val: &Value,
        ) -> Result<Value, Error> {
            let idx_i64 = if let Value::Integer(i) = index_val {
                *i
            } else {
                bail!(
                    "Can not access a tuple with: {:?} - index must be an integer",
                    index_val
                )
            };
            if let Value::Tuple(t_arc) = obj_val {
                let t_len = t_arc.len();
                if idx_i64 < 0 || (idx_i64 as usize) >= t_len {
                    bail!("index out of bounds: {}", idx_i64);
                }
                let final_idx_usize = idx_i64 as usize;
                t_arc[final_idx_usize].value_of(ctx).await
            } else {
                bail!(
                    "Can not access type: {:?} - expected a Tuple",
                    obj_val.type_of_simple()
                )
            }
        }

        let obj_eval = args[0].value_of(ctx.clone()).await?;
        let index_arg = &args[1];

        if let Value::NativeObject(native_obj_ref) = &obj_eval {
            if let Some(acc_obj) = native_obj_ref.as_accessible() {
                call_accessible(ctx, acc_obj, index_arg).await
            } else if let Some(eval_obj) = native_obj_ref.as_evaluatable() {
                let inner_obj = eval_obj.value_of(ctx.clone()).await?;
                call_tuple(ctx, inner_obj, index_arg).await
            } else {
                bail!("NativeObject not accessible or tuple")
            }
        } else if let Value::Tuple(_) = &obj_eval {
            call_tuple(ctx, obj_eval, index_arg).await
        } else {
            bail!(
                "Object {:?} is not Tuple nor Accessible",
                obj_eval.type_of_simple()
            )
        }
    }

    fn unresovled_ids<'s: 'o, 'o>(&'s self, args: &'s [Value], ids: &mut HashSet<&'o Value>) {
        args[0].unresovled_ids(ids);
    }
}

function_head!(If(cond: Boolean, yes: Any, no: Any) => Any);
#[async_trait]
impl Callable for If {
    async fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        let mut targs: Vec<Type> = Vec::with_capacity(args.len());
        for x in args {
            targs.push(x.type_of(ctx.clone()).await?);
        }
        args!(targs, cond, yes, no);
        if Type::Boolean != cond {
            bail!("Condition type {:?} is not a Boolean", cond);
        }
        if yes != no {
            bail!("Condition return type must be same: {:?} {:?}", yes, no);
        }
        Ok(yes)
    }
    async fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        let cond: bool = args[0].value_of(ctx.clone()).await?.try_into()?;
        if cond {
            args[1].value_of(ctx).await
        } else {
            args[2].value_of(ctx).await
        }
    }
}

#[derive(Clone)] // Added Clone
pub struct ScopeBinding {
    // Made pub
    ctx: ScriptContextWeakRef,
    value: Value,
}

impl std::fmt::Debug for ScopeBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopeBinding")
            .field("value", &self.value)
            .finish()
    }
}

impl std::hash::Hash for ScopeBinding {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

#[async_trait]
impl Evaluatable for ScopeBinding {
    async fn type_of(&self, _ctx: ScriptContextRef) -> Result<Type, Error> {
        let strong_ctx = self
            .ctx
            .upgrade()
            .ok_or_else(|| err_msg("Scope context lost for type_of"))?;
        self.value.type_of(strong_ctx).await
    }
    async fn value_of(&self, _calling_ctx: ScriptContextRef) -> Result<Value, Error> {
        let strong_ctx = self
            .ctx
            .upgrade()
            .ok_or_else(|| err_msg("Scope context lost for value_of"))?;
        self.value.real_value_of(strong_ctx).await
    }
}

impl NativeObject for ScopeBinding {
    fn as_evaluatable(&self) -> Option<&dyn Evaluatable> {
        Some(self)
    }
    fn as_callable(&self) -> Option<&dyn Callable> {
        None
    }
    // Added this to make it a valid NativeObject, assuming it doesn't need to be indexable/accessible
    fn as_indexable(&self) -> Option<&dyn Indexable> {
        None
    }
    fn as_accessible(&self) -> Option<&dyn Accessible> {
        None
    }
}

function_head!(Scope(vars: Type::array_of(Type::Any), expr: Any) => Any);
impl Scope {
    fn make_context(
        vars: &[Value],
        outer_ctx: ScriptContextRef,
    ) -> Result<ScriptContextRef, Error> {
        let mut error: Option<Error> = None;
        let ctx_arc = Arc::new_cyclic(|weak_self| {
            let mut new_ctx = ScriptContext::new(Some(outer_ctx.clone()));
            for v_or_pf in vars.iter() {
                match v_or_pf {
                    Value::ParsedFunction(parsed_fn_arc) => {
                        let name_str = match &parsed_fn_arc.name_ident {
                            Value::Identifier(s) => s.clone(),
                            _ => {
                                error = Some(err_msg("Function name must be an identifier"));
                                break;
                            }
                        };
                        let mut arg_names_str = Vec::new();
                        for arg_ident_val in &parsed_fn_arc.arg_idents {
                            match arg_ident_val {
                                Value::Identifier(s) => arg_names_str.push(s.clone()),
                                _ => {
                                    error = Some(err_msg("Function arguments must be identifiers"));
                                    break;
                                }
                            }
                        }
                        if error.is_some() {
                            break;
                        } // Check error before continuing
                        let udf = UserDefinedFunction {
                            name: Some(name_str.clone()),
                            arg_names: arg_names_str,
                            body: parsed_fn_arc.body.clone(),
                            captured_context: weak_self.clone(),
                        };
                        new_ctx
                            .varibles
                            .insert(name_str, Value::Function(Arc::new(udf)));
                    }
                    Value::Tuple(pair_arc) => {
                        let t = pair_arc.as_ref();
                        if t.len() != 2 {
                            error =
                                Some(err_msg(format!("Invalid variable binding tuple: {:?}", t)));
                            break;
                        }
                        let id = match &t[0] {
                            Value::Identifier(s) => s.clone(),
                            _ => {
                                error = Some(err_msg("Binding name must be an identifier"));
                                break;
                            }
                        };
                        let value = t[1].clone();
                        let scope_bound_value = ScopeBinding {
                            ctx: weak_self.clone(),
                            value,
                        };
                        new_ctx.varibles.insert(id, scope_bound_value.into());
                    }
                    _ => {
                        error = Some(err_msg(format!(
                            "Invalid item in let binding list: {:?}. Expected Tuple or ParsedFunction.",
                            v_or_pf
                        )));
                        break;
                    }
                }
            }
            new_ctx
        });
        if let Some(e) = error {
            Err(e)
        } else {
            Ok(ctx_arc)
        }
    }
}
#[async_trait]
impl Callable for Scope {
    async fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        let fn_ctx = Self::make_context(args[0].as_vec(), ctx)?;
        let expr = args[1].type_of(fn_ctx).await?;
        Ok(expr)
    }
    async fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        let new_scope_ctx = Self::make_context(args[0].as_vec(), ctx)?;
        args[1].real_value_of(new_scope_ctx).await
    }
    fn unresovled_ids<'s: 'o, 'o>(
        &'s self,
        args: &'s [Value],
        main_output_ids: &mut HashSet<&'o Value>,
    ) {
        let vars_array_val = &args[0];
        let let_body_expr = &args[1];
        let mut let_defined_names = HashSet::<String>::new();
        if let Value::Array(vars_arc) = vars_array_val {
            for binding_val in vars_arc.iter() {
                match binding_val {
                    Value::Tuple(pair) if pair.len() == 2 => {
                        if let Value::Identifier(name_str) = &pair[0] {
                            let_defined_names.insert(name_str.clone());
                        }
                    }
                    Value::ParsedFunction(pf) => {
                        if let Value::Identifier(name_str) = &pf.name_ident {
                            let_defined_names.insert(name_str.clone());
                        }
                    }
                    _ => continue,
                }
            }
        }
        if let Value::Array(vars_arc) = vars_array_val {
            for binding_val in vars_arc.iter() {
                let assign_value_ref = match binding_val {
                    Value::Tuple(pair) if pair.len() == 2 => &pair[1],
                    Value::ParsedFunction(pf) => &pf.body,
                    _ => continue,
                };
                assign_value_ref.unresovled_ids(main_output_ids);
            }
        }
        let mut temp_body_unresolved_ids = HashSet::new();
        let_body_expr.unresovled_ids(&mut temp_body_unresolved_ids);
        for id_val_from_body in temp_body_unresolved_ids {
            if let Value::Identifier(name_str_from_body) = id_val_from_body {
                if !let_defined_names.contains(name_str_from_body) {
                    main_output_ids.insert(id_val_from_body);
                }
            }
        }
    }
}
