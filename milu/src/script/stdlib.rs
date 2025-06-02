use async_trait::async_trait;
use std::convert::TryInto; // Removed RefCell

use easy_error::bail;
use tracing::trace;

use super::*;

#[macro_export]
macro_rules! function_head {
    ($name:ident ($($aname:ident : $atype:expr),+) => $rtype:expr) => {

        // the String field is added to avoid hashing a empty struct always returns same value
        #[derive(Clone,Hash)]
        pub struct $name(String);

        #[allow(dead_code)]
        impl $name {
            pub fn stub() -> $name {$name(stringify!($name).into())}
            pub fn make_call($($aname : Value),+) -> Call {
                Call::new(vec![$name(stringify!($name).into()).into(), $($aname),+ ])
            }
        }
        impl NativeObject for $name {
            fn as_callable(&self) -> Option<&dyn Callable>{Some(self)}
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f,"{}", stringify!($name))
            }
        }
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f,"{}", stringify!($name))
            }
        }
    };
}

#[macro_export]
macro_rules! args {
    ($args:ident, $($aname:ident),+) => {
        let mut iter = $args.into_iter();
        $(let $aname = iter.next().unwrap();)+
    };
    ($args:ident, ctx=$ctx:ident, $($aname:ident),+) => {
        args!($args, ctx=$ctx, opts=expand, $($aname),+);
    };
    ($args:ident, ctx=$ctx:ident, opts=expand, $($aname:ident),+) => {
        let mut iter = $args.into_iter();
        $(
            let $aname = iter.next().unwrap().real_value_of($ctx.clone()).await?;
        )+
    };
    ($args:ident, ctx=$ctx:ident, opts=raw, $($aname:ident),+) => {
        let mut iter = $args.into_iter();
        $(
            let $aname = iter.next().unwrap();
        )+
    };
}

#[macro_export]
macro_rules! function {
    ($name:ident ($($aname:ident : $atype:expr),+) => $rtype:expr, $body:tt) =>{
        function!($name ($($aname : $atype),+) => $rtype, ctx=ctx, $body);
    };
    ($name:ident ($($aname:ident : $atype:expr),+) => $rtype:expr, ctx=$ctx:ident, $body:tt) => {
        function!($name ($($aname : $atype),+) => $rtype, ctx=$ctx, arg_opts=expand, $body);
    };
    ($name:ident ($($aname:ident : $atype:expr),+) => $rtype:expr, ctx=$ctx:ident, arg_opts=$arg_opts:ident, $body:tt) => {
        $crate::function_head!($name ($($aname : $atype),+) => $rtype);
        #[async_trait]
        impl Callable for $name {
            async fn signature( // Made async
                &self,
                $ctx: ScriptContextRef,
                args: &[Value],
            ) -> Result<Type, Error>
            {
                let mut targs : Vec<Type> = Vec::with_capacity(args.len());
                for x in args {
                    let t = x.real_type_of($ctx.clone()).await?; // Added await
                    targs.push(t);
                }
                $crate::args!(targs, $($aname),+);
                use Type::*;
                $(if $aname != $atype {
                    bail!("argument {} type mismatch, required: {} provided: {:?}",
                        stringify!($aname),
                        stringify!($atype),
                        $aname
                    )
                })+
                Ok($rtype)
            }
            #[allow(unused_braces)]
            async fn call(
                &self,
                $ctx: ScriptContextRef,
                args: &[Value],
            ) -> Result<Value, Error>
            {
                $crate::args!(args, ctx=$ctx, opts=$arg_opts, $($aname),+);
                $body
            }
        }
    };
}

// Access an array which is a sequence of values in same type with a dynamic index
// Can not access a tuple dynamically because it's not able to do type inference statically.
function_head!(Index(obj: Any, index: Any) => Any);
#[async_trait]
impl Callable for Index {
    async fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        let obj_val = &args[0]; // Renamed obj to obj_val to avoid conflict
        let index_val = &args[1]; // Renamed index to index_val
        if index_val.type_of(ctx.clone()).await? != Type::Integer {
            // Added await
            bail!("Index not a integer type")
        } else if let Value::NativeObject(nobj) = obj_val {
            // Used obj_val
            if let Some(idx) = nobj.as_indexable() {
                idx.type_of_member(ctx).await
            } else {
                bail!("NativeObject not in indexable")
            }
        } else if let Type::Array(t) = obj_val.type_of(ctx).await? {
            // Used obj_val, added await
            Ok(*t)
        } else {
            bail!("Object does not implement Indexable: {:?}", obj_val) // Used obj_val
        }
    }
    async fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        args!(args, obj, index);
        let index: i64 = index.value_of(ctx.clone()).await?.try_into()?;
        let obj = obj.value_of(ctx.clone()).await?;
        let obj: &dyn Indexable = match &obj {
            Value::Array(a) => a.as_ref(),
            Value::NativeObject(a) => a
                .as_indexable()
                .ok_or_else(|| err_msg("NativeObject does not implement Indexible"))?,
            _ => bail!("type mismatch"),
        };
        obj.get(index)?.value_of(ctx).await
    }
}

// Access a nativeobject or a tuple
function_head!(Access(obj: Any, index: Any) => Any);
#[async_trait]
impl Callable for Access {
    async fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        // Made async
        async fn accessible(
            // Made async
            ctx: ScriptContextRef,
            obj: &dyn Accessible,
            index: &Value,
        ) -> Result<Type, Error> {
            let index = if let Value::Identifier(index) = index {
                index
            } else {
                bail!("Can not access a NativeObject with: {:?}", index)
            };
            obj.type_of(index, ctx).await // Added await
        }

        async fn tuple(_ctx: ScriptContextRef, obj: Type, index: &Value) -> Result<Type, Error> {
            let index = if let Value::Integer(index) = index {
                index
            } else {
                bail!("Can not access a tuple with: {}", index)
            };
            if let Type::Tuple(mut t) = obj {
                Ok(t.remove(*index as usize))
            } else {
                bail!("Can not access type: {}", obj)
            }
        }

        let obj = &args[0];
        // if obj is an identifier, we need to resolve it from context
        let objt = obj.type_of(ctx.clone()).await?; // Added .await as Value::type_of is async
        trace!("obj={:?} objt={:?}", obj, objt);
        // index is always a literal value, either identifier or integer
        let index = &args[1];
        if let Type::NativeObject(obj_arc) = objt {
            if let Some(acc_obj) = obj_arc.as_accessible() {
                accessible(ctx, acc_obj, index).await
            } else if let Some(eval_obj) = obj_arc.as_evaluatable() {
                let inner_obj_type = eval_obj.type_of(ctx.clone()).await?; // Added .await
                tuple(ctx, inner_obj_type, index).await
            } else {
                bail!("NativeObject not accessible or tuple")
            }
        } else if let Type::Tuple(_) = objt {
            tuple(ctx, objt, index).await // Added await
        } else {
            bail!("Object {:?} is not Tuple nor Accessible", obj)
        }
    }

    async fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        async fn accessible(
            ctx: ScriptContextRef,
            obj: &dyn Accessible,
            index: &Value,
        ) -> Result<Value, Error> {
            let index = if let Value::Identifier(index) = index {
                index
            } else {
                bail!("Can not access a NativeObject with: {:?}", index)
            };
            let ret = obj.get(index)?;
            ret.value_of(ctx).await
        }

        async fn tuple(
            ctx: ScriptContextRef,
            obj: Value,
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
            if let Value::Tuple(t) = obj {
                let t_len = t.len();
                // Bounds check
                if idx_i64 < 0 || (idx_i64 as usize) >= t_len {
                    // Match the error message format that array tests expect for "index out of bounds: <index>"
                    bail!("index out of bounds: {}", idx_i64);
                }
                let final_idx_usize = idx_i64 as usize;
                t[final_idx_usize].value_of(ctx).await
            } else {
                bail!("Can not access type: {:?} - expected a Tuple", obj)
            }
        }

        let obj_val = args[0].value_of(ctx.clone()).await?;
        let index = &args[1];
        if let Value::NativeObject(native_obj_ref) = &obj_val {
            if let Some(acc_obj) = native_obj_ref.as_accessible() {
                accessible(ctx, acc_obj, index).await
            } else if let Some(eval_obj) = native_obj_ref.as_evaluatable() {
                let inner_obj = eval_obj.value_of(ctx.clone()).await?;
                tuple(ctx, inner_obj, index).await
            } else {
                bail!("NativeObject not accessible or tuple")
            }
        } else if let Value::Tuple(_) = &obj_val {
            tuple(ctx, obj_val, index).await
        } else {
            bail!("Object {:?} is not Tuple nor Accessible", obj_val)
        }
    }

    fn unresovled_ids<'s: 'o, 'o>(&'s self, args: &'s [Value], ids: &mut HashSet<&'o Value>) {
        // Changed &self to &'s self
        args[0].unresovled_ids(ids) // args[1] is always literal identifier or integer, thus not unresolved
    }
}

function_head!(If(cond: Boolean, yes: Any, no: Any) => Any);
#[async_trait]
impl Callable for If {
    async fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        let mut targs: Vec<Type> = Vec::with_capacity(args.len());
        for x in args {
            targs.push(x.type_of(ctx.clone()).await?); // Added await
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

struct ScopeBinding {
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

#[async_trait] // Ensure async_trait is here
impl Evaluatable for ScopeBinding {
    async fn type_of(&self, _ctx: ScriptContextRef) -> Result<Type, Error> {
        // Made async
        // If self.value.type_of becomes async, this will need .await
        // For now, assuming self.value.type_of is still effectively sync or blocks if it calls async code
        self.value.type_of(self.ctx.upgrade().unwrap()).await
    }

    async fn value_of(&self, _calling_ctx: ScriptContextRef) -> Result<Value, Error> {
        // A ScopeBinding always evaluates its stored value within its captured context.
        // The calling_ctx is not used here because the value's resolution is fixed at definition.
        self.value.real_value_of(self.ctx.upgrade().unwrap()).await
    }
}

impl NativeObject for ScopeBinding {
    fn as_evaluatable(&self) -> Option<&dyn Evaluatable> {
        Some(self)
    }
    fn as_callable(&self) -> Option<&dyn Callable> {
        None // ScopeBinding itself is not callable
    }
}

// Removed impl Callable for ScopeBinding block

function_head!(Scope(vars: Array, expr: Any) => Any);
impl Scope {
    fn make_context(
        vars: &[Value],
        outer_ctx: ScriptContextRef,
    ) -> Result<ScriptContextRef, Error> {
        // Use Arc::new_cyclic to allow self-referential context
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
// Note: #[async_trait] was already on `impl Scope` which is fine.
// We are modifying `impl Callable for Scope` which is separate.
#[async_trait]
impl Callable for Scope {
    async fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        let fn_ctx = Self::make_context(args[0].as_vec(), ctx)?;
        let expr = args[1].type_of(fn_ctx).await?; // Added await
        Ok(expr)
    }
    async fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        let new_scope_ctx = Self::make_context(args[0].as_vec(), ctx)?;
        // Use real_value_of to ensure the result of the 'in' expression is fully unwrapped
        args[1].real_value_of(new_scope_ctx).await
    }

    fn unresovled_ids<'s: 'o, 'o>(
        &'s self,
        args: &'s [Value],
        main_output_ids: &mut HashSet<&'o Value>,
    ) {
        let vars_array_val = &args[0]; // Value::Array of bindings
        let let_body_expr = &args[1]; // The "in" expression

        let mut let_defined_names = HashSet::<String>::new();

        // First pass: collect all names defined on the LHS of bindings in this let block
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

        // Second pass: process RHS of each binding.
        // Unresolved IDs from RHS are added directly to main_output_ids.
        // This means they are checked against the scope *outside* this 'let' block,
        // and are not resolved by other bindings in the *same* 'let' block.
        // This matches the test's expectation for 'a' in 'b=a+1'.
        if let Value::Array(vars_arc) = vars_array_val {
            for binding_val in vars_arc.iter() {
                let assign_value_ref = match binding_val {
                    Value::Tuple(pair) if pair.len() == 2 => &pair[1],
                    Value::ParsedFunction(pf) => &pf.body,
                    _ => continue,
                };
                // Value::unresovled_ids (called by assign_value_ref.unresovled_ids)
                // for ParsedFunction already handles filtering out its own arguments.
                // So, whatever remains in main_output_ids from this call are
                // truly unresolved from the perspective of the function's body and its arguments.
                assign_value_ref.unresovled_ids(main_output_ids);
            }
        }

        // Third pass: process the main body expression (the "in" part)
        let mut temp_body_unresolved_ids = HashSet::new();
        let_body_expr.unresovled_ids(&mut temp_body_unresolved_ids);

        for id_val_from_body in temp_body_unresolved_ids {
            if let Value::Identifier(name_str_from_body) = id_val_from_body {
                if !let_defined_names.contains(name_str_from_body) {
                    main_output_ids.insert(id_val_from_body);
                }
            }
            // else: Non-identifiers from the body are not added here.
            // If an OpCall, for instance, was in temp_body_unresolved_ids, it means its *name* was unresolved,
            // or its arguments contained unresolved identifiers. These would have been Value::Identifier.
        }
    }
}

function_head!(IsMemberOf(a: Any, ary: Array) => Boolean);
#[async_trait]
impl Callable for IsMemberOf {
    async fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        let mut targs: Vec<Type> = Vec::with_capacity(args.len());
        for x in args {
            targs.push(x.type_of(ctx.clone()).await?); // Added await
        }
        args!(targs, a, ary);
        let ary_type = if let Type::Array(inner_type) = ary {
            *inner_type
        } else {
            bail!("argument type {:?} is not an Array", ary);
        };
        if a != ary_type {
            bail!(
                "subject must have on same type with array: subj={:?} array_member_type={:?}",
                a,
                ary_type
            );
        }
        Ok(Type::Boolean)
    }
    async fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        args!(args, ctx = ctx, a, ary);
        let vec: Arc<Vec<Value>> = ary.try_into()?;
        for v_val_in_array in vec.iter() {
            let v_eval = v_val_in_array.value_of(ctx.clone()).await?;
            if v_eval == a {
                return Ok(true.into());
            }
        }
        Ok(false.into())
    }
}

function!(Not(b:Boolean)=>Boolean, {
    let b:bool = b.try_into()?;
    Ok((!b).into())
});

function!(BitNot(b:Integer)=>Integer, {
    let b:i64 = b.try_into()?;
    Ok((!b).into())
});

function!(Negative(b:Integer)=>Integer, {
    let b:i64 = b.try_into()?;
    Ok((-b).into())
});

macro_rules! int_op_div_mod {
    ($name:ident, $op:tt) => {
        function!($name(a: Integer, b: Integer) => Integer, {
            // 'a' and 'b' are Value::Integer from args! macro, or Value::Any if type check is loose
            // try_into() is on Value itself.
            let a_val: i64 = a.clone().try_into().map_err(|_| err_msg(format!("type mismatch: expected Integer for LHS, got {:?}", a)))?;
            let b_val: i64 = b.clone().try_into().map_err(|_| err_msg(format!("type mismatch: expected Integer for RHS, got {:?}", b)))?;
            if b_val == 0 {
                bail!("division by zero");
            }
            Ok((a_val $op b_val).into())
        });
    }
}

macro_rules! int_op {
    ($name:ident, $op:tt) => {
        function!($name(a: Integer, b: Integer) => Integer, {
            let a_val: i64 = a.clone().try_into().map_err(|_| err_msg(format!("type mismatch: expected Integer for LHS, got {:?}", a)))?;
            let b_val: i64 = b.clone().try_into().map_err(|_| err_msg(format!("type mismatch: expected Integer for RHS, got {:?}", b)))?;
            Ok((a_val $op b_val).into())
        });
    }
}

int_op!(Plus,+);
int_op!(Minus,-);
int_op!(Multiply,*);
int_op_div_mod!(Divide,/);
int_op_div_mod!(Mod,%);
int_op!(BitAnd,&);
int_op!(BitOr,|);
int_op!(BitXor,^);
int_op!(ShiftLeft,<<);
int_op!(ShiftRight,>>);
function!(ShiftRightUnsigned(a: Integer, b: Integer)=>Integer, {
    let a:i64 = a.try_into()?;
    let b:i64 = b.try_into()?;
    let a = a as u64;
    let a = (a >> b) as i64;
    Ok(a.into())
});

function!(And(a: Boolean, b: Boolean)=>Boolean, ctx=ctx, arg_opts=raw,{
    let a_val:bool = a.real_value_of(ctx.clone()).await?.try_into()?;
    let b_val:bool = b.real_value_of(ctx).await?.try_into()?;
    let ret:bool = a_val && b_val;
    Ok(ret.into())
});

function!(Or(a: Boolean, b: Boolean)=>Boolean, ctx=ctx, arg_opts=raw,{
    let a_val:bool = a.real_value_of(ctx.clone()).await?.try_into()?;
    let b_val:bool = b.real_value_of(ctx).await?.try_into()?;
    let ret:bool = a_val || b_val;
    Ok(ret.into())
});

function!(Xor(a: Boolean, b: Boolean)=>Boolean, ctx=ctx, arg_opts=raw,{
    let a_val:bool = a.real_value_of(ctx.clone()).await?.try_into()?;
    let b_val:bool = b.real_value_of(ctx).await?.try_into()?;
    let ret:bool = a_val ^ b_val;
    Ok(ret.into())
});

macro_rules! compare_op {
    ($name:ident, $op:tt, $fallback_different_types:expr) => {
        function!($name(a: Any, b: Any) => Boolean, {
            match (a, b) {
                (Value::Integer(a_val), Value::Integer(b_val)) => Ok((a_val $op b_val).into()),
                (Value::String(a_val), Value::String(b_val)) => Ok((a_val $op b_val).into()),
                (Value::Boolean(a_val), Value::Boolean(b_val)) => Ok((a_val $op b_val).into()),
                // If types are different, or types are same but not Integer/String/Boolean (e.g. Array, Tuple)
                _ => Ok($fallback_different_types.into()),
            }
        });
    }
}

// Note: Greater, GreaterOrEqual, Lesser, LesserOrEqual might also need a decision for mixed types.
// For now, they will use the old panic behavior if we don't update them.
// Or, if we want them to also return a specific boolean or error for mixed types,
// they would need to use the new macro or have their own specific logic.
// The subtask is only for Equal & NotEqual, so only they are changed.
// To keep the old behavior for other compare_op users if any, we might need two versions of the macro
// or handle it inside. For now, let's assume only Equal/NotEqual use this for the fix.
// Reverting to a panic for other comparison ops if they don't match specific types.
macro_rules! old_compare_op_behavior {
    ($name:ident, $op:tt) => {
        function!($name(a: Any, b: Any) => Boolean, {
            match (a,b) {
                (Value::Integer(a_val),Value::Integer(b_val)) => Ok((a_val $op b_val).into()),
                (Value::String(a_val),Value::String(b_val)) => Ok((a_val $op b_val).into()),
                (Value::Boolean(a_val),Value::Boolean(b_val)) => Ok((a_val $op b_val).into()),
                _ => panic!("comparison not implemented for these types") // More specific panic
            }
        });
    }
}

old_compare_op_behavior!(Greater, >);
old_compare_op_behavior!(GreaterOrEqual, >=);
old_compare_op_behavior!(Lesser, <);
old_compare_op_behavior!(LesserOrEqual, <=);
compare_op!(Equal, ==, false); // If types are different, Equal is false
compare_op!(NotEqual, !=, true); // If types are different, NotEqual is true

function!(Like(a: String, b: String)=>Boolean, {
    let a:String = a.try_into()?;
    let b:String = b.try_into()?;
    let re = regex::Regex::new(&b).context("failed to compile regex")?;
    Ok(re.is_match(&a).into())
});

function!(NotLike(a: String, b: String)=>Boolean, {
    let a:String = a.try_into()?;
    let b:String = b.try_into()?;
    let re = regex::Regex::new(&b).context("failed to compile regex")?;
    Ok((!re.is_match(&a)).into())
});

function!(ToString(s: Any)=>String, {
    Ok(s.to_string().into())
});

function!(ToInteger(s: String)=>Integer, {
    let s:String = s.try_into()?;
    s.parse::<i64>().map(Into::into)
        .context(format!("failed to parse integer: {}", s))
});

function!(Split(a: String, b: String)=>Type::array_of(String), {
    let s:String = a.try_into()?;
    let d:String = b.try_into()?;
    Ok(s.split(&d).map(Into::into).collect::<Vec<Value>>().into())
});

function!(StringConcat(a: Type::array_of(String))=>String, ctx=ctx, {
    let s:Arc<Vec<Value>> = a.try_into()?;
    let mut ret = String::new();
    for sv in s.iter(){
        let sv = sv.real_value_of(ctx.clone()).await?;
        let sv: String = sv.try_into()?;
        ret += &sv;
    }
    Ok(ret.into())
});

#[cfg(test)]
mod tests {
    // use super::super::*;
    use super::*;
    use crate::script::Value; // Ensure Value is in scope for macro usage if not already.

    // Helper test functions for callbacks
    function!(TestHelperAddOne(val: Integer) => Integer, {
        let v: i64 = val.try_into()?;
        Ok(Value::Integer(v + 1))
    });

    function!(TestHelperToString(val: Any) => String, {
        Ok(Value::String(val.to_string().into()))
    });

    function!(TestHelperSum(acc: Integer, val: Integer) => Integer, {
        let a: i64 = acc.try_into()?;
        let v: i64 = val.try_into()?;
        Ok(Value::Integer(a + v))
    });

    function!(TestHelperIsEven(val: Integer) => Boolean, {
        let v: i64 = val.try_into()?;
        Ok(Value::Boolean(v % 2 == 0))
    });

    macro_rules! op_test {
        ($name:ident, $fn:ident, [ $($in:expr),+ ] , $out:expr) => {
            #[tokio::test]
            async fn $name() {
                let ctx : ScriptContextRef = Default::default();
                let func_call_val : Value = $fn::make_call( $($in),+ ).into();
                let expected_output_val : Value = $out;

                // Test signature (type check)
                let expected_type = expected_output_val.type_of(ctx.clone()).await
                    .unwrap_or_else(|e| panic!("Error getting type of expected output for {}: {:?}", stringify!($name), e));
                let actual_type_result = func_call_val.type_of(ctx.clone()).await; // Changed to async call
                assert!(actual_type_result.is_ok(), "Type signature check failed for {}: {:?}", stringify!($name), actual_type_result.err().unwrap());
                assert_eq!(expected_type, actual_type_result.unwrap(), "Type mismatch for {}", stringify!($name));

                // Test call (value evaluation)
                let actual_value_result = func_call_val.value_of(ctx).await; // Changed to async call
                assert!(actual_value_result.is_ok(), "Value evaluation failed for {}: {:?}", stringify!($name), actual_value_result.err().unwrap());
                assert_eq!(actual_value_result.unwrap(), expected_output_val, "Value mismatch for {}", stringify!($name));
            }
        };
    }

    macro_rules! op_error_test {
        ($name:ident, $fn:ident, [ $($in:expr),+ ] , $expected_error_substring:expr) => {
            #[tokio::test]
            async fn $name() {
                let ctx : ScriptContextRef = Default::default();
                let func_call_val : Value = $fn::make_call( $($in),+ ).into();

                // Check if signature catches the error (type error)
                let type_result = func_call_val.type_of(ctx.clone()).await;

                let value_result = func_call_val.value_of(ctx).await;

                let error_message = match (type_result, value_result) {
                    (Err(type_err), _) => { // If type_of fails, that's the primary error
                        type_err.to_string()
                    },
                    (_, Err(val_err)) => { // If type_of succeeds but value_of fails
                        val_err.to_string()
                    },
                    (Ok(t), Ok(v)) => {
                        panic!("Expected error for '{}', but got Ok(type: {:?}, value: {:?})", stringify!($name), t, v)
                    }
                };

                assert!(
                    error_message.contains($expected_error_substring),
                    "Error message for '{}' was '{}', expected to contain '{}'",
                    stringify!($name), error_message, $expected_error_substring
                );
            }
        };
    }

    op_test!(
        access_tuple,
        Access,
        [Value::Tuple(Arc::new(vec![1.into(), 2.into()])), 0.into()],
        1.into()
    );

    #[derive(Debug)]
    struct Test {
        map: HashMap<String, Value>,
        array: Vec<Value>,
    }

    impl Test {
        fn new() -> Self {
            let mut map: HashMap<String, Value> = Default::default();
            map.insert("test".into(), 1.into());
            let array = vec![1.into(), 2.into(), 3.into()];
            Self { map, array }
        }
    }

    impl std::hash::Hash for Test {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            std::hash::Hash::hash(&self.map.keys().collect::<Vec<_>>(), state);
        }
    }

    impl NativeObject for Test {
        fn as_accessible(&self) -> Option<&dyn Accessible> {
            Some(&self.map)
        }

        fn as_indexable(&self) -> Option<&dyn Indexable> {
            Some(&self.array)
        }
    }

    op_test!(
        access_hashmap,
        Access,
        [Test::new().into(), Value::Identifier("test".into())],
        1.into()
    );

    op_test!(index, Index, [Test::new().into(), 0.into()], 1.into());

    op_test!(not, Not, [false.into()], true.into());
    op_test!(bit_not, BitNot, [(!1234).into()], 1234.into());
    op_test!(negative, Negative, [1234.into()], (-1234).into());

    macro_rules! int_op_test {
        ($name:ident, $fn:ident, $op:tt) => {
            op_test!($name, $fn, [1234.into(),4.into()], (1234 $op 4).into());
        };
    }

    int_op_test!(plus,Plus,+);
    int_op_test!(minus,Minus,-);
    int_op_test!(mul,Multiply,*);
    int_op_test!(div,Divide,/);
    int_op_test!(imod,Mod,%);
    int_op_test!(band,BitAnd,&);
    int_op_test!(bor,BitOr,|);
    int_op_test!(bxor,BitXor,^);
    int_op_test!(shl,ShiftLeft,<<);
    int_op_test!(shr,ShiftRight,>>);
    op_test!(
        shru,
        ShiftRightUnsigned,
        [1234.into(), 45.into()],
        ((1234u64 >> 45) as i64).into()
    );

    macro_rules! bool_op_test {
        ($name:ident, $fn:ident, $op:tt) => {
            op_test!($name, $fn, [true.into(), false.into()], (true $op false).into());
        };
    }

    bool_op_test!(and,And,&&);
    bool_op_test!(or,Or,||);
    bool_op_test!(xor,Xor,^);

    macro_rules! cmp_op_test {
        ($name:ident, $fn:ident, $op:tt) => {
            op_test!($name, $fn, [1234.into(),4567.into()], (1234 $op 4567).into());
        };
    }

    cmp_op_test!(greater,Greater,>);
    cmp_op_test!(lesser,Lesser,<);
    cmp_op_test!(greater_or_equal,GreaterOrEqual,>=);
    cmp_op_test!(lesser_or_equal,LesserOrEqual,<=);
    cmp_op_test!(equal,Equal,==);
    cmp_op_test!(not_equal,NotEqual,!=);

    op_test!(like, Like, ["abc".into(), "a".into()], true.into());
    op_test!(not_like, NotLike, ["abc".into(), "a".into()], false.into());

    op_test!(
        is_member_of,
        IsMemberOf,
        [1.into(), vec![1.into()].into()],
        true.into()
    );

    op_test!(to_string, ToString, [false.into()], "false".into());
    op_test!(to_integer, ToInteger, ["1234".into()], 1234.into());
    op_test!(
        split,
        Split,
        ["1,2".into(), ",".into()],
        vec!["1".into(), "2".into()].into()
    );
    op_test!(
        string_concat,
        StringConcat,
        [vec!["1".into(), "2".into()].into()],
        "12".into()
    );

    // --- New Error Condition & Edge Case Tests for stdlib functions ---

    // Index Errors
    op_error_test!(
        index_with_non_integer,
        Index,
        [Value::Array(Arc::new(vec![1.into()])), "a".into()],
        "Index not a integer type"
    );
    // Note: Testing Index with a non-indexable (e.g. string "abc"[0]) depends on how parser creates the OpCall.
    // If parser directly calls Value::Array().get(), it's not an Index stdlib call.
    // Assuming Index stdlib is used:
    op_error_test!(
        index_on_non_indexable_script_value,
        Index,
        ["abc".into(), 0.into()],
        "Object does not implement Indexable"
    );

    // Access Errors
    op_error_test!(
        access_with_non_string_or_int_key_for_tuple,
        Access,
        [Value::Tuple(Arc::new(vec![1.into()])), true.into()],
        "Can not access a tuple with"
    );
    // Accessing native object with wrong key type is also tricky if parser handles it.
    // If Access stdlib is called:
    // Assuming Test::new() native object from existing tests, and it's accessible.
    // Accessing TestNativeSimple with a non-string identifier would be a parser error for `obj.true`
    // If it were `obj."true"`, then Access would get Value::String("true")
    op_error_test!(
        access_native_with_non_identifier_val,
        Access,
        [Test::new().into(), true.into()],
        "Can not access a NativeObject with"
    );

    // IsMemberOf Edge Cases
    op_test!(
        is_member_of_empty_array,
        IsMemberOf,
        [1.into(), Value::Array(Arc::new(vec![]))],
        false.into()
    );
    op_error_test!(
        is_member_of_array_different_type,
        IsMemberOf,
        [1.into(), Value::Array(Arc::new(vec!["a".into()]))],
        "subject must have on same type with array"
    );

    // Arithmetic Ops Errors
    op_error_test!(
        divide_by_zero_stdlib,
        Divide,
        [1.into(), 0.into()],
        "division by zero"
    );
    op_error_test!(
        mod_by_zero_stdlib,
        Mod,
        [1.into(), 0.into()],
        "division by zero"
    );

    // Like / NotLike Errors
    op_error_test!(
        like_invalid_regex,
        Like,
        ["abc".into(), "[".into()],
        "failed to compile regex"
    );

    // ToInteger Errors
    op_error_test!(
        to_integer_non_integer_string,
        ToInteger,
        ["abc".into()],
        "failed to parse integer: abc"
    );
    op_error_test!(
        to_integer_float_string,
        ToInteger,
        ["1.0".into()],
        "failed to parse integer: 1.0"
    );
    op_error_test!(
        to_integer_empty_string,
        ToInteger,
        ["".into()],
        "failed to parse integer: "
    );

    // Split Edge Cases
    // Behavior of split by empty string: Rust's split by "" gives ["", "a", "b", "c", ""]. If that's desired:
    // op_test!(split_by_empty_delimiter, Split, ["abc".into(), "".into()], Value::Array(Arc::new(vec!["".into(), "a".into(), "b".into(), "c".into(), "".into()])));
    // However, many languages error or have different behavior. Let's assume it returns array of chars if empty, or error.
    // Current impl of split in Rust would yield ["", "a", "b", "c", ""]. Let's match that.
    op_test!(
        split_by_empty_delimiter,
        Split,
        ["abc".into(), "".into()],
        Value::Array(Arc::new(vec![
            "".into(),
            "a".into(),
            "b".into(),
            "c".into(),
            "".into()
        ]))
    );
    op_test!(
        split_empty_string,
        Split,
        ["".into(), ",".into()],
        Value::Array(Arc::new(vec!["".into()]))
    ); // "".split(",") -> [""]
    op_test!(
        split_by_delimiter_not_present,
        Split,
        ["abc".into(), "d".into()],
        Value::Array(Arc::new(vec!["abc".into()]))
    );

    // StringConcat Edge Cases
    op_test!(
        strcat_empty_array,
        StringConcat,
        [Value::Array(Arc::new(vec![]))],
        "".into()
    );
    op_test!(
        strcat_array_one_string,
        StringConcat,
        [Value::Array(Arc::new(vec!["a".into()]))],
        "a".into()
    );
    op_test!(
        strcat_array_with_empty_strings,
        StringConcat,
        [Value::Array(Arc::new(vec![
            "a".into(),
            "".into(),
            "b".into()
        ]))],
        "ab".into()
    );
    op_error_test!(
        strcat_array_non_string,
        StringConcat,
        [Value::Array(Arc::new(vec![1.into()]))],
        "type mismatch"
    );

    // And / Or Short-circuiting
    // These tests need to be done via eval_test in script.rs as op_test directly calls the function, bypassing script evaluation logic.
    // See script.rs for these tests if added there:
    // eval_test!("true || (1/0 == 1)", Value::Boolean(true));
    // eval_test!("false && (1/0 == 1)", Value::Boolean(false));
    // For stdlib direct call, short-circuiting isn't observable as args are pre-evaluated by script engine.
    // We can test the non-short-circuiting behavior (both args evaluated by `args!` macro):
    op_test!(
        and_op_true_true,
        And,
        [true.into(), true.into()],
        true.into()
    );
    op_test!(
        or_op_false_false,
        Or,
        [false.into(), false.into()],
        false.into()
    );

    // Comparison Ops (Equal, NotEqual) Type Mismatch
    // These tests are changed from op_error_test! to op_test! as they should now return booleans.
    op_test!(
        equal_different_types,
        Equal,
        [1.into(), "1".into()],
        false.into()
    );
    op_test!(
        not_equal_different_types,
        NotEqual,
        [1.into(), "1".into()],
        true.into()
    );

    // --- Array Function Tests ---

    // Map Tests
    op_test!(map_empty_array, Map, [Value::Array(Arc::new(vec![])), TestHelperAddOne::stub().into()], Value::Array(Arc::new(vec![])));
    op_test!(map_integers_add_one, Map,
        [Value::Array(Arc::new(vec![1.into(), 2.into(), 3.into()])), TestHelperAddOne::stub().into()],
        Value::Array(Arc::new(vec![2.into(), 3.into(), 4.into()]))
    );
    op_test!(map_integers_to_string, Map,
        [Value::Array(Arc::new(vec![1.into(), 2.into()])), TestHelperToString::stub().into()],
        Value::Array(Arc::new(vec![Value::String("1".into()), Value::String("2".into())]))
    );

    // Reduce Tests
    op_test!(reduce_empty_array, Reduce,
        [Value::Array(Arc::new(vec![])), Value::Integer(10), TestHelperSum::stub().into()],
        Value::Integer(10)
    );
    op_test!(reduce_integers_sum, Reduce,
        [Value::Array(Arc::new(vec![1.into(), 2.into(), 3.into()])), Value::Integer(0), TestHelperSum::stub().into()],
        Value::Integer(6)
    );
    op_test!(reduce_integers_sum_with_initial, Reduce,
        [Value::Array(Arc::new(vec![1.into(), 2.into(), 3.into()])), Value::Integer(10), TestHelperSum::stub().into()],
        Value::Integer(16)
    );

    // Filter Tests
    op_test!(filter_empty_array, Filter,
        [Value::Array(Arc::new(vec![])), TestHelperIsEven::stub().into()],
        Value::Array(Arc::new(vec![]))
    );
    op_test!(filter_integers_is_even, Filter,
        [Value::Array(Arc::new(vec![1.into(), 2.into(), 3.into(), 4.into(), 5.into()])), TestHelperIsEven::stub().into()],
        Value::Array(Arc::new(vec![2.into(), 4.into()]))
    );
    // Define TestHelperTrue and TestHelperFalse using function! macro for consistency
    function!(TestHelperTrue(_val: Any) => Boolean, { Ok(Value::Boolean(true)) });
    function!(TestHelperFalse(_val: Any) => Boolean, { Ok(Value::Boolean(false)) });

    op_test!(filter_integers_keep_all, Filter,
        [Value::Array(Arc::new(vec![1.into(), 2.into()])), TestHelperTrue::stub().into()],
        Value::Array(Arc::new(vec![1.into(), 2.into()]))
    );
    op_test!(filter_integers_remove_all, Filter,
        [Value::Array(Arc::new(vec![1.into(), 2.into()])), TestHelperFalse::stub().into()],
        Value::Array(Arc::new(vec![]))
    );

    // Find Tests
    op_test!(find_empty_array, Find,
        [Value::Array(Arc::new(vec![])), TestHelperIsEven::stub().into()],
        false.into() // Updated: expect Value::Boolean(false)
    );
    op_test!(find_integer_is_even_found, Find,
        [Value::Array(Arc::new(vec![1.into(), 3.into(), 4.into(), 6.into()])), TestHelperIsEven::stub().into()],
        4.into() // Should return the first even number found
    );
    op_test!(find_integer_is_even_not_found, Find,
        [Value::Array(Arc::new(vec![1.into(), 3.into(), 5.into()])), TestHelperIsEven::stub().into()],
        false.into() // Updated: expect Value::Boolean(false)
    );

    // FindIndex Tests
    op_test!(find_index_empty_array, FindIndex,
        [Value::Array(Arc::new(vec![])), TestHelperIsEven::stub().into()],
        Value::Integer(-1)
    );
    op_test!(find_index_integer_is_even_found, FindIndex,
        [Value::Array(Arc::new(vec![1.into(), 3.into(), 4.into(), 6.into()])), TestHelperIsEven::stub().into()],
        Value::Integer(2) // Index of '4'
    );
    op_test!(find_index_integer_is_even_not_found, FindIndex,
        [Value::Array(Arc::new(vec![1.into(), 3.into(), 5.into()])), TestHelperIsEven::stub().into()],
        Value::Integer(-1)
    );

    // ForEach Tests
    op_test!(for_each_empty_array, ForEach,
        [Value::Array(Arc::new(vec![])), TestHelperAddOne::stub().into()],
        true.into() // Updated: ForEach returns true
    );
    op_test!(for_each_integers, ForEach,
        [Value::Array(Arc::new(vec![1.into(), 2.into()])), TestHelperAddOne::stub().into()],
        true.into() // Updated: Callback is executed, ForEach returns true
    );

    // IndexOf Tests
    op_test!(index_of_empty_array, IndexOf, [Value::Array(Arc::new(vec![])), 1.into(), 0.into()], Value::Integer(-1));
    op_test!(index_of_found, IndexOf, [Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])), 20.into(), 0.into()], Value::Integer(1));
    op_test!(index_of_not_found, IndexOf, [Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])), 40.into(), 0.into()], Value::Integer(-1));
    op_test!(index_of_from_index_positive_found, IndexOf, [Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into(), 20.into()])), 20.into(), 2.into()], Value::Integer(3));
    op_test!(index_of_from_index_positive_not_found, IndexOf, [Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])), 20.into(), 2.into()], Value::Integer(-1));
    op_test!(index_of_from_index_negative_found, IndexOf, [Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])), 10.into(), (-3).into()], Value::Integer(0)); // -3 from end is index 0
    op_test!(index_of_from_index_negative_found_mid, IndexOf, [Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into(), 40.into()])), 30.into(), (-2).into()], Value::Integer(2)); // -2 from end is index 2
    op_test!(index_of_from_index_out_of_bounds_positive, IndexOf, [Value::Array(Arc::new(vec![10.into(), 20.into()])), 10.into(), 5.into()], Value::Integer(-1));
    op_test!(index_of_from_index_out_of_bounds_negative, IndexOf, [Value::Array(Arc::new(vec![10.into(), 20.into()])), 10.into(), (-5).into()], Value::Integer(0)); // -5 from end is effectively 0

    // Includes Tests
    op_test!(includes_empty_array, Includes, [Value::Array(Arc::new(vec![])), 1.into(), 0.into()], Value::Boolean(false));
    op_test!(includes_found, Includes, [Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])), 20.into(), 0.into()], Value::Boolean(true));
    op_test!(includes_not_found, Includes, [Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])), 40.into(), 0.into()], Value::Boolean(false));
    op_test!(includes_from_index_positive_found, Includes, [Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into(), 20.into()])), 20.into(), 2.into()], Value::Boolean(true));
    op_test!(includes_from_index_positive_not_found, Includes, [Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])), 20.into(), 2.into()], Value::Boolean(false));
    op_test!(includes_from_index_negative_found, Includes, [Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])), 10.into(), (-3).into()], Value::Boolean(true));
    op_test!(includes_from_index_out_of_bounds_positive, Includes, [Value::Array(Arc::new(vec![10.into(), 20.into()])), 10.into(), 5.into()], Value::Boolean(false));
    op_test!(includes_from_index_out_of_bounds_negative, Includes, [Value::Array(Arc::new(vec![10.into(), 20.into()])), 10.into(), (-5).into()], Value::Boolean(true)); // -5 from end is effectively 0

    // Join Tests
    op_test!(join_empty_array, Join, [Value::Array(Arc::new(vec![])), ",".into()], Value::String("".into()));
    op_test!(join_single_element, Join, [Value::Array(Arc::new(vec!["a".into()])), ",".into()], Value::String("a".into()));
    op_test!(join_multiple_elements, Join, [Value::Array(Arc::new(vec!["a".into(), "b".into(), "c".into()])), ",".into()], Value::String("a,b,c".into()));
    op_test!(join_with_empty_separator, Join, [Value::Array(Arc::new(vec!["a".into(), "b".into(), "c".into()])), "".into()], Value::String("abc".into()));
    op_test!(join_with_null_like_elements, Join, // Assuming Value::Null.to_string() is empty string as per Join impl.
        [Value::Array(Arc::new(vec!["a".into(), Value::Null, "c".into()])), ",".into()], Value::String("a,,c".into())
    );
    op_test!(join_with_non_string_elements, Join, // Uses .to_string() for elements
        [Value::Array(Arc::new(vec![1.into(), true.into(), "c".into()])), "-".into()], Value::String("1-true-c".into())
    );

    // Slice Tests
    op_test!(slice_empty_array, Slice, [Value::Array(Arc::new(vec![])), 0.into(), 0.into()], Value::Array(Arc::new(vec![])));
    op_test!(slice_basic, Slice, [Value::Array(Arc::new(vec![1.into(),2.into(),3.into(),4.into()])), 1.into(), 3.into()], Value::Array(Arc::new(vec![2.into(),3.into()])));
    op_test!(slice_to_end, Slice, [Value::Array(Arc::new(vec![1.into(),2.into(),3.into(),4.into()])), 2.into(), 4.into()], Value::Array(Arc::new(vec![3.into(),4.into()])));
    op_test!(slice_from_beginning, Slice, [Value::Array(Arc::new(vec![1.into(),2.into(),3.into(),4.into()])), 0.into(), 2.into()], Value::Array(Arc::new(vec![1.into(),2.into()])));
    op_test!(slice_negative_begin, Slice, [Value::Array(Arc::new(vec![1.into(),2.into(),3.into(),4.into()])), (-2).into(), 4.into()], Value::Array(Arc::new(vec![3.into(),4.into()])));
    op_test!(slice_negative_end, Slice, [Value::Array(Arc::new(vec![1.into(),2.into(),3.into(),4.into()])), 1.into(), (-1).into()], Value::Array(Arc::new(vec![2.into(),3.into()])));
    op_test!(slice_negative_begin_and_end, Slice, [Value::Array(Arc::new(vec![1.into(),2.into(),3.into(),4.into()])), (-3).into(), (-1).into()], Value::Array(Arc::new(vec![2.into(),3.into()])));
    op_test!(slice_begin_out_of_bounds_positive, Slice, [Value::Array(Arc::new(vec![1.into(),2.into()])), 5.into(), 6.into()], Value::Array(Arc::new(vec![])));
    op_test!(slice_end_out_of_bounds_positive, Slice, [Value::Array(Arc::new(vec![1.into(),2.into()])), 0.into(), 5.into()], Value::Array(Arc::new(vec![1.into(),2.into()])));
    op_test!(slice_begin_greater_than_end, Slice, [Value::Array(Arc::new(vec![1.into(),2.into()])), 1.into(), 0.into()], Value::Array(Arc::new(vec![])));
    op_test!(slice_full_array_clone, Slice, [Value::Array(Arc::new(vec![1.into(),2.into()])), 0.into(), 2.into()], Value::Array(Arc::new(vec![1.into(),2.into()])));
    op_test!(slice_begin_equals_end, Slice, [Value::Array(Arc::new(vec![1.into(),2.into(),3.into()])), 1.into(), 1.into()], Value::Array(Arc::new(vec![])));

    // --- String Function Tests ---

    // StringCharAt and StringCharCodeAt
    op_test!(string_char_at_basic, StringCharAt, ["hello".into(), 1.into()], "e".into());
    op_test!(string_char_at_start, StringCharAt, ["hello".into(), 0.into()], "h".into());
    op_test!(string_char_at_end, StringCharAt, ["hello".into(), 4.into()], "o".into());
    op_test!(string_char_at_out_of_bounds_positive, StringCharAt, ["hello".into(), 10.into()], "".into());
    // StringCharAt negative index is an error, not an op_test for specific value. Add op_error_test later.

    op_test!(string_char_code_at_basic, StringCharCodeAt, ["hello".into(), 1.into()], ('e' as i64).into());
    op_test!(string_char_code_at_start, StringCharCodeAt, ["hello".into(), 0.into()], ('h' as i64).into());
    op_test!(string_char_code_at_out_of_bounds_positive, StringCharCodeAt, ["hello".into(), 10.into()], Value::Integer(-1)); // Updated

    // StringEndsWith, StringIncludes, StringStartsWith
    op_test!(string_ends_with_true, StringEndsWith, ["hello".into(), "lo".into(), 5.into()], true.into());
    op_test!(string_ends_with_false, StringEndsWith, ["hello".into(), "lo".into(), 4.into()], false.into()); // "hell" does not end with "lo"
    op_test!(string_ends_with_length_param, StringEndsWith, ["hello".into(), "o".into(), 4.into()], false.into()); // "hell" does not end with "o"
    op_test!(string_ends_with_full_match_with_len, StringEndsWith, ["hello".into(), "hell".into(), 4.into()], true.into());
    op_test!(string_ends_with_empty_search, StringEndsWith, ["hello".into(), "".into(), 5.into()], true.into());

    op_test!(string_includes_true, StringIncludes, ["hello world".into(), "world".into(), 0.into()], true.into());
    op_test!(string_includes_false, StringIncludes, ["hello world".into(), "worldz".into(), 0.into()], false.into());
    op_test!(string_includes_position_true, StringIncludes, ["hello world".into(), "world".into(), 5.into()], true.into());
    op_test!(string_includes_position_false, StringIncludes, ["hello world".into(), "hello".into(), 5.into()], false.into());

    op_test!(string_starts_with_true, StringStartsWith, ["hello".into(), "he".into(), 0.into()], true.into());
    op_test!(string_starts_with_false, StringStartsWith, ["hello".into(), "hi".into(), 0.into()], false.into());
    op_test!(string_starts_with_position_true, StringStartsWith, ["hello".into(), "ll".into(), 2.into()], true.into());
    op_test!(string_starts_with_position_false, StringStartsWith, ["hello".into(), "he".into(), 2.into()], false.into());
    op_test!(string_starts_with_empty_search, StringStartsWith, ["hello".into(), "".into(), 0.into()], true.into());

    // StringIndexOf
    op_test!(string_index_of_found, StringIndexOf, ["hello".into(), "ll".into(), 0.into()], 2.into());
    op_test!(string_index_of_not_found, StringIndexOf, ["hello".into(), "x".into(), 0.into()], (-1).into());
    op_test!(string_index_of_from_index_found, StringIndexOf, ["hello hello".into(), "h".into(), 1.into()], 6.into());
    op_test!(string_index_of_empty_search, StringIndexOf, ["hello".into(), "".into(), 0.into()], 0.into());
    op_test!(string_index_of_empty_search_at_len, StringIndexOf, ["hello".into(), "".into(), 5.into()], 5.into());

    // StringMatch
    op_test!(string_match_found, StringMatch, ["hello".into(), "l+".into()], Value::Array(Arc::new(vec!["ll".into()])));
    op_test!(string_match_not_found, StringMatch, ["hello".into(), "x+".into()], Value::Array(Arc::new(vec![]))); // Updated
    // Test with optional group not matching - e.g. "(\w+)( \d+)?" for "hello"
    // captures.iter() would give Some("hello"), None for the optional group.
    // The StringMatch function now puts Value::String("".into()) for None capture.
    op_test!(string_match_optional_group_not_matched, StringMatch,
        ["hello".into(), "(\\w+)( \\d+)?".into()],
        Value::Array(Arc::new(vec!["hello".into(), "hello".into(), "".into()])) // Updated: optional group is ""
    );
    op_test!(string_match_with_groups, StringMatch, ["hello 123".into(), "(\\w+) (\\d+)".into()], Value::Array(Arc::new(vec!["hello 123".into(), "hello".into(), "123".into()])));


    // StringReplace and StringReplaceRegex
    op_test!(string_replace_literal, StringReplace, ["hello world".into(), "world".into(), "Rust".into()], "hello Rust".into());
    op_test!(string_replace_literal_no_match, StringReplace, ["hello".into(), "x".into(), "y".into()], "hello".into());
    op_test!(string_replace_regex_first, StringReplaceRegex, ["abab".into(), "b".into(), "c".into()], "acac".into()); // Should be "acab" if only first, "acac" if all. Current is all.
    op_test!(string_replace_regex_all, StringReplaceRegex, ["abab".into(), "b".into(), "c".into()], "acac".into());
    op_test!(string_replace_regex_groups_not_supported_yet, StringReplaceRegex, ["hello 123".into(), "(\\w+) (\\d+)".into(), "$2 $1".into()], "$2 $1".into()); // Placeholder, current impl is literal replacement

    // StringSlice
    op_test!(string_slice_basic, StringSlice, ["hello".into(), 1.into(), 4.into()], "ell".into());
    op_test!(string_slice_negative_begin, StringSlice, ["hello".into(), (-3).into(), 4.into()], "ll".into());
    op_test!(string_slice_negative_end, StringSlice, ["hello".into(), 1.into(), (-1).into()], "ell".into());
    op_test!(string_slice_begin_greater_than_end, StringSlice, ["hello".into(), 3.into(), 1.into()], "".into());
    op_test!(string_slice_full, StringSlice, ["hello".into(), 0.into(), 5.into()], "hello".into());

    // StringSubstring
    op_test!(string_substring_basic, StringSubstring, ["hello".into(), 1.into(), 4.into()], "ell".into());
    op_test!(string_substring_start_greater_than_end, StringSubstring, ["hello".into(), 4.into(), 1.into()], "ell".into()); // Swaps
    op_test!(string_substring_negative_treated_as_zero, StringSubstring, ["hello".into(), (-2).into(), 3.into()], "hel".into());
    op_test!(string_substring_index_out_of_bounds, StringSubstring, ["hello".into(), 0.into(), 10.into()], "hello".into());

    // StringLowerCase, StringUpperCase, StringTrim
    op_test!(string_lower_case, StringLowerCase, ["HeLlO".into()], "hello".into());
    op_test!(string_upper_case, StringUpperCase, ["HeLlO".into()], "HELLO".into());
    op_test!(string_trim_basic, StringTrim, ["  hello  ".into()], "hello".into());
    op_test!(string_trim_no_whitespace, StringTrim, ["hello".into()], "hello".into());
    op_test!(string_trim_only_whitespace, StringTrim, ["   ".into()], "".into());

    // --- Error Tests ---

    // Array function error tests
    op_error_test!(map_non_array_arg, Map, [1.into(), TestHelperAddOne::stub().into()], "argument array type mismatch");
    op_error_test!(map_non_function_callback, Map, [Value::Array(Arc::new(vec![])), 1.into()], "Second argument to map must be a function");

    op_error_test!(reduce_non_array_arg, Reduce, [1.into(), 0.into(), TestHelperSum::stub().into()], "argument array type mismatch");
    op_error_test!(reduce_non_function_callback, Reduce, [Value::Array(Arc::new(vec![])), 0.into(), 1.into()], "Third argument to reduce must be a function");

    op_error_test!(filter_non_array_arg, Filter, [1.into(), TestHelperIsEven::stub().into()], "argument array type mismatch");
    op_error_test!(filter_non_function_callback, Filter, [Value::Array(Arc::new(vec![])), 1.into()], "Second argument to filter must be a function");
    op_error_test!(filter_callback_returns_non_boolean, Filter,
        [Value::Array(Arc::new(vec![1.into()])), TestHelperAddOne::stub().into()], // AddOne returns Integer
        "Filter function must return a Boolean"
    );

    op_error_test!(find_non_array_arg, Find, [1.into(), TestHelperIsEven::stub().into()], "argument array type mismatch");
    op_error_test!(find_non_function_callback, Find, [Value::Array(Arc::new(vec![])), 1.into()], "Second argument to find must be a function");
    op_error_test!(find_callback_returns_non_boolean, Find,
        [Value::Array(Arc::new(vec![1.into()])), TestHelperAddOne::stub().into()],
        "Find function must return a Boolean"
    );

    op_error_test!(find_index_non_array_arg, FindIndex, [1.into(), TestHelperIsEven::stub().into()], "argument array type mismatch");
    op_error_test!(find_index_non_function_callback, FindIndex, [Value::Array(Arc::new(vec![])), 1.into()], "Second argument to findIndex must be a function");
    op_error_test!(find_index_callback_returns_non_boolean, FindIndex,
        [Value::Array(Arc::new(vec![1.into()])), TestHelperAddOne::stub().into()],
        "FindIndex function must return a Boolean"
    );

    op_error_test!(for_each_non_array_arg, ForEach, [1.into(), TestHelperAddOne::stub().into()], "argument array type mismatch");
    op_error_test!(for_each_non_function_callback, ForEach, [Value::Array(Arc::new(vec![])), 1.into()], "Second argument to forEach must be a function");

    op_error_test!(index_of_non_array_arg, IndexOf, [1.into(), 1.into(), 0.into()], "argument array type mismatch");
    op_error_test!(index_of_non_integer_from_index, IndexOf, [Value::Array(Arc::new(vec![])), 1.into(), "a".into()], "argument from_index type mismatch");

    op_error_test!(includes_non_array_arg, Includes, [1.into(), 1.into(), 0.into()], "argument array type mismatch");
    op_error_test!(includes_non_integer_from_index, Includes, [Value::Array(Arc::new(vec![])), 1.into(), "a".into()], "argument from_index type mismatch");

    op_error_test!(join_non_array_arg, Join, [1.into(), ",".into()], "argument array type mismatch");
    op_error_test!(join_non_string_separator, Join, [Value::Array(Arc::new(vec![])), 1.into()], "argument separator type mismatch");

    op_error_test!(slice_non_array_arg, Slice, [1.into(), 0.into(), 1.into()], "argument array type mismatch");
    op_error_test!(slice_non_integer_begin, Slice, [Value::Array(Arc::new(vec![])), "a".into(), 1.into()], "argument begin_index type mismatch");
    op_error_test!(slice_non_integer_end, Slice, [Value::Array(Arc::new(vec![])), 0.into(), "a".into()], "argument end_index type mismatch");

    // String function error tests
    op_error_test!(string_char_at_non_string, StringCharAt, [1.into(), 0.into()], "argument text type mismatch");
    op_error_test!(string_char_at_non_integer_index, StringCharAt, ["hi".into(), "a".into()], "argument index type mismatch");
    op_error_test!(string_char_at_negative_index, StringCharAt, ["hello".into(), (-1).into()], "Index out of bounds: index cannot be negative");

    op_error_test!(string_char_code_at_non_string, StringCharCodeAt, [1.into(), 0.into()], "argument text type mismatch");
    op_error_test!(string_char_code_at_non_integer_index, StringCharCodeAt, ["hi".into(), "a".into()], "argument index type mismatch");
    op_error_test!(string_char_code_at_negative_index, StringCharCodeAt, ["hello".into(), (-1).into()], "Index out of bounds: index cannot be negative");

    op_error_test!(string_match_invalid_regex, StringMatch, ["hello".into(), "[".into()], "Invalid regex pattern");
    op_error_test!(string_replace_regex_invalid_regex, StringReplaceRegex, ["h".into(), "[".into(), "a".into()], "Invalid regex pattern");

}

// Array operations

// map(array, function)
function!(Map(array: Array, func: Any) => Type::array_of(Any), ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;
    let mut result_array = Vec::with_capacity(arr_val.len());

    let func_val = func.value_of(ctx.clone()).await?;
    // Ensure func_val is a callable Value
    let callable_value = match &func_val {
        Value::Function(_) => func_val.clone(),
        Value::NativeObject(no) if no.as_callable().is_some() => func_val.clone(),
        _ => bail!("Second argument to map must be a function, got {:?}", func_val),
    };

    for item in arr_val.iter() {
        let item_val = item.value_of(ctx.clone()).await?;
        // Pass callable_value directly to Call::new
        let call = Call::new(vec![callable_value.clone(), item_val]);
        let result_item = call.value_of(ctx.clone()).await?;
        result_array.push(result_item);
    }
    Ok(Value::Array(Arc::new(result_array)))
});

// find(array, function) -> Any (element or Null)
function!(Find(array: Array, func: Any) => Any, ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;

    let func_val = func.value_of(ctx.clone()).await?;
    // Ensure func_val is a callable Value
    let callable_value = match &func_val {
        Value::Function(_) => func_val.clone(),
        Value::NativeObject(no) if no.as_callable().is_some() => func_val.clone(),
        _ => bail!("Second argument to find must be a function, got {:?}", func_val),
    };

    for item in arr_val.iter() {
        let item_clone = item.clone(); // Clone for potential return
        let item_val_for_fn = item.value_of(ctx.clone()).await?;

        let call = Call::new(vec![callable_value.clone(), item_val_for_fn]);
        let result_val = call.value_of(ctx.clone()).await?;

        let passes_test: bool = result_val.try_into().map_err(|e| {
            err_msg(format!("Find function must return a Boolean, got {:?} (error: {})", result_val, e))
        })?;

        if passes_test {
            return Ok(item_clone); // Return the original item
        }
    }
    Ok(Value::Boolean(false)) // Return false if not found
});

// findIndex(array, function) -> Integer
function!(FindIndex(array: Array, func: Any) => Integer, ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;

    let func_val = func.value_of(ctx.clone()).await?;
    // Ensure func_val is a callable Value
    let callable_value = match &func_val {
        Value::Function(_) => func_val.clone(),
        Value::NativeObject(no) if no.as_callable().is_some() => func_val.clone(),
        _ => bail!("Second argument to findIndex must be a function, got {:?}", func_val),
    };

    for (index, item) in arr_val.iter().enumerate() {
        let item_val_for_fn = item.value_of(ctx.clone()).await?;

        let call = Call::new(vec![callable_value.clone(), item_val_for_fn]);
        let result_val = call.value_of(ctx.clone()).await?;

        let passes_test: bool = result_val.try_into().map_err(|e| {
            err_msg(format!("FindIndex function must return a Boolean, got {:?} (error: {})", result_val, e))
        })?;

        if passes_test {
            return Ok(Value::Integer(index as i64));
        }
    }
    Ok(Value::Integer(-1)) // Return -1 if not found
});

// forEach(array, function) -> Null (or some void equivalent)
// The return type of forEach is now Boolean.
function!(ForEach(array: Array, func: Any) => Boolean, ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;

    let func_val = func.value_of(ctx.clone()).await?;
    // Ensure func_val is a callable Value
    let callable_value = match &func_val {
        Value::Function(_) => func_val.clone(),
        Value::NativeObject(no) if no.as_callable().is_some() => func_val.clone(),
        _ => bail!("Second argument to forEach must be a function, got {:?}", func_val),
    };

    for item in arr_val.iter() {
        let item_val_for_fn = item.value_of(ctx.clone()).await?;
        let call = Call::new(vec![callable_value.clone(), item_val_for_fn]);
        // Execute the call, but ignore its result for forEach
        call.value_of(ctx.clone()).await?;
    }
    Ok(Value::Boolean(true)) // forEach now returns true.
});

// indexOf(array, searchElement, fromIndex) -> Integer
function!(IndexOf(array: Array, search_element: Any, from_index: Integer) => Integer, ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;
    let search_val = search_element.value_of(ctx.clone()).await?;
    let from_idx_i64: i64 = from_index.try_into()?;

    // Determine the actual starting index for iteration.
    // JS Array.prototype.indexOf behavior:
    // If fromIndex < 0, it's treated as an offset from the end of the array.
    // (e.g., if fromIndex is -1, search the whole array. If -2, search from the second to last).
    // If fromIndex >= array.length, -1 is returned.
    // If fromIndex is not provided or undefined, it defaults to 0.
    // For simplicity with current macro, from_index is mandatory.

    let len = arr_val.len();
    let start_usize: usize;

    if from_idx_i64 >= len as i64 {
        return Ok(Value::Integer(-1));
    } else if from_idx_i64 < 0 {
        // Simplified: treat negative as 0. A more compliant version would be:
        // start_usize = (len as i64 + from_idx_i64).try_into().unwrap_or(0);
        // if from_idx_i64 + (len as i64) < 0 { start_usize = 0; } else { start_usize = (from_idx_i64 + len as i64) as usize}
        // For now, if from_idx_i64 is -5 and len is 3, it will be 0.
        // If from_idx_i64 is -2 and len is 5, it will be 3.
        let effective_start = len as i64 + from_idx_i64;
        start_usize = if effective_start < 0 { 0 } else { effective_start as usize };

    } else {
        start_usize = from_idx_i64 as usize;
    }

    // Ensure start_usize is not out of bounds after potential negative calculation
    if start_usize >= len {
         return Ok(Value::Integer(-1));
    }

    for (index, item) in arr_val.iter().enumerate().skip(start_usize) {
        let item_val = item.value_of(ctx.clone()).await?;
        if item_val == search_val {
            return Ok(Value::Integer(index as i64));
        }
    }

    Ok(Value::Integer(-1)) // Not found
});

// includes(array, valueToFind, fromIndex) -> Boolean
function!(Includes(array: Array, value_to_find: Any, from_index: Integer) => Boolean, ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;
    let search_val = value_to_find.value_of(ctx.clone()).await?;
    let from_idx_i64: i64 = from_index.try_into()?;

    let len = arr_val.len();
    if len == 0 {
        return Ok(Value::Boolean(false));
    }
    let start_usize: usize;

    // JS Array.prototype.includes behavior for fromIndex:
    // If fromIndex >= arr.length, false is returned. Array is not searched.
    // If fromIndex < 0, it's an offset from the end. If fromIndex <= -arr.length, treated as 0.
    if from_idx_i64 >= len as i64 {
        return Ok(Value::Boolean(false));
    } else if from_idx_i64 < 0 {
        let effective_start = len as i64 + from_idx_i64;
        start_usize = if effective_start < 0 { 0 } else { effective_start as usize };
    } else {
        start_usize = from_idx_i64 as usize;
    }

    // Note: If after calculation, start_usize >= len, the loop .skip(start_usize) will simply yield no items.

    for item in arr_val.iter().skip(start_usize) {
        let item_val = item.value_of(ctx.clone()).await?;
        // Comparison logic: Value implements PartialEq.
        // JS `includes` uses "SameValueZero" comparison, which treats NaN === NaN as true.
        // Value's current PartialEq might not do that if Value can represent NaN.
        // Assuming Value::Float(f64::NAN) == Value::Float(f64::NAN) is handled by f64's PartialEq if needed,
        // or we might need a custom check if NaN is a distinct Value variant.
        // For now, standard PartialEq is used.
        if item_val == search_val {
            return Ok(Value::Boolean(true));
        }
    }

    Ok(Value::Boolean(false)) // Not found
});

// join(array, separator) -> String
function!(Join(array: Array, separator: String) => String, ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;
    let sep_str: String = separator.try_into()?; // Ensure separator is a string

    let mut result_str = String::new();

    for (index, item) in arr_val.iter().enumerate() {
        let item_val = item.value_of(ctx.clone()).await?;
        let item_str = match item_val {
            Value::Null => String::new(), // Convert Null to empty string
            // TODO: Other Value types might need specific string conversions.
            // Assuming a basic .to_string() for others.
            // If Value has a more specific string conversion method, use that.
            _ => item_val.to_string(), // Fallback to Display trait impl
        };

        result_str.push_str(&item_str);
        if index < arr_val.len() - 1 {
            result_str.push_str(&sep_str);
        }
    }
    Ok(Value::String(result_str.into()))
});

// slice(array, begin, end) -> Array
function!(Slice(array: Array, begin_index: Integer, end_index: Integer) => Type::array_of(Any), ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;
    let len = arr_val.len();

    let mut begin: i64 = begin_index.try_into()?;
    let mut end: i64 = end_index.try_into()?;

    // Resolve negative indices
    if begin < 0 {
        begin += len as i64;
    }
    if end < 0 {
        end += len as i64;
    }

    // Clamp indices to valid range
    // `begin` should be between 0 and len.
    // `end` should be between 0 and len.
    begin = begin.max(0).min(len as i64);
    end = end.max(0).min(len as i64);

    let mut result_array = Vec::new();
    if begin < end { // Only slice if begin is less than end
        // .slice in Rust is exclusive for the end, matching JS behavior
        // Ensure that begin and end are converted to usize for slicing
        let start_usize = begin as usize;
        let end_usize = end as usize;

        // Iterate and clone elements for the new array.
        // Values in arr_val are already `Value` types.
        // Shallow copy means cloning the Value references/values.
        for i in start_usize..end_usize {
            if let Some(val_ref) = arr_val.get(i) {
                 result_array.push(val_ref.clone());
            } else {
                // This case should ideally not be reached if clamping is correct
                // and len is derived from arr_val.
                break;
            }
        }
    }
    // If begin >= end, an empty array is returned, which is correct.

    Ok(Value::Array(Arc::new(result_array)))
});

// String operations

// charAt(string, index) -> String
function!(StringCharAt(text: String, index: Integer) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    let idx: i64 = index.try_into()?;

    if idx < 0 {
        bail!("Index out of bounds: index cannot be negative, got {}", idx);
    }
    let char_opt = s.chars().nth(idx as usize);
    match char_opt {
        Some(ch) => Ok(Value::String(ch.to_string().into())),
        None => Ok(Value::String("".into())) // JS returns empty string for out-of-bounds
    }
});

// replace(string, pattern: String|RegExpStr, replacement: String|Function) -> String
// For now:
// 1. replace(String, PatternString, ReplacementString) - PatternString is a literal string. Replaces first.
// 2. replace(String, RegExpString, ReplacementString) - RegExpString is a regex. Replaces first or all based on regex.
// Replacement with a function is NOT supported in this version.
// Special replacement patterns in ReplacementString (e.g., $&) are NOT supported initially.
// This version is for LITERAL string replacement.
function!(StringReplace(text: String, pattern: String, replacement: String) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    let p_str: String = pattern.try_into()?;
    let repl_text: String = replacement.try_into()?;

    // Simple string replacement, first occurrence (like Rust's str.replacen(p_str, &repl_text, 1))
    // For char-based replacement rather than byte-based:
    // This is tricky with Rust's string.find which is byte-based.
    // A full char-correct version would be more involved or require iterating chars.
    // For now, using byte-based find and replace, which is fine if pattern and string are ASCII or pattern appears consistently.
    // This is equivalent to `s.replacen(&p_str, &repl_text, 1)` but done manually to illustrate.
    if let Some(byte_idx) = s.find(&p_str) {
        let mut result = String::with_capacity(s.len() - p_str.len() + repl_text.len());
        result.push_str(&s[..byte_idx]);
        result.push_str(&repl_text);
        result.push_str(&s[byte_idx + p_str.len()..]);
        Ok(Value::String(result.into()))
    } else {
        Ok(Value::String(s.into())) // No match, return original string
    }
});

// This version is for REGEX string replacement.
function!(StringReplaceRegex(text: String, regexp_pattern: String, replacement: String) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    let pattern_str: String = regexp_pattern.try_into()?;
    let repl_text: String = replacement.try_into()?;

    match regex::Regex::new(&pattern_str) {
        Ok(re) => {
            // JS .replace with regex:
            // - If regex is global (/g), replaces all matches.
            // - If regex is not global, replaces only the first match.
            // The `regex` crate's `replace` method replaces the first match found.
            // `replace_all` replaces all non-overlapping matches.
            // To mimic JS, we'd need to check for a /g flag in pattern_str or assume.
            // For now, let's assume this function replaces ALL matches like `replace_all`.
            // If only first is desired, StringReplace should be used or a non-global regex pattern.
            let result = re.replace_all(&s, repl_text.as_str()).to_string();
            Ok(Value::String(result.into()))
        }
        Err(e) => {
            bail!("Invalid regex pattern for StringReplaceRegex: {} - Error: {}", pattern_str, e)
        }
    }
});

// slice(string, beginIndex, endIndex) -> String
function!(StringSlice(text: String, begin_index: Integer, end_index: Integer) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    let s_chars: Vec<char> = s.chars().collect(); // Work with chars for correct indexing
    let len = s_chars.len();

    let mut begin: i64 = begin_index.try_into()?;
    let mut end: i64 = end_index.try_into()?;

    // JS String.prototype.slice behavior:
    // If begin is NaN, it's treated as 0. If end is NaN, it's treated as str.length.
    // Current setup uses Integer type, so NaN is not expected directly.
    // Negative indices:
    if begin < 0 { begin = len as i64 + begin; }
    if end < 0 { end = len as i64 + end; }

    // Clamp indices to the range [0, len]
    let start_idx = (begin.max(0) as usize).min(len);
    let end_idx = (end.max(0) as usize).min(len);

    if start_idx >= end_idx {
        Ok(Value::String("".into())) // Empty string if start is after end or equal
    } else {
        let result_s: String = s_chars[start_idx..end_idx].iter().collect();
        Ok(Value::String(result_s.into()))
    }
});

// startsWith(string, searchString, position) -> Boolean
// position: The position in this string at which to begin searching for searchString. Defaults to 0.
function!(StringStartsWith(text: String, search_string: String, position: Integer) => Boolean, ctx=ctx, {
    let s: String = text.try_into()?;
    let search: String = search_string.try_into()?;
    let pos_val: i64 = position.try_into()?;

    let s_char_len = s.chars().count();

    // Determine start char index based on position.
    // JS: If position < 0, it is treated as 0.
    // JS: If position > str.length, it's false (unless searchString is also empty).
    let start_char_index = if pos_val < 0 {
        0
    } else if pos_val >= s_char_len as i64 {
        // If position is >= length, it can only start with ""
        // However, Rust's s[start..].starts_with() handles out-of-bounds slice gracefully for empty pattern.
        // Let's clamp start_char_index to s_char_len for safety with manual iteration/slicing.
        s_char_len
    } else {
        pos_val as usize
    };

    // Efficiently get the relevant part of the string to check
    // Using s.chars().skip(start_char_index).as_str() is not directly possible.
    // Reconstruct the substring or iterate:
    let mut main_iter = s.chars().skip(start_char_index);
    let mut search_iter = search.chars();

    loop {
        match (search_iter.next(), main_iter.next()) {
            (Some(sc), Some(mc)) => {
                if sc != mc {
                    return Ok(Value::Boolean(false)); // Mismatch
                }
            }
            (Some(_), None) => return Ok(Value::Boolean(false)), // Main string ended before search string
            (None, _) => return Ok(Value::Boolean(true)), // Search string exhausted, all matched
        }
    }
    // Unreachable if search string is not empty. If search string is empty, it's true.
    // The loop handles empty search string correctly (None, _) -> true.
});

// substring(string, indexStart, indexEnd) -> String
// indexEnd is mandatory for this implementation.
function!(StringSubstring(text: String, index_start: Integer, index_end: Integer) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    let s_chars: Vec<char> = s.chars().collect();
    let len = s_chars.len();

    let mut start_val: i64 = index_start.try_into()?;
    let mut end_val: i64 = index_end.try_into()?;

    // JS String.prototype.substring behavior:
    // If indexStart/End is < 0 or NaN, it is treated as 0.
    // If indexStart/End is > length, it is treated as length.
    start_val = start_val.max(0);
    end_val = end_val.max(0);

    let mut final_start_idx = (start_val as usize).min(len);
    let mut final_end_idx = (end_val as usize).min(len);

    // If indexStart > indexEnd, swap them.
    if final_start_idx > final_end_idx {
        std::mem::swap(&mut final_start_idx, &mut final_end_idx);
    }

    let result_s: String = s_chars[final_start_idx..final_end_idx].iter().collect();
    Ok(Value::String(result_s.into()))
});

// toLowerCase(string) -> String
function!(StringLowerCase(text: String) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    Ok(Value::String(s.to_lowercase().into()))
});

// toUpperCase(string) -> String
function!(StringUpperCase(text: String) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    Ok(Value::String(s.to_uppercase().into()))
});

// trim(string) -> String
function!(StringTrim(text: String) => String, ctx=ctx, {
    let s: String = text.try_into()?;
    // JS trim removes whitespace from both ends. Whitespace is defined as space, tab, no-break space, etc.
    // Rust's trim() method removes leading and trailing characters matching `char::is_whitespace`.
    Ok(Value::String(s.trim().into()))
});


// match(string, regexp_str) -> Array of strings
function!(StringMatch(text: String, regexp_str: String) => Type::array_of(String), ctx=ctx, {
    // Returns Array(String)
    // Note: JS String.prototype.match returns an array with additional properties (index, input, groups)
    // This simplified version will return an array of matched strings.
    // If regexp has /g flag, all matches are returned. Otherwise, only the first match.
    // The current regex crate doesn't directly expose flag parsing from a string like "/pattern/g".
    // We assume the regexp_str is just the pattern itself. For global match, user might call repeatedly or use a different function.
    // For simplicity, this will behave like a non-global match (find first match).

    let s: String = text.try_into()?;
    let pattern: String = regexp_str.try_into()?;

    match regex::Regex::new(&pattern) {
        Ok(re) => {
            if let Some(captures) = re.captures(&s) {
                // For a non-global match, JS returns an array where:
                // index 0: the full match
                // index 1..N: a capture group
                // plus .index, .input, .groups properties.
                // We will return an array of [full_match, group1, group2, ...].
                let mut result_array = Vec::new();
                for cap in captures.iter() {
                    match cap {
                        Some(m) => result_array.push(Value::String(m.as_str().into())),
                        None => result_array.push(Value::String("".into())), // Represent non-matched optional group as empty string
                    }
                }
                Ok(Value::Array(Arc::new(result_array)))
            } else {
                Ok(Value::Array(Arc::new(vec![]))) // No match, return empty array
            }
        }
        Err(e) => {
            bail!("Invalid regex pattern: {} - Error: {}", pattern, e)
        }
    }
});

// charCodeAt(string, index) -> Integer (representing Unicode value)
function!(StringCharCodeAt(text: String, index: Integer) => Integer, ctx=ctx, {
    let s: String = text.try_into()?;
    let idx: i64 = index.try_into()?;

    if idx < 0 {
        bail!("Index out of bounds: index cannot be negative, got {}", idx);
    }
    let char_opt = s.chars().nth(idx as usize);
    match char_opt {
        Some(ch) => Ok(Value::Integer(ch as i64)), // Cast char to i64 for Unicode value
        None => Ok(Value::Integer(-1)) // Return -1 for out-of-bounds
    }
});

// endsWith(string, searchString, length) -> Boolean
// length parameter specifies the portion of the string to be searched, as if the string only had that many characters.
function!(StringEndsWith(text: String, search_string: String, length: Integer) => Boolean, ctx=ctx, {
    let s: String = text.try_into()?;
    let search: String = search_string.try_into()?;
    let len_val: i64 = length.try_into()?;

    // Validate and determine the effective length of the string to consider
    let s_char_len = s.chars().count();
    let effective_len = if len_val < 0 {
        s_char_len // Or treat as error? JS defaults to string's length if undefined, or clamps.
                   // Let's clamp to s_char_len. No, JS: "If provided, it is used as the length of str."
                   // "Defaults to str.length."
                   // Forcing a positive integer for simplicity with the macro.
                   // Or, if len_val is i64, it can be < 0.
                   // MDN: "If length is provided, it is used as the length of str. Defaults to str.length."
                   // "If length is greater than str.length, it will be treated as str.length."
                   // "If length is less than 0, it will be treated as 0."
        0
    } else {
        (len_val as usize).min(s_char_len)
    };

    // Take the substring according to effective_len
    let s_substr: String = s.chars().take(effective_len).collect();

    Ok(Value::Boolean(s_substr.ends_with(&search)))
});

// includes(string, searchString, position) -> Boolean
// position: The position in this string at which to begin searching for searchString. Defaults to 0.
function!(StringIncludes(text: String, search_string: String, position: Integer) => Boolean, ctx=ctx, {
    let s: String = text.try_into()?;
    let search: String = search_string.try_into()?;
    let pos_val: i64 = position.try_into()?;

    let s_char_len = s.chars().count();

    // Determine start index based on position.
    // JS: If position < 0, it is treated as 0.
    // JS: If position >= str.length, it is treated as str.length (effectively, search will fail unless searchString is empty).
    let start_char_index = if pos_val < 0 {
        0
    } else if pos_val >= s_char_len as i64 {
        s_char_len // effectively, can only find ""
    } else {
        pos_val as usize
    };

    // Get the substring to search within.
    // String.match_indices(pat) might be more efficient but returns byte indices.
    // Sticking to char based logic for now.
    let s_substr: String = s.chars().skip(start_char_index).collect();

    Ok(Value::Boolean(s_substr.contains(&search)))
});

// indexOf(string, searchValue, fromIndex) -> Integer
// fromIndex: The index to start the search from. Defaults to 0.
function!(StringIndexOf(text: String, search_value: String, from_index: Integer) => Integer, ctx=ctx, {
    let s: String = text.try_into()?;
    let search_s: String = search_value.try_into()?;
    let from_idx_i64: i64 = from_index.try_into()?;

    let s_char_len = s.chars().count();

    // Determine start char index based on from_index.
    // JS: If fromIndex < 0, it is treated as 0.
    // JS: If fromIndex >= str.length, it is treated as str.length (search will only find "" at the end).
    let start_char_index = if from_idx_i64 < 0 {
        0
    } else if from_idx_i64 >= s_char_len as i64 {
        s_char_len
    } else {
        from_idx_i64 as usize
    };

    // If search_s is empty and start_char_index is beyond the string length, JS returns s_char_len.
    // If search_s is empty and start_char_index is within string length, JS returns start_char_index.
    if search_s.is_empty() {
        return Ok(Value::Integer( (start_char_index).min(s_char_len) as i64 ));
    }

    // Create a substring starting from start_char_index
    // This is not the most efficient way for indexOf, as we lose original indices.
    // A better way is to use .match_indices() on the original string or iterate chars and slice.
    // Let's try to find the char index directly.

    // Convert to Vec<char> to work with char indices if necessary, though iterating and finding sub-sequences is tricky.
    // Rust's str.find() works on byte indices. For char indices, we need to be careful.
    // A simpler approach for char-based indexing:
    if start_char_index >= s_char_len && !search_s.is_empty() { // Cannot find non-empty string if starting at/after end
        return Ok(Value::Integer(-1));
    }

    let mut char_idx = 0;
    let mut main_iter = s.chars().skip(start_char_index);
    let mut temp_s = String::with_capacity(s.len() - start_char_index); // preallocate

    // Construct the relevant part of the string
    for char_s in main_iter {
        temp_s.push(char_s);
    }

    // Now search in the constructed substring
    if let Some(found_byte_idx) = temp_s.find(&search_s) {
        // `found_byte_idx` is the byte index in `temp_s`. We need to convert it to char index.
        let char_match_index_in_temp_s = temp_s[..found_byte_idx].chars().count();
        Ok(Value::Integer((start_char_index + char_match_index_in_temp_s) as i64))
    } else {
        Ok(Value::Integer(-1))
    }
});


// reduce(array, initial_value, function)
function!(Reduce(array: Array, initial_value: Any, func: Any) => Any, ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;
    let mut accumulator = initial_value.value_of(ctx.clone()).await?;

    let func_val = func.value_of(ctx.clone()).await?;
    // Ensure func_val is a callable Value
    let callable_value = match &func_val {
        Value::Function(_) => func_val.clone(),
        Value::NativeObject(no) if no.as_callable().is_some() => func_val.clone(),
        _ => bail!("Third argument to reduce must be a function, got {:?}", func_val),
    };

    for item in arr_val.iter() {
        let current_value = item.value_of(ctx.clone()).await?;
        let call = Call::new(vec![
            callable_value.clone(),
            accumulator.clone(), // Pass current accumulator
            current_value,       // Pass current item
        ]);
        accumulator = call.value_of(ctx.clone()).await?; // Update accumulator with the result
    }
    Ok(accumulator)
});

// filter(array, function)
function!(Filter(array: Array, func: Any) => Type::array_of(Any), ctx=ctx, {
    let arr_val: Arc<Vec<Value>> = array.try_into()?;
    let mut result_array = Vec::new();

    let func_val = func.value_of(ctx.clone()).await?;
    // Ensure func_val is a callable Value
    let callable_value = match &func_val {
        Value::Function(_) => func_val.clone(),
        Value::NativeObject(no) if no.as_callable().is_some() => func_val.clone(),
        _ => bail!("Second argument to filter must be a function, got {:?}", func_val),
    };

    for item in arr_val.iter() {
        // Important: The item itself should be passed to the filter function, not its evaluated value,
        // if the function expects to operate on references or if the item is a complex structure
        // that shouldn't be eagerly evaluated before the function call.
        // However, typical filter functions in languages like JS operate on values.
        // The current `map` implementation uses `item.value_of().await?`. Let's be consistent.
        let item_clone = item.clone(); // Clone before potential evaluation if needed by function
        let item_val_for_fn = item.value_of(ctx.clone()).await?;

        let call = Call::new(vec![callable_value.clone(), item_val_for_fn]);
        let result_val = call.value_of(ctx.clone()).await?;

        let passes_test: bool = result_val.try_into().map_err(|e| {
            err_msg(format!("Filter function must return a Boolean, got {:?} (error: {})", result_val, e))
        })?;

        if passes_test {
            // Store the original item, not the evaluated item_val_for_fn,
            // to preserve its original form (e.g. if it was an unevaluated variable)
            result_array.push(item_clone);
        }
    }
    Ok(Value::Array(Arc::new(result_array)))
});
