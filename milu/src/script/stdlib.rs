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
}
