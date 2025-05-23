use std::convert::TryInto;

use easy_error::{bail, err_msg, Error, ResultExt};
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
            let $aname = iter.next().unwrap().real_value_of($ctx.clone())?;
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
        impl Callable for $name {
            fn signature(
                &self,
                $ctx: ScriptContextRef,
                args: &[Value],
            ) -> Result<Type, Error>
            {
                if args.len() != count_args!($($aname)+) {
                     bail!(
                        "For function {}, expected {} arguments, got {}",
                        stringify!($name),
                        count_args!($($aname)+),
                        args.len()
                    );
                }
                let mut targs : Vec<Type> = Vec::with_capacity(args.len());
                for x in args {
                    let t = x.real_type_of($ctx.clone())?;
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
            fn call(
                &self,
                $ctx: ScriptContextRef,
                args: &[Value],
            ) -> Result<Value, Error>
            {
                 if args.len() != count_args!($($aname)+) {
                     bail!(
                        "For function {}, expected {} arguments at call time, got {}",
                        stringify!($name),
                        count_args!($($aname)+),
                        args.len()
                    );
                }
                $crate::args!(args, ctx=$ctx, opts=$arg_opts, $($aname),+);
                $body
            }
        }
    };
}

#[macro_export]
macro_rules! count_args {
    ($head:ident $($tail:ident)*) => {
        1 + count_args!($($tail)*)
    };
    () => { 0 };
}


// Access an array which is a sequence of values in same type with a dynamic index
// Can not access a tuple dynamically because it's not able to do type inference statically.
function_head!(Index(obj: Any, index: Any) => Any);
impl Callable for Index {
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        if args.len() != 2 { bail!("Index expects 2 arguments"); }
        let obj = &args[0];
        let index_arg = &args[1];
        if index_arg.real_type_of(ctx.clone())? != Type::Integer {
            bail!("Index not a integer type")
        } else if let Value::NativeObject(nobj) = obj {
            if let Some(idx) = nobj.as_indexable() {
                idx.type_of_member(ctx)
            } else {
                bail!("NativeObject not in indexable")
            }
        } else if let Type::Array(t) = obj.real_type_of(ctx)? {
            Ok(*t)
        } else {
            bail!("Object does not implement Indexable: {:?}", obj)
        }
    }
    fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        if args.len() != 2 { bail!("Index expects 2 arguments at call time"); }
        let obj_val = args[0].real_value_of(ctx.clone())?;
        let index_val = args[1].real_value_of(ctx.clone())?;
        
        let index: i64 = index_val.try_into()?;
        let obj_to_index: &dyn Indexable = match &obj_val {
            Value::Array(a) => a.as_ref(),
            Value::NativeObject(a) => a
                .as_indexable()
                .ok_or_else(|| err_msg("NativeObject does not implement Indexible"))?,
            _ => bail!("type mismatch, not indexable: {:?}", obj_val),
        };
        obj_to_index.get(index)?.value_of(ctx)
    }
}

// Access a nativeobject or a tuple
function_head!(Access(obj: Any, index: Any) => Any);
impl Callable for Access {
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        if args.len() != 2 { bail!("Access expects 2 arguments"); }
        fn accessible(
            ctx: ScriptContextRef,
            obj: &dyn Accessible,
            index: &Value,
        ) -> Result<Type, Error> {
            let index = if let Value::Identifier(index) = index { // Index here must be a literal identifier
                index
            } else {
                bail!("Can not access a NativeObject with non-identifier key: {:?}", index)
            };
            obj.type_of(index, ctx)
        }

        fn tuple(_ctx: ScriptContextRef, obj_type: Type, index: &Value) -> Result<Type, Error> {
            let index_val = if let Value::Integer(i) = index { // Index here must be a literal integer
                *i
            } else {
                bail!("Can not access a tuple with non-integer key: {}", index)
            };
            if let Type::Tuple(mut t) = obj_type {
                 if index_val < 0 || index_val as usize >= t.len() {
                    bail!("Tuple index out of bounds: {}", index_val);
                }
                Ok(t.remove(index_val as usize))
            } else {
                bail!("Can not access type as tuple: {}", obj_type)
            }
        }

        let obj_type = args[0].real_type_of(ctx.clone())?;
        let index_val = &args[1]; // This is Value::Identifier or Value::Integer from parser

        match obj_type {
            Type::NativeObject(obj_ref) => {
                 if let Some(acc_obj) = obj_ref.as_accessible() {
                    accessible(ctx, acc_obj, index_val)
                } else if let Some(eval_obj) = obj_ref.as_evaluatable() {
                    let concrete_obj_type = eval_obj.type_of(ctx.clone())?;
                    tuple(ctx, concrete_obj_type, index_val)
                } else {
                    bail!("NativeObject not accessible or tuple-like")
                }
            }
            Type::Tuple(_) => tuple(ctx, obj_type, index_val),
            _ => bail!("Object {:?} is not Tuple nor Accessible", args[0]),
        }
    }

    fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        if args.len() != 2 { bail!("Access expects 2 arguments at call time"); }
        fn accessible(
            ctx: ScriptContextRef,
            obj: &dyn Accessible,
            index: &Value,
        ) -> Result<Value, Error> {
             let index_str = if let Value::Identifier(s) = index { s } else { unreachable!("Access key must be identifier for accessible") };
            let ret = obj.get(index_str)?;
            ret.value_of(ctx)
        }

        fn tuple(ctx: ScriptContextRef, obj_val: Value, index: &Value) -> Result<Value, Error> {
            let index_i64 = if let Value::Integer(i) = index { *i } else { unreachable!("Access key must be integer for tuple") };
            if let Value::Tuple(t) = obj_val {
                if index_i64 < 0 || index_i64 as usize >= t.len() {
                    bail!("Tuple index out of bounds: {}", index_i64);
                }
                t[index_i64 as usize].value_of(ctx)
            } else {
                 unreachable!("Object must be tuple value at this point")
            }
        }
        
        let obj_val = args[0].real_value_of(ctx.clone())?;
        let index_key = &args[1]; // This is Value::Identifier or Value::Integer from parser

        match obj_val {
            Value::NativeObject(ref obj_native) => {
                if let Some(acc_obj) = obj_native.as_accessible() {
                    accessible(ctx, acc_obj, index_key)
                } else if let Some(eval_obj) = obj_native.as_evaluatable() {
                    let concrete_obj = eval_obj.value_of(ctx.clone())?;
                    tuple(ctx, concrete_obj, index_key)
                } else {
                    bail!("NativeObject not accessible or tuple-like for call")
                }
            }
            Value::Tuple(_) => tuple(ctx, obj_val, index_key),
            _ => bail!("Object {:?} is not Tuple nor Accessible for call", args[0]),
        }
    }

    fn unresovled_ids<'s: 'o, 'o>(&self, args: &'s [Value], ids: &mut HashSet<&'o Value>) {
        args[0].unresovled_ids(ids) 
    }
}

function_head!(If(cond: Boolean, yes: Any, no: Any) => Any);
impl Callable for If {
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        if args.len() != 3 { bail!("If expects 3 arguments"); }
        let mut targs: Vec<Type> = Vec::with_capacity(args.len());
        for x in args {
            targs.push(x.real_type_of(ctx.clone())?);
        }
        args!(targs, cond, yes, no);
        if Type::Boolean != cond {
            bail!("Condition type {:?} is not a Boolean", cond);
        }
        if yes != no { // Type::Any will make this always true if one branch is Any
            bail!("Condition return type must be same: {:?} vs {:?}", yes, no);
        }
        Ok(yes) // If one is Any, this will be Any. If types are same, it's that type.
    }
    fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        if args.len() != 3 { bail!("If expects 3 arguments at call time"); }
        let cond: bool = args[0].real_value_of(ctx.clone())?.try_into()?;
        if cond {
            args[1].real_value_of(ctx)
        } else {
            args[2].real_value_of(ctx)
        }
    }
}

#[derive(Clone)] // Added Clone
struct ScopeBinding {
    ctx: ScriptContextRef,
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
        // Note: Hashing context might be problematic if it leads to deep or recursive hashing.
        // For now, rely on Value's hash.
    }
}


impl NativeObject for ScopeBinding {
    fn as_evaluatable(&self) -> Option<&dyn Evaluatable> {
        Some(self)
    }
}
impl Evaluatable for ScopeBinding {
    fn type_of(&self, _ctx: ScriptContextRef) -> Result<Type, Error> {
        // The _ctx here is the calling context, self.ctx is the definition context.
        self.value.real_type_of(self.ctx.clone())
    }

    fn value_of(&self, ctx: ScriptContextRef) -> Result<Value, Error> {
        // Evaluate the stored value in its original definition context,
        // then, if it's another layer of evaluatable (like a nested scope), evaluate that in the new calling context.
        self.value.real_value_of(self.ctx.clone())?.real_value_of(ctx)
    }
}


function_head!(Scope(vars: Array, expr: Any) => Any);
impl Scope {
    fn make_context(vars_val: &Value, outer_ctx: ScriptContextRef) -> Result<ScriptContextRef, Error> {
        let vars_array = match vars_val {
            Value::Array(arr) => arr,
            _ => bail!("Scope variables definition must be an array of tuples")
        };

        let mut nctx = ScriptContext::new(Some(outer_ctx.clone()));
        for v_tuple_val in vars_array.iter() {
            let t = match v_tuple_val {
                Value::Tuple(t_arc) => t_arc,
                _ => bail!("Each variable in scope must be a tuple (identifier, value)")
            };

            if t.len() != 2 { bail!("Variable assignment tuple must have 2 elements"); }

            let id: String = match &t[0] {
                 Value::Identifier(id_str) => id_str.clone(),
                 _=> bail!("Variable name in scope must be an identifier")
            };
            let value_expr = t[1].clone();
            
            // The value expression is bound using the outer_ctx (closure)
            let bound_value = ScopeBinding {
                ctx: outer_ctx.clone(), 
                value: value_expr,
            };
            nctx.set(id, bound_value.into());
        }
        Ok(Arc::new(nctx))
    }
}
impl Callable for Scope {
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        if args.len() != 2 { bail!("Scope expects 2 arguments"); }
        let new_scope_ctx = Self::make_context(&args[0].real_value_of(ctx.clone())?, ctx)?;
        args[1].real_type_of(new_scope_ctx)
    }
    fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        if args.len() != 2 { bail!("Scope expects 2 arguments at call time"); }
        let new_scope_ctx = Self::make_context(&args[0].real_value_of(ctx.clone())?, ctx)?;
        args[1].real_value_of(new_scope_ctx)
    }

    fn unresovled_ids<'s: 'o, 'o>(&self, args: &'s [Value], ids: &mut HashSet<&'o Value>) {
        if args.len() != 2 { return; }
        let mut unresolved_in_expr = HashSet::new();
        args[1].unresovled_ids(&mut unresolved_in_expr); 

        let mut known_in_scope = HashSet::new();
         if let Value::Array(var_defs) = &args[0] { // vars are defined as an array of tuples
            for v_tuple in var_defs.iter() {
                if let Value::Tuple(t) = v_tuple {
                    if !t.is_empty() { known_in_scope.insert(&t[0]); } // t[0] is the identifier
                    if t.len() > 1 { t[1].unresovled_ids(ids); } // Value expression can have unresolved IDs from outer scope
                }
            }
        }
        let unresolved_leaking = unresolved_in_expr.difference(&known_in_scope).cloned().collect();
        *ids = ids.union(&unresolved_leaking).cloned().collect();
    }
}

function_head!(IsMemberOf(a: Any, ary: Array) => Boolean);
impl Callable for IsMemberOf {
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        if args.len() != 2 { bail!("IsMemberOf expects 2 arguments"); }
        let mut targs: Vec<Type> = Vec::with_capacity(args.len());
        for x in args {
            targs.push(x.real_type_of(ctx.clone())?);
        }
        args!(targs, a, ary_type); // Renamed to ary_type to avoid conflict
        let item_type_in_array = if let Type::Array(inner_type) = ary_type {
            *inner_type
        } else {
            bail!("Second argument to IsMemberOf must be an Array, got {:?}", ary_type);
        };
        // Allow comparison if 'a' can fit into array's item type, or if array is Array(Any)
        if a != item_type_in_array && item_type_in_array != Type::Any && a != Type::Any {
            bail!(
                "Subject type must match array's element type for IsMemberOf: subj={:?}, array_element_type={:?}",
                a,
                item_type_in_array
            );
        }
        Ok(Type::Boolean)
    }
    fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        if args.len() != 2 { bail!("IsMemberOf expects 2 arguments at call time"); }
        let item_to_check = args[0].real_value_of(ctx.clone())?;
        let array_val = args[1].real_value_of(ctx.clone())?;

        let vec: Arc<Vec<Value>> = array_val.try_into()?;
        for v_expr in vec.iter() {
            if v_expr.real_value_of(ctx.clone())? == item_to_check {
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

macro_rules! int_op{
    ($name:ident, $op:tt) =>{
        function!($name(a: Integer, b: Integer)=>Integer, {
            let a:i64 = a.try_into()?;
            let b:i64 = b.try_into()?;
            Ok((a $op b).into())
        });
    }
}

int_op!(Plus,+);
int_op!(Minus,-);
int_op!(Multiply,*);
int_op!(Divide,/);
int_op!(Mod,%);
int_op!(BitAnd,&);
int_op!(BitOr,|);
int_op!(BitXor,^);
int_op!(ShiftLeft,<<);
int_op!(ShiftRight,>>);
function!(ShiftRightUnsigned(a: Integer, b: Integer)=>Integer, {
    let a:i64 = a.try_into()?;
    let b:i64 = b.try_into()?;
    let a_u64 = a as u64; // Perform shift on u64
    let result_u64 = a_u64 >> b;
    Ok((result_u64 as i64).into()) // Cast back to i64
});

function!(And(a: Boolean, b: Boolean)=>Boolean, ctx=ctx, arg_opts=raw,{
    let a_val:bool = a.real_value_of(ctx.clone())?.try_into()?;
    if !a_val { // Short-circuit
        return Ok(false.into());
    }
    let b_val:bool = b.real_value_of(ctx)?.try_into()?;
    Ok(b_val.into())
});

function!(Or(a: Boolean, b: Boolean)=>Boolean, ctx=ctx, arg_opts=raw,{
    let a_val:bool = a.real_value_of(ctx.clone())?.try_into()?;
    if a_val { // Short-circuit
        return Ok(true.into());
    }
    let b_val:bool = b.real_value_of(ctx)?.try_into()?;
    Ok(b_val.into())
});

function!(Xor(a: Boolean, b: Boolean)=>Boolean, ctx=ctx, arg_opts=raw,{
    let a_val:bool = a.real_value_of(ctx.clone())?.try_into()?;
    let b_val:bool = b.real_value_of(ctx)?.try_into()?;
    Ok((a_val ^ b_val).into())
});

macro_rules! compare_op{
    ($name:ident, $op:tt) =>{
        function!($name(a: Any, b: Any)=>Boolean, {
            // For comparison, we allow comparing different types, they will just be unequal.
            // Only specific type combinations are meaningfully comparable with $op.
            // Current Value::PartialEq handles cross-type comparison as always false.
            // Here we rely on that, and for same-type, it will be applied.
            // This means (Integer(1) == String("1")) is false by Value::PartialEq.
            // If we need specific cross-type comparisons like (1 == "1") to be true,
            // this logic needs to be much more complex.
            // The current setup is simple: types must generally match for $op to be true (except for !=).
            match (a,b) {
                (Value::Integer(v_a),Value::Integer(v_b)) => Ok((v_a $op v_b).into()),
                (Value::String(v_a),Value::String(v_b)) => Ok((v_a $op v_b).into()),
                (Value::Boolean(v_a),Value::Boolean(v_b)) => Ok((v_a $op v_b).into()),
                // Add other specific comparable types if needed, e.g. Array == Array
                // For any other combination of types, the behavior of $op might be undefined or always false.
                // If $op is == or !=, Value's inherent PartialEq will handle it.
                // For >, <, >=, <=, only same-type comparisons are meaningful here.
                (v_a, v_b) => if stringify!($op) == "==" {
                        Ok((v_a == v_b).into())
                    } else if stringify!($op) == "!=" {
                        Ok((v_a != v_b).into())
                    } else {
                        bail!("Cannot apply operator '{}' to incompatible types: {:?} and {:?}", stringify!($op), v_a.type_of(ctx.clone())?, v_b.type_of(ctx)?)
                    }
            }
        });
    }
}

compare_op!(Greater, >);
compare_op!(GreaterOrEqual, >=);
compare_op!(Lesser, <);
compare_op!(LesserOrEqual, <=);
compare_op!(Equal, == );
compare_op!(NotEqual, !=);

function!(Like(a: String, b: String)=>Boolean, {
    let a_str:String = a.try_into()?;
    let b_pattern:String = b.try_into()?;
    let re = regex::Regex::new(&b_pattern).context(format!("Failed to compile regex pattern: {}",b_pattern))?;
    Ok(re.is_match(&a_str).into())
});

function!(NotLike(a: String, b: String)=>Boolean, {
    let a_str:String = a.try_into()?;
    let b_pattern:String = b.try_into()?;
    let re = regex::Regex::new(&b_pattern).context(format!("Failed to compile regex pattern: {}",b_pattern))?;
    Ok((!re.is_match(&a_str)).into())
});

function!(ToString(s: Any)=>String, {
    // Convert the already evaluated 's' (which is a Value) to its string representation.
    Ok(s.to_string().into())
});

function!(ToInteger(s: String)=>Integer, { // Expects a String Value
    let s_val:String = s.try_into()?;
    s_val.parse::<i64>().map(Into::into)
        .context(format!("failed to parse integer from string: \"{}\"", s_val))
});

function!(Split(a: String, b: String)=>Type::array_of(String), {
    let s_val:String = a.try_into()?;
    let d_val:String = b.try_into()?;
    Ok(s_val.split(&d_val).map(|sub| Value::String(sub.to_string())).collect::<Vec<Value>>().into())
});

function!(StringConcat(a: Type::array_of(String))=>String, ctx=ctx, { // Takes an Array of String values
    let s_arc_vec:Arc<Vec<Value>> = a.try_into()?;
    let mut ret = String::new();
    for val_item in s_arc_vec.iter(){
        // Each item in s_arc_vec should already be a Value::String due to type checking.
        // If Array(Any) was passed, this might need real_value_of and then try_into.
        // But signature demands Array(String).
        let sv: String = val_item.clone().try_into()?; // Clone needed as try_into takes ownership
        ret += &sv;
    }
    Ok(ret.into())
});

// Manually define ArrayConcatOp using function_head! and impl Callable
function_head!(ArrayConcatOp(a: Array, b: Array) => Array); // Placeholder for macro

impl Callable for ArrayConcatOp {
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        if args.len() != 2 {
            bail!("ArrayConcatOp expects 2 arguments, got {}", args.len());
        }

        let arg_type_a = args[0].real_type_of(ctx.clone())?;
        let arg_type_b = args[1].real_type_of(ctx.clone())?;

        let type_a = match arg_type_a {
            Type::Array(inner_a) => *inner_a,
            _ => bail!("First argument to '|' must be an array, got {}", arg_type_a),
        };

        let type_b = match arg_type_b {
            Type::Array(inner_b) => *inner_b,
            _ => bail!("Second argument to '|' must be an array, got {}", arg_type_b),
        };
        
        let result_inner_type = match (type_a.clone(), type_b.clone()) {
            (Type::Any, Type::Any) => Type::Any,
            (Type::Any, other_b) => other_b,
            (other_a, Type::Any) => other_a,
            (ref other_a_ref, ref other_b_ref) if other_a_ref == other_b_ref => type_a.clone(),
            _ => {
                bail!(
                    "Array element types are incompatible for concatenation: {} vs {}",
                    type_a,
                    type_b
                )
            }
        };
        Ok(Type::array_of(result_inner_type))
    }

    fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        if args.len() != 2 { bail!("ArrayConcatOp expects 2 arguments at call time"); }

        let a_val = args[0].real_value_of(ctx.clone())?;
        let b_val = args[1].real_value_of(ctx.clone())?;

        let a_arc: Arc<Vec<Value>> = match a_val {
            Value::Array(arr) => arr,
            _ => bail!("First argument to '|' must evaluate to an array at runtime, got {:?}", args[0]),
        };
        let b_arc: Arc<Vec<Value>> = match b_val {
            Value::Array(arr) => arr,
            _ => bail!("Second argument to '|' must evaluate to an array at runtime, got {:?}", args[1]),
        };
        
        let mut concatenated_vec = Vec::with_capacity(a_arc.len() + b_arc.len());
        concatenated_vec.extend_from_slice(&a_arc);
        concatenated_vec.extend_from_slice(&b_arc);

        Ok(Value::Array(Arc::new(concatenated_vec)))
    }
}

// --- Repeat Function Implementation ---
function_head!(Repeat(item: Any, count: Integer) => Array); // Placeholder for macro

impl Callable for Repeat {
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        if args.len() != 2 {
            bail!("repeat function expects 2 arguments: item and count, got {}", args.len());
        }

        let item_type = args[0].real_type_of(ctx.clone())?;
        let count_type = args[1].real_type_of(ctx.clone())?;

        if count_type != Type::Integer {
            bail!("repeat function's second argument (count) must be an integer, got {}", count_type);
        }

        // This is the signature of the Repeat function itself, not the type of an OpCall(Repeat, ...)
        Ok(Type::Function { 
            params: vec![item_type.clone(), Type::Integer], 
            ret: Box::new(Type::array_of(item_type))
        })
    }

    fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        if args.len() != 2 { 
            bail!("repeat function expects 2 arguments at call time, got {}", args.len());
        }

        // Args are already evaluated by the Call mechanism if this is part of OpCall.
        // If called directly (e.g. from Rust), ensure they are values.
        let item_val = args[0].real_value_of(ctx.clone())?; 
        let count_val = args[1].real_value_of(ctx.clone())?;

        let count: i64 = match count_val {
            Value::Integer(i) => i,
            _ => return Err(err_msg(format!("repeat count must be an integer at call time, got {:?}", args[1])))
        };
        
        if count < 0 {
            bail!("repeat count cannot be negative, got {}", count);
        }
        if count > 1000000 { // Arbitrary limit to prevent memory exhaustion
            bail!("repeat count {} is too large (max 1,000,000)", count);
        }


        let mut repeated_vec: Vec<Value> = Vec::with_capacity(count as usize);
        for _ in 0..count {
            repeated_vec.push(item_val.clone());
        }

        Ok(Value::Array(Arc::new(repeated_vec)))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // Helper macro for op_test to get types of evaluated values
    macro_rules! op_test {
        ($name:ident, $fn:ident, [ $($in_expr:expr),+ ] , $out_expr:expr) => {
            #[test]
            fn $name() {
                let ctx : ScriptContextRef = Default::default();
                
                // Simulate parsing and then evaluation for input values
                let inputs_str = stringify!([ $($in_expr),+ ]); // Not perfect, but for literals.
                let parsed_inputs_res: Result<Vec<Value>, _> = vec![$(
                    super::super::super::parser::parse($in_expr).map_err(|e| e.to_string())
                ),+].into_iter().collect();

                let mut in_values: Vec<Value> = Vec::new();
                for res_val in parsed_inputs_res.unwrap_or_else(|e| panic!("Failed to parse input for op_test {}: {}. Input string: {}", stringify!($name), e, inputs_str)) {
                    in_values.push(res_val.value_of(ctx.clone()).unwrap());
                }
                
                let func_call_val = $fn::make_call( $(in_values.remove(0)),+ );
                
                let parsed_output_res = super::super::super::parser::parse($out_expr).map_err(|e| e.to_string());
                let output_val : Value = parsed_output_res.unwrap_or_else(|e| panic!("Failed to parse output for op_test {}: {}", stringify!($name), e)).value_of(ctx.clone()).unwrap();

                // Check type of the call expression based on evaluated input values.
                // Note: OpCall::type_of evaluates its arguments first.
                let call_type = func_call_val.type_of(ctx.clone()).unwrap();
                
                let expected_output_type = output_val.type_of(ctx.clone()).unwrap();
                assert_eq!(call_type, expected_output_type, "Type mismatch for {}", stringify!($name));
                
                let ret = func_call_val.value_of(ctx).unwrap();
                assert_eq!(ret, output_val, "Value mismatch for {}", stringify!($name));
            }
        };
    }
    
    // Simplified op_test_error: checks error during value_of (runtime)
    macro_rules! op_test_error {
        ($name:ident, $fn:ident, [ $($in_expr:expr),+ ] , $expected_error_msg:expr) => {
            #[test]
            fn $name() {
                let ctx : ScriptContextRef = Default::default();
                 let parsed_inputs_res: Result<Vec<Value>, _> = vec![$(
                    super::super::super::parser::parse($in_expr).map_err(|e| e.to_string())
                ),+].into_iter().collect();
                let mut in_values: Vec<Value> = parsed_inputs_res.unwrap().into_iter().map(|v| v.value_of(ctx.clone()).unwrap()).collect();

                let func_call_val = $fn::make_call( $(in_values.remove(0)),+ );

                match func_call_val.value_of(ctx) {
                    Err(e) => {
                        let error_string = e.to_string();
                        assert!(error_string.contains($expected_error_msg), "Error message '{}' does not contain expected substring '{}'", error_string, $expected_error_msg);
                    }
                    Ok(val) => panic!("Expected error containing '{}', but got Ok({:?}) for test {}", $expected_error_msg, val, stringify!($name)),
                }
            }
        };
    }
    
    // Simplified op_test_signature_error: checks error during type_of (compile time / signature check)
    macro_rules! op_test_signature_error {
         ($name:ident, $fn:ident, [ $($in_expr:expr),+ ] , $expected_error_msg:expr) => {
            #[test]
            fn $name() {
                let ctx : ScriptContextRef = Default::default();
                 let parsed_inputs_res: Result<Vec<Value>, _> = vec![$(
                    super::super::super::parser::parse($in_expr).map_err(|e| e.to_string())
                ),+].into_iter().collect();
                // For signature errors, we often don't need to evaluate the *values* of inputs,
                // just their AST representation to get their types.
                // However, make_call expects Value, so we parse.
                // `type_of` on OpCall will evaluate args to get their types.
                let mut in_values: Vec<Value> = parsed_inputs_res.unwrap().into_iter().collect();

                let func_call_val = $fn::make_call( $(in_values.remove(0)),+ );

                match func_call_val.type_of(ctx) {
                    Err(e) => {
                        let error_string = e.to_string();
                        assert!(error_string.contains($expected_error_msg), "Signature error message '{}' does not contain expected substring '{}'", error_string, $expected_error_msg);
                    }
                    Ok(typ) => panic!("Expected signature error containing '{}', but got Ok({:?}) for test {}", $expected_error_msg, typ, stringify!($name)),
                }
            }
        };
    }


    op_test!(access_tuple_eval, Access, ["(1, \"hello\").1"], "\"hello\"");
    
    #[derive(Debug, Clone)] struct TestAccessible { map: HashMap<String, Value> }
    impl TestAccessible { fn new_val(k: &str, v: Value) -> Value { let mut m = HashMap::new(); m.insert(k.to_string(), v); Value::NativeObject(Arc::new(Box::new(Self {map: m}))) } }
    impl std::hash::Hash for TestAccessible { fn hash<H: std::hash::Hasher>(&self, _state: &mut H) { /* simplified */ } }
    impl NativeObject for TestAccessible { fn as_accessible(&self) -> Option<&dyn Accessible> { Some(self) } }
    impl Accessible for TestAccessible {
        fn names(&self) -> Vec<&str> { self.map.keys().map(|s| s.as_str()).collect() }
        fn type_of(&self, name: &str, ctx: ScriptContextRef) -> Result<Type, Error> { self.map.get(name).ok_or_else(|| err_msg("not found"))?.type_of(ctx) }
        fn get(&self, name: &str) -> Result<Value, Error> { self.map.get(name).cloned().ok_or_else(|| err_msg("not found")) }
    }

    #[derive(Debug, Clone)] struct TestIndexable { array: Vec<Value> }
    impl TestIndexable { fn new_val(v: Vec<Value>) -> Value { Value::NativeObject(Arc::new(Box::new(Self {array: v}))) } }
    impl std::hash::Hash for TestIndexable { fn hash<H: std::hash::Hasher>(&self, _state: &mut H) { /* simplified */ } }
    impl NativeObject for TestIndexable { fn as_indexable(&self) -> Option<&dyn Indexable> { Some(self) } }
    impl Indexable for TestIndexable {
        fn length(&self) -> usize { self.array.len() }
        fn type_of_member(&self, ctx: ScriptContextRef) -> Result<Type, Error> { if self.array.is_empty() { Ok(Type::Any) } else { self.array[0].type_of(ctx) }}
        fn get(&self, index: i64) -> Result<Value, Error> { self.array.get(index as usize).cloned().ok_or_else(||err_msg("out of bounds")) }
    }

    op_test!(not_eval, Not, ["false"], "true");
    op_test!(bit_not_eval, BitNot, ["!1234"], "1234"); // BitNot stdlib might need fix if ! is only for bool
    op_test!(negative_eval, Negative, ["1234"], "-1234");

    op_test!(plus_eval,Plus,["1234", "4"], "1238");
    op_test!(minus_eval,Minus,["1234", "4"], "1230");
    op_test!(mul_eval,Multiply,["1234", "4"], "4936");
    op_test!(div_eval,Divide,["1234", "4"], "308");
    op_test!(mod_eval,Mod,["1234", "4"], "2");
    op_test!(band_eval,BitAnd,["10", "12"], "8"); // 1010 & 1100 = 1000
    op_test!(bor_eval,BitOr,["10", "12"], "14");  // 1010 | 1100 = 1110
    op_test!(bxor_eval,BitXor,["10", "12"], "6"); // 1010 ^ 1100 = 0110
    op_test!(shl_eval,ShiftLeft,["10", "1"], "20");
    op_test!(shr_eval,ShiftRight,["10", "1"], "5");
    op_test!(shru_eval, ShiftRightUnsigned, ["-10", "1"], format!("{}", ((-10i64) as u64 >> 1) as i64));


    op_test!(and_eval,And,["true", "false"], "false");
    op_test!(or_eval,Or,["true", "false"], "true");
    op_test!(xor_eval,Xor,["true", "false"], "true");
    
    op_test!(greater_eval,Greater,["1234","4567"], "false");
    op_test!(lesser_eval,Lesser,["1234","4567"], "true");
    op_test!(greater_or_equal_eval,GreaterOrEqual,["1234","1234"], "true");
    op_test!(lesser_or_equal_eval,LesserOrEqual,["1234","1234"], "true");
    op_test!(equal_eval_int,Equal,["1234","1234"], "true");
    op_test!(not_equal_eval_int,NotEqual,["1234","4567"], "true");
    op_test!(equal_eval_str,Equal,["\"abc\"","\"abc\""], "true");
    op_test!(not_equal_eval_str,NotEqual,["\"abc\"","\"def\""], "true");


    op_test!(like_eval, Like, ["\"abc\"", "\".*c\""], "true");
    op_test!(not_like_eval, NotLike, ["\"abc\"", "\".*d\""], "true");

    op_test!(is_member_of_eval_true, IsMemberOf, ["1", "[1,2,3]"], "true");
    op_test!(is_member_of_eval_false, IsMemberOf, ["4", "[1,2,3]"], "false");
    op_test!(is_member_of_eval_str_true, IsMemberOf, ["\"a\"", "[\"a\",\"b\"]"], "true");


    op_test!(to_string_eval, ToString, ["false"], "\"false\"");
    op_test!(to_integer_eval, ToInteger, ["\"1234\""], "1234");
    op_test!(split_eval, Split, ["\"1,2,3\"", "\",\""], "[\"1\",\"2\",\"3\"]");
    op_test!(string_concat_eval, StringConcat, ["[\"1\",\"2\",\"3\"]"], "\"123\"");

    op_test!(array_concat_op_eval_num, ArrayConcatOp, ["[1,2]", "[3,4]"], "[1,2,3,4]");
    op_test!(array_concat_op_eval_str, ArrayConcatOp, ["[\"a\"]", "[\"b\"]"], "[\"a\",\"b\"]");
    op_test!(array_concat_op_eval_empty_left_eval, ArrayConcatOp, ["[]", "[3,4]"], "[3,4]");
    op_test!(array_concat_op_eval_empty_right_eval, ArrayConcatOp, ["[1,2]", "[]"], "[1,2]");
    op_test!(array_concat_op_eval_empty_both_eval, ArrayConcatOp, ["[]", "[]"], "[]");

    op_test_signature_error!(array_concat_type_error_eval, ArrayConcatOp, ["[1]", "[\"a\"]"], "Array element types are incompatible");
    op_test_signature_error!(array_concat_arg_not_array_left_eval, ArrayConcatOp, ["1", "[\"a\"]"], "First argument to '|' must be an array");


    // --- Repeat Function Tests ---
    op_test!(repeat_string_eval, Repeat, ["\"a\"", "3"], "[\"a\", \"a\", \"a\"]");
    op_test!(repeat_integer_eval, Repeat, ["10", "2"], "[10, 10]");
    op_test!(repeat_boolean_eval, Repeat, ["true", "1"], "[true]");
    op_test!(repeat_zero_count_eval, Repeat, ["\"x\"", "0"], "[]");

    op_test_error!(repeat_negative_count_eval, Repeat, ["\"a\"", "-1"], "repeat count cannot be negative");
    op_test_signature_error!(repeat_non_integer_count_eval, Repeat, ["\"a\"", "\"b\""], "repeat function's second argument (count) must be an integer");

    #[test]
    fn repeat_signature_test_direct() {
        let ctx: ScriptContextRef = Default::default();
        let repeat_stub = Repeat::stub(); // The NativeObject itself

        // Test signature with (String, Integer) args
        let args_str_int = &[Value::String("hello".into()), Value::Integer(3.into())];
        let signature_str_int = repeat_stub.signature(ctx.clone(), args_str_int).unwrap();
        assert_eq!(signature_str_int, Type::Function {
            params: vec![Type::String, Type::Integer],
            ret: Box::new(Type::array_of(Type::String)),
        });

        // Test signature with (Integer, Integer) args
        let args_int_int = &[Value::Integer(123.into()), Value::Integer(3.into())];
        let signature_int_int = repeat_stub.signature(ctx.clone(), args_int_int).unwrap();
         assert_eq!(signature_int_int, Type::Function {
            params: vec![Type::Integer, Type::Integer],
            ret: Box::new(Type::array_of(Type::Integer)),
        });

        // Test signature error for non-integer count
        let args_invalid_count = &[Value::String("a".into()), Value::String("b".into())];
        let signature_invalid_res = repeat_stub.signature(ctx.clone(), args_invalid_count);
        assert!(signature_invalid_res.is_err());
        assert!(signature_invalid_res.unwrap_err().to_string().contains("repeat function's second argument (count) must be an integer"));
    
        // Test signature error for wrong number of arguments
        let args_wrong_count = &[Value::String("a".into())];
        let signature_wrong_count_res = repeat_stub.signature(ctx, args_wrong_count);
        assert!(signature_wrong_count_res.is_err());
        assert!(signature_wrong_count_res.unwrap_err().to_string().contains("repeat function expects 2 arguments"));
    }
}
[end of milu/src/script/stdlib.rs]
