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
                $crate::args!(args, ctx=$ctx, opts=$arg_opts, $($aname),+);
                $body
            }
        }
    };
}

// Access an array which is a sequence of values in same type with a dynamic index
// Can not access a tuple dynamically because it's not able to do type inference statically.
function_head!(Index(obj: Any, index: Any) => Any);
impl Callable for Index {
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        let obj = &args[0];
        let index = &args[1];
        if index.type_of(ctx.clone())? != Type::Integer {
            bail!("Index not a integer type")
        } else if let Value::NativeObject(nobj) = obj {
            if let Some(idx) = nobj.as_indexable() {
                idx.type_of_member(ctx)
            } else {
                bail!("NativeObject not in indexable")
            }
        } else if let Type::Array(t) = obj.type_of(ctx)? {
            Ok(*t)
        } else {
            bail!("Object does not implement Indexable: {:?}", obj)
        }
    }
    fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        args!(args, obj, index);
        let index: i64 = index.value_of(ctx.clone())?.try_into()?;
        let obj = obj.value_of(ctx.clone())?;
        let obj: &dyn Indexable = match &obj {
            Value::Array(a) => a.as_ref(),
            Value::NativeObject(a) => a
                .as_indexable()
                .ok_or_else(|| err_msg("NativeObject does not implement Indexible"))?,
            _ => bail!("type mismatch"),
        };
        obj.get(index)?.value_of(ctx)
    }
}

// Access a nativeobject or a tuple
function_head!(Access(obj: Any, index: Any) => Any);
impl Callable for Access {
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        fn accessible(
            ctx: ScriptContextRef,
            obj: &dyn Accessible,
            index: &Value,
        ) -> Result<Type, Error> {
            let index = if let Value::Identifier(index) = index {
                index
            } else {
                bail!("Can not access a NativeObject with: {:?}", index)
            };
            obj.type_of(index, ctx)
        }

        fn tuple(_ctx: ScriptContextRef, obj: Type, index: &Value) -> Result<Type, Error> {
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
        let objt = obj.type_of(ctx.clone())?;
        trace!("obj={:?} objt={:?}", obj, objt);
        // index is always a literal value, either identifier or integer
        let index = &args[1];
        if let Type::NativeObject(obj) = objt {
            if let Some(obj) = obj.as_accessible() {
                accessible(ctx, obj, index)
            } else if let Some(obj) = obj.as_evaluatable() {
                let obj = obj.type_of(ctx.clone())?;
                tuple(ctx, obj, index)
            } else {
                bail!("NativeObject not accessible or tuple")
            }
        } else if let Type::Tuple(_) = objt {
            tuple(ctx, objt, index)
        } else {
            bail!("Object {:?} is not Tuple nor Accessible", obj)
        }
    }

    fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        fn accessible(
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
            ret.value_of(ctx)
        }

        fn tuple(ctx: ScriptContextRef, obj: Value, index: &Value) -> Result<Value, Error> {
            let index = if let Value::Integer(index) = index {
                index
            } else {
                bail!("Can not access a tuple with: {}", index)
            };
            if let Value::Tuple(t) = obj {
                t[*index as usize].value_of(ctx)
            } else {
                bail!("Can not access type: {}", obj)
            }
        }

        let obj = args[0].value_of(ctx.clone())?;
        let index = &args[1]; // index is always a literal value, either identifier or integer
        if let Value::NativeObject(obj) = obj {
            if let Some(obj) = obj.as_accessible() {
                accessible(ctx, obj, index)
            } else if let Some(obj) = obj.as_evaluatable() {
                let obj = obj.value_of(ctx.clone())?;
                tuple(ctx, obj, index)
            } else {
                bail!("NativeObject not accessible or tuple")
            }
        } else if let Value::Tuple(_) = obj {
            tuple(ctx, obj, index)
        } else {
            bail!("Object {:?} is not Tuple nor Accessible", obj)
        }
    }

    fn unresovled_ids<'s: 'o, 'o>(&'s self, args: &'s [Value], ids: &mut HashSet<&'o Value>) { // Changed &self to &'s self
        args[0].unresovled_ids(ids) // args[1] is always literal identifier or integer, thus not unresolved
    }
}

function_head!(If(cond: Boolean, yes: Any, no: Any) => Any);
impl Callable for If {
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        let mut targs: Vec<Type> = Vec::with_capacity(args.len());
        for x in args {
            targs.push(x.type_of(ctx.clone())?);
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
    fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        let cond: bool = args[0].value_of(ctx.clone())?.try_into()?;
        if cond {
            args[1].value_of(ctx)
        } else {
            args[2].value_of(ctx)
        }
    }
}

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
    }
}

impl Evaluatable for ScopeBinding {
    fn type_of(&self, _ctx: ScriptContextRef) -> Result<Type, Error> {
        self.value.type_of(self.ctx.clone())
    }

    fn value_of(&self, ctx: ScriptContextRef) -> Result<Value, Error> {
        self.value.value_of(self.ctx.clone())?.value_of(ctx)
    }
}

impl NativeObject for ScopeBinding {
    fn as_evaluatable(&self) -> Option<&dyn Evaluatable> {
        Some(self)
    }
    fn as_callable(&self) -> Option<&dyn Callable> {
        Some(self) // Allow ScopeBinding to be treated as Callable
    }
}

impl Callable for ScopeBinding {
    fn signature(&self, _ctx: ScriptContextRef, _args: &[Value]) -> Result<Type, Error> {
        // ScopeBinding is not directly callable as a function.
        // Its purpose is to wrap values in a 'let' binding for lazy evaluation.
        // However, for type checking or analysis, it might need a signature.
        // Returning Any, or perhaps the type of the wrapped value.
        self.value.type_of(self.ctx.clone())
    }

    fn call(&self, _ctx: ScriptContextRef, _args: &[Value]) -> Result<Value, Error> {
        // ScopeBinding is not directly callable. It resolves during 'value_of'.
        bail!("ScopeBinding is not directly callable. It should be resolved via value_of.")
    }

    fn unresovled_ids<'s: 'o, 'o>(&'s self, _args: &'s [Value], ids: &mut HashSet<&'o Value>) {
        // A ScopeBinding's unresolved IDs are those in its wrapped value.
        // The 'args' for Callable are not relevant here as ScopeBinding isn't a function call itself.
        // The context for these unresolved IDs is implicitly the one where 'value' is defined,
        // but unresovled_ids is a static check.
        self.value.unresovled_ids(ids);
    }
}


function_head!(Scope(vars: Array, expr: Any) => Any);
impl Scope {
    fn make_context(vars: &[Value], outer_ctx: ScriptContextRef) -> Result<ScriptContextRef, Error> {
        // 1. Create the Arc for the new context first. This Arc will be captured by UDFs.
        //    Initialize with an empty variable map for now.
        let new_ctx_arc = Arc::new(ScriptContext::new(Some(outer_ctx.clone())));

        // 2. Iterate and prepare bindings. For UDFs, they capture new_ctx_arc.
        //    This means we need to store them temporarily then update new_ctx_arc's internal map.
        let mut temp_bindings = HashMap::new();

        for v_or_pf in vars.iter() {
            match v_or_pf {
                Value::ParsedFunction(parsed_fn_arc) => {
                    let name_str = match &parsed_fn_arc.name_ident {
                        Value::Identifier(s) => s.clone(),
                        _ => return Err(err_msg("Function name must be an identifier")),
                    };
                    let mut arg_names_str = Vec::new();
                    for arg_ident_val in &parsed_fn_arc.arg_idents {
                        match arg_ident_val {
                            Value::Identifier(s) => arg_names_str.push(s.clone()),
                            _ => return Err(err_msg("Function arguments must be identifiers")),
                        }
                    }
                    let udf = UserDefinedFunction {
                        name: Some(name_str.clone()),
                        arg_names: arg_names_str,
                        body: parsed_fn_arc.body.clone(),
                        captured_context: new_ctx_arc.clone(), // CRUCIAL CHANGE HERE
                    };
                    temp_bindings.insert(name_str, Value::UserDefined(Arc::new(udf)));
                }
                Value::Tuple(pair_arc) => {
                    let t = pair_arc.as_ref();
                    if t.len() != 2 {
                        return Err(err_msg(format!("Invalid variable binding tuple: {:?}", t)));
                    }
                    let id = match &t[0] {
                        Value::Identifier(s) => s.clone(),
                        _ => return Err(err_msg("Binding name must be an identifier")),
                    };
                    let value = t[1].clone();
                    let scope_bound_value = ScopeBinding {
                        ctx: outer_ctx.clone(), // ScopeBinding still captures outer_ctx for expression eval
                        value,
                    };
                    temp_bindings.insert(id, scope_bound_value.into());
                }
                _ => {
                    return Err(err_msg(format!(
                        "Invalid item in let binding list: {:?}. Expected Tuple or ParsedFunction.",
                        v_or_pf
                    )));
                }
            }
        }

        // 3. Populate the ScriptContext within the Arc. This requires mutable access.
        //    If Arc::get_mut returns None (because UDFs have cloned new_ctx_arc),
        //    this indicates ScriptContext.varibles needs interior mutability (e.g. RefCell/Mutex)
        //    or ScriptContext needs a method to take ownership of varibles after construction.
        //    For this exercise, we'll assume Arc::get_mut works for simplicity,
        //    or that this step conceptually represents correctly initializing the shared context.
        // if let Some(mutable_ctx) = Arc::get_mut(&mut new_ctx_arc) {
        //     mutable_ctx.varibles = temp_bindings;
        // } else {
        //     return Err(err_msg("Failed to get mutable context; this indicates an issue with shared access for setting up recursive captures."));
        // }
        // Directly modify the varibles in the ScriptContext pointed to by new_ctx_arc.
        // This is possible because varibles is now a RwLock.
        *new_ctx_arc.varibles.write().unwrap() = temp_bindings;
        Ok(new_ctx_arc)
    }
}
impl Callable for Scope {
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        let ctx = Self::make_context(args[0].as_vec(), ctx)?;
        let expr = args[1].type_of(ctx)?;
        Ok(expr)
    }
    fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        let ctx = Self::make_context(args[0].as_vec(), ctx)?;
        args[1].value_of(ctx)
    }

    fn unresovled_ids<'s: 'o, 'o>(&'s self, args: &'s [Value], main_output_ids: &mut HashSet<&'o Value>) {
        let vars_array_val = &args[0]; // Value::Array of bindings
        let let_body_expr = &args[1];  // The "in" expression

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
impl Callable for IsMemberOf {
    fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error> {
        let mut targs: Vec<Type> = Vec::with_capacity(args.len());
        for x in args {
            targs.push(x.type_of(ctx.clone())?);
        }
        args!(targs, a, ary);
        let ary = if let Type::Array(ary) = ary {
            *ary
        } else {
            bail!("argument type {:?} is not an Array", ary);
        };
        if a != ary {
            bail!(
                "subject must have on same type with array: subj={:?} array={:?}",
                a,
                ary
            );
        }
        Ok(Type::Boolean)
    }
    fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error> {
        args!(args, ctx = ctx, a, ary);
        let vec: Arc<Vec<Value>> = ary.try_into()?;
        let iter = vec.iter().map(|v| v.value_of(ctx.clone()));
        for v in iter {
            if v? == a {
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
    let a = a as u64;
    let a = (a >> b) as i64;
    Ok(a.into())
});

function!(And(a: Boolean, b: Boolean)=>Boolean, ctx=ctx, arg_opts=raw,{
    let a:bool = a.real_value_of(ctx.clone())?.try_into()?;
    let ret:bool = a && b.real_value_of(ctx)?.try_into()?;
    Ok(ret.into())
});

function!(Or(a: Boolean, b: Boolean)=>Boolean, ctx=ctx, arg_opts=raw,{
    let a:bool = a.real_value_of(ctx.clone())?.try_into()?;
    let ret:bool = a || b.real_value_of(ctx)?.try_into()?;
    Ok(ret.into())
});

function!(Xor(a: Boolean, b: Boolean)=>Boolean, ctx=ctx, arg_opts=raw,{
    let a:bool = a.real_value_of(ctx.clone())?.try_into()?;
    let b:bool = b.real_value_of(ctx)?.try_into()?;
    let ret:bool = a ^ b;
    Ok(ret.into())
});

macro_rules! compare_op{
    ($name:ident, $op:tt) =>{
        function!($name(a: Any, b: Any)=>Boolean, {
            match (a,b) {
                (Value::Integer(a),Value::Integer(b)) => Ok((a $op b).into()),
                (Value::String(a),Value::String(b)) => Ok((a $op b).into()),
                (Value::Boolean(a),Value::Boolean(b)) => Ok((a $op b).into()),
                _ => panic!("not implemented")
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
        let sv = sv.real_value_of(ctx.clone())?;
        let sv: String = sv.try_into()?;
        ret += &sv;
    }
    Ok(ret.into())
});

#[cfg(test)]
mod tests {
    // use super::super::*;
    use super::*;
    macro_rules! op_test {
        ($name:ident, $fn:ident, [ $($in:expr),+ ] , $out:expr) => {
            #[test]
            fn $name() {
                let ctx : ScriptContextRef = Default::default();
                let func : Value = $fn::make_call( $($in),+ ).into();
                let output : Value = $out;
                let otype = output.type_of(ctx.clone()).unwrap();
                let rtype = func.type_of(ctx.clone()).unwrap();
                assert_eq!(otype, rtype);
                let ret = func.value_of(ctx).unwrap();
                assert_eq!(ret, output);
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
}
