use crate::{args, function, function_head}; // Added macro imports
use async_trait::async_trait;
use anyhow::{Result, Context, bail};
use std::convert::TryInto;
use std::sync::Arc; // For IsMemberOf if it takes Arc<Vec<Value>>

use crate::script::{Callable, Evaluatable, ScriptContextRef, Type, Value}; // Added Evaluatable

// Note: The function! and function_head! macros are defined in stdlib/mod.rs

// --- Core Operations ---

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
            let a_val: i64 = a.clone().try_into().map_err(|_| anyhow::anyhow!(format!("type mismatch: expected Integer for LHS, got {:?}", a)))?;
            let b_val: i64 = b.clone().try_into().map_err(|_| anyhow::anyhow!(format!("type mismatch: expected Integer for RHS, got {:?}", b)))?;
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
            let a_val: i64 = a.clone().try_into().map_err(|_| anyhow::anyhow!(format!("type mismatch: expected Integer for LHS, got {:?}", a)))?;
            let b_val: i64 = b.clone().try_into().map_err(|_| anyhow::anyhow!(format!("type mismatch: expected Integer for RHS, got {:?}", b)))?;
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
    if !(0..64).contains(&b) {
        bail!("Shift amount for ShiftRightUnsigned must be between 0 and 63, got {}", b);
    }
    let val_a = a as u64; // Cast to u64 for unsigned shift
    let result = (val_a >> b) as i64; // Shift and cast back to i64
    Ok(result.into())
});

function!(And(a: Boolean, b: Boolean)=>Boolean, ctx=ctx, arg_opts=raw,{
    {
        let a_val: bool = a.real_value_of(ctx.clone()).await?.try_into()?;
        if !a_val {
            return Ok(false.into());
        }
        let b_val: bool = b.real_value_of(ctx).await?.try_into()?;
        Ok(b_val.into())
    }
});

function!(Or(a: Boolean, b: Boolean)=>Boolean, ctx=ctx, arg_opts=raw,{
    {
        let a_val: bool = a.real_value_of(ctx.clone()).await?.try_into()?;
        if a_val {
            return Ok(true.into());
        }
        let b_val: bool = b.real_value_of(ctx).await?.try_into()?;
        Ok(b_val.into())
    }
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
                _ => Ok($fallback_different_types.into()),
            }
        });
    }
}

macro_rules! old_compare_op_behavior {
    ($name:ident, $op:tt) => {
        function!($name(a: Any, b: Any) => Boolean, {
            match (a,b) {
                (Value::Integer(a_val),Value::Integer(b_val)) => Ok((a_val $op b_val).into()),
                (Value::String(a_val),Value::String(b_val)) => Ok((a_val $op b_val).into()),
                (Value::Boolean(a_val),Value::Boolean(b_val)) => Ok((a_val $op b_val).into()),
                (a_v,b_v) => bail!("Comparison not implemented for these types: {:?} and {:?}", a_v.type_of_simple(), b_v.type_of_simple())
            }
        });
    }
}

old_compare_op_behavior!(Greater, >);
old_compare_op_behavior!(GreaterOrEqual, >=);
old_compare_op_behavior!(Lesser, <);
old_compare_op_behavior!(LesserOrEqual, <=);
compare_op!(Equal, ==, false);
compare_op!(NotEqual, !=, true);

function!(Like(a: String, b: String)=>Boolean, {
    let a_str:String = a.try_into()?;
    let b_str:String = b.try_into()?;
    let re = regex::Regex::new(&b_str).context("failed to compile regex")?;
    Ok(re.is_match(&a_str).into())
});

function!(NotLike(a: String, b: String)=>Boolean, {
    let a_str:String = a.try_into()?;
    let b_str:String = b.try_into()?;
    let re = regex::Regex::new(&b_str).context("failed to compile regex")?;
    Ok((!re.is_match(&a_str)).into())
});

function!(ToString(s: Any)=>String, {
    Ok(s.to_string().into())
});

function!(ToInteger(s: String)=>Integer, {
    let s_val:String = s.try_into()?;
    s_val.parse::<i64>().map(Into::into)
        .context(format!("failed to parse integer: {}", s_val))
});

function_head!(IsMemberOf(a: Any, ary: Type::array_of(Type::Any)) => Boolean);
#[async_trait]
impl Callable for IsMemberOf {
    async fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type> {
        let mut targs: Vec<Type> = Vec::with_capacity(args.len());
        for x in args {
            targs.push(x.type_of(ctx.clone()).await?);
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
    async fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value> {
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
