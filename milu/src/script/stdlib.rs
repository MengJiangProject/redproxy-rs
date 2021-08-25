use std::convert::TryInto;

use easy_error::bail;

use super::*;

macro_rules! function_head {
    ($name:ident ($($aname:ident : $atype:ident),+) => $rtype:expr) => {

        // the String field is added to avoid hashing a empty struct always returns same value
        #[derive(Clone,Hash)]
        pub struct $name(String);

        #[allow(dead_code)]
        impl<'a> $name {
            pub fn stub() -> $name {$name(stringify!($name).into())}
            pub fn new($($aname : Value<'a>),+) -> Call<'a> {
                Call::new(vec![$name(stringify!($name).into()).into(), $($aname),+ ])
            }
        }
        impl<'a> NativeObject<'a> for $name {
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

macro_rules! args {
    ($args:ident, $($aname:ident),+) => {
        let mut iter = $args.into_iter();
        $(let $aname: Type = iter.next().unwrap();)+
    };
    ($args:ident, ctx=$ctx:ident, $($aname:ident),+) => {
        let mut iter = $args.into_iter();
        $(let $aname = iter.next().unwrap().value_of($ctx.clone())?;)+
    }
}

macro_rules! function {
    ($name:ident ($($aname:ident : $atype:ident),+) => $rtype:expr, $self:ident, $body:tt) => {
        function_head!($name ($($aname : $atype),+) => $rtype);
        impl Callable for $name {
            fn signature<'a:'b,'b>(
                &self,
                ctx: ScriptContextRef<'b>,
                args: &Vec<Value<'a>>,
            ) -> Result<Type, Error>
            {
                let mut targs : Vec<Type> = Vec::with_capacity(args.len());
                for x in args {
                    targs.push(x.type_of(ctx.clone())?);
                }
                args!(targs, $($aname),+);
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
            fn call<'a:'b,'b>(
                &self,
                ctx: ScriptContextRef<'b>,
                args: &Vec<Value<'a>>,
            ) -> Result<Value<'b>, Error>
            {
                args!(args, ctx=ctx, $($aname),+);
                $body
            }
        }
    };
}

function_head!(Index(obj: Any, index: Any) => Any);
impl Callable for Index {
    fn signature<'a: 'b, 'b>(
        &self,
        ctx: ScriptContextRef<'b>,
        args: &Vec<Value<'a>>,
    ) -> Result<Type, Error> {
        let mut targs: Vec<Type> = Vec::with_capacity(args.len());
        for x in args {
            targs.push(x.type_of(ctx.clone())?);
        }
        args!(targs, obj, _index);
        if let Type::Array(t) = obj {
            Ok(*t)
        } else {
            bail!(
                "trying to index type {:?} which does not implement Indexable",
                obj
            )
        }
    }
    fn call<'a: 'b, 'b>(
        &self,
        ctx: ScriptContextRef<'b>,
        args: &Vec<Value<'a>>,
    ) -> Result<Value<'b>, Error> {
        args!(args, ctx = ctx, obj, index);
        let index: i64 = index.try_into()?;
        let obj: &dyn Indexable = match &obj {
            Value::Array(a) => a.as_ref(),
            Value::NativeObject(a) => a
                .as_indexable()
                .ok_or(err_msg("NativeObject does not implement Indexible"))?,
            _ => bail!("type mismatch"),
        };
        obj.get(index)?.value_of(ctx)
    }
}

function_head!(Access(obj: Any, index: Any) => Any);
impl Callable for Access {
    fn signature<'a: 'b, 'b>(
        &self,
        ctx: ScriptContextRef<'b>,
        args: &Vec<Value<'a>>,
    ) -> Result<Type, Error> {
        // args!(args, obj, index);
        let obj = &args[0];
        let index = &args[1];
        let index = if let Value::Identifier(index) = index {
            index
        } else {
            bail!("Index must be an identifier")
        };
        if let Value::NativeObject(obj) = obj {
            let obj = obj
                .as_accessible()
                .ok_or(err_msg("Object not accessible"))?;
            let t = obj.get(index)?;
            Ok(t.type_of(ctx)?)
        } else {
            bail!("Type {:?} does not implement Accessible", obj)
        }
    }
    fn call<'a: 'b, 'b>(
        &self,
        ctx: ScriptContextRef<'b>,
        args: &Vec<Value<'a>>,
    ) -> Result<Value<'b>, Error> {
        let obj = args[0].value_of(ctx.clone())?;
        let index = &args[1];
        let index = if let Value::Identifier(index) = index {
            index
        } else {
            bail!("Index must be an identifier")
        };
        if let Value::NativeObject(obj) = obj {
            let obj = obj
                .as_accessible()
                .ok_or(err_msg("Object not accessible"))?;
            obj.get(index)?.value_of(ctx)
        } else {
            bail!("Type {:?} does not implement Accessible", obj)
        }
    }
}

function_head!(If(cond: Boolean, yes: Any, no: Any) => Any);
impl Callable for If {
    fn signature<'a: 'b, 'b>(
        &self,
        ctx: ScriptContextRef<'b>,
        args: &Vec<Value<'a>>,
    ) -> Result<Type, Error> {
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
    fn call<'a: 'b, 'b>(
        &self,
        ctx: ScriptContextRef<'b>,
        args: &Vec<Value<'a>>,
    ) -> Result<Value<'b>, Error> {
        let cond: bool = args[0].value_of(ctx.clone())?.try_into()?;
        if cond {
            args[1].value_of(ctx)
        } else {
            args[2].value_of(ctx)
        }
    }
}

function_head!(Scope(vars: Array, expr: Any) => Any);
impl Scope {
    fn make_context<'value, 'ctx>(
        vars: &Vec<Value<'value>>,
        ctx: ScriptContextRef<'ctx>,
    ) -> Result<ScriptContextRef<'ctx>, Error>
    where
        'value: 'ctx,
    {
        let mut nctx = ScriptContext::new(Some(ctx));
        for v in vars.iter() {
            let t = v.as_vec();
            let id: String = t[0].as_str().to_owned();
            let value = t[1].unsafe_clone();
            nctx.set(id, value);
        }
        Ok(Arc::new(nctx))
    }
}
impl Callable for Scope {
    fn signature<'a: 'b, 'b>(
        &self,
        ctx: ScriptContextRef<'b>,
        args: &Vec<Value<'a>>,
    ) -> Result<Type, Error> {
        let ctx = Self::make_context(&args[0].as_vec(), ctx)?;
        let expr = args[1].type_of(ctx)?;
        Ok(expr)
    }
    fn call<'a: 'b, 'b>(
        &self,
        ctx: ScriptContextRef<'b>,
        args: &Vec<Value<'a>>,
    ) -> Result<Value<'b>, Error> {
        let ctx = Self::make_context(&args[0].as_vec(), ctx)?;
        args[1].value_of(ctx)
    }
}

function_head!(MemberOf(a: Any, ary: Array) => Boolean);
impl Callable for MemberOf {
    fn signature<'a: 'b, 'b>(
        &self,
        ctx: ScriptContextRef<'b>,
        args: &Vec<Value<'a>>,
    ) -> Result<Type, Error> {
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
    fn call<'a: 'b, 'b>(
        &self,
        ctx: ScriptContextRef<'b>,
        args: &Vec<Value<'a>>,
    ) -> Result<Value<'b>, Error> {
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

function!(Not(b:Boolean)=>Boolean, self, {
    let b:bool = b.try_into()?;
    Ok((!b).into())
});

function!(BitNot(b:Integer)=>Integer, self, {
    let b:i64 = b.try_into()?;
    Ok((!b).into())
});

function!(Negative(b:Integer)=>Integer, self, {
    let b:i64 = b.try_into()?;
    Ok((-b).into())
});

macro_rules! int_op{
    ($name:ident, $op:tt) =>{
        function!($name(a: Integer, b: Integer)=>Integer, self, {
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
function!(ShiftRightUnsigned(a: Integer, b: Integer)=>Integer, self, {
    let a:i64 = a.try_into()?;
    let b:i64 = b.try_into()?;
    let a = a as u64;
    let a = (a >> b) as i64;
    Ok(a.into())
});

macro_rules! bool_op{
    ($name:ident, $op:tt) =>{
        function!($name(a: Boolean, b: Boolean)=>Boolean, self, {
            let a:bool = a.try_into()?;
            let b:bool = b.try_into()?;
            Ok((a $op b).into())
        });
    }
}
// TODO: implement shortcut evaluation here?
bool_op!(And,&&);
bool_op!(Or,||);
bool_op!(Xor,^);

macro_rules! compare_op{
    ($name:ident, $op:tt) =>{
        function!($name(a: Any, b: Any)=>Boolean, self, {
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

function!(Like(a: String, b: String)=>Boolean, self, {
    let a:String = a.try_into()?;
    let b:String = b.try_into()?;
    let re = regex::Regex::new(&b).context("failed to compile regex")?;
    Ok(re.is_match(&a).into())
});

function!(NotLike(a: String, b: String)=>Boolean, self, {
    let a:String = a.try_into()?;
    let b:String = b.try_into()?;
    let re = regex::Regex::new(&b).context("failed to compile regex")?;
    Ok((!re.is_match(&a)).into())
});

function!(ToString(s: Any)=>String, self, {
    Ok(s.to_string().into())
});

function!(ToInteger(s: String)=>Integer, self, {
    let s:String = s.try_into()?;
    s.parse::<i64>().map(Into::into)
        .context(format!("failed to parse integer: {}", s))
});

function!(Split(a: String, b: String)=>Type::array_of(String), self, {
    let s:String = a.try_into()?;
    let d:String = b.try_into()?;
    Ok(s.split(&d).map(Into::into).collect::<Vec<Value>>().into())
});

#[cfg(test)]
mod tests {
    // use super::super::*;
    use super::*;

    macro_rules! op_test {
        ($name:ident, $fn:ident, [ $($in:expr),+ ] , $out:expr) => {
            #[test]
            fn $name() {
                let ctx = Default::default();
                let func = Box::new($fn::new( $($in),+ ));
                let output = $out;
                // let input = $in;
                let ret = func.call(ctx).unwrap();
                assert_eq!(ret, output);
            }
        };
    }

    op_test!(not, Not, [false.into()], true.into());
    op_test!(bit_not, BitNot, [(!1234).into()], 1234.into());
    op_test!(negative, Negative, [1234.into()], (-1234).into());

    macro_rules! int_op_test {
        ($name:ident, $fn:ident, $op:tt) => {
            op_test!($name, $fn, [1234.into(),45.into()], (1234 $op 45).into());
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
        member_of,
        MemberOf,
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
}
