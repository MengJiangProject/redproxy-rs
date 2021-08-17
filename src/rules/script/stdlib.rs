use std::convert::TryInto;

use easy_error::bail;

use super::*;

macro_rules! function_head {
    ($name:ident ($($aname:ident : $atype:ident),+) => $rtype:expr) => {
        #[derive(Debug, Clone)]
        pub struct $name {
            // $($aname : Value),+
        }
        #[allow(dead_code)]
        impl $name {
            pub fn new($($aname : Value),+) -> Call {
                Call::new(vec![$name::stub(), $($aname),+ ])
            }
            pub fn stub() -> Value {
                #[derive(Debug,Eq,PartialEq,Clone)]
                pub struct Stub ;
                impl NativeObject for Stub {
                    fn type_of(&self, _ctx: &ScriptContext) -> Result<Type, Error>{Ok(Type::NativeObject)}
                    fn value_of(&self, _ctx: &ScriptContext) -> Result<Value, Error>{
                        Ok($name::stub())
                    }
                    fn as_accessible(&self) -> Option<Box<dyn Accessible>>{None}
                    fn as_indexable(&self) -> Option<Box<dyn Indexable>>{None}
                    fn as_callable(&self) -> Option<Box<dyn Callable>>{Some(Box::new($name{}))}
                    fn as_any(&self) -> &dyn std::any::Any {self}
                    fn equals(&self, other: &dyn NativeObject) -> bool {
                        other.as_any().downcast_ref::<Self>().map_or(false, |a| self == a)
                    }
                }
                Value::NativeObject(Box::new(Stub))
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
        $(let $aname: Value = iter.next().unwrap().value_of($ctx)?;)+
    }
}

macro_rules! function {
    ($name:ident ($($aname:ident : $atype:ident),+) => $rtype:expr, $self:ident, $body:tt) => {
        function_head!($name ($($aname : $atype),+) => $rtype);
        impl Callable for $name {
            fn name(&self) -> &str {
                stringify!($name)
            }
            fn signature(&self, _ctx: &ScriptContext, args: Vec<Type>, _vals: &Vec<Value>) -> Result<Type,Error> {
                args!(args, $($aname),+);
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
            fn call(&$self,  ctx: &ScriptContext, args:&Vec<Value>) -> Result<Value, Error> {
                args!(args, ctx=ctx, $($aname),+);
                $body
            }
        }
    };
}

function_head!(Index(obj: Any, index: Any) => Any);
impl Callable for Index {
    fn signature(
        &self,
        _ctx: &ScriptContext,
        args: Vec<Type>,
        _vals: &Vec<Value>,
    ) -> Result<Type, Error> {
        args!(args, obj, _index);
        if let Type::Array(t) = obj {
            Ok(*t)
        } else {
            bail!(
                "trying to index type {:?} which does not implement Indexable",
                obj
            )
        }
    }
    fn call(&self, ctx: &ScriptContext, args: &Vec<Value>) -> Result<Value, Error> {
        args!(args, ctx = ctx, obj, index);
        let index: i64 = index.try_into()?;
        let obj: Box<dyn Indexable> = match obj {
            Value::Array(a) => a,
            Value::NativeObject(a) => a
                .as_indexable()
                .ok_or(err_msg("NativeObject does not implement Indexible"))?,
            _ => bail!("type mismatch"),
        };
        obj.get(index)?.value_of(ctx)
    }
    fn name(&self) -> &str {
        "Index"
    }
}

function_head!(Access(obj: Any, index: Any) => Any);
impl Callable for Access {
    fn signature(
        &self,
        ctx: &ScriptContext,
        _args: Vec<Type>,
        vals: &Vec<Value>,
    ) -> Result<Type, Error> {
        // args!(args, obj, index);
        let obj = &vals[0];
        let index = &vals[1];
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
    fn call(&self, ctx: &ScriptContext, args: &Vec<Value>) -> Result<Value, Error> {
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
            obj.get(index)?.value_of(ctx)
        } else {
            bail!("Type {:?} does not implement Accessible", obj)
        }
    }
    fn name(&self) -> &str {
        "Access"
    }
}

function_head!(If(cond: Boolean, yes: Any, no: Any) => Any);
impl Callable for If {
    fn signature(
        &self,
        _ctx: &ScriptContext,
        args: Vec<Type>,
        _vals: &Vec<Value>,
    ) -> Result<Type, Error> {
        // use Type::*;
        args!(args, cond, yes, no);
        if Type::Boolean != cond {
            bail!("Condition type {:?} is not a Boolean", cond);
        }
        if yes != no {
            bail!("Condition return type must be same: {:?} {:?}", yes, no);
        }
        Ok(yes)
    }
    fn call(&self, ctx: &ScriptContext, args: &Vec<Value>) -> Result<Value, Error> {
        let cond: bool = args[0].value_of(ctx)?.try_into()?;
        if cond {
            args[1].value_of(ctx)
        } else {
            args[2].value_of(ctx)
        }
    }
    fn name(&self) -> &str {
        "If"
    }
}

function_head!(MemberOf(a: Any, ary: Array) => Boolean);
impl Callable for MemberOf {
    fn signature(
        &self,
        _ctx: &ScriptContext,
        args: Vec<Type>,
        _vals: &Vec<Value>,
    ) -> Result<Type, Error> {
        // use Type::*;
        args!(args, a, ary);
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
    fn call(&self, ctx: &ScriptContext, args: &Vec<Value>) -> Result<Value, Error> {
        args!(args, ctx = ctx, a, ary);
        let vec: Vec<Value> = ary.try_into()?;
        Ok(vec.into_iter().any(|v| v == a).into())
    }
    fn name(&self) -> &str {
        "MemberOf"
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

macro_rules! bool_op{
    ($name:ident, $op:tt) =>{
        function!($name(a: Boolean, b: Boolean)=>Boolean, self, {
            let a:bool = a.try_into()?;
            let b:bool = b.try_into()?;
            Ok((a $op b).into())
        });
    }
}

bool_op!(And,&&);
bool_op!(Or,||);

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
                let ret = func.call(&ctx).unwrap();
                assert_eq!(ret, output);
            }
        };
    }

    op_test!(not, Not, [false.into()], true.into());
    op_test!(bit_not, BitNot, [(!1234).into()], 1234.into());

    macro_rules! int_op_test {
        ($name:ident, $fn:ident, $op:tt) => {
            op_test!($name, $fn, [1234.into(),4567.into()], (1234 $op 4567).into());
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

    macro_rules! bool_op_test {
        ($name:ident, $fn:ident, $op:tt) => {
            op_test!($name, $fn, [true.into(), false.into()], (true $op false).into());
        };
    }

    bool_op_test!(and,And,&&);
    bool_op_test!(or,Or,||);

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
