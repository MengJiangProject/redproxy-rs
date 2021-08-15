use std::convert::TryInto;

use easy_error::{bail, err_msg};

use super::*;
#[derive(Debug, Clone)]
pub struct Index {
    obj: Value,
    index: Value,
}
impl Index {
    pub fn new(obj: Value, index: Value) -> Self {
        Self { obj, index }
    }
}
impl Callable for Index {
    fn signature(&self) -> Result<Type, Error> {
        // use Type::*;
        let t = self.obj.type_of()?;
        if let Type::Array(t) = t {
            Ok(*t)
        } else {
            bail!(
                "trying to index type {:?} which does not implement Indexable",
                t
            )
        }
    }
    fn call(self) -> Result<Value, Error> {
        match self.obj {
            Value::Array(a) => {
                let index: i64 = self.index.try_into()?;
                let index: Result<usize, std::num::TryFromIntError> = if index >= 0 {
                    index.try_into()
                } else {
                    (-index).try_into().map(|i: usize| a.len() - i)
                };
                let i: usize = index.context("failed to cast index from i64")?;
                Ok(a[i].clone())
            }
            _ => bail!("type mismatch"),
        }
    }
    fn name(&self) -> &str {
        "Index"
    }
    fn paramters(&self) -> Box<[&Value]> {
        Box::new([&self.obj, &self.index])
    }
    // fn clone(&self) -> Box<dyn Callable> {
    //     Box::new(Clone::clone(self))
    // }
}

#[derive(Debug, Clone)]
pub struct Access {
    obj: Value,
    index: Value,
}
impl Access {
    pub fn new(obj: Value, index: Value) -> Self {
        Self { obj, index }
    }
}
impl Callable for Access {
    fn signature(&self) -> Result<Type, Error> {
        // use Type::*;
        let t = self.obj.type_of()?;
        if let Type::NativeObject = t {
            Ok(t)
        } else {
            bail!(
                "trying to access type {:?} which does not implement Accessible",
                t
            )
        }
    }
    fn call(self) -> Result<Value, Error> {
        match self.obj {
            Value::Array(a) => {
                let index: i64 = self.index.try_into()?;
                let index: Result<usize, std::num::TryFromIntError> = if index >= 0 {
                    index.try_into()
                } else {
                    (-index).try_into().map(|i: usize| a.len() - i)
                };
                let i: usize = index.context("failed to cast index from i64")?;
                Ok(a[i].clone())
            }
            _ => bail!("type mismatch"),
        }
    }
    fn name(&self) -> &str {
        "Access"
    }
    fn paramters(&self) -> Box<[&Value]> {
        Box::new([&self.obj, &self.index])
    }
    // fn clone(&self) -> Box<dyn Callable> {
    //     Box::new(Clone::clone(self))
    // }
}

#[derive(Debug, Clone)]
pub struct Call {
    // obj: Value,
    args: Vec<Value>,
}
impl Call {
    pub fn new(args: Vec<Value>) -> Self {
        Self { args }
    }
}
impl Callable for Call {
    fn signature(&self) -> Result<Type, Error> {
        // use Type::*;
        let t = self.args[0].type_of()?;
        if let Type::NativeObject = t {
            Ok(t)
        } else {
            bail!(
                "trying to access type {:?} which does not implement Accessible",
                t
            )
        }
    }
    fn call(self) -> Result<Value, Error> {
        todo!()
    }
    fn name(&self) -> &str {
        "Access"
    }
    fn paramters(&self) -> Box<[&Value]> {
        let v: Vec<_> = self.args.iter().collect();
        v.into_boxed_slice()
    }
    // fn clone(&self) -> Box<dyn Callable> {
    //     Box::new(Clone::clone(self))
    // }
}
macro_rules! function {
    // ($name:ident ($($aname:ident : $atype:expr),+) => $rtype:expr, $body:tt) => {
    //     function!($name ($($aname : $atype),+) => $rtype, self, $body);
    // };
    ($name:ident ($($aname:ident : $atype:expr),+) => $rtype:expr, $self:ident, $body:tt) => {
        #[derive(Debug, Clone)]
        pub struct $name {
            $($aname : Value),+
        }
        impl $name {
            pub fn new($($aname : Value),+) -> Self {
                $name { $($aname),+ }
            }
        }
        impl Callable for $name {
            fn signature(&self) -> Result<Type,Error> {
                use Type::*;
                let vtype = [$(self.$aname.type_of()?),+];
                let rtype = [$($atype),+];
                if vtype == rtype {
                    Ok($rtype)
                }else{
                    easy_error::bail!("argument type mismatch, required: {:?} provided: {:?}",rtype,vtype)
                }
            }
            fn call($self) -> Result<Value, Error> {
                $body
            }
            fn name(&self) -> &str {
                stringify!($name)
            }
            fn paramters(&self) -> Box<[&Value]>{
                Box::new([$(&self.$aname),+])
            }
            // fn clone(&self) -> Box<dyn Callable> {
            //     Box::new(Clone::clone(self))
            // }
        }
        // impl From<$name> for Value {
        //     fn from(x: $name) -> Self {
        //         Value::Lambda(Box::new(x))
        //     }
        // }
    };
}

macro_rules! array_of {
    ($t:ident) => {
        Array(Box::new($t))
    };
}

function!(Not(b:Boolean)=>Boolean, self, {
    let b:bool = self.b.try_into()?;
    Ok((!b).into())
});

function!(BitNot(b:Integer)=>Integer, self, {
    let b:i64 = self.b.try_into()?;
    Ok((!b).into())
});

macro_rules! int_op{
    ($name:ident, $op:tt) =>{
        function!($name(a: Integer, b: Integer)=>Integer, self, {
            let a:i64 = self.a.try_into()?;
            let b:i64 = self.b.try_into()?;
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
            let a:bool = self.a.try_into()?;
            let b:bool = self.b.try_into()?;
            Ok((a $op b).into())
        });
    }
}

bool_op!(And,&&);
bool_op!(Or,||);

macro_rules! compare_op{
    ($name:ident, $op:tt) =>{
        function!($name(a: Any, b: Any)=>Boolean, self, {
            match (self.a,self.b) {
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
    let a:String = self.a.try_into()?;
    let b:String = self.b.try_into()?;
    let re = regex::Regex::new(&b).context("failed to compile regex")?;
    Ok(re.is_match(&a).into())
});

function!(NotLike(a: String, b: String)=>Boolean, self, {
    let a:String = self.a.try_into()?;
    let b:String = self.b.try_into()?;
    let re = regex::Regex::new(&b).context("failed to compile regex")?;
    Ok((!re.is_match(&a)).into())
});

function!(ToString(s: Any)=>String, self, {
    Ok(self.s.to_string().into())
});

function!(ToInteger(s: String)=>Integer, self, {
    let s:String = self.s.try_into()?;
    s.parse::<i64>().map(Into::into)
        .context(format!("failed to parse integer: {}", s))
});

function!(Split(a: String, b: String)=>array_of!(String), self, {
    let s:String = self.a.try_into()?;
    let d:String = self.b.try_into()?;
    Ok(s.split(&d).map(Into::into).collect::<Vec<Value>>().into())
});

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    macro_rules! op_test {
        ($name:ident, $fn:ident, [ $($in:expr),+ ] , $out:expr) => {
            #[test]
            fn $name() {
                let func = $fn::new( $($in),+ );
                let output = $out;
                // let input = $in;
                let ret = func.call().unwrap();
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

    op_test!(to_string, ToString, [false.into()], "false".into());
    op_test!(to_integer, ToInteger, ["1234".into()], 1234.into());
    op_test!(
        split,
        Split,
        ["1,2".into(), ",".into()],
        vec!["1".into(), "2".into()].into()
    );
}
