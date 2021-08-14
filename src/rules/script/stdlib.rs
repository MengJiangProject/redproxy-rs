use std::convert::TryInto;

use super::*;

macro_rules! function {
    ($name:ident ($aname:ident : $atype:ident) => $rtype:expr, $body:tt) => {
        function!($name ($aname : [ $atype ]) => $rtype, $body);
    };
    ($name:ident ($aname:ident : [$($atype:expr),*]) => $rtype:expr, $body:tt) => {
        struct $name;
        impl Callable for $name {
            fn signature(&self) -> (Type, Box<[Type]>) {
                use Type::*;
                ($rtype, Box::new([$($atype),*]))
            }
            fn call(&self, mut $aname: Vec<Value>) -> Result<Value, Error> {
                $body
            }
        }
    };
}

macro_rules! array_of {
    ($t:ident) => {
        Array(Box::new($t))
    };
}

function!(Not(args:Boolean)=>Boolean,{
    let b:bool = args.remove(0).try_into()?;
    Ok((!b).into())
});

function!(BitNot(args:Integer)=>Integer,{
    let b:i64 = args.remove(0).try_into()?;
    Ok((!b).into())
});

macro_rules! int_op{
    ($name:ident, $op:tt) =>{
        function!($name(args:[Integer,Integer])=>Integer,{
            let a:i64 = args.remove(0).try_into()?;
            let b:i64 = args.remove(0).try_into()?;
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
        function!($name(args:[Boolean,Boolean])=>Boolean,{
            let a:bool = args.remove(0).try_into()?;
            let b:bool = args.remove(0).try_into()?;
            Ok((a $op b).into())
        });
    }
}

bool_op!(And,&&);
bool_op!(Or,||);

function!(ToString(args: Any)=>String,{
    Ok(args.remove(0).to_string().into())
});

function!(ToInteger(args: String)=>Integer,{
    let s:String = args.remove(0).try_into()?;
    s.parse::<i64>().map(Into::into)
        .context(format!("failed to parse integer: {}", s))
});

function!(Split(args: [String,String])=>array_of!(String),{
    let s:String = args.remove(0).try_into()?;
    let d:String = args.remove(0).try_into()?;
    Ok(s.split(&d).map(Into::into).collect::<Vec<Value>>().into())
});

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    macro_rules! op_test {
        ($name:ident, $fn:ident, $in:expr, $out:expr) => {
            #[test]
            fn $name() {
                let func = $fn;
                let output = $out;
                let input = $in;
                let ret = func.call(input).unwrap();
                assert_eq!(ret, output);
            }
        };
    }

    op_test!(not, Not, vec![false.into()], true.into());
    op_test!(bit_not, BitNot, vec![(!1234).into()], 1234.into());

    macro_rules! int_op_test {
        ($name:ident, $fn:ident, $op:tt) => {
            op_test!($name, $fn, vec![1234.into(),4567.into()], (1234 $op 4567).into());
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
            op_test!($name, $fn, vec![true.into(), false.into()], (true $op false).into());
        };
    }

    bool_op_test!(and,And,&&);
    bool_op_test!(or,Or,||);

    op_test!(to_string, ToString, vec![false.into()], "false".into());
    op_test!(to_integer, ToInteger, vec!["1234".into()], 1234.into());
    op_test!(
        split,
        Split,
        vec!["1,2".into(), ",".into()],
        vec!["1".into(), "2".into()].into()
    );
}
