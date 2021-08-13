use std::{fmt, num::ParseIntError};

use nom::{
    branch::alt,
    bytes::{complete::tag, complete::tag_no_case},
    character::{
        complete::multispace0,
        complete::{alpha1, alphanumeric1, char, digit1, hex_digit1, oct_digit1, one_of},
    },
    combinator::{all_consuming, cut, map, map_res, opt, recognize},
    error::{context, ContextError, FromExternalError, ParseError},
    multi::{many0, many1, separated_list0},
    sequence::{delimited, pair, preceded, terminated, tuple},
    AsChar, IResult, InputTakeAtPosition, Parser,
};

mod string;

#[derive(Debug, Eq, PartialEq)]
pub enum Value {
    Identifier(String),
    Array(Box<Vec<Value>>),
    String(String),
    Integer(i64),
    Boolean(bool),
    Expression(Box<Expr>),
}

impl From<Vec<Value>> for Value {
    fn from(x: Vec<Value>) -> Self {
        Self::Array(x.into())
    }
}

impl From<Expr> for Value {
    fn from(x: Expr) -> Self {
        Self::Expression(x.into())
    }
}

#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum Expr {
    //prioity 8
    Call(Value, Vec<Value>),
    Index(Value, Value),
    Access(Value, Value),
    //prioity 7
    Not(Value),
    Inverse(Value),
    //prioity 6
    Multiply(Value, Value),
    Divide(Value, Value),
    Mod(Value, Value),
    //prioity 5
    Plus(Value, Value),
    Minus(Value, Value),
    //prioity 4
    Greater(Value, Value),
    GreaterOrEqual(Value, Value),
    Lesser(Value, Value),
    LesserOrEqual(Value, Value),
    //prioity 3
    Equal(Value, Value),
    NotEqual(Value, Value),
    Like(Value, Value),
    NotLike(Value, Value),
    //prioity 2.3
    BitAnd(Value, Value),
    //prioity 2.2
    BitXor(Value, Value),
    //prioity 2.1
    BitOr(Value, Value),
    //prioity 2
    And(Value, Value),
    //prioity 1
    Or(Value, Value),
}

impl Expr {
    fn parse_many(op: &str, mut args: Vec<Value>) -> Self {
        let op = op.to_ascii_lowercase();
        match op.as_str() {
            //prioity 7
            "call" => {
                let f = args.remove(0);
                Self::Call(f, args)
            }
            "index" => {
                let p1 = args.remove(0);
                let p2 = args.remove(0);
                Self::Index(p1, p2)
            }
            "access" => {
                let p1 = args.remove(0);
                let p2 = args.remove(0);
                Self::Access(p1, p2)
            }
            _ => panic!("not implemented"),
        }
    }
    fn parse1(op: &str, p1: Value) -> Self {
        let op = op.to_ascii_lowercase();
        match op.as_str() {
            //prioity 7
            "!" => Self::Not(p1),
            "~" => Self::Inverse(p1),
            _ => panic!("not implemented"),
        }
    }
    fn parse2(op: &str, p1: Value, p2: Value) -> Self {
        let op = op.to_ascii_lowercase();
        match op.as_str() {
            //prioity 6
            "*" => Self::Multiply(p1, p2),
            "/" => Self::Divide(p1, p2),
            "%" => Self::Mod(p1, p2),
            //prioity 5
            "+" => Self::Plus(p1, p2),
            "-" => Self::Minus(p1, p2),
            //prioity 4
            ">" => Self::Greater(p1, p2),
            ">=" => Self::GreaterOrEqual(p1, p2),
            "<" => Self::Lesser(p1, p2),
            "<=" => Self::LesserOrEqual(p1, p2),
            //prioity 3
            "==" => Self::Equal(p1, p2),
            "!=" => Self::NotEqual(p1, p2),
            "=~" => Self::Like(p1, p2),
            "!~" => Self::NotLike(p1, p2),
            //prioity 2
            "&&" | "and" => Self::And(p1, p2),
            //prioity 1
            "||" | "or" => Self::Or(p1, p2),
            _ => panic!("not implemented"),
        }
    }
}

// all combinator made by this macro will remove any leading whitespaces
macro_rules! rule {
    (#$($args:tt)*) => (
        rule!(#$($args)*);
    );

    ($vis:vis $name:ident, $body:tt) => {
        rule!($vis $name ( i ) -> &'a str, ctx, $body);
    };

    ($vis:vis $name:ident -> $rt:ty, $body:tt) => {
        rule!($vis $name ( i ) -> $rt, ctx, $body);
    };

    ($vis:vis $name:ident ( $input:ident ), $body:tt) => {
        rule!($vis $name ( $input ) -> &'a str, ctx, $body);
    };

    ($vis:vis $name:ident ( $input:ident ) -> $rt:ty, $body:tt) => {
        rule!($vis $name ( $input ) -> $rt, ctx, $body);
    };

    ($vis:vis $name:ident ( $input:ident ) -> $rt:ty, $context:ident, $body:tt) => {
        #[allow(dead_code)]
        $vis fn $name<'a, E>($input: &'a str) -> IResult<&'a str, $rt, E>
        where
            E: ParseError<&'a str>
                + ContextError<&'a str>
                + FromExternalError<&'a str, ParseIntError>
                + fmt::Debug,
        {
            $context!($name, $body, $input)
        }
    };
}

#[allow(unused_macros)]
macro_rules! no_ctx {
    ($name:ident, $body:tt, $input:ident) => {
        $body
    };
}

#[allow(unused_macros)]
macro_rules! ctx {
    ($name:ident, $body:tt, $input:ident) => {
        context(stringify!($name), ws($body))($input)
    };
}

// ignore leading whitespaces
fn ws<I, O, E, F>(f: F) -> impl FnMut(I) -> IResult<I, O, E>
where
    I: InputTakeAtPosition,
    E: ParseError<I>,
    F: Parser<I, O, E>,
    <I as InputTakeAtPosition>::Item: AsChar + Clone,
{
    preceded(multispace0, f)
}

rule!(boolean -> bool, {
    let parse_true = nom::combinator::value(true, tag("true"));
    let parse_false = nom::combinator::value(false, tag("false"));
    alt((parse_true, parse_false))
});

use string::parse_string as string;

rule!(hexadecimal, {
    preceded(
        tag_no_case("0x"),
        recognize(many1(terminated(hex_digit1, many0(char('_'))))),
    )
});

rule!(octal, {
    preceded(
        tag_no_case("0o"),
        recognize(many1(terminated(oct_digit1, many0(char('_'))))),
    )
});

rule!(binary, {
    preceded(
        tag_no_case("0b"),
        recognize(many1(terminated(one_of("01"), many0(char('_'))))),
    )
});

rule!(decimal, {
    recognize(many1(terminated(digit1, many0(char('_')))))
});

rule!(integer -> i64, {
    fn atoi(n: u32) -> impl Fn(&str) -> Result<i64, ParseIntError> {
        move |x| i64::from_str_radix(x, n)
    }
    alt((
        map_res(binary, atoi(2)),
        map_res(octal, atoi(8)),
        map_res(hexadecimal, atoi(16)),
        map_res(decimal, atoi(10)),
    ))
});

rule!(identifier -> Value, {
    map(
        recognize(pair(
            alt((alpha1, tag("_"))),
            many0(alt((alphanumeric1, tag("_")))),
        )),
        |x|Value::Identifier(String::from(x)),
    )
});

rule!(array -> Value, {
    let body = terminated(
        separated_list0(ws(char(',')), op_1),
        opt(ws(char(',')))
    );
    map(delimited(char('['), cut(body),ws(char(']'))), Into::into)
});

rule!(value -> Value, {
    // println!("value: i={}", i);
    alt((
        map(string, Value::String),
        map(integer, Value::Integer),
        map(boolean, Value::Boolean),
        identifier,
        array,
    ))
});

rule!(op_value -> Value, {
    alt((
        delimited(char('('), ws(op_1), ws(char(')'))),
        delimited(char('('), ws(value), ws(char(')'))),
        value,
    ))
});

rule!(op_index -> (&str,Vec<Value>), {
    map(
        delimited(tag("["), op_1, ws(char(']'))),
        |idx| ("index", vec![idx])
    )
});

rule!(op_access -> (&str,Vec<Value>), {
    map(
        preceded(tag("."), identifier),
        |id| ("access", vec![id])
    )
});

rule!(op_call -> (&str,Vec<Value>), {
    map(
        delimited(
            char('('),
            separated_list0(ws(char(',')), op_1),
            ws(char(')'))
        ),
        |args|("call",args)
    )
});

rule!(op_8(i) -> Value, {
    map(
        tuple((
            op_value,
            many0(alt((
                op_index,
                op_access,
                op_call
            )))
        )) ,
    |(p1, expr)| {
        println!("p1={:?} expr={:?}", p1, expr);
        expr.into_iter().fold(p1, |p1, val| {
            let (op, mut args) : (&str,Vec<Value>) = val;
            args.insert(0,p1);
            Expr::parse_many(op, args).into()
        })
    })
});

//unary opreator
rule!(op_7(i) -> Value, {
    alt((
        map(tuple((alt((tag("!"), tag("~"))), op_7)),
            |(op,p1)|Expr::parse1(op, p1).into()
        ),
        op_8
    ))
});

macro_rules! op_rule {
    ($name:ident, $next:ident, $tags:tt) => {
        rule!($name(i) -> Value, {
            map(tuple((
                $next,
                many0(tuple((
                    ws(alt($tags)),
                    $next
                )))
            )),
            |(p1, expr)| parse_expr(p1, expr))
        });
    };
}

op_rule!(op_6, op_7, (tag("*"), tag("/"), tag("%")));
op_rule!(op_5, op_6, (tag("+"), tag("-")));
op_rule!(op_4, op_5, (tag(">"), tag(">="), tag("<"), tag("<=")));
op_rule!(op_3, op_4, (tag("=="), tag("!="), tag("=~"), tag("!~")));
op_rule!(op_2, op_3, (tag("&&"), tag_no_case("and")));
op_rule!(op_1, op_2, (tag("||"), tag_no_case("or")));

fn parse_expr(p1: Value, rem: Vec<(&str, Value)>) -> Value {
    rem.into_iter().fold(p1, |p1, val| {
        let (op, p2) = val;
        Expr::parse2(op, p1, p2).into()
    })
}

rule!(pub root(i)->Value, { all_consuming(terminated(op_1,multispace0)) });

#[cfg(test)]
mod tests {
    // use super::super::filter::Filter;
    use super::*;
    macro_rules! expr {
        ($id:ident,$name:ident) => {
            #[allow(unused_macros)]
            macro_rules! $id {
                ($st:expr) => {
                    Value::Expression(Box::new(Expr::$name($st)))
                };
                ($p1:expr,$p2:expr) => {
                    Value::Expression(Box::new(Expr::$name($p1, $p2)))
                };
            }
        };
    }

    expr!(not, Not);
    expr!(inverse, Inverse);
    expr!(and, And);
    expr!(or, Or);
    expr!(plus, Plus);
    expr!(equal, Equal);
    expr!(call, Call);
    expr!(index, Index);
    expr!(access, Access);

    macro_rules! id {
        ($st:expr) => {
            Value::Identifier($st.to_string())
        };
    }

    macro_rules! str {
        ($st:expr) => {
            Value::String($st.to_string())
        };
    }

    macro_rules! int {
        ($st:expr) => {
            Value::Integer($st)
        };
    }

    macro_rules! bool {
        ($st:expr) => {
            Value::Boolean($st)
        };
    }

    macro_rules! array {
        ($st:expr) => {
            Value::Array(Box::new($st))
        };
    }

    #[inline]
    fn assert_ast(input: &str, value: Value) {
        let output = root::<nom::error::VerboseError<&str>>(input);
        println!("input={}\noutput={:?}", input, output);
        assert_eq!(output.unwrap().1, value);
    }

    #[test]
    fn op_8() {
        let input = "a(b).c[d]";
        let value = index!(access!(call!(id!("a"), vec![id!("b")]), id!("c")), id!("d"));
        assert_ast(input, value);
    }

    #[test]
    fn simple_op() {
        let input = "x+1";
        let value = plus!(id!("x"), int!(1));
        assert_ast(input, value);
    }

    #[test]
    fn root_is_value() {
        let input = "x";
        let value = id!("x");
        assert_ast(input, value);
    }

    #[test]
    fn tailing_spaces() {
        let input = "          x \r\n\t        ";
        let value = id!("x");
        assert_ast(input, value);
    }

    #[test]
    fn root_is_wraped_value() {
        let input = " ( ( ( ( x ) ) ) ) ";
        let value = id!("x");
        assert_ast(input, value);
    }

    #[test]
    fn opreator_priority() {
        let input = "1 && ( 2 ) || 3 == 4";
        let value = or!(and!(int!(1), int!(2)), equal!(int!(3), int!(4)));
        assert_ast(input, value);
    }

    #[test]
    fn paren() {
        let input = "1 && ( 2 || 3 )";
        let value = { and!(int!(1), or!(int!(2), int!(3))) };
        assert_ast(input, value);
    }

    #[test]
    fn unary() {
        let input = " ! ! ( ~ true ) ";
        let value = not!(not!(inverse!(Value::Boolean(true))));
        assert_ast(input, value);
    }

    #[test]
    fn complex() {
        let input = " 1 == [ \"test\" , 0x1 , 0b10 , 0o3 , false , xyz == 1 ] ";
        let value = {
            equal!(
                int!(1),
                array!(vec![
                    str!("test"),
                    int!(1),
                    int!(2),
                    int!(3),
                    bool!(false),
                    equal!(id!("xyz"), int!(1)),
                ])
            )
        };
        assert_ast(input, value);
    }
}
