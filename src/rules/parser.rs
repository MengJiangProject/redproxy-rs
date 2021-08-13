use std::{fmt, num::ParseIntError};

use nom::{
    branch::alt,
    bytes::{complete::tag, complete::tag_no_case},
    character::{
        complete::multispace0,
        complete::{alpha1, alphanumeric1, char, digit1, hex_digit1, oct_digit1, one_of},
    },
    combinator::{complete, cut, map, map_res, opt, recognize},
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
    //prioity 7
    Call(Value, Vec<Value>),
    Index(Value, Value),
    Member(Value, Value),
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
    fn parse(op: &str, p1: Value, p2: Value) -> Self {
        let op = op.to_ascii_lowercase();
        match op.as_str() {
            //prioity 7
            // "!" => Self::Not(p1),
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

#[allow(unused_macros)]
macro_rules! id {
    ($name:ident, $body:tt, $input:ident) => {
        $body
    };
}

macro_rules! ctx {
    ($name:ident, $body:tt, $input:ident) => {
        context(stringify!($name), $body)($input)
    };
}

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
        // #[allow(dead_code)]
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

// rule!(parse_str, i, {
//     escaped(alphanumeric1, '\\', one_of("\"n\\"))
// });

// rule!(string, i, String, {
//     let f = super::string::parse_string;
//     f
// });

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

rule!(identifier -> String, {
    map(
        recognize(pair(
            alt((alpha1, tag("_"))),
            many0(alt((alphanumeric1, tag("_")))),
        )),
        String::from,
    )
});

rule!(array -> Value, {
    let body = terminated(
        separated_list0(ws(char(',')), root),
        preceded(ws(opt(char(','))), ws(char(']'))),
    );
    map(preceded(char('['), cut(body)), Into::into)
});

rule!(value -> Value, {
    // println!("value: i={}", i);
    ws(alt((
        map(string, Value::String),
        map(integer, Value::Integer),
        map(boolean, Value::Boolean),
        map(identifier, Value::Identifier),
        array,
    )))
});

rule!(op_value -> Value, {
    alt((
        delimited(char('('), op_1, char(')')),
        delimited(char('('), value, char(')')),
        value,
    ))
});

// use nom::*;
// named!(op_value_dbg(&str) -> Expr, dbg_basic!(
//     alt!(
//         dbg_basic!(delimited!(char('('), op_1, char(')')))|
//         dbg_basic!(delimited!(char('('), value, char(')')))|
//         dbg_basic!(value)
//     ))
// );

// named!(
//     op_3_dbg(&str)->Vec<(&str,Expr)>,
//     dbg_basic!(many0!(tuple!(
//         dbg_basic!(alt!(
//             tag!("==")|
//             tag!("!=")
//         )),
//         dbg_basic!(op_value_dbg)
//     )))
// );

macro_rules! op_rule {
    ($name:ident, $next:ident, $tags:tt) => {
        rule!($name(i) -> Value, {
            map(tuple((
                ws($next),
                many0(tuple((
                    ws(alt($tags)),
                    ws($next)
                )))
            )),
            |(p1, expr)| parse_expr(p1, expr))
        });
    };
}

op_rule!(op_3, op_value, (tag("=="), tag("!=")));
op_rule!(op_2, op_3, (tag("&&"), tag_no_case("and")));
op_rule!(op_1, op_2, (tag("||"), tag_no_case("or")));

// rule!(op_3(i) -> Value, id, {
//     let (i, p1) = ws(op_value)(i)?;
//     let (i, expr) = many0(tuple((ws(alt((tag("=="), tag("!=")))), ws(op_value))))(i)?;
//     // println!("op3 p1={:?} expr={:?} i={:?}", p1, expr, i);
//     Ok((i, parse_expr(p1, expr)))
// });

// rule!(op_2(i) -> Value, {
//     map(tuple((
//         ws(op_3),
//         many0(tuple((ws(alt((tag("&&"), tag_no_case("and")))), ws(op_3))))
//     )) , |(p1, expr)| parse_expr(p1, expr))
// });

// rule!(op_1(i) -> Value, {
//     map(tuple((
//         ws(op_2),
//         many0(tuple((ws(alt((tag("||"), tag_no_case("or")))), ws(op_2))))
//     )) , |(p1, expr)| parse_expr(p1, expr))
// });

fn parse_expr(p1: Value, rem: Vec<(&str, Value)>) -> Value {
    rem.into_iter().fold(p1, |p1, val| {
        let (op, p2) = val;
        Expr::parse(op, p1, p2).into()
    })
}

rule!(pub root(i)->Value, { complete(terminated(op_1,multispace0)) });

#[cfg(test)]
mod tests {
    use super::super::filter::Filter;
    use super::*;
    #[test]
    fn simple_op() {
        let t = {
            Value::Expression(Box::new(Expr::Equal(
                Value::Identifier("x".to_string()),
                Value::Integer(1),
            )))
        };
        let input = "x==1";
        let output = input.parse::<Filter>();
        println!("input={}\noutput={:?}", input, output);
        assert_eq!(output.unwrap().root(), &t);
    }

    #[test]
    fn root_is_value() {
        let t = { Value::Identifier("x".to_string()) };
        let input = "x";
        let output = input.parse::<Filter>();
        println!("input={}\noutput={:?}", input, output);
        assert_eq!(output.unwrap().root(), &t);
    }

    #[test]
    fn tailing_spaces() {
        let t = { Value::Identifier("x".to_string()) };
        let input = "          x         ";
        let output = input.parse::<Filter>();
        println!("input={}\noutput={:?}", input, output);
        assert_eq!(output.unwrap().root(), &t);
    }

    #[test]
    fn root_is_wraped_value() {
        let t = { Value::Identifier("x".to_string()) };
        let input = "((((x))))";
        let output = input.parse::<Filter>();
        println!("input={}\noutput={:?}", input, output);
        assert_eq!(output.unwrap().root(), &t);
    }

    #[test]
    fn opreator_priority() {
        let t = {
            Value::Expression(Box::new(Expr::Or(
                Value::Expression(Box::new(Expr::And(Value::Integer(1), Value::Integer(2)))),
                Value::Expression(Box::new(Expr::Equal(Value::Integer(3), Value::Integer(4)))),
            )))
        };
        let input = "1&&(2)||3==4";
        let output = input.parse::<Filter>();
        println!("input={}\noutput={:?}", input, output);
        assert_eq!(output.unwrap().root(), &t);
    }

    #[test]
    fn paren() {
        let t = {
            Value::Expression(Box::new(Expr::And(
                Value::Integer(1),
                Value::Expression(Box::new(Expr::Or(Value::Integer(2), Value::Integer(3)))),
            )))
        };
        let input = "1&&(2||3)";
        let output = input.parse::<Filter>();
        println!("input={}\noutput={:?}", input, output);
        assert_eq!(output.unwrap().root(), &t);
    }

    #[test]
    fn complex() {
        let t = {
            Value::Expression(Box::new(Expr::NotEqual(
                Value::Integer(1),
                Value::Array(Box::new(vec![
                    Value::String("test".into()),
                    Value::Integer(1),
                    Value::Integer(2),
                    Value::Integer(3),
                    Value::Boolean(false),
                    Value::Expression(Box::new(Expr::Equal(
                        Value::Identifier("xyz".into()),
                        Value::Integer(1),
                    ))),
                ])),
            )))
        };
        let input = "1!=[\"test\", 0x1\r\n, 0b10,0o3, \tfalse, xyz == 1 ]";
        let output = input.parse::<Filter>();
        println!("input={}\noutput={:?}", input, output);
        assert_eq!(output.unwrap().root(), &t);
    }
}
