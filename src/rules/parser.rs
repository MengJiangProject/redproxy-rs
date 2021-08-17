use std::{fmt, num::ParseIntError};

use nom::{
    branch::alt,
    bytes::{complete::tag, complete::tag_no_case},
    character::{
        complete::multispace0,
        complete::{alpha1, alphanumeric1, char, digit1, hex_digit1, oct_digit1, one_of},
    },
    combinator::{all_consuming, cut, map, map_opt, map_res, opt, recognize},
    error::{context, ContextError, FromExternalError, ParseError},
    multi::{many0, many1, separated_list0},
    sequence::{delimited, pair, preceded, terminated, tuple as nom_tuple},
    AsChar, IResult, InputTakeAtPosition, Parser,
};

mod string;
use super::script::stdlib::*;
use super::script::{Call, Value};

fn parse_many(op: &str, mut args: Vec<Value>) -> Value {
    let op = op.to_ascii_lowercase();
    match op.as_str() {
        //prioity 7
        "call" => {
            // let f = args.remove(0);
            Call::new(args).into()
        }
        "index" => {
            let p1 = args.remove(0);
            let p2 = args.remove(0);
            Index::new(p1, p2).into()
        }
        "access" => {
            let p1 = args.remove(0);
            let p2 = args.remove(0);
            Access::new(p1, p2).into()
        }
        _ => panic!("not implemented"),
    }
}
fn parse1(op: &str, p1: Value) -> Value {
    let op = op.to_ascii_lowercase();
    match op.as_str() {
        //prioity 7
        "!" => Not::new(p1).into(),
        "~" => BitNot::new(p1).into(),
        _ => panic!("not implemented"),
    }
}
fn parse2(op: &str, p1: Value, p2: Value) -> Value {
    let op = op.to_ascii_lowercase();

    match op.as_str() {
        //prioity 6
        "*" => Multiply::new(p1, p2).into(),
        "/" => Divide::new(p1, p2).into(),
        "%" => Mod::new(p1, p2).into(),
        //prioity 5
        "+" => Plus::new(p1, p2).into(),
        "-" => Minus::new(p1, p2).into(),
        //prioity 4
        ">" => Greater::new(p1, p2).into(),
        ">=" => GreaterOrEqual::new(p1, p2).into(),
        "<" => Lesser::new(p1, p2).into(),
        "<=" => LesserOrEqual::new(p1, p2).into(),
        //prioity 3
        "==" => Equal::new(p1, p2).into(),
        "!=" => NotEqual::new(p1, p2).into(),
        "=~" => Like::new(p1, p2).into(),
        "!~" => NotLike::new(p1, p2).into(),
        "in" => MemberOf::new(p1, p2).into(),
        //prioity 2
        "&&" | "and" => And::new(p1, p2).into(),
        //prioity 1
        "||" | "or" => Or::new(p1, p2).into(),
        _ => panic!("not implemented"),
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

rule!(string -> Value, {
    map(string::parse_string,Into::into)
});

rule!(boolean -> Value, {
    let parse_true = nom::combinator::value(true, tag("true"));
    let parse_false = nom::combinator::value(false, tag("false"));
    map(alt((parse_true, parse_false)),Into::into)
});

rule!(null -> Value, {
    nom::combinator::value(Value::Null, tag("null"))
});

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

rule!(integer -> Value, {
    fn atoi(n: u32) -> impl Fn(&str) -> Result<Value, ParseIntError> {
        move |x| i64::from_str_radix(x, n).map(Into::into)
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
        separated_list0(ws(char(',')), op_0),
        opt(ws(char(',')))
    );
    map(delimited(char('['), cut(body),ws(char(']'))), Into::into)
});

rule!(tuple -> Value, {
    let body = map_opt(
        pair(many0(terminated(
            op_0,
            ws(char(','))
        )),opt(op_0)),
        |(mut ary,last)|{
            if ary.is_empty() && last.is_some() {
                return None
            }
            if let Some(v) = last {
                ary.push(v);
            }
            Some(ary)
        }
    );
    map(map(delimited(char('('), body,ws(char(')'))), Box::new), Value::Tuple)
});

rule!(value -> Value, {
    // println!("value: i={}", i);
    alt((
        string,
        boolean,
        integer,
        identifier,
        array,
        tuple,
    ))
});

rule!(op_value -> Value, {
    alt((
        delimited(char('('), ws(op_0), ws(char(')'))),
        delimited(char('('), ws(value), ws(char(')'))),
        value,
    ))
});

rule!(op_index -> (&str,Vec<Value>), {
    map(
        delimited(tag("["), op_0, ws(char(']'))),
        |idx| ("index", vec![idx])
    )
});

rule!(op_access -> (&str,Vec<Value>), {
    map(
        preceded(tag("."), alt((identifier,integer))),
        |id| ("access", vec![id])
    )
});

rule!(op_call -> (&str,Vec<Value>), {
    map(
        delimited(
            char('('),
            separated_list0(ws(char(',')), op_0),
            ws(char(')'))
        ),
        |args|("call",args)
    )
});

rule!(op_8(i) -> Value, {
    map(
        nom_tuple((
            op_value,
            many0(alt((
                op_index,
                op_access,
                op_call
            )))
        )) ,
    |(p1, expr)| {
        // println!("p1={:?} expr={:?}", p1, expr);
        expr.into_iter().fold(p1, |p1, val| {
            let (op, mut args) : (&str,Vec<Value>) = val;
            args.insert(0,p1);
            parse_many(op, args).into()
        })
    })
});

//unary opreator
rule!(op_7(i) -> Value, {
    alt((
        map(nom_tuple((alt((tag("!"), tag("~"))), op_7)),
            |(op,p1)|parse1(op, p1).into()
        ),
        op_8
    ))
});

macro_rules! op_rule {
    ($name:ident, $next:ident, $tags:tt) => {
        rule!($name(i) -> Value, {
            map(nom_tuple((
                $next,
                many0(nom_tuple((
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
op_rule!(
    op_3,
    op_4,
    (
        tag("=="),
        tag("!="),
        tag("=~"),
        tag("!~"),
        tag_no_case("in")
    )
);
op_rule!(op_2, op_3, (tag("&&"), tag_no_case("and")));
op_rule!(op_1, op_2, (tag("||"), tag_no_case("or")));

rule!(op_if(i) -> Value, {
    map(
        alt((
            nom_tuple((
                preceded(tag("if"),op_0),
                preceded(ws(tag("then")),op_0),
                preceded(ws(tag("else")),op_0),
            )) ,
            nom_tuple((
                terminated(op_1,ws(tag("?"))),
                terminated(op_0,ws(tag(":"))),
                op_0
            )) ,
        )),
        |(cond, yes, no)| {
            If::new(cond, yes, no).into()
        }
    )
});

rule!(op_0 -> Value, {
    alt((
        op_if,
        op_1
    ))
});

fn parse_expr(p1: Value, rem: Vec<(&str, Value)>) -> Value {
    rem.into_iter().fold(p1, |p1, val| {
        let (op, p2) = val;
        parse2(op, p1, p2).into()
    })
}

rule!(pub root(i)->Value, { all_consuming(terminated(op_0,multispace0)) });

#[cfg(test)]
mod tests {
    // use super::super::filter::Filter;
    // use super::super::script::stdlib::*;
    use super::*;
    macro_rules! expr {
        ($id:ident,$name:ident) => {
            #[allow(unused_macros)]
            macro_rules! $id {
                ($p1:expr) => {
                    $name::new($p1).into()
                };
                ($p1:expr,$p2:expr) => {
                    $name::new($p1, $p2).into()
                };
                ($p1:expr,$p2:expr,$p3:expr) => {
                    $name::new($p1, $p2, $p3).into()
                };
            }
        };
    }

    expr!(not, Not);
    expr!(bit_not, BitNot);
    expr!(and, And);
    expr!(or, Or);
    expr!(plus, Plus);
    expr!(equal, Equal);
    expr!(member_of, MemberOf);
    expr!(call, Call);
    expr!(index, Index);
    expr!(access, Access);
    expr!(branch, If);

    // macro_rules! call {
    //     ($p1:expr) => {
    //         Call::new($p1).into()
    //     };
    // }

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

    macro_rules! tuple {
        ($($st:expr),*) => {
            Value::Tuple(Box::new(vec![
                $($st),*
            ]))
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
        let value = index!(access!(call!(vec![id!("a"), id!("b")]), id!("c")), id!("d"));
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
        let value = not!(not!(bit_not!(bool!(true))));
        assert_ast(input, value);
    }

    #[test]
    fn tuple_array() {
        let input = "[ ( ) , ( ( 1 ) , ) , ( 1 , 2 ) , ( 1 , 2 , ) ]";
        let value = array!(vec![
            tuple!(),
            tuple!(int!(1)),
            tuple!(int!(1), int!(2)),
            tuple!(int!(1), int!(2)),
        ]);
        assert_ast(input, value);
    }

    #[test]
    fn branch() {
        let input = "if a then b else if c then d else e";
        let value = branch!(id!("a"), id!("b"), branch!(id!("c"), id!("d"), id!("e")));
        assert_ast(input, value);
        let input = "(a ? b : c) ? d : e";
        let value = branch!(branch!(id!("a"), id!("b"), id!("c")), id!("d"), id!("e"));
        assert_ast(input, value);
    }

    #[test]
    fn complex() {
        let input = " 1 in [ \"test\" , 0x1 , 0b10 , 0o3 , false , if xyz == 1 then 2 else 3] ";
        let value = {
            member_of!(
                int!(1),
                array!(vec![
                    str!("test"),
                    int!(1),
                    int!(2),
                    int!(3),
                    bool!(false),
                    branch!(equal!(id!("xyz"), int!(1)), int!(2), int!(3))
                ])
            )
        };
        assert_ast(input, value);
    }
}
