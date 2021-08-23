use std::{fmt, num::ParseIntError, rc::Rc};

use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, tag_no_case, take_until},
    character::complete::{
        alpha1, alphanumeric1, char, digit1, hex_digit1, multispace0, multispace1, oct_digit1,
        one_of,
    },
    combinator::{all_consuming, cut, map, map_opt, map_res, opt, recognize},
    error::{context, ContextError, FromExternalError, ParseError},
    multi::{many0, many1, separated_list0},
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple as nom_tuple},
    IResult, Parser,
};

mod string;
use super::script::stdlib::*;
use super::script::{Call, Value};

fn parse_many<'v>(op: &str, mut args: Vec<Value<'v>>) -> Value<'v> {
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
fn parse1<'v>(op: &str, p1: Value<'v>) -> Value<'v> {
    let op = op.to_ascii_lowercase();
    match op.as_str() {
        //prioity 7
        "!" => Not::new(p1).into(),
        "~" => BitNot::new(p1).into(),
        "-" => Negative::new(p1).into(),
        _ => panic!("not implemented"),
    }
}
fn parse2<'v>(op: &str, p1: Value<'v>, p2: Value<'v>) -> Value<'v> {
    let op = op.to_ascii_lowercase();

    match op.as_str() {
        //prioity 6
        "*" => Multiply::new(p1, p2).into(),
        "/" => Divide::new(p1, p2).into(),
        "%" => Mod::new(p1, p2).into(),
        //prioity 5
        "+" => Plus::new(p1, p2).into(),
        "-" => Minus::new(p1, p2).into(),
        //prioity 4.1
        "<<" => ShiftLeft::new(p1, p2).into(),
        ">>" => ShiftRight::new(p1, p2).into(),
        ">>>" => ShiftRightUnsigned::new(p1, p2).into(),
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
        "_:" => MemberOf::new(p1, p2).into(),
        //prioity 2.x
        "&" => BitAnd::new(p1, p2).into(),
        "^" => BitXor::new(p1, p2).into(),
        "|" => BitOr::new(p1, p2).into(),
        //prioity 2
        "&&" | "and" => And::new(p1, p2).into(),
        //prioity 1
        "^^" | "xor" => Xor::new(p1, p2).into(),
        //prioity 1
        "||" | "or" => Or::new(p1, p2).into(),
        _ => panic!("not implemented"),
    }
}

// struct ParserContext<'a> {
//     input: &'a str,
//     ids: Vec<&'a str>,
// }
// all combinator made by this macro will remove any leading whitespaces
macro_rules! rule {
    (#$($args:tt)*) => (
        rule!(#$($args)*);
    );

    ($vis:vis $name:ident, $body:block) => {
        rule!($vis $name ( i ) -> &'a str, ctx, $body);
    };

    ($vis:vis $name:ident, $ctx:ident, $body:block) => {
        rule!($vis $name ( i ) -> &'a str, $ctx, $body);
    };

    ($vis:vis $name:ident -> $rt:ty, $body:block) => {
        rule!($vis $name ( i ) -> $rt, ctx, $body);
    };

    ($vis:vis $name:ident ( $input:ident ), $body:block) => {
        rule!($vis $name ( $input ) -> &'a str, ctx, $body);
    };

    ($vis:vis $name:ident ( $input:ident ), $ctx:ident, $body:block) => {
        rule!($vis $name ( $input ) -> &'a str, $ctx, $body);
    };

    ($vis:vis $name:ident ( $input:ident ) -> $rt:ty, $body:block) => {
        rule!($vis $name ( $input ) -> $rt, ctx, $body);
    };

    ($vis:vis $name:ident ( $input:ident ) -> $rt:ty, $context:ident, $body:block) => {
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

    // ($vis:vis $name:ident ( $input:ident ) -> $rt:ty, $context:ident, $body:tt) => {
    //     #[allow(dead_code)]
    //     $vis fn $name<'a, O, E, F>($input: F) -> impl FnMut(&'a str) -> IResult<&'a str, O, E>
    //     where
    //         E: ParseError<&'a str>
    //             + ContextError<&'a str>
    //             + FromExternalError<&'a str, ParseIntError>
    //             + fmt::Debug,
    //         F: Parser<&'a str, O, E>,
    //     {
    //         $context!($name, $body, $input)
    //     }
    // };
}

#[allow(unused_macros)]
macro_rules! no_ctx {
    ($name:ident, $body:block, $input:ident) => {
        ($body)
    };
}

#[allow(unused_macros)]
macro_rules! ctx {
    ($name:ident, $body:block, $input:ident) => {
        context(stringify!($name), ws($body))($input)
    };
}

//for debug use
#[allow(unused_macros)]
macro_rules! tap {
    ($e:expr) => {
        |i| {
            let x = $e(i);
            println!("tap: {}\nin: {}\nout: {:?}", stringify!($e), i, x);
            x
        }
    };
}

rule!(eol_comment(i), no_ctx, {
    recognize(pair(char('#'), is_not("\n\r")))(i)
});
rule!(inline_comment(i), no_ctx, {
    delimited(tag("/*"), take_until("*/"), tag("*/"))(i)
});
rule!(blank(i), no_ctx, {
    recognize(many0(alt((multispace1, eol_comment, inline_comment))))(i)
});

// ignore leading whitespaces
fn ws<'a, O, E, F>(f: F) -> impl FnMut(&'a str) -> IResult<&'a str, O, E>
where
    E: ParseError<&'a str>
        + ContextError<&'a str>
        + FromExternalError<&'a str, ParseIntError>
        + fmt::Debug,
    F: Parser<&'a str, O, E>,
{
    preceded(blank, f)
}

rule!(string -> Value<'static>, {
    map(string::parse_string,Into::into)
});

rule!(boolean -> Value<'static>, {
    let parse_true = nom::combinator::value(true, tag("true"));
    let parse_false = nom::combinator::value(false, tag("false"));
    map(alt((parse_true, parse_false)),Into::into)
});

rule!(null -> Value<'static>, {
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

rule!(integer -> Value<'static>, {
    fn atoi(n: u32) -> impl Fn(&str) -> Result<Value<'static>, ParseIntError> {
        move |x| i64::from_str_radix(x, n).map(Into::into)
    }
    alt((
        map_res(binary, atoi(2)),
        map_res(octal, atoi(8)),
        map_res(hexadecimal, atoi(16)),
        map_res(decimal, atoi(10)),
    ))
});

rule!(identifier -> Value<'static>, {
    map(
        recognize(pair(
            alt((alpha1, tag("_"))),
            many0(alt((alphanumeric1, tag("_")))),
        )),
        |x|Value::Identifier(String::from(x)),
    )
});

rule!(array -> Value<'static>, {
    let body = terminated(
        separated_list0(ws(char(',')), op_0),
        opt(ws(char(',')))
    );
    map(delimited(char('['), cut(body),ws(char(']'))), Into::into)
});

rule!(tuple -> Value<'static>, {
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
    map(map(delimited(char('('), body,ws(char(')'))), Rc::new), Value::Tuple)
});

rule!(value -> Value<'static>, {
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

rule!(op_value -> Value<'static>, {
    alt((
        delimited(char('('), ws(op_0), ws(char(')'))),
        delimited(char('('), ws(value), ws(char(')'))),
        value,
    ))
});

rule!(op_index -> (&'a str,Vec<Value<'static>>), {
    map(
        delimited(tag("["), op_0, ws(char(']'))),
        |idx| ("index", vec![idx])
    )
});

rule!(op_access -> (&'a str,Vec<Value<'static>>), {
    map(
        preceded(tag("."), alt((identifier,integer))),
        |id| ("access", vec![id])
    )
});

rule!(op_call -> (&'a str,Vec<Value<'static>>), {
    map(
        delimited(
            char('('),
            separated_list0(ws(char(',')), op_0),
            ws(char(')'))
        ),
        |args|("call",args)
    )
});

rule!(op_8(i) -> Value<'static>, {
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
rule!(op_7(i) -> Value<'static>, {
    alt((
        map(nom_tuple((alt((tag("!"), tag("~"), tag("-"))), op_7)),
            |(op,p1)|parse1(op, p1).into()
        ),
        op_8
    ))
});

macro_rules! op_rule {
    ($name:ident, $next:ident, $tags:expr ) => {
        rule!($name(i) -> Value<'static>, {
            map(
                nom_tuple((
                    $next,
                    many0(nom_tuple((
                        ws($tags),
                        $next
                    )))
                )),
                |(p1, expr)|
                    expr.into_iter().fold(p1, |p1, val| {
                        let (op, p2) = val;
                        parse2(op, p1, p2).into()
                    })
            )
        });
    };
}

op_rule!(op_6, op_7, alt((tag("*"), tag("/"), tag("%"),)));
op_rule!(op_5, op_6, alt((tag("+"), tag("-"))));
op_rule!(op_4_1, op_5, alt((tag("<<"), tag(">>"), tag(">>>"))));
op_rule!(
    op_4,
    op_4_1,
    alt((tag(">"), tag(">="), tag("<"), tag("<=")))
);
op_rule!(
    op_3,
    op_4,
    alt((tag("=="), tag("!="), tag("=~"), tag("!~"), tag("_:")))
);
op_rule!(op_2_5, op_3, tag("&"));
op_rule!(op_2_4, op_2_5, tag("^"));
op_rule!(op_2_3, op_2_4, tag("|"));
op_rule!(op_2, op_2_3, alt((tag("&&"), tag_no_case("and"))));
op_rule!(op_1, op_2, alt((tag("||"), tag_no_case("or"))));

rule!(op_if(i) -> Value<'static>, {
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

rule!(op_assign -> Value<'static>, {
    map(
        separated_pair(identifier,ws(tag("=")),op_0),
        |(name,value)| Value::Tuple(Rc::new(vec![name,value]))
    )
});

rule!(op_let -> Value<'static>, {
    map(
        nom_tuple((
            preceded(tag("let"),
                terminated(
                    separated_list0(ws(char(';')), op_assign),
                    opt(ws(char(';')))
                )
            ),
            preceded(ws(tag("in")),op_0),
        )),
        |(vars,expr)| Scope::new(vars.into(),expr).into()
    )
});

rule!(op_0 -> Value<'static>, {
    alt((
        op_if,
        op_let,
        op_1
    ))
});

rule!(pub root(i)->Value<'static>, {
    all_consuming(terminated(op_0,delimited(multispace0,opt(tag(";;")),multispace0)))
});

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
    expr!(neg, Negative);
    expr!(and, And);
    expr!(or, Or);
    expr!(band, BitAnd);
    expr!(bor, BitOr);
    expr!(bxor, BitXor);
    expr!(plus, Plus);
    expr!(minus, Minus);
    expr!(mul, Multiply);
    expr!(div, Divide);
    expr!(equal, Equal);
    expr!(member_of, MemberOf);
    expr!(call, Call);
    expr!(scope, Scope);
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
        ($($st:expr),*) => {
            Value::Array(Rc::new(vec![
                $($st),*
            ]))
        };
    }

    macro_rules! tuple {
        ($($st:expr),*) => {
            Value::Tuple(Rc::new(vec![
                $($st),*
            ]))
        };
    }

    #[inline]
    fn assert_ast(input: &str, value: Value<'static>) {
        let output = root::<nom::error::VerboseError<&str>>(input);
        println!("input={}\noutput={:?}", input, output);
        assert_eq!(output.unwrap().1, value);
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
        let input = "\r\n\t x \r\n\t ";
        let value = id!("x");
        assert_ast(input, value);
        let input = " ( ( ( ( x ) ) ) ) ";
        let value = id!("x");
        assert_ast(input, value);
    }

    #[test]
    fn opreator_priority() {
        let input = "1 && ( 2 ) || 3 == 4";
        let value = or!(and!(int!(1), int!(2)), equal!(int!(3), int!(4)));
        assert_ast(input, value);
        let input = "1 ^ 4 & ( 2 | 3 )";
        let value = { bxor!(int!(1), band!(int!(4), bor!(int!(2), int!(3)))) };
        assert_ast(input, value);
    }

    #[test]
    fn op_8() {
        let input = "a(b).c[d]";
        let value = index!(access!(call!(vec![id!("a"), id!("b")]), id!("c")), id!("d"));
        assert_ast(input, value);
    }

    #[test]
    fn op_7() {
        let input = " ! ! ( ~ true ) ";
        let value = not!(not!(bit_not!(bool!(true))));
        assert_ast(input, value);
    }

    #[test]
    fn op_6() {
        let input = "1 * 1 / -2";
        let value = div!(mul!(int!(1), int!(1)), neg!(int!(2)));
        assert_ast(input, value);
    }
    #[test]
    fn op_5() {
        let input = "1+1-2";
        let value = minus!(plus!(int!(1), int!(1)), int!(2));
        assert_ast(input, value);
    }

    #[test]
    fn tuple_array() {
        let input = "[ ( ) , ( ( 1 ) , ) , ( 1 , 2 ) , ( 1 , 2 , ) ]";
        let value = array!(
            tuple!(),
            tuple!(int!(1)),
            tuple!(int!(1), int!(2)),
            tuple!(int!(1), int!(2))
        );
        assert_ast(input, value);
    }

    #[test]
    fn branch() {
        let input = "if a then b else if c then d else e";
        let value = branch!(id!("a"), id!("b"), branch!(id!("c"), id!("d"), id!("e")));
        assert_ast(input, value);
        let input = "if if a then b else c then d else e";
        let value = branch!(branch!(id!("a"), id!("b"), id!("c")), id!("d"), id!("e"));
        assert_ast(input, value);
        let input = "(a ? b : c) ? d : e";
        let value = branch!(branch!(id!("a"), id!("b"), id!("c")), id!("d"), id!("e"));
        assert_ast(input, value);
    }

    #[test]
    fn scope() {
        let value: Value = scope!(
            array!(tuple!(id!("a"), int!(1)), tuple!(id!("b"), int!(2))),
            plus!(id!("a"), id!("b"))
        );
        let input = "let a=1;b=2 in a+b";
        assert_ast(input, value.clone());
        let input = "let a=1;b=2; in a+b";
        assert_ast(input, value);
    }

    #[test]
    fn comments() {
        let input = "if #comments\r\n a /* \r\n /* */then/**/b else c";
        let value = branch!(id!("a"), id!("b"), id!("c"));
        assert_ast(input, value);
        let input = r#" [
            " #not a comment ",
            " /* also not a comment " , " */"
        ]"#;
        let value = array!(
            str!(" #not a comment "),
            str!(" /* also not a comment "),
            str!(" */")
        );
        assert_ast(input, value);
    }

    #[test]
    fn complex() {
        let input = " 1 _: [ \"test\" , 0x1 , 0b10 , 0o3 , false , if xyz == 1 then 2 else 3] ";
        let value = {
            member_of!(
                int!(1),
                array!(
                    str!("test"),
                    int!(1),
                    int!(2),
                    int!(3),
                    bool!(false),
                    branch!(equal!(id!("xyz"), int!(1)), int!(2), int!(3))
                )
            )
        };
        assert_ast(input, value);
    }
}
