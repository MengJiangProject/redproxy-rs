use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, tag_no_case, take_until},
    character::complete::{
        alpha1, alphanumeric1, char, digit1, hex_digit1, multispace0, multispace1, oct_digit1,
        one_of,
    },
    combinator::{all_consuming, cut, map, map_opt, map_res, opt, recognize},
    error::{context, convert_error, ContextError, FromExternalError, ParseError, VerboseError},
    multi::{many0, many1, separated_list0},
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple as nom_tuple},
    IResult, Parser,
};
use nom_locate::LocatedSpan;
use std::{fmt, num::ParseIntError, sync::Arc};

mod string;
use super::script::stdlib::*;
use super::script::{Call, Value};

pub type Span<'s> = LocatedSpan<&'s str>;

fn parse_many(op: Span, mut args: Vec<Value>) -> Value {
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
            Index::make_call(p1, p2).into()
        }
        "access" => {
            let p1 = args.remove(0);
            let p2 = args.remove(0);
            Access::make_call(p1, p2).into()
        }
        _ => panic!("not implemented"),
    }
}
fn parse1(op: Span, p1: Value) -> Value {
    let op = op.to_ascii_lowercase();
    match op.as_str() {
        //prioity 7
        "!" => Not::make_call(p1).into(),
        "~" => BitNot::make_call(p1).into(),
        "-" => Negative::make_call(p1).into(),
        _ => panic!("not implemented"),
    }
}
fn parse2(op: Span, p1: Value, p2: Value) -> Value {
    let op = op.to_ascii_lowercase();

    match op.as_str() {
        //prioity 6
        "*" => Multiply::make_call(p1, p2).into(),
        "/" => Divide::make_call(p1, p2).into(),
        "%" => Mod::make_call(p1, p2).into(),
        //prioity 5
        "+" => Plus::make_call(p1, p2).into(),
        "-" => Minus::make_call(p1, p2).into(),
        //prioity 4.1
        "<<" => ShiftLeft::make_call(p1, p2).into(),
        ">>" => ShiftRight::make_call(p1, p2).into(),
        ">>>" => ShiftRightUnsigned::make_call(p1, p2).into(),
        //prioity 4
        ">" => Greater::make_call(p1, p2).into(),
        ">=" => GreaterOrEqual::make_call(p1, p2).into(),
        "<" => Lesser::make_call(p1, p2).into(),
        "<=" => LesserOrEqual::make_call(p1, p2).into(),
        //prioity 3
        "==" => Equal::make_call(p1, p2).into(),
        "!=" => NotEqual::make_call(p1, p2).into(),
        "=~" => Like::make_call(p1, p2).into(),
        "!~" => NotLike::make_call(p1, p2).into(),
        "_:" => MemberOf::make_call(p1, p2).into(),
        //prioity 2.x
        "&" => BitAnd::make_call(p1, p2).into(),
        "^" => BitXor::make_call(p1, p2).into(),
        "|" => BitOr::make_call(p1, p2).into(),
        //prioity 2
        "&&" | "and" => And::make_call(p1, p2).into(),
        //prioity 1
        "^^" | "xor" => Xor::make_call(p1, p2).into(),
        //prioity 1
        "||" | "or" => Or::make_call(p1, p2).into(),
        _ => panic!("not implemented"),
    }
}

// struct ParserContext<'a> {
//     input: Span<'a>,
//     ids: Vec<Span<'a>>,
// }
// all combinator made by this macro will remove any leading whitespaces
macro_rules! rule {
    (#$($args:tt)*) => (
        rule!(#$($args)*);
    );

    ($vis:vis $name:ident, $body:block) => {
        rule!($vis $name ( i ) -> Span<'a>, ctx, $body);
    };

    ($vis:vis $name:ident, $ctx:ident, $body:block) => {
        rule!($vis $name ( i ) -> Span<'a>, $ctx, $body);
    };

    ($vis:vis $name:ident -> $rt:ty, $body:block) => {
        rule!($vis $name ( i ) -> $rt, ctx, $body);
    };

    ($vis:vis $name:ident ( $input:ident ), $body:block) => {
        rule!($vis $name ( $input ) -> Span<'a>, ctx, $body);
    };

    ($vis:vis $name:ident ( $input:ident ), $ctx:ident, $body:block) => {
        rule!($vis $name ( $input ) -> Span<'a>, $ctx, $body);
    };

    ($vis:vis $name:ident ( $input:ident ) -> $rt:ty, $body:block) => {
        rule!($vis $name ( $input ) -> $rt, ctx, $body);
    };

    ($vis:vis $name:ident ( $input:ident ) -> $rt:ty, $context:ident, $body:block) => {
        #[allow(dead_code)]
        $vis fn $name<'a, E>($input: Span<'a>) -> IResult<Span<'a>, $rt, E>
        where
            E: ParseError<Span<'a>>
                + ContextError<Span<'a>>
                + FromExternalError<Span<'a>, ParseIntError>
                + fmt::Debug,
        {
            $context!($name, $body, $input)
        }
    };

    // ($vis:vis $name:ident ( $input:ident ) -> $rt:ty, $context:ident, $body:tt) => {
    //     #[allow(dead_code)]
    //     $vis fn $name<'a, O, E, F>($input: F) -> impl FnMut(Span<'a>) -> IResult<Span<'a>, O, E>
    //     where
    //         E: ParseError<Span<'a>>
    //             + ContextError<Span<'a>>
    //             + FromExternalError<Span<'a>, ParseIntError>
    //             + fmt::Debug,
    //         F: Parser<Span<'a>, O, E>,
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
fn ws<'a, O, E, F>(f: F) -> impl FnMut(Span<'a>) -> IResult<Span<'a>, O, E>
where
    E: ParseError<Span<'a>>
        + ContextError<Span<'a>>
        + FromExternalError<Span<'a>, ParseIntError>
        + fmt::Debug,
    F: Parser<Span<'a>, O, E>,
{
    preceded(blank, f)
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
    fn atoi<'a>(n: u32) -> impl Fn(Span<'a>) -> Result<Value, ParseIntError> {
        move |x| i64::from_str_radix(*x, n).map(Into::into)
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
        |x:Span|Value::Identifier(String::from(*x)),
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
    map(map(delimited(char('('), body,ws(char(')'))), Arc::new), Value::Tuple)
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

rule!(op_index -> (Span<'a>,Vec<Value>), {
    map(
        delimited(tag("["), op_0, ws(char(']'))),
        |idx| (Span::new("index"), vec![idx])
    )
});

rule!(op_access -> (Span<'a>,Vec<Value>), {
    map(
        preceded(tag("."), alt((identifier,integer))),
        |id| (Span::new("access"), vec![id])
    )
});

rule!(op_call -> (Span<'a>,Vec<Value>), {
    map(
        delimited(
            char('('),
            separated_list0(ws(char(',')), op_0),
            ws(char(')'))
        ),
        |args|(Span::new("call"),args)
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
            let (op, mut args) : (Span,Vec<Value>) = val;
            args.insert(0,p1);
            parse_many(op, args)
        })
    })
});

//unary opreator
rule!(op_7(i) -> Value, {
    alt((
        map(nom_tuple((alt((tag("!"), tag("~"), tag("-"))), op_7)),
            |(op,p1)|parse1(op, p1)
        ),
        op_8
    ))
});

macro_rules! op_rule {
    ($name:ident, $next:ident, $tags:expr ) => {
        rule!($name(i) -> Value, {
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
            If::make_call(cond, yes, no).into()
        }
    )
});

rule!(op_assign -> Value, {
    map(
        separated_pair(identifier,ws(tag("=")),op_0),
        |(name,value)| Value::Tuple(Arc::new(vec![name,value]))
    )
});

rule!(op_let -> Value, {
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
        |(vars,expr)| Scope::make_call(vars.into(),expr).into()
    )
});

rule!(op_0 -> Value, {
    alt((
        op_if,
        op_let,
        op_1
    ))
});

rule!(root(i)->Value, {
    all_consuming(terminated(op_0,delimited(multispace0,opt(tag(";;")),multispace0)))
});

pub fn parse(input: &str) -> Result<Value, SyntaxError> {
    root::<VerboseError<Span>>(Span::new(input))
        .map(|x| x.1)
        .map_err(|err| SyntaxError::new(err, input))
}

pub struct SyntaxError {
    msg: String,
}

impl SyntaxError {
    fn new(e: nom::Err<VerboseError<Span>>, input: &str) -> Self {
        let msg = match e {
            nom::Err::Error(e) | nom::Err::Failure(e) => convert_error(
                input,
                VerboseError {
                    errors: e
                        .errors
                        .into_iter()
                        .map(|(span, e)| (*span, e))
                        .collect::<Vec<_>>(),
                },
            ),
            _ => e.to_string(),
        };
        SyntaxError { msg }
    }
}

impl std::error::Error for SyntaxError {}
impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SyntaxError: {}", self.msg)
    }
}

impl fmt::Debug for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SyntaxError: {}", self.msg)
    }
}

#[cfg(test)]
mod tests {
    // use super::super::filter::Filter;
    // use super::super::script::stdlib::*;
    use super::*;
    macro_rules! expr {
        ($id:ident,$name:ident) => {
            expr!($id, $name, make_call);
        };
        ($id:ident,$name:ident,$make_call:ident) => {
            #[allow(unused_macros)]
            macro_rules! $id {
                ($p1:expr) => {
                    $name::$make_call($p1).into()
                };
                ($p1:expr,$p2:expr) => {
                    $name::$make_call($p1, $p2).into()
                };
                ($p1:expr,$p2:expr,$p3:expr) => {
                    $name::$make_call($p1, $p2, $p3).into()
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
    expr!(call, Call, new);
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
            Value::Array(Arc::new(vec![
                $($st),*
            ]))
        };
    }

    macro_rules! tuple {
        ($($st:expr),*) => {
            Value::Tuple(Arc::new(vec![
                $($st),*
            ]))
        };
    }

    #[inline]
    fn assert_ast(input: &str, value: Value) {
        let output = parse(input);
        println!("input={}\noutput={:?}", input, output);
        assert_eq!(output.unwrap(), value);
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
