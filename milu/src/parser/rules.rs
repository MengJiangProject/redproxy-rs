use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_until, take_while},
    character::complete::{
        alpha1, alphanumeric1, char, digit1, hex_digit1, multispace1, oct_digit1, one_of,
    },
    combinator::{cut, map, map_opt, map_res, opt, recognize},
    error::{ContextError, FromExternalError, ParseError, context},
    multi::{many0, many1, separated_list0},
    sequence::{delimited, pair, preceded, separated_pair, terminated},
};
use std::{fmt, num::ParseIntError, sync::Arc}; // Added Arc for ParsedFunction and Value::Tuple/Array

// Use super:: to access Span from mod.rs, and items from sibling modules string/template
// Also, script items are now referenced via crate::
use super::Span;
use super::string as string_module; // Assuming string.rs contains parse_string
use super::template as template_module; // Assuming template.rs contains parse_template
use crate::script::stdlib::*;
use crate::script::{Call, ParsedFunction, Value};

// Helper functions parse_many, parse1, parse2 moved here
pub fn parse_many(op: Span, mut args: Vec<Value>) -> Value {
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
pub fn parse1(op: Span, p1: Value) -> Value {
    let op = op.to_ascii_lowercase();
    match op.as_str() {
        //prioity 7
        "!" => Not::make_call(p1).into(),
        "~" => BitNot::make_call(p1).into(),
        "-" => Negative::make_call(p1).into(),
        _ => panic!("not implemented"),
    }
}
pub fn parse2(op: Span, p1: Value, p2: Value) -> Value {
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
        "_:" => IsMemberOf::make_call(p1, p2).into(),
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

// rule macro moved here, ensure it uses pub for functions if they need to be accessed from mod.rs (e.g. root)
// The macro itself does not need to be pub unless used in other modules directly.
// Functions generated by rule! are made pub.
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
        pub fn $name<'a, E>($input: Span<'a>) -> IResult<Span<'a>, $rt, E> // Changed to pub fn
        where
            E: ParseError<Span<'a>>
                + ContextError<Span<'a>>
                + FromExternalError<Span<'a>, ParseIntError>
                + fmt::Debug,
        {
            $context!($name, $body, $input)
        }
    };
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
        context(stringify!($name), ws($body)).parse($input)
    };
}

//for debug use
#[allow(unused_macros)]
#[macro_export] // Keep if this is intended for wide use, otherwise remove or make local
macro_rules! tap {
    ($e:expr) => {
        |i| {
            let x = $e(i);
            println!("tap: {}\nin: {}\nout: {:?}", stringify!($e), i, x);
            x
        }
    };
}

rule!(pub eol_comment(i), no_ctx, { // Added pub
    recognize(preceded(
        char('#'),
        take_while(|c: char| c != '\n' && c != '\r'),
    ))
    .parse(i)
});
rule!(pub inline_comment(i), no_ctx, { // Added pub
    delimited(tag("/*"), take_until("*/"), tag("*/")).parse(i)
});
rule!(pub blank(i), no_ctx, { // Added pub
    recognize(many0(alt((multispace1, eol_comment, inline_comment)))).parse(i)
});

// ignore leading whitespaces
pub fn ws<'a, O, E, F>(f: F) -> impl Parser<Span<'a>, Output = O, Error = E>
// Added pub
where
    E: ParseError<Span<'a>>
        + ContextError<Span<'a>>
        + FromExternalError<Span<'a>, ParseIntError>
        + fmt::Debug,
    F: Parser<Span<'a>, Output = O, Error = E>,
{
    preceded(blank, f)
}

rule!(pub string -> Value, { // Added pub
    map(string_module::parse_string,Into::into)
});

rule!(pub template -> Value, { // Added pub
    map(template_module::parse_template, |v| StringConcat::make_call(v.into()).into() )
});

rule!(pub boolean -> Value, { // Added pub
    let parse_true = nom::combinator::value(true, tag("true"));
    let parse_false = nom::combinator::value(false, tag("false"));
    map(alt((parse_true, parse_false)),Into::into)
});

rule!(pub hexadecimal, { // Added pub
    preceded(
        tag_no_case("0x"),
        recognize(many1(terminated(hex_digit1, many0(char('_'))))),
    )
});

rule!(pub octal, { // Added pub
    preceded(
        tag_no_case("0o"),
        recognize(many1(terminated(oct_digit1, many0(char('_'))))),
    )
});

rule!(pub binary, { // Added pub
    preceded(
        tag_no_case("0b"),
        recognize(many1(terminated(one_of("01"), many0(char('_'))))),
    )
});

rule!(pub decimal, { // Added pub
    recognize(pair(digit1, many0(preceded(char('_'), digit1))))
});

rule!(pub integer -> Value, { // Added pub
    fn atoi<'a>(n: u32) -> impl Fn(Span<'a>) -> Result<Value, ParseIntError> {
        move |s: Span<'a>| {
            let cleaned_str = s.fragment().replace("_", "");
            i64::from_str_radix(&cleaned_str, n).map(Into::into)
        }
    }
    alt((
        map_res(binary, atoi(2)),
        map_res(octal, atoi(8)),
        map_res(hexadecimal, atoi(16)),
        map_res(decimal, atoi(10)),
    ))
});

rule!(pub identifier -> Value, { // Added pub
    map(
        recognize(pair(
            alt((alpha1, tag("_"))),
            many0(alt((alphanumeric1, tag("_")))),
        )),
        |x:Span|Value::Identifier(String::from(*x)),
    )
});

rule!(pub array -> Value, { // Added pub
    let body = terminated(
        separated_list0(ws(char(',')), op_0),
        opt(ws(char(',')))
    );
    map(delimited(char('['), cut(body),ws(char(']'))), Into::into)
});

rule!(pub tuple -> Value, { // Added pub
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

rule!(pub value -> Value, { // Added pub
    alt((
        string,
        template,
        boolean,
        integer,
        identifier,
        array,
        tuple,
    ))
});

rule!(pub op_value -> Value, { // Added pub
    alt((
        delimited(char('('), ws(op_0), ws(char(')'))),
        delimited(char('('), ws(value), ws(char(')'))),
        value,
    ))
});

rule!(pub op_index -> (Span<'a>,Vec<Value>), { // Added pub
    map(
        delimited(tag("["), op_0, ws(char(']'))),
        |idx| (Span::new("index"), vec![idx])
    )
});

rule!(pub signed_integer_for_access -> Value, { // Added pub
    map_res(
        recognize(pair(opt(char('-')), decimal)),
        |s: Span| s.fragment().parse::<i64>().map(Value::Integer)
    )
});

rule!(pub op_access -> (Span<'a>,Vec<Value>), { // Added pub
    map(
        preceded(tag("."), alt((identifier, signed_integer_for_access))),
        |val| (Span::new("access"), vec![val])
    )
});

rule!(pub op_call -> (Span<'a>,Vec<Value>), { // Added pub
    map(
        delimited(
            char('('),
            separated_list0(ws(char(',')), op_0),
            ws(char(')'))
        ),
        |args|(Span::new("call"),args)
    )
});

rule!(pub op_8(i) -> Value, { // Added pub
    map(
        (
            op_value,
            many0(alt((
                op_index,
                op_access,
                op_call
            )))
        ),
    |(p1, expr)| {
        expr.into_iter().fold(p1, |p1, val| {
            let (op, mut args) : (Span,Vec<Value>) = val;
            args.insert(0,p1);
            parse_many(op, args)
        })
    })
});

rule!(pub op_7(i) -> Value, { // Added pub
    alt((
        map((alt((tag("!"), tag("~"), tag("-"))), op_7),
            |(op,p1)|parse1(op, p1)
        ),
        op_8
    ))
});

// op_rule macro moved here. Functions generated by it are made pub by the rule! macro it invokes.
macro_rules! op_rule {
    ($name:ident, $next:ident, $tags:expr ) => {
        rule!(pub $name(i) -> Value, { // Added pub to the rule! invocation
            map(
                (
                    $next,
                    many0((
                        ws($tags),
                        $next
                    ))
                ),
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

rule!(pub op_if(i) -> Value, { // Added pub
    map(
        alt((
            (
                preceded(tag("if"),op_0),
                preceded(ws(tag("then")),op_0),
                preceded(ws(tag("else")),op_0),
            ) ,
            (
                terminated(op_1,ws(tag("?"))),
                terminated(op_0,ws(tag(":"))),
                op_0
            ) ,
        )),
        |(cond, yes, no)| {
            If::make_call(cond, yes, no).into()
        }
    )
});

rule!(pub func_args_def -> Vec<Value>, { // Added pub
    delimited(
        char('('),
        separated_list0(ws(char(',')), identifier),
        ws(char(')'))
    )
});

rule!(pub op_assign -> Value, { // Added pub
    alt((
        map(
            (
                identifier,
                ws(func_args_def),
                ws(char('=')),
                cut(op_0)
            ),
            |(name_ident, arg_idents, _, body)| {
                Value::ParsedFunction(Arc::new(ParsedFunction {
                    name_ident,
                    arg_idents,
                    body,
                }))
            }
        ),
        map(
            separated_pair(identifier, ws(char('=')), op_0),
            |(name, value)| Value::Tuple(Arc::new(vec![name, value]))
        )
    ))
});

rule!(pub op_let -> Value, { // Added pub
    map(
        (
            preceded(terminated(tag("let"), cut(multispace1)),
                terminated(
                    separated_list0(ws(char(';')), ws(op_assign)),
                    opt(ws(char(';')))
                )
            ),
            preceded(ws(tag("in")),op_0),
        ),
        |(vars,expr)| Scope::make_call(vars.into(),expr).into()
    )
});

rule!(pub op_0 -> Value, { // Added pub
    alt((
        op_if,
        op_let,
        op_assign,
        op_1
    ))
});

rule!(pub root(i)->Value, { // Added pub, this is used by parse() in mod.rs
    nom::combinator::all_consuming(terminated(op_0, ws(opt(tag(";;"))))) // all_consuming needs to be qualified or use statement added
});
