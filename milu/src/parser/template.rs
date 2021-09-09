use nom::{
    branch::alt,
    bytes::streaming::is_not,
    character::streaming::char,
    combinator::{map, value, verify},
    error::{ContextError, FromExternalError, ParseError},
    multi::fold_many0,
    sequence::{delimited, preceded},
    IResult,
};

use crate::{parser::string::parse_escaped_whitespace, script::Value};

use super::string::parse_unicode;
use super::Span;

#[derive(Debug, Clone, PartialEq, Eq)]
enum StringFragment<'a> {
    Literal(Span<'a>),
    EscapedChar(char),
    EscapedWS,
    TemplateElement(Value),
}

fn parse_escaped_char<'a, E>(input: Span<'a>) -> IResult<Span<'a>, char, E>
where
    E: ParseError<Span<'a>> + FromExternalError<Span<'a>, std::num::ParseIntError>,
{
    preceded(
        char('\\'),
        alt((
            parse_unicode,
            value('\n', char('n')),
            value('\r', char('r')),
            value('\t', char('t')),
            value('\u{08}', char('b')),
            value('\u{0C}', char('f')),
            value('\\', char('\\')),
            value('/', char('/')),
            value('"', char('"')),
            value('$', char('$')),
        )),
    )(input)
}

fn parse_template_literal<'a, E: ParseError<Span<'a>>>(
    input: Span<'a>,
) -> IResult<Span<'a>, Span<'a>, E> {
    let not_quote_slash = is_not("`$\\");
    verify(not_quote_slash, |s: &Span| !s.is_empty())(input)
}

fn parse_template_element<'a, E>(input: Span<'a>) -> IResult<Span<'a>, Value, E>
where
    E: ParseError<Span<'a>>
        + FromExternalError<Span<'a>, std::num::ParseIntError>
        + ContextError<Span<'a>>
        + std::fmt::Debug,
{
    preceded(char('$'), delimited(char('{'), super::op_0, char('}')))(input)
}

fn parse_template_fragment<'a, E>(input: Span<'a>) -> IResult<Span<'a>, StringFragment<'a>, E>
where
    E: ParseError<Span<'a>>
        + FromExternalError<Span<'a>, std::num::ParseIntError>
        + ContextError<Span<'a>>
        + std::fmt::Debug,
{
    alt((
        map(parse_template_literal, StringFragment::Literal),
        map(parse_escaped_char, StringFragment::EscapedChar),
        map(parse_template_element, StringFragment::TemplateElement),
        value(StringFragment::EscapedWS, parse_escaped_whitespace),
    ))(input)
}

pub fn parse_template<'a, E>(input: Span<'a>) -> IResult<Span<'a>, Vec<Value>, E>
where
    E: ParseError<Span<'a>>
        + FromExternalError<Span<'a>, std::num::ParseIntError>
        + ContextError<Span<'a>>
        + std::fmt::Debug,
{
    let build_string = fold_many0(
        parse_template_fragment,
        Vec::<Value>::new,
        |mut acc, fragment| {
            match fragment {
                StringFragment::Literal(s) => acc.push(s.to_string().into()),
                StringFragment::EscapedChar(c) => acc.push(c.to_string().into()),
                StringFragment::TemplateElement(v) => acc.push(v),
                _ => {}
            }
            acc
        },
    );
    delimited(char('`'), build_string, char('`'))(input)
}
