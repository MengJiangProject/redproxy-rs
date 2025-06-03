use nom::{
    IResult,
    Parser,
    branch::alt,
    bytes::streaming::{is_not, tag}, // Added tag for parse_template_element
    character::streaming::char,
    combinator::{cut, map, value, verify}, // Added cut
    error::{ContextError, FromExternalError, ParseError},
    multi::fold_many0,
    sequence::{delimited, preceded, terminated}, // Added terminated
};

use super::Span; // Corrected path
use super::rules::op_0; // Corrected path
use super::string::parse_escaped_whitespace;
use super::string::parse_unicode; // Corrected path
use crate::script::Value; // Corrected path

// This was likely defined in string.rs or a shared place. For now, defining it here.
// If string.rs also needs it, it should be moved to a common module like parser/common.rs or parser/utils.rs
// For now, to get template.rs to compile, I'm including a version of it.
// The original `parse_unicode` was in `string.rs` as `pub(super) fn parse_unicode...`
// which means it was callable from `parser/mod.rs` (the old `parser.rs`).
// If `string.rs` is now a sibling module to `template.rs`, then `string::parse_unicode` would be the path.

#[derive(Debug, Clone, PartialEq, Eq)]
enum StringFragment<'a> {
    Literal(Span<'a>),
    EscapedChar(char),
    EscapedWS,
    TemplateElement(Value),
}

// Copied from original parser.rs context, may need path adjustments for parse_unicode
// Assuming parse_unicode is made public in string.rs or moved to a shared location.
// For now, this might cause an error if string::parse_unicode isn't visible.
fn parse_escaped_char<'a, E>(input: Span<'a>) -> IResult<Span<'a>, char, E>
where
    E: ParseError<Span<'a>> + FromExternalError<Span<'a>, std::num::ParseIntError>,
{
    preceded(
        char('\\'),
        alt((
            parse_unicode, // This needs to be resolvable
            value('\n', char('n')),
            value('\r', char('r')),
            value('\t', char('t')),
            value('\u{08}', char('b')),
            value('\u{0C}', char('f')),
            value('\\', char('\\')),
            value('/', char('/')),
            value('"', char('"')),
            value('$', char('$')),
            value('`', char('`')),
        )),
    )
    .parse(input)
}

fn parse_template_literal<'a, E: ParseError<Span<'a>>>(
    input: Span<'a>,
) -> IResult<Span<'a>, Span<'a>, E> {
    let not_quote_slash = is_not("`$\\");
    verify(not_quote_slash, |s: &Span| !s.is_empty()).parse(input)
}

// Note: op_0 comes from rules.rs, so that needs to be correctly imported.
fn parse_template_element<'a, E>(input: Span<'a>) -> IResult<Span<'a>, Value, E>
where
    E: ParseError<Span<'a>>
        + FromExternalError<Span<'a>, std::num::ParseIntError>
        + ContextError<Span<'a>>
        + std::fmt::Debug,
{
    preceded(
        tag("${"),                        // Using nom::bytes::streaming::tag
        cut(terminated(op_0, char('}'))), // op_0 needs to be in scope
    )
    .parse(input)
}

fn parse_template_fragment<'a, E>(input: Span<'a>) -> IResult<Span<'a>, StringFragment<'a>, E>
where
    E: ParseError<Span<'a>>
        + FromExternalError<Span<'a>, std::num::ParseIntError>
        + ContextError<Span<'a>>
        + std::fmt::Debug,
{
    alt((
        map(parse_escaped_char, StringFragment::EscapedChar),
        map(parse_template_element, StringFragment::TemplateElement),
        map(char('$'), |c: char| StringFragment::EscapedChar(c)),
        map(parse_template_literal, StringFragment::Literal),
        value(StringFragment::EscapedWS, parse_escaped_whitespace), // This needs to be resolvable
    ))
    .parse(input)
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
                StringFragment::Literal(s) => acc.push(s.fragment().to_string().into()), // .fragment() added
                StringFragment::EscapedChar(c) => acc.push(c.to_string().into()),
                StringFragment::TemplateElement(v) => acc.push(v),
                StringFragment::EscapedWS => {} // Explicitly handle EscapedWS if it shouldn't add to vec
            }
            acc
        },
    );
    delimited(char('`'), build_string, char('`')).parse(input)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*; // For parse_template itself and Span from current module (template.rs)
    use crate::parser::Span as ParserSpan; // Keep Span alias if needed, or use crate::parser::Span directly
    use crate::parser::parse; // For assert_parse_template_error helper
    use crate::script::Value; // For complex expression test
    use crate::script::stdlib::{Greater, If}; // For complex expression test
    use crate::{array, id, int, plus, str, strcat}; // Changed to crate:: for macros
    // For creating Spans in tests if needed, or use ParserSpan

    // Helper for asserting successful template parsing
    fn assert_template_ast(input: &str, expected_vec: Vec<Value>) {
        // Ensure Span type is consistent. parse_template expects nom_locate::LocatedSpan<&str>
        // The Span type alias in parser/mod.rs should be this.
        // If tests create Spans, they should use the same type.
        let span_input = ParserSpan::new(input); // Use the aliased Span from parser
        let result = parse_template::<nom_language::error::VerboseError<ParserSpan>>(span_input);
        assert!(result.is_ok(), "Parsing failed for input: {}", input);
        let (_, parsed_vec) = result.unwrap();

        let expected_value = if parsed_vec.is_empty() {
            strcat!(array!())
        } else {
            strcat!(Value::Array(Arc::new(expected_vec)))
        };

        let overall_parse_result = crate::parser::parse(input);
        assert!(
            overall_parse_result.is_ok(),
            "Overall parsing failed for input: {}. Error: {:?}",
            input,
            overall_parse_result.err()
        );
        let actual_value_from_parser = overall_parse_result.unwrap();

        assert_eq!(
            actual_value_from_parser, expected_value,
            "Mismatch for input: {}",
            input
        );
    }

    fn assert_parse_template_error(input: &str) {
        assert!(parse(input).is_err(), "Expected error for input: {}", input);
    }

    #[test]
    fn test_empty_template() {
        assert_template_ast("``", vec![]);
    }

    #[test]
    fn test_template_with_only_static_text() {
        assert_template_ast("`hello world`", vec![str!("hello world")]);
    }

    #[test]
    fn test_template_with_only_one_expression() {
        assert_template_ast("`${1+2}`", vec![plus!(int!(1), int!(2))]);
    }

    #[test]
    fn test_template_with_multiple_expressions() {
        assert_template_ast("`${1} ${2}`", vec![int!(1), str!(" "), int!(2)]);
    }

    #[test]
    fn test_template_with_text_and_expressions() {
        assert_template_ast(
            "`hello ${name} world`",
            vec![str!("hello "), id!("name"), str!(" world")],
        );
    }

    #[test]
    fn test_template_with_expressions_at_start_end() {
        assert_template_ast("`${1}text`", vec![int!(1), str!("text")]);
        assert_template_ast("`text${2}`", vec![str!("text"), int!(2)]);
    }

    #[test]
    fn test_template_with_complex_expression() {
        assert_template_ast(
            "`value: ${if x > 0 then y else z}`",
            vec![
                str!("value: "),
                Value::OpCall(Arc::new(crate::script::Call::new(vec![
                    // Path to Call
                    Value::NativeObject(Arc::new(Box::new(If::stub()))),
                    Value::OpCall(Arc::new(crate::script::Call::new(vec![
                        // Path to Call
                        Value::NativeObject(Arc::new(Box::new(Greater::stub()))),
                        id!("x"),
                        int!(0),
                    ]))),
                    id!("y"),
                    id!("z"),
                ]))),
            ],
        );
    }

    #[test]
    fn test_unterminated_template_literal() {
        assert_parse_template_error("`abc");
    }

    #[test]
    fn test_unterminated_expression_in_template() {
        assert_parse_template_error("`${1+2`");
        assert_parse_template_error("`${1+`");
    }

    #[test]
    fn test_invalid_escape_sequence_in_template() {
        assert_parse_template_error("`\\x`");
    }

    #[test]
    fn test_syntax_error_in_embedded_expression() {
        assert_parse_template_error("`${1 + * 2}`");
    }

    #[test]
    fn test_dangling_dollar_in_template() {
        assert_template_ast(
            "`hello $world`",
            vec![str!("hello "), str!("$"), str!("world")],
        );
        assert_template_ast("`$`", vec![str!("$")]);
    }

    #[test]
    fn test_escaped_backticks_and_dollar_signs() {
        assert_template_ast(
            "`\\`\\${value}`",
            vec![str!("`"), str!("$"), str!("{value}")],
        );
    }

    #[test]
    fn test_template_with_empty_expression_placeholder() {
        assert_parse_template_error("`${}`");
    }

    #[test]
    fn test_nested_templates_parsed_correctly_by_main_parser() {
        assert_template_ast(
            "`outer: ${`inner: ${x}`}`",
            vec![str!("outer: "), strcat!(array!(str!("inner: "), id!("x")))],
        );
    }
}
