use nom::{
    branch::alt,
    bytes::streaming::is_not,
    character::streaming::char,
    combinator::{map, value, verify},
    error::{ContextError, FromExternalError, ParseError},
    multi::fold_many0,
    sequence::{delimited, preceded},
    IResult, Parser,
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
            value('`', char('`')), // Added for escaped backtick \`
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

fn parse_template_element<'a, E>(input: Span<'a>) -> IResult<Span<'a>, Value, E>
where
    E: ParseError<Span<'a>>
        + FromExternalError<Span<'a>, std::num::ParseIntError>
        + ContextError<Span<'a>>
        + std::fmt::Debug,
{
    // Use tag to match "${" literally. If this passes, then cut.
    preceded(
        nom::bytes::streaming::tag("${"),
        nom::combinator::cut(nom::sequence::terminated(super::op_0, char('}'))),
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
        map(parse_escaped_char, StringFragment::EscapedChar), // Priority 1: Escaped characters (e.g., \$, \`, \\)
        map(parse_template_element, StringFragment::TemplateElement), // Priority 2: Template expressions (e.g., ${expr})
        map(char('$'), |c: char| StringFragment::EscapedChar(c)), // Priority 3: Literal '$', treated like an escaped char for simplicity
        map(parse_template_literal, StringFragment::Literal), // Priority 4: Regular text segments
        value(StringFragment::EscapedWS, parse_escaped_whitespace), // Priority 5: Escaped whitespace
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
                StringFragment::Literal(s) => acc.push(s.to_string().into()),
                StringFragment::EscapedChar(c) => acc.push(c.to_string().into()),
                StringFragment::TemplateElement(v) => acc.push(v),
                _ => {}
            }
            acc
        },
    );
    delimited(char('`'), build_string, char('`')).parse(input)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::parser::parse; // For assert_parse_template_error helper
    use crate::parser::tests::{array, id, int, plus, str, strcat}; // Adjust if macros are not public
    use crate::script::stdlib::*;
    use crate::script::Call;
    use crate::script::Value;

    // Helper for asserting successful template parsing
    fn assert_template_ast(input: &str, expected_vec: Vec<Value>) {
        let result = parse_template::<nom_language::error::VerboseError<Span>>(Span::new(input));
        assert!(result.is_ok(), "Parsing failed for input: {}", input);
        let (_, parsed_vec) = result.unwrap();

        // Construct the expected Value::OpCall(Arc<Call>) for strcat
        let expected_value = if parsed_vec.is_empty() {
            strcat!(array!()) // Handles `` ` `` resulting in strcat!([])
        } else {
            strcat!(Value::Array(Arc::new(expected_vec)))
        };

        // The parse_template function itself returns Vec<Value>,
        // but the overall parser (in parser.rs) wraps this into a strcat call.
        // To test template.rs in isolation, we check the Vec<Value>.
        // However, for integration, it's good to also see how it fits.
        // The main `parse` function (from parser.rs) does the strcat wrapping.
        // Let's use that for a more integrated test of template parsing.
        let overall_parse_result = crate::parser::parse(input); // Assuming parse() is accessible
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

    // Helper for error tests
    fn assert_parse_template_error(input: &str) {
        // We test errors through the main parse function because template parsing errors
        // are often caught by the surrounding grammar or expression parsing within ${}.
        assert!(parse(input).is_err(), "Expected error for input: {}", input);
    }

    // Basic Template Tests
    #[test]
    fn test_empty_template() {
        // The parser wraps the result of parse_template (which is Vec<Value>)
        // into a StringConcat call. So, `` ` `` becomes strcat!(array!()).
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
        // Note: The current parse_template logic might produce a flat Vec<Value>
        // like vec![expr1, str!(" "), expr2]. The strcat macro in parser.rs tests might handle this.
        // Let's assume spaces between expressions become separate string literals.
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
        // Original expectation, which might be misaligned with parser output if 'if' and '>' become NativeObjects
        // If parser produces NativeObject(If) etc., this test will fail, and needs proper test macros (branch!, greater!)
        // or public constructors for Call to assert the correct NativeObject structure.
        assert_template_ast(
            "`value: ${if x > 0 then y else z}`",
            vec![
                str!("value: "),
                // Expecting NativeObject for 'if' and '>'
                Value::OpCall(Arc::new(Call::new(vec![
                    Value::NativeObject(Arc::new(Box::new(If::stub()))), // if
                    Value::OpCall(Arc::new(Call::new(vec![
                        // condition: x > 0
                        Value::NativeObject(Arc::new(Box::new(Greater::stub()))), // >
                        id!("x"),
                        int!(0),
                    ]))),
                    id!("y"), // then branch
                    id!("z"), // else branch
                ]))),
            ],
        );
    }

    // Error Conditions
    #[test]
    fn test_unterminated_template_literal() {
        assert_parse_template_error("`abc");
    }

    #[test]
    fn test_unterminated_expression_in_template() {
        assert_parse_template_error("`${1+2`"); // Missing closing } for expression
        assert_parse_template_error("`${1+`"); // Missing operand and closing }
    }

    #[test]
    fn test_invalid_escape_sequence_in_template() {
        // Note: \x is not a supported escape in the template string parser
        assert_parse_template_error("`\\x`");
    }

    #[test]
    fn test_syntax_error_in_embedded_expression() {
        assert_parse_template_error("`${1 + * 2}`"); // Invalid operator usage inside ${}
    }

    #[test]
    fn test_dangling_dollar_in_template() {
        // A single '$' not followed by '{' should be treated as a literal '$' or error.
        // Current parser might treat '$' as start of an escape if not part of ${expr}
        // The provided `parse_escaped_char` for templates includes `value('$', char('$'))`
        // which means `\$` is an escaped dollar. A raw `$` not part of `${` is literal.
        assert_template_ast(
            "`hello $world`",
            vec![str!("hello "), str!("$"), str!("world")],
        );
        assert_template_ast("`$`", vec![str!("$")]);
    }

    // Edge Cases
    #[test]
    fn test_escaped_backticks_and_dollar_signs() {
        // `\` is escaped as `\\`
        // `\${value}` should result in literal "${value}" if $ is only special before {
        // parse_escaped_char in template.rs has: value('$', char('$')), so `\$` -> `$`
        assert_template_ast(
            "`\\`\\${value}`",
            vec![str!("`"), str!("$"), str!("{value}")],
        );
    }

    #[test]
    fn test_template_with_empty_expression_placeholder() {
        // `${}` is likely a syntax error for the inner expression parser (op_0)
        assert_parse_template_error("`${}`");
    }

    #[test]
    fn test_nested_templates_parsed_correctly_by_main_parser() {
        // This relies on the main parser invoking the template parser recursively.
        // The `parse_template` function itself doesn't directly handle nesting,
        // but the `op_0` called inside `${...}` can parse another template.
        assert_template_ast(
            "`outer: ${`inner: ${x}`}`",
            vec![str!("outer: "), strcat!(array!(str!("inner: "), id!("x")))],
        );
    }
}
