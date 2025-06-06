//! This example shows an example of how to parse an escaped string. The
//! rules for the string are similar to JSON and rust. A string is:
//!
//! - Enclosed by double quotes
//! - Can contain any raw unescaped code point besides \ and "
//! - Matches the following escape sequences: \b, \f, \n, \r, \t, \", \\, \/
//! - Matches code points like Rust: \u{XXXX}, where XXXX can be up to 6
//!   hex characters
//! - an escape followed by whitespace consumes all whitespace between the
//!   escape and the next non-whitespace character

// #![cfg(feature = "alloc")]
// #[global_allocator]
// static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

use nom::branch::alt;
use nom::bytes::streaming::{is_not, take_while_m_n};
use nom::character::streaming::{char, multispace1};
use nom::combinator::{cut, map, map_opt, map_res, value, verify};
use nom::error::{FromExternalError, ParseError};
use nom::multi::fold_many0;
use nom::sequence::{delimited, preceded};
use nom::{IResult, Parser};

use super::Span;
// parser combinators are constructed from the bottom up:
// first we write parsers for the smallest elements (escaped characters),
// then combine them into larger parsers.

/// Parse a unicode sequence, of the form u{XXXX}, where XXXX is 1 to 6
/// hexadecimal numerals. We will combine this later with parse_escaped_char
/// to parse sequences like \u{00AC}.
pub(crate) fn parse_unicode<'a, E>(input: Span<'a>) -> IResult<Span<'a>, char, E>
where
    E: ParseError<Span<'a>> + FromExternalError<Span<'a>, std::num::ParseIntError>,
{
    // `take_while_m_n` parses between `m` and `n` bytes (inclusive) that match
    // a predicate. `parse_hex` here parses between 1 and 6 hexadecimal numerals.
    let parse_hex = take_while_m_n(1, 6, |c: char| c.is_ascii_hexdigit());

    // `preceeded` takes a prefix parser, and if it succeeds, returns the result
    // of the body parser. In this case, it parses u{XXXX}.
    let parse_delimited_hex = preceded(
        char('u'),
        // `delimited` is like `preceded`, but it parses both a prefix and a suffix.
        // It returns the result of the middle parser. In this case, it parses
        // {XXXX}, where XXXX is 1 to 6 hex numerals, and returns XXXX
        delimited(char('{'), parse_hex, char('}')),
    );

    // `map_res` takes the result of a parser and applies a function that returns
    // a Result. In this case we take the hex bytes from parse_hex and attempt to
    // convert them to a u32.
    let parse_u32 = map_res(parse_delimited_hex, move |hex: Span| {
        u32::from_str_radix(&hex, 16)
    });

    // map_opt is like map_res, but it takes an Option instead of a Result. If
    // the function returns None, map_opt returns an error. In this case, because
    // not all u32 values are valid unicode code points, we have to fallibly
    // convert to char with from_u32.
    map_opt(parse_u32, std::char::from_u32).parse(input)
}

/// Parse an escaped character: \n, \t, \r, \u{00AC}, etc.
fn parse_escaped_char<'a, E>(input: Span<'a>) -> IResult<Span<'a>, char, E>
where
    E: ParseError<Span<'a>> + FromExternalError<Span<'a>, std::num::ParseIntError>,
{
    preceded(
        char('\\'),
        // `alt` tries each parser in sequence, returning the result of
        // the first successful match
        // `cut` commits to parsing an escape sequence if a `\` is found
        cut(alt((
            parse_unicode,
            // The `value` parser returns a fixed value (the first argument) if its
            // parser (the second argument) succeeds. In these cases, it looks for
            // the marker characters (n, r, t, etc) and returns the matching
            // character (\n, \r, \t, etc).
            value('\n', char('n')),
            value('\r', char('r')),
            value('\t', char('t')),
            value('\u{08}', char('b')),
            value('\u{0C}', char('f')),
            value('\\', char('\\')),
            value('/', char('/')),
            value('"', char('"')),
        ))),
    )
    .parse(input)
}

/// Parse a backslash, followed by any amount of whitespace. This is used later
/// to discard any escaped whitespace.
pub(crate) fn parse_escaped_whitespace<'a, E: ParseError<Span<'a>>>(
    input: Span<'a>,
) -> IResult<Span<'a>, Span<'a>, E> {
    preceded(char('\\'), multispace1).parse(input)
}

/// Parse a non-empty block of text that doesn't include \ or "
fn parse_literal<'a, E: ParseError<Span<'a>>>(input: Span<'a>) -> IResult<Span<'a>, Span<'a>, E> {
    // `is_not` parses a string of 0 or more characters that aren't one of the
    // given characters.
    let not_quote_slash = is_not("\"\\");

    // `verify` runs a parser, then runs a verification function on the output of
    // the parser. The verification function accepts out output only if it
    // returns true. In this case, we want to ensure that the output of is_not
    // is non-empty.
    verify(not_quote_slash, |s: &Span| !s.is_empty()).parse(input)
}

/// A string fragment contains a fragment of a string being parsed: either
/// a non-empty Literal (a series of non-escaped characters), a single
/// parsed escaped character, or a block of escaped whitespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StringFragment<'a> {
    Literal(Span<'a>),
    EscapedChar(char),
    EscapedWS,
}

/// Combine parse_literal, parse_escaped_whitespace, and parse_escaped_char
/// into a StringFragment.
fn parse_fragment<'a, E>(input: Span<'a>) -> IResult<Span<'a>, StringFragment<'a>, E>
where
    E: ParseError<Span<'a>> + FromExternalError<Span<'a>, std::num::ParseIntError>,
{
    alt((
        // The `map` combinator runs a parser, then applies a function to the output
        // of that parser.
        map(parse_literal, StringFragment::Literal),
        // Try parsing escaped whitespace first, as it also starts with a '\'
        value(StringFragment::EscapedWS, parse_escaped_whitespace),
        map(parse_escaped_char, StringFragment::EscapedChar),
    ))
    .parse(input)
}

/// Parse a string. Use a loop of parse_fragment and push all of the fragments
/// into an output string.
pub fn parse_string<'a, E>(input: Span<'a>) -> IResult<Span<'a>, String, E>
where
    E: ParseError<Span<'a>> + FromExternalError<Span<'a>, std::num::ParseIntError>,
{
    // fold_many0 is the equivalent of iterator::fold. It runs a parser in a loop,
    // and for each output value, calls a folding function on each output value.
    let build_string = fold_many0(
        // Our parser function– parses a single string fragment
        parse_fragment,
        // Our init value, an empty string
        String::new,
        // Our folding function. For each fragment, append the fragment to the
        // string.
        |mut string, fragment| {
            match fragment {
                StringFragment::Literal(s) => string.push_str(&s),
                StringFragment::EscapedChar(c) => string.push(c),
                StringFragment::EscapedWS => {}
            }
            string
        },
    );

    // Finally, parse the string. Note that, if `build_string` could accept a raw
    // " character, the closing delimiter " would never match. When using
    // `delimited` with a looping parser (like fold_many0), be sure that the
    // loop won't accidentally match your closing delimiter!
    delimited(char('"'), build_string, char('"')).parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_string() {
        let data = Span::new("\"abc\"");
        println!("EXAMPLE 1:\nParsing a simple input string: {}", data);
        let result = parse_string::<()>(data).unwrap().1;
        assert_eq!(result, String::from("abc"));
        println!("Result: {}\n\n", result);
        let data = Span::new(
            "\"tab:\\tafter tab, newline:\\nnew line, quote: \\\", emoji: \\u{1F602}, newline:\\nescaped whitespace: \\    abc\"",
        );
        println!(
            "EXAMPLE 2:\nParsing a string with escape sequences, newline literal, and escaped whitespace:\n\n{}\n",
            data
        );
        let result = parse_string::<()>(data).unwrap().1;
        assert_eq!(
            result,
            String::from(
                "tab:\tafter tab, newline:\nnew line, quote: \", emoji: 😂, newline:\nescaped whitespace: abc"
            )
        );
        println!("Result:\n\n{}", result);
    }

    // Helper for error tests
    fn assert_parse_string_error(input: &str) {
        let data = Span::new(input);
        assert!(parse_string::<nom_language::error::VerboseError<Span>>(data).is_err());
    }

    #[test]
    fn test_unterminated_string() {
        assert_parse_string_error("\"abc");
    }

    #[test]
    fn test_invalid_unicode_escape_too_many_digits() {
        assert_parse_string_error("\"\\u{FFFFFFF}\""); // More than 6 hex digits
    }

    #[test]
    fn test_invalid_unicode_escape_empty() {
        assert_parse_string_error("\"\\u{}\"");
    }

    #[test]
    fn test_invalid_unicode_escape_invalid_char() {
        assert_parse_string_error("\"\\u{FFFG}\""); // G is not a hex digit
    }

    #[test]
    fn test_invalid_escape_sequence() {
        assert_parse_string_error("\"\\x\""); // \x is not a valid escape in this parser
        // The following case is handled by parse_escaped_whitespace, so it's not an error.
        // assert_parse_string_error("\"\\ \"");
        assert_parse_string_error("\"\\"); // Dangling backslash
    }

    #[test]
    fn test_dangling_backslash_at_end() {
        assert_parse_string_error("\"abc\\");
    }

    #[test]
    fn test_empty_string() {
        let data = Span::new("\"\"");
        let result = parse_string::<()>(data).unwrap().1;
        assert_eq!(result, String::from(""));
    }

    #[test]
    fn test_string_with_only_escape_sequences() {
        let data = Span::new("\"\\n\\t\\\"\\\\\""); // \n, \t, \", \\
        let result = parse_string::<()>(data).unwrap().1;
        assert_eq!(result, String::from("\n\t\"\\"));
    }

    #[test]
    fn test_string_with_all_valid_escapes() {
        let data = Span::new("\"\\b\\f\\n\\r\\t\\\"\\\\\\/\\u{0041}\""); // \b \f \n \r \t \" \\ \/ \u{0041} (A)
        let result = parse_string::<()>(data).unwrap().1;
        assert_eq!(result, String::from("\u{08}\u{0C}\n\r\t\"\\/A"));
    }

    #[test]
    fn test_string_with_escaped_whitespace() {
        let data = Span::new("\"a\\   b\\ \t\nc\""); // 'a', escaped spaces, 'b', escaped space, tab, newline, 'c'
        let result = parse_string::<()>(data).unwrap().1;
        assert_eq!(result, String::from("abc")); // Escaped whitespace should be consumed
    }
}
