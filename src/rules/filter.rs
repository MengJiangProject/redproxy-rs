use std::{fmt, str::FromStr};

use nom::error::{convert_error, VerboseError};

use super::parser::*;

#[derive(Debug, Eq, PartialEq)]
pub struct Filter {
    root: Value,
}

impl FromStr for Filter {
    type Err = SyntaxError;

    fn from_str<'a>(s: &'a str) -> Result<Self, Self::Err> {
        root::<VerboseError<&str>>(s)
            .map(|(rest, root)| {
                assert!(
                    rest.is_empty(),
                    "parser not complete: val={:?} left={:}",
                    root,
                    rest,
                );
                Filter { root }
            })
            .map_err(|e| SyntaxError::new(e, s))
    }
}

// #[derive(Debug)]
pub struct SyntaxError {
    msg: String,
}

impl SyntaxError {
    fn new(e: nom::Err<VerboseError<&str>>, input: &str) -> Self {
        let msg = match e {
            nom::Err::Error(e) | nom::Err::Failure(e) => convert_error(input, e),
            _ => e.to_string(),
        };
        SyntaxError { msg }
    }
}

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
