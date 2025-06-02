use nom_language::error::{convert_error, VerboseError}; // Keep for SyntaxError
use nom_locate::LocatedSpan;
// std::fmt is needed for Display/Debug impls of SyntaxError
// other std items like ParseIntError, Arc are used in rules.rs or implicitly via Value
use std::fmt;

// Module declarations
mod rules;
mod string; // string and template are used by rules, so they should be sibling modules or public from rules
mod template;
pub mod test_utils; // Made public, no longer cfg(test)
#[cfg(test)]
mod tests; // Keep tests module declaration

pub use rules::*; // Re-export all rules
                  // Removed: pub use test_utils::*;

// Keep items that are not parser rules themselves
use super::script::Value; // Value is used in parse() return type and SyntaxError context

pub type Span<'s> = LocatedSpan<&'s str>;

// `parse` function remains in mod.rs as it's the main public API
pub fn parse(input: &str) -> Result<Value, SyntaxError> {
    root::<VerboseError<Span>>(Span::new(input)) // root is now pub from rules
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
