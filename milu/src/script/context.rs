use easy_error::{bail, Error};
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
}; // Removed err_msg

// Assuming other modules are correctly set up in `super` or `crate::script`
use super::stdlib;
use super::value::Value; // Value is stored in ScriptContext // For Default impl

#[derive(Debug)]
pub struct ScriptContext {
    parent: Option<ScriptContextRef>,
    pub varibles: HashMap<String, Value>, // Made varibles public
}

pub type ScriptContextRef = Arc<ScriptContext>;
pub type ScriptContextWeakRef = Weak<ScriptContext>;

impl ScriptContext {
    pub fn new(parent: Option<ScriptContextRef>) -> Self {
        Self {
            parent,
            varibles: Default::default(),
        }
    }

    pub fn lookup(&self, id: &str) -> Result<Value, Error> {
        if let Some(r) = self.varibles.get(id) {
            tracing::trace!("lookup({})={}", id, r);
            Ok(r.clone())
        } else if let Some(p) = &self.parent {
            p.lookup(id)
        } else {
            bail!("\"{}\" is undefined", id)
        }
    }

    pub fn set(&mut self, id: String, value: Value) {
        self.varibles.insert(id, value);
    }
}

impl Default for ScriptContext {
    fn default() -> Self {
        let mut map = HashMap::default();

        // These paths should work due to re-exports in stdlib/mod.rs
        map.insert("to_string".to_string(), stdlib::ToString::stub().into());
        map.insert("to_integer".to_string(), stdlib::ToInteger::stub().into());
        map.insert("split".to_string(), stdlib::Split::stub().into());
        map.insert("strcat".to_string(), stdlib::StringConcat::stub().into());
        map.insert("like".to_string(), stdlib::Like::stub().into());
        map.insert("not_like".to_string(), stdlib::NotLike::stub().into());
        map.insert("char_at".to_string(), stdlib::StringCharAt::stub().into());
        map.insert(
            "char_code_at".to_string(),
            stdlib::StringCharCodeAt::stub().into(),
        );
        map.insert(
            "ends_with".to_string(),
            stdlib::StringEndsWith::stub().into(),
        );
        map.insert(
            "includes".to_string(),
            stdlib::StringIncludes::stub().into(),
        ); // String includes
        map.insert("index_of".to_string(), stdlib::StringIndexOf::stub().into()); // String index_of
        map.insert("match_str".to_string(), stdlib::StringMatch::stub().into());
        map.insert("replace".to_string(), stdlib::StringReplace::stub().into());
        map.insert(
            "replace_regex".to_string(),
            stdlib::StringReplaceRegex::stub().into(),
        );
        map.insert("slice".to_string(), stdlib::StringSlice::stub().into()); // String slice
        map.insert(
            "starts_with".to_string(),
            stdlib::StringStartsWith::stub().into(),
        );
        map.insert(
            "substring".to_string(),
            stdlib::StringSubstring::stub().into(),
        );
        map.insert(
            "lower_case".to_string(),
            stdlib::StringLowerCase::stub().into(),
        );
        map.insert(
            "upper_case".to_string(),
            stdlib::StringUpperCase::stub().into(),
        );
        map.insert("trim".to_string(), stdlib::StringTrim::stub().into());
        map.insert("map".to_string(), stdlib::Map::stub().into());
        map.insert("reduce".to_string(), stdlib::Reduce::stub().into());
        map.insert("filter".to_string(), stdlib::Filter::stub().into());
        map.insert("find".to_string(), stdlib::Find::stub().into());
        map.insert("find_index".to_string(), stdlib::FindIndex::stub().into());
        map.insert("for_each".to_string(), stdlib::ForEach::stub().into());
        map.insert("array_index_of".to_string(), stdlib::IndexOf::stub().into()); // Array IndexOf
        map.insert(
            "array_includes".to_string(),
            stdlib::Includes::stub().into(),
        ); // Array Includes
        map.insert("join".to_string(), stdlib::Join::stub().into());
        map.insert("array_slice".to_string(), stdlib::Slice::stub().into()); // Array Slice

        // Note: The original Default impl did not include core operators like Plus, Minus, etc.
        // or control flow like If, Scope, Index, Access. These are typically handled by the parser
        // creating Value::OpCall directly rather than being looked up by name in context.
        // If they were meant to be here, they'd be added like:
        // map.insert("Plus".to_string(), stdlib::Plus::stub().into());

        Self {
            parent: None,
            varibles: map,
        }
    }
}
