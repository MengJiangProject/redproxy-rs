// Utilties for script tests

use crate::script::{
    Accessible, Callable, Evaluatable, Indexable, NativeObject, ScriptContextRef, Type, Value,
};
use easy_error::{bail, err_msg, Error};
// Arc is not directly used in the moved code blocks but might be relevant for how these objects are used elsewhere.
// For now, let's only include what's directly necessary for these implementations. ScriptContextRef handles Arc internally.

// Copied NativeObject impl for (String, u32)
impl NativeObject for (String, u32) {
    fn as_accessible(&self) -> Option<&dyn Accessible> {
        Some(self)
    }
    fn as_evaluatable(&self) -> Option<&dyn Evaluatable> {
        Some(self)
    }
    fn as_indexable(&self) -> Option<&dyn Indexable> {
        Some(self)
    }
    // No as_callable
}

#[async_trait::async_trait]
impl Accessible for (String, u32) {
    fn names(&self) -> Vec<&str> {
        vec!["length", "x"]
    }
    async fn type_of(&self, name: &str, _ctx: ScriptContextRef) -> Result<Type, Error> {
        match name {
            "length" | "x" => Ok(Type::Integer),
            _ => bail!("no such property"),
        }
    }
    fn get(&self, name: &str) -> Result<Value, Error> {
        match name {
            "length" => Ok((self.0.len() as i64).into()),
            "x" => Ok(self.1.into()),
            _ => bail!("no such property"),
        }
    }
}

#[async_trait::async_trait]
impl Indexable for (String, u32) {
    fn length(&self) -> usize {
        self.0.len()
    }
    async fn type_of_member(&self, _ctx: ScriptContextRef) -> Result<Type, Error> {
        Ok(Type::Integer)
    }
    fn get(&self, index: i64) -> Result<Value, Error> {
        let n_char_val = self
            .0
            .chars()
            .nth(index as usize)
            .ok_or_else(|| err_msg("index out of range"))? as i64;
        Ok(n_char_val.into())
    }
}

#[async_trait::async_trait]
impl Evaluatable for (String, u32) {
    async fn type_of(&self, _ctx: ScriptContextRef) -> Result<Type, Error> {
        Ok(Type::String)
    }
    async fn value_of(&self, _ctx: ScriptContextRef) -> Result<Value, Error> {
        Ok(self.0.to_owned().into())
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct TestNativeSimple; // Made pub
impl NativeObject for TestNativeSimple {
    fn as_accessible(&self) -> Option<&dyn Accessible> {
        Some(self)
    }
}
#[async_trait::async_trait]
impl Accessible for TestNativeSimple {
    fn names(&self) -> Vec<&str> {
        vec!["valid_prop"]
    }
    async fn type_of(&self, name: &str, _ctx: ScriptContextRef) -> Result<Type, Error> {
        if name == "valid_prop" {
            Ok(Type::Integer)
        } else {
            bail!("no such property")
        }
    }
    fn get(&self, name: &str) -> Result<Value, Error> {
        if name == "valid_prop" {
            Ok(Value::Integer(123))
        } else {
            bail!("no such property: {}", name)
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct TestNativeFailingAccess; // Made pub
impl NativeObject for TestNativeFailingAccess {
    fn as_accessible(&self) -> Option<&dyn Accessible> {
        Some(self)
    }
}
#[async_trait::async_trait]
impl Accessible for TestNativeFailingAccess {
    fn names(&self) -> Vec<&str> {
        vec!["prop_that_fails"]
    }
    async fn type_of(&self, _name: &str, _ctx: ScriptContextRef) -> Result<Type, Error> {
        Ok(Type::Integer) // Type is Integer, but get will fail
    }
    fn get(&self, name: &str) -> Result<Value, Error> {
        bail!("native error on get for {}", name)
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct TestNativeFailingCall; // Made pub
impl NativeObject for TestNativeFailingCall {
    fn as_callable(&self) -> Option<&dyn Callable> {
        Some(self)
    }
}
#[async_trait::async_trait]
impl Callable for TestNativeFailingCall {
    async fn signature(&self, _ctx: ScriptContextRef, _args: &[Value]) -> Result<Type, Error> {
        Ok(Type::Integer) // Signature is Integer, but call will fail
    }
    async fn call(&self, _ctx: ScriptContextRef, _args: &[Value]) -> Result<Value, Error> {
        bail!("native error on call")
    }
}
