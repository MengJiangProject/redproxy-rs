use async_trait::async_trait;
use easy_error::{bail, err_msg, Error};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom; // For Indexable<Vec<Value>>

// Forward declare types used in traits, assuming they will be in scope via `super` or `crate::script`
use super::context::ScriptContextRef; // Assuming context.rs for ScriptContextRef
use super::types::Type; // Assuming types.rs for Type
use super::value::Value; // Assuming value.rs for Value

#[async_trait]
pub trait Evaluatable: Send + Sync {
    async fn type_of(&self, ctx: ScriptContextRef) -> Result<Type, Error>;
    async fn value_of(&self, ctx: ScriptContextRef) -> Result<Value, Error>;
}

#[async_trait]
pub trait Indexable: Send + Sync {
    fn length(&self) -> usize;
    async fn type_of_member(&self, ctx: ScriptContextRef) -> Result<Type, Error>;
    fn get(&self, index: i64) -> Result<Value, Error>;
}

#[async_trait]
pub trait Accessible: Send + Sync {
    fn names(&self) -> Vec<&str>;
    async fn type_of(&self, name: &str, ctx: ScriptContextRef) -> Result<Type, Error>;
    fn get(&self, name: &str) -> Result<Value, Error>;
}

#[async_trait]
pub trait Callable: Send + Sync {
    async fn signature(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Type, Error>;
    async fn call(&self, ctx: ScriptContextRef, args: &[Value]) -> Result<Value, Error>;
    fn unresovled_ids<'s: 'o, 'o>(&'s self, args: &'s [Value], ids: &mut HashSet<&'o Value>) {
        args.iter().for_each(|v| v.unresovled_ids(ids))
    }
}

#[async_trait]
impl Accessible for HashMap<String, Value> {
    fn names(&self) -> Vec<&str> {
        self.keys().map(String::as_str).collect()
    }

    async fn type_of(&self, name: &str, ctx: ScriptContextRef) -> Result<Type, Error> {
        let val = Accessible::get(self, name)?;
        val.type_of(ctx).await
    }

    fn get(&self, name: &str) -> Result<Value, Error> {
        self.get(name)
            .cloned()
            .ok_or_else(|| err_msg(format!("undefined: {}", name)))
    }
}

#[async_trait]
impl Indexable for Vec<Value> {
    fn length(&self) -> usize {
        self.len()
    }

    async fn type_of_member(&self, ctx: ScriptContextRef) -> Result<Type, Error> {
        // To handle empty array, should return Type::Any or a specific error/option
        if self.is_empty() {
            return Ok(Type::Any); // Or appropriate type for empty array members if defined
        }
        let x = Indexable::get(self, 0)?;
        x.type_of(ctx).await
    }

    fn get(&self, index: i64) -> Result<Value, Error> {
        let len = self.len();
        let final_idx: usize;

        if index >= 0 {
            final_idx = index as usize;
        } else {
            if len == 0 {
                bail!(
                    "index out of bounds: array is empty, len is 0, index was {}",
                    index
                );
            }
            if let Some(positive_offset) = index
                .checked_neg()
                .and_then(|val| usize::try_from(val).ok())
            {
                if positive_offset > len {
                    bail!(
                        "index out of bounds: negative index {} is too large for array of len {}",
                        index,
                        len
                    );
                }
                final_idx = len - positive_offset;
            } else {
                bail!("index out of bounds: invalid negative index {}", index);
            }
        }

        if final_idx >= len {
            bail!("index out of bounds: {}", index);
        }
        Ok(self[final_idx].clone())
    }
}

pub trait NativeObjectHash {
    fn gen_hash(&self) -> u64;
    fn hash_with_state(&self, st: &mut dyn std::hash::Hasher);
}

impl<T> NativeObjectHash for T
where
    T: std::hash::Hash + ?Sized + NativeObject,
{
    fn gen_hash(&self) -> u64 {
        use std::hash::Hasher;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
    fn hash_with_state(&self, mut st: &mut dyn std::hash::Hasher) {
        self.hash(&mut st);
    }
}

pub trait NativeObject: std::fmt::Debug + NativeObjectHash + Send + Sync {
    // Added Send + Sync
    fn as_evaluatable(&self) -> Option<&dyn Evaluatable> {
        None
    }
    fn as_accessible(&self) -> Option<&dyn Accessible> {
        None
    }
    fn as_indexable(&self) -> Option<&dyn Indexable> {
        None
    }
    fn as_callable(&self) -> Option<&dyn Callable> {
        None
    }
}

pub type NativeObjectRef = Box<dyn NativeObject + Send + Sync>; // Already Send + Sync

impl Eq for NativeObjectRef {}
impl PartialEq for NativeObjectRef {
    fn eq(&self, other: &NativeObjectRef) -> bool {
        self.gen_hash() == other.gen_hash()
    }
}

impl std::hash::Hash for NativeObjectRef {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash_with_state(state)
    }
}
