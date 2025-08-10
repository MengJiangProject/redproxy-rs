// Module declarations for the refactored components
pub mod context;
pub mod functions;
pub mod stdlib; // Retain stdlib module
pub mod traits;
pub mod types;
pub mod value;

#[cfg(test)]
pub mod test_utils;
#[cfg(test)]
mod tests; // tests.rs is now a sibling module

// Re-export key items to be available under `crate::script::*`
pub use context::*;
pub use functions::*;
pub use traits::*;
pub use types::*;
pub use value::*;

// Explicitly re-export items that might be needed by `crate::script::stdlib::*` or other modules
// if they were previously relying on them being directly in `crate::script`.
// Many of these are already covered by the `pub use <module>::*` above.
// However, it's good to be mindful if stdlib macros or functions specifically need something
// from the top level of `crate::script` that isn't a direct export from one of the new modules.

// The `use` statements from the old script.rs that are broadly used.
// Some of these might be more appropriately placed in submodules if their usage is localized.
pub use async_trait::async_trait; // Used in traits.rs, functions.rs, etc.
pub use anyhow::{Result, bail}; // Widely used for error handling
pub use std::{
    collections::{HashMap, HashSet}, // HashMap used in context.rs, traits.rs; HashSet in traits.rs, functions.rs, value.rs
    convert::TryFrom,                // Used in value.rs (TryFrom<Value>) and stdlib functions
    fmt::Display,                    // Used in types.rs, value.rs, functions.rs
    sync::{Arc, Weak}, // Arc/Weak used in context.rs, types.rs, value.rs, functions.rs
};
