//! RedProxy-RS Library
//!
//! A high-performance proxy routing tool that translates between protocols
//! and selects destination proxies by policy.

pub mod access_log;
pub mod cli;
pub mod common;
pub mod config;
pub mod connectors;
pub mod context;
pub mod copy;
pub mod io;
pub mod listeners;
pub mod rules;
pub mod server;

#[cfg(feature = "metrics")]
pub mod metrics;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Re-export commonly used types for convenience
pub use config::Config;
pub use context::{Context, ContextRef, TargetAddress};
pub use server::ProxyServer;
