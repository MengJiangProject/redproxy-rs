//! I/O streaming and buffering utilities for redproxy
//!
//! This module provides:
//! - `IOStream` trait for type-erased async streams with splice optimization
//! - `BufferedStream` for fine-grained buffer control
//! - Copy operations for unidirectional and bidirectional data transfer
//! - Linux splice() integration for zero-copy performance

mod bidirectional;
mod buffered;
mod copy;
mod stream;

pub use bidirectional::BidirectionalCopy;
pub use buffered::{BufferedStream, IOBufStream};
pub use copy::CopyOperation;
pub use stream::{IOStream, make_buffered_stream};
