//! This module exports helpers for implementing the `Arbitrary` trait on types that build on
//! top of primitives provided by this crate.

pub use crate::ast::{ident::arbitrary as ident, path::arbitrary as path};
