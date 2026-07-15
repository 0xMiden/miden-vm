//! Code-generation backends over the constraint IR.
//!
//! Only backends free of target-crate dependencies live here; a target with its
//! own machinery (the ACE circuit in `miden-ace-codegen`) owns its backend as an
//! IR consumer.

pub mod rust_eval;
