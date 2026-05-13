//! Interprocedural type inference for decompiled IR.
//!
//! This module infers conservative type summaries for procedures.

mod declared;
mod domain;
mod expr_defs;
mod inter;
mod intra;
mod origin;
mod stdlib;
mod summary;

pub(crate) use declared::{declared_summary_for_proc, declared_summary_for_proc_with_arity};
pub use domain::{InferredType, TypeRequirement, VarKey};
#[doc(hidden)]
pub use inter::infer_type_summaries_from_lifted;
pub use summary::{TypeSummary, TypeSummaryMap};
