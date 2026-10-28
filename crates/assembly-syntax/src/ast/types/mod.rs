//! The type system a MASM signature is written in.
//!
//! The types themselves come from [`midenc_hir_type`] and are re-exported here. On top of them,
//! [`signatures`] converts between the values a signature names and the felts the VM stack holds.

pub mod signatures;

pub use midenc_hir_type::*;

pub use self::signatures::{
    FeltCodec, MIDEN_CORE_TYPES, TypedError, TypedProcInfo, WitScalarCodec, WordCodec,
};
