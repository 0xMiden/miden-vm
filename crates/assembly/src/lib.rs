#![no_std]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

use miden_core::{ONE, ZERO};

mod assembler;
mod basic_block_builder;
mod fmp;
mod instruction;
pub mod linker;
mod mast_forest_builder;
mod procedure;

#[cfg(test)]
mod mast_forest_merger_tests;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
#[cfg(test)]
mod tests;

// Re-exported for downstream crates
pub use miden_assembly_syntax::{
    KernelLibrary, Library, ModuleParser, Parse, ParseOptions, Path, PathBuf, ast,
    ast::{GlobalItemIndex, ModuleIndex},
    debuginfo::{
        self, DefaultSourceManager, SourceFile, SourceId, SourceManager, SourceSpan, Span, Spanned,
    },
    diagnostics,
    diagnostics::{Report, report},
    library,
};
/// Syntax components for the Miden Assembly AST
/// Merkelized abstract syntax tree (MAST) components defining Miden VM programs.
pub use miden_core::{mast, utils};

#[doc(hidden)]
pub use self::linker::{LinkLibraryKind, LinkerError};
pub use self::{
    assembler::Assembler,
    procedure::{Procedure, ProcedureContext},
};

// CONSTANTS
// ================================================================================================

/// The maximum number of elements that can be popped from the advice stack in a single `adv_push`
/// instruction.
const ADVICE_READ_LIMIT: u8 = 16;

/// The maximum number of bits by which a u32 value can be shifted in a bitwise operation.
const MAX_U32_SHIFT_VALUE: u8 = 31;

/// The maximum number of bits by which a u32 value can be rotated in a bitwise operation.
const MAX_U32_ROTATE_VALUE: u8 = 31;

/// The maximum number of bits allowed for the exponent parameter for exponentiation instructions.
const MAX_EXP_BITS: u8 = 64;

// HELPERS
// ================================================================================================

/// Pushes the provided value onto the stack using the most optimal sequence of operations.
fn push_value_ops(value: miden_core::Felt) -> alloc::vec::Vec<miden_core::Operation> {
    use miden_core::Operation::*;

    if value == ZERO {
        vec![Pad]
    } else if value == ONE {
        vec![Pad, Incr]
    } else {
        vec![Push(value)]
    }
}
