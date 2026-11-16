//! Authored Miden VM AIRs, trace schemas, public inputs, and relation boundaries.
//!
//! The VM is a four-AIR statement:
//!
//! - [`CoreAir`] contains the [decoder], operand [stack], and system constraints.
//! - [`ChipletsAir`] contains the stacked hash controller, bitwise, memory, ACE, and kernel-ROM
//!   chiplets.
//! - [`EidosCompressionAir`] proves the 32-row Eidos compression computations requested by the hash
//!   controller.
//! - [`And8LookupAir`] is a fixed byte-pair table for byte AND, Eidos compression rotation
//!   contributions, and [16-bit range checks].
//!
//! Typed LogUp relations tie these AIRs and their internal components together. The constraints are
//! described in the VM [design documentation].
//!
//! [decoder]: https://docs.miden.xyz/miden-vm/design/decoder
//! [stack]: https://docs.miden.xyz/miden-vm/design/stack
//! [16-bit range checks]: https://docs.miden.xyz/miden-vm/design/range
//! [design documentation]: https://docs.miden.xyz/miden-vm/design

mod airs;
mod constraints;
mod execution_trace;
mod inputs;
pub mod logup;
#[cfg(test)]
mod lookup_tests;
mod proof_order;
pub mod statement;
pub mod trace;

#[cfg(test)]
mod tests;

pub use airs::{
    And8LookupAir, ChipletsAir, CoreAir, EidosCompressionAir, LOGUP_AUX_TRACE_WIDTH, MidenAir,
    MidenAirBuilder,
};
pub use constraints::{
    and8_lookup,
    and8_lookup::columns::{And8LookupCols, And8LookupPreprocessedCols},
    chiplets::{
        columns::{
            AceCols, AceEvalCols, AceReadCols, AeadStreamCols, AeadStreamHighFirstCols,
            AeadStreamHighSecondCols, AeadStreamLowSecondCols, AeadStreamReadCols, BitwiseOpCols,
            ControllerCols, KernelRomCols, MemoryCols,
        },
        selectors::ChipletActiveFlags,
    },
    columns::{ChipletCols, CoreCols},
    decoder::columns::DecoderCols,
    eidos_compression,
    eidos_compression::{EidosCompressionCols, NUM_COLS as NUM_EIDOS_COMPRESSION_COLS},
    ext_field::QuadFeltExpr,
    stack::columns::StackCols,
    system::columns::SystemCols,
};
pub use execution_trace::{ChipletsLengths, TraceLenSummary, TraceLenSummaryError, VmTrace};
pub use inputs::{NUM_PUBLIC_VALUES, PublicInputs};
pub use proof_order::{AIRS, MIDEN_AIR_COUNT};
pub use statement::hash_kernel_digests;
