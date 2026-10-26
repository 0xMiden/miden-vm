#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod ace;
mod airs;
mod constraints;
pub mod geometry;
mod inputs;
pub mod logup;
pub mod lookup;
pub mod precompiles;
mod proof_order;
pub mod shared;
mod statement;
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
    chiplets::columns::{
        AceCols, AceEvalCols, AceReadCols, AeadStreamCols, AeadStreamHighFirstCols,
        AeadStreamHighSecondCols, AeadStreamLowSecondCols, AeadStreamReadCols, BitwiseCols,
        ControllerCols, KernelRomCols, MemoryCols,
    },
    columns::{ChipletCols, CoreCols},
    decoder::columns::DecoderCols,
    ext_field::QuadFeltExpr,
    stack::columns::StackCols,
    system::columns::SystemCols,
};
pub use inputs::{NUM_PUBLIC_VALUES, PublicInputs};
pub use miden_core::{
    Felt,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
    utils::ToElements,
};
pub use miden_lifted_stark::{
    StarkConfig,
    air::{
        AirBuilder, BaseAir, ConstraintCounts, ConstraintDegrees, ExtensionBuilder, LiftedAir,
        LiftedAirBuilder, MultiAir, PermutationAirBuilder, ProverStatement, Statement,
    },
    debug,
    pcs::PcsParams,
};
pub use proof_order::{AIRS, MIDEN_AIR_COUNT};
pub use shared::{
    config, eidos_compression,
    eidos_compression::{EidosCompressionCols, NUM_COLS as NUM_EIDOS_COMPRESSION_COLS},
};
pub use statement::{MidenMultiAir, hash_kernel_digests};
