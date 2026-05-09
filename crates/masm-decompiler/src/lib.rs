mod callgraph;
mod frontend;
mod ir;
mod lift;
mod semantics;
mod signature;
mod symbol;
mod types;

pub use callgraph::{CallGraph, ProcNode};
pub use frontend::{LibraryRoot, Program, Workspace};
pub use ir::{
    AdvLoad, AdvStore, BinOp, Call, Constant, Expr, IfPhi, IndexExpr, Intrinsic, LocalAccessKind,
    LocalLoad, LocalStore, LocalStoreW, LoopPhi, LoopVar, MemAccessKind, MemLoad, MemStore, Stmt,
    UnOp, ValueId, Var, VarBase,
};
pub use lift::{LiftingError, LiftingResult, lift_proc};
#[doc(hidden)]
pub use semantics::{
    INTRINSIC_ADV_PIPE, INTRINSIC_ADV_PUSH, INTRINSIC_ADV_PUSHW, INTRINSIC_MEM_STREAM,
    INTRINSIC_MTREE_GET, INTRINSIC_MTREE_MERGE, INTRINSIC_MTREE_SET, INTRINSIC_MTREE_VERIFY,
    intrinsic_asserts_u32_args, intrinsic_base_name, intrinsic_memory_address_arg_index,
    intrinsic_merkle_root_arg_range, intrinsic_nonzero_arg_index,
    intrinsic_positional_u32_arg_range, intrinsic_requires_u32_precondition,
};
pub use signature::{
    ProcSignature, SignatureMap, infer_signatures, refine_public_signature_inputs,
};
pub use symbol::{
    path::SymbolPath,
    resolution::{ResolutionError, ResolutionResult, SymbolResolver, create_resolver},
};
#[doc(hidden)]
pub use types::infer_type_summaries_from_lifted;
pub use types::{
    InferredType, TypeRequirement, TypeSummary, TypeSummaryMap, VarKey, infer_type_summaries,
};
