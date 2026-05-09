mod callgraph;
mod frontend;
mod ir;
mod lift;
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
