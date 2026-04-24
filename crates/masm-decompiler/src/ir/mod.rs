//! Intermediate representation for decompiled MASM.
//!
//! This module defines the core IR types used to represent decompiled code.
//! The IR is structured (no CFG), with explicit `If`, `While`, and `Repeat`
//! constructs.

use miden_assembly_syntax::{
    ast::{ImmFelt, ImmU8, ImmU32, Immediate},
    debuginfo::SourceSpan,
    parser::PushValue,
};

/// Index expression used for variable subscripts.
///
/// Subscripts track array-like access patterns in loops, allowing the
/// decompiler to represent values produced across iterations. For variables
/// outside loops, the subscript is a constant equal to the stack depth.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IndexExpr {
    /// Constant index value.
    Const(i64),
    /// Loop counter reference by nesting depth (0 = outermost loop).
    LoopVar(usize),
    /// Sum of two index expressions.
    Add(Box<IndexExpr>, Box<IndexExpr>),
    /// Product of two index expressions.
    Mul(Box<IndexExpr>, Box<IndexExpr>),
}

/// Unique SSA identifier for a single value definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ValueId(u64);

impl ValueId {
    /// Create a new value identifier from a raw integer.
    ///
    /// This is primarily intended for tests and deterministic fixtures.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw integer value of this identifier.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<u64> for ValueId {
    fn from(raw: u64) -> Self {
        Self(raw)
    }
}

/// Base identity for a variable reference.
///
/// `Value` represents a concrete SSA definition. `LoopInput` represents the
/// entry-stack snapshot for a repeat loop, indexed by the loop counter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VarBase {
    /// A concrete SSA value definition.
    Value(ValueId),
    /// Entry stack snapshot for a repeat loop identified by `loop_depth`.
    LoopInput {
        /// The nesting depth of the repeat loop.
        loop_depth: usize,
    },
}

impl VarBase {
    /// Return the loop depth for loop-input bases, if any.
    pub const fn loop_depth(&self) -> Option<usize> {
        match self {
            VarBase::LoopInput { loop_depth } => Some(*loop_depth),
            VarBase::Value(_) => None,
        }
    }

    /// Return the value identifier for value bases, if any.
    pub const fn value_id(&self) -> Option<ValueId> {
        match self {
            VarBase::Value(id) => Some(*id),
            VarBase::LoopInput { .. } => None,
        }
    }
}

/// Variable representing a stack value.
///
/// Variables carry a base identity (`VarBase`), a birth depth, and a subscript
/// expression for loop indexing. For variables outside loops, the subscript is
/// a constant equal to the stack depth. For variables inside non-neutral loops,
/// the subscript is an expression involving loop counters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Var {
    /// Base identity for this variable.
    pub base: VarBase,
    /// Stack depth when this variable was created (birth depth).
    pub stack_depth: usize,
    /// Subscript expression for variable indexing.
    pub subscript: IndexExpr,
}

impl Var {
    /// Create a new variable with a constant subscript equal to the stack depth.
    pub fn new(value_id: ValueId, stack_depth: usize) -> Self {
        Self {
            base: VarBase::Value(value_id),
            stack_depth,
            subscript: IndexExpr::Const(stack_depth as i64),
        }
    }

    /// Create a new loop-input variable for a repeat loop entry snapshot.
    pub fn loop_input(loop_depth: usize, stack_depth: usize, subscript: IndexExpr) -> Self {
        Self {
            base: VarBase::LoopInput { loop_depth },
            stack_depth,
            subscript,
        }
    }

    /// Return a copy of this variable with a new subscript.
    pub fn with_subscript(&self, subscript: IndexExpr) -> Self {
        Self {
            base: self.base.clone(),
            stack_depth: self.stack_depth,
            subscript,
        }
    }

    /// Return a copy of this variable with a new base identity.
    pub fn with_base(&self, base: VarBase) -> Self {
        Self {
            base,
            stack_depth: self.stack_depth,
            subscript: self.subscript.clone(),
        }
    }
}

/// Loop variable representing the iteration counter of a repeat loop.
///
/// Loop variables are distinct from stack variables ([`Var`]). They represent
/// iteration counters and only appear in loop headers and subscript expressions
/// ([`IndexExpr::LoopVar`]), never as operands in regular expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoopVar {
    /// Nesting depth of this loop (0 for outermost, 1 for next level, etc.).
    pub loop_depth: usize,
}

impl LoopVar {
    /// Create a new loop variable at the given nesting depth.
    pub const fn new(loop_depth: usize) -> Self {
        Self { loop_depth }
    }
}

/// Expression tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// Boolean true literal.
    True,
    /// Boolean false literal.
    False,
    /// Variable reference.
    Var(Var),
    /// Constant literal.
    Constant(Constant),
    /// Binary operator application.
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// Unary operator application.
    Unary(UnOp, Box<Expr>),
    /// Ternary conditional expression.
    Ternary {
        /// Condition expression.
        cond: Box<Expr>,
        /// Expression when condition is true.
        then_expr: Box<Expr>,
        /// Expression when condition is false.
        else_expr: Box<Expr>,
    },
    /// Word equality comparison `(lhs0..lhs3) == (rhs0..rhs3)`.
    EqW {
        /// Left-hand side word values.
        lhs: Box<[Var; 4]>,
        /// Right-hand side word values.
        rhs: Box<[Var; 4]>,
    },
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Eq,
    Neq,
    Lt,
    Lte,
    Gt,
    Gte,
    U32And,
    U32Or,
    U32Xor,
    U32Shl,
    U32Shr,
    U32Rotr,
    U32Lt,
    U32Lte,
    U32Gt,
    U32Gte,
    U32WrappingAdd,
    U32WrappingSub,
    U32WrappingMul,
    /// Exponentiation where the exponent is interpreted as a u32 value.
    U32Exp,
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    /// Logical not.
    Not,
    /// Arithmetic negation.
    Neg,
    /// Multiplicative inverse in the base field (`x^-1 mod p`).
    Inv,
    /// Cast to a 32-bit unsigned value (`x mod 2^32`).
    U32Cast,
    /// Test whether the value is representable as a 32-bit unsigned integer.
    U32Test,
    /// Bitwise NOT on a 32-bit unsigned value.
    U32Not,
    /// Count leading zeros in a 32-bit word.
    U32Clz,
    /// Count trailing zeros in a 32-bit word.
    U32Ctz,
    /// Count leading ones in a 32-bit word.
    U32Clo,
    /// Count trailing ones in a 32-bit word.
    U32Cto,
    /// Compute 2^x (fails if x > 63 in MASM semantics).
    Pow2,
}

/// Constant literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constant {
    /// Field element literal.
    Felt(u64),
    /// Word literal (4 felts).
    Word([u64; 4]),
    /// Named constant identifier.
    Defined(String),
}

impl Constant {
    /// Check if this constant is a felt literal.
    pub fn as_felt(&self) -> Option<u64> {
        match self {
            Constant::Felt(v) => Some(*v),
            _ => None,
        }
    }

    /// Check if this constant is a word literal.
    pub fn as_word(&self) -> Option<&[u64; 4]> {
        match self {
            Constant::Word(w) => Some(w),
            _ => None,
        }
    }

    /// Check if this constant is zero.
    pub fn is_zero(&self) -> bool {
        match self {
            Constant::Felt(v) => *v == 0,
            Constant::Word(w) => w.iter().all(|&x| x == 0),
            Constant::Defined(_) => false,
        }
    }

    /// Check if this constant is one.
    pub fn is_one(&self) -> bool {
        match self {
            Constant::Felt(v) => *v == 1,
            Constant::Word(w) => w[0] == 1 && w[1] == 0 && w[2] == 0 && w[3] == 0,
            Constant::Defined(_) => false,
        }
    }
}

impl From<ImmFelt> for Constant {
    fn from(imm: ImmFelt) -> Self {
        match imm {
            Immediate::Value(span) => Constant::Felt(span.inner().as_canonical_u64()),
            Immediate::Constant(id) => Constant::Defined(id.to_string()),
        }
    }
}

impl From<PushValue> for Constant {
    fn from(val: PushValue) -> Self {
        match val {
            PushValue::Int(int) => match int {
                miden_assembly_syntax::parser::IntValue::U8(v) => Constant::Felt(v as u64),
                miden_assembly_syntax::parser::IntValue::U16(v) => Constant::Felt(v as u64),
                miden_assembly_syntax::parser::IntValue::U32(v) => Constant::Felt(v as u64),
                miden_assembly_syntax::parser::IntValue::Felt(f) => {
                    Constant::Felt(f.as_canonical_u64())
                },
            },
            PushValue::Word(w) => Constant::Word([
                w.0[0].as_canonical_u64(),
                w.0[1].as_canonical_u64(),
                w.0[2].as_canonical_u64(),
                w.0[3].as_canonical_u64(),
            ]),
        }
    }
}

impl From<Constant> for Expr {
    fn from(constant: Constant) -> Self {
        Expr::Constant(constant)
    }
}

impl From<PushValue> for Expr {
    fn from(value: PushValue) -> Self {
        Expr::Constant(Constant::from(value))
    }
}

impl From<&PushValue> for Expr {
    fn from(value: &PushValue) -> Self {
        Expr::from(*value)
    }
}

impl From<&Immediate<PushValue>> for Expr {
    fn from(imm: &Immediate<PushValue>) -> Self {
        match imm {
            Immediate::Value(span) => Expr::from(span.inner()),
            Immediate::Constant(id) => Expr::Constant(Constant::Defined(id.to_string())),
        }
    }
}

impl From<&ImmFelt> for Expr {
    fn from(imm: &ImmFelt) -> Self {
        match imm {
            Immediate::Value(span) => {
                Expr::Constant(Constant::Felt(span.inner().as_canonical_u64()))
            },
            Immediate::Constant(id) => Expr::Constant(Constant::Defined(id.to_string())),
        }
    }
}

impl From<&ImmU32> for Expr {
    fn from(imm: &ImmU32) -> Self {
        match imm {
            Immediate::Value(span) => Expr::Constant(Constant::Felt(u64::from(*span.inner()))),
            Immediate::Constant(id) => Expr::Constant(Constant::Defined(id.to_string())),
        }
    }
}

impl From<&ImmU8> for Expr {
    fn from(imm: &ImmU8) -> Self {
        match imm {
            Immediate::Value(span) => Expr::Constant(Constant::Felt(u64::from(*span.inner()))),
            Immediate::Constant(id) => Expr::Constant(Constant::Defined(id.to_string())),
        }
    }
}

/// Memory load operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemLoad {
    /// Memory access shape and byte order.
    pub kind: MemAccessKind,
    /// Address operands for the load.
    pub address: Vec<Var>,
    /// Output variables produced by the load.
    pub outputs: Vec<Var>,
}

/// Memory store operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemStore {
    /// Memory access shape and byte order.
    pub kind: MemAccessKind,
    /// Address operands for the store.
    pub address: Vec<Var>,
    /// Values written by the store.
    pub values: Vec<Var>,
}

/// Advice stack load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvLoad {
    /// Output variables produced by the load.
    pub outputs: Vec<Var>,
}

/// Advice stack store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvStore {
    /// Values consumed by the store.
    pub values: Vec<Var>,
}

/// Local variable load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLoad {
    /// Local load shape and byte order.
    pub kind: LocalAccessKind,
    /// Local variable index.
    pub index: u16,
    /// Output variables produced by the load.
    pub outputs: Vec<Var>,
}

/// Memory access shape and byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemAccessKind {
    /// Scalar element access (`mem_load` / `mem_store`).
    Element,
    /// Word access in big-endian order (`mem_loadw_be` / `mem_storew_be`).
    WordBe,
    /// Word access in little-endian order (`mem_loadw_le` / `mem_storew_le`).
    WordLe,
}

/// Local-memory access shape and byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAccessKind {
    /// Scalar element access (`loc_load.i`).
    Element,
    /// Word access in big-endian order (`loc_loadw_be.i`).
    WordBe,
    /// Word access in little-endian order (`loc_loadw_le.i`).
    WordLe,
}

/// Local variable store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalStore {
    /// Local variable index.
    pub index: u16,
    /// Values written to the local.
    pub values: Vec<Var>,
}

/// Local word store operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalStoreW {
    /// Local access shape and byte order.
    pub kind: LocalAccessKind,
    /// Local variable index.
    pub index: u16,
    /// Word values written to the local (top of stack first).
    pub values: Vec<Var>,
}

/// Procedure call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// Resolved target name.
    ///
    /// During lifting this is fully-qualified. The final decompilation output may
    /// shorten it to an equivalent module-relative form for readability.
    pub target: String,
    /// Input arguments popped from the stack.
    pub args: Vec<Var>,
    /// Output results pushed onto the stack.
    pub results: Vec<Var>,
}

/// Named intrinsic operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intrinsic {
    /// Intrinsic name.
    pub name: String,
    /// Input arguments popped from the stack.
    pub args: Vec<Var>,
    /// Output results pushed onto the stack.
    pub results: Vec<Var>,
}

/// Phi node for an if/else merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfPhi {
    /// Merged destination value.
    pub dest: Var,
    /// Value produced by the then-branch.
    pub then_var: Var,
    /// Value produced by the else-branch.
    pub else_var: Var,
}

/// Phi node for loop-carried values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopPhi {
    /// Loop-carried destination value.
    pub dest: Var,
    /// Initial value before the loop.
    pub init: Var,
    /// Value produced at the end of one iteration.
    pub step: Var,
}

/// Statement in the IR.
///
/// All control flow is structured: `If`, `While`, and `Repeat` contain
/// their bodies directly rather than using branch markers or CFG edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stmt {
    /// Assignment to a variable.
    Assign {
        /// Source span of the originating instruction.
        span: SourceSpan,
        /// Destination variable.
        dest: Var,
        /// Assigned expression.
        expr: Expr,
    },
    /// Memory load operation.
    MemLoad {
        /// Source span of the originating instruction.
        span: SourceSpan,
        /// Memory load description.
        load: MemLoad,
    },
    /// Memory store operation.
    MemStore {
        /// Source span of the originating instruction.
        span: SourceSpan,
        /// Memory store description.
        store: MemStore,
    },
    /// Advice stack load.
    AdvLoad {
        /// Source span of the originating instruction.
        span: SourceSpan,
        /// Advice stack load description.
        load: AdvLoad,
    },
    /// Advice stack store.
    AdvStore {
        /// Source span of the originating instruction.
        span: SourceSpan,
        /// Advice stack store description.
        store: AdvStore,
    },
    /// Local variable load.
    LocalLoad {
        /// Source span of the originating instruction.
        span: SourceSpan,
        /// Local variable load description.
        load: LocalLoad,
    },
    /// Local variable store.
    LocalStore {
        /// Source span of the originating instruction.
        span: SourceSpan,
        /// Local variable store description.
        store: LocalStore,
    },
    /// Local word store.
    LocalStoreW {
        /// Source span of the originating instruction.
        span: SourceSpan,
        /// Local word store description.
        store: LocalStoreW,
    },
    /// Call to a known procedure.
    Call {
        /// Source span of the originating instruction.
        span: SourceSpan,
        /// Call description.
        call: Call,
    },
    /// Exec call to a known procedure.
    Exec {
        /// Source span of the originating instruction.
        span: SourceSpan,
        /// Call description.
        call: Call,
    },
    /// Syscall to a known procedure.
    SysCall {
        /// Source span of the originating instruction.
        span: SourceSpan,
        /// Call description.
        call: Call,
    },
    /// Dynamic call with unknown target.
    DynCall {
        /// Source span of the originating instruction.
        span: SourceSpan,
        /// Input arguments popped from the stack.
        args: Vec<Var>,
        /// Output results pushed onto the stack.
        results: Vec<Var>,
    },
    /// Named intrinsic operation.
    Intrinsic {
        /// Source span of the originating instruction.
        span: SourceSpan,
        /// Intrinsic description.
        intrinsic: Intrinsic,
    },
    /// Repeat loop with a known iteration count.
    Repeat {
        /// Source span of the originating repeat operation.
        span: SourceSpan,
        /// Loop counter variable.
        loop_var: LoopVar,
        /// Number of iterations.
        loop_count: usize,
        /// Loop body statements.
        body: Vec<Stmt>,
        /// Loop phi nodes (reserved for future use in repeat loops).
        phis: Vec<LoopPhi>,
    },
    /// If/else conditional.
    If {
        /// Source span of the originating if operation.
        span: SourceSpan,
        /// Condition expression.
        cond: Expr,
        /// Then branch statements.
        then_body: Vec<Stmt>,
        /// Else branch statements.
        else_body: Vec<Stmt>,
        /// Phi nodes merging stack values after the branches.
        phis: Vec<IfPhi>,
    },
    /// While loop.
    While {
        /// Source span of the originating while operation.
        span: SourceSpan,
        /// Condition expression.
        cond: Expr,
        /// Loop body statements.
        body: Vec<Stmt>,
        /// Phi nodes for loop-carried values.
        phis: Vec<LoopPhi>,
    },
    /// Return statement.
    Return {
        /// Source span of the originating instruction.
        span: SourceSpan,
        /// Return values.
        values: Vec<Var>,
    },
}
