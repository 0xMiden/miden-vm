use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use core::ops::RangeInclusive;

use proptest::{arbitrary::Arbitrary, prelude::*};

use super::*;
use crate::{
    Felt, Word,
    advice::AdviceMap,
    mast::{
        CallNodeBuilder, DenseMastForestBuilder, DynNodeBuilder, ExternalNodeBuilder,
        JoinNodeBuilder, LoopNodeBuilder, SplitNodeBuilder,
    },
    operations::{AssemblyOp, Operation},
    program::{KernelDescriptor, KernelError, Program},
};

// Strategy for operations without immediate values (non-control flow)
pub fn op_no_imm_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![
        Just(Operation::Add),
        Just(Operation::Mul),
        Just(Operation::Neg),
        Just(Operation::Inv),
        Just(Operation::Incr),
        Just(Operation::And),
        Just(Operation::Or),
        Just(Operation::Not),
        Just(Operation::Eq),
        Just(Operation::Eqz),
        Just(Operation::Drop),
        Just(Operation::Pad),
        Just(Operation::Swap),
        Just(Operation::SwapW),
        Just(Operation::SwapW2),
        Just(Operation::SwapW3),
        Just(Operation::SwapDW),
        Just(Operation::MovUp2),
        Just(Operation::MovUp3),
        Just(Operation::MovUp4),
        Just(Operation::MovUp5),
        Just(Operation::MovUp6),
        Just(Operation::MovUp7),
        Just(Operation::MovUp8),
        Just(Operation::MovDn2),
        Just(Operation::MovDn3),
        Just(Operation::MovDn4),
        Just(Operation::MovDn5),
        Just(Operation::MovDn6),
        Just(Operation::MovDn7),
        Just(Operation::MovDn8),
        Just(Operation::CSwap),
        Just(Operation::CSwapW),
        Just(Operation::Dup0),
        Just(Operation::Dup1),
        Just(Operation::Dup2),
        Just(Operation::Dup3),
        Just(Operation::Dup4),
        Just(Operation::Dup5),
        Just(Operation::Dup6),
        Just(Operation::Dup7),
        Just(Operation::Dup9),
        Just(Operation::Dup11),
        Just(Operation::Dup13),
        Just(Operation::Dup15),
        Just(Operation::MLoad),
        Just(Operation::MStore),
        Just(Operation::MLoadW),
        Just(Operation::MStoreW),
        Just(Operation::MStream),
        Just(Operation::Pipe),
        Just(Operation::AdvPop),
        Just(Operation::AdvPopW),
        Just(Operation::U32split),
        Just(Operation::U32add),
        Just(Operation::U32sub),
        Just(Operation::U32mul),
        Just(Operation::U32div),
        Just(Operation::U32and),
        Just(Operation::U32xor),
        Just(Operation::U32add3),
        Just(Operation::U32madd),
        Just(Operation::SDepth),
        Just(Operation::Caller),
        Just(Operation::Clk),
        Just(Operation::Emit),
        Just(Operation::Ext2Mul),
        Just(Operation::Expacc),
        Just(Operation::HPerm),
        // Note: We exclude Assert here because it has an immediate value (error code)
    ]
}

// Strategy for operations with immediate values
pub fn op_with_imm_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![any::<u64>().prop_map(Felt::new_unchecked).prop_map(Operation::Push)]
}

// Strategy for all non-control flow operations
pub fn op_non_control_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![op_no_imm_strategy(), op_with_imm_strategy(),]
}

// Strategy for sequences of operations
pub fn op_non_control_sequence_strategy(
    max_length: usize,
) -> impl Strategy<Value = Vec<Operation>> {
    prop::collection::vec(op_non_control_strategy(), 1..=max_length)
}

/// Returns `true` if `op` cannot fail during execution regardless of the contents of the
/// operand stack, the advice provider, or memory.
///
/// This is the operation pool used for basic blocks in [`GenerationMode::Executable`].
/// Excluded categories and why:
///
/// - `Inv` (traps on zero), `And`/`Or`/`Not`/`CSwap`/`CSwapW` (require binary operands);
/// - all `U32*` operations (require operands in the `u32` range);
/// - memory operations (`MLoad`/`MStore`/`MLoadW`/`MStoreW`/`MStream`/`Pipe`; address validity and,
///   for `Pipe`, advice availability);
/// - advice operations (`AdvPop`/`AdvPopW`; fail when the advice stack is empty);
/// - `Caller` (only valid inside a syscall context), `Emit` (host/event dependent), `Assert` and
///   the crypto/STARK helpers (`HPerm`, `MpVerify`, `FriE2F4`, ...), whose processor
///   implementations have error paths.
pub fn is_infallible_op(op: &Operation) -> bool {
    matches!(
        op,
        Operation::Noop
            | Operation::Add
            | Operation::Mul
            | Operation::Neg
            | Operation::Incr
            | Operation::Eq
            | Operation::Eqz
            | Operation::Ext2Mul
            | Operation::Expacc
            | Operation::Drop
            | Operation::Pad
            | Operation::Swap
            | Operation::SwapW
            | Operation::SwapW2
            | Operation::SwapW3
            | Operation::SwapDW
            | Operation::MovUp2
            | Operation::MovUp3
            | Operation::MovUp4
            | Operation::MovUp5
            | Operation::MovUp6
            | Operation::MovUp7
            | Operation::MovUp8
            | Operation::MovDn2
            | Operation::MovDn3
            | Operation::MovDn4
            | Operation::MovDn5
            | Operation::MovDn6
            | Operation::MovDn7
            | Operation::MovDn8
            | Operation::Dup0
            | Operation::Dup1
            | Operation::Dup2
            | Operation::Dup3
            | Operation::Dup4
            | Operation::Dup5
            | Operation::Dup6
            | Operation::Dup7
            | Operation::Dup9
            | Operation::Dup11
            | Operation::Dup13
            | Operation::Dup15
            | Operation::SDepth
            | Operation::Clk
            | Operation::Push(_)
    )
}

/// Strategy for operations that satisfy [`is_infallible_op`].
///
/// Used for basic blocks in [`GenerationMode::Executable`] so that generated blocks never
/// trap at runtime, whatever the operand stack contains.
pub fn op_infallible_strategy() -> impl Strategy<Value = Operation> {
    op_non_control_strategy().prop_filter("infallible operations only", is_infallible_op)
}

/// Strategy for sequences of infallible operations.
pub fn op_infallible_sequence_strategy(max_length: usize) -> impl Strategy<Value = Vec<Operation>> {
    prop::collection::vec(op_infallible_strategy(), 1..=max_length)
}

// ---------- Parameters ----------

/// Parameters for generating BasicBlockNode instances
#[derive(Clone, Debug)]
pub struct BasicBlockNodeParams {
    /// Maximum number of operations in a generated basic block
    pub max_ops_len: usize,
    /// When `true`, only operations satisfying [`is_infallible_op`] are sampled, so the
    /// generated block cannot trap at runtime. Set by the forest generator in
    /// [`GenerationMode::Executable`].
    pub infallible_ops_only: bool,
}

impl Default for BasicBlockNodeParams {
    fn default() -> Self {
        Self {
            max_ops_len: 8,
            infallible_ops_only: false,
        }
    }
}

// ---------- Arbitrary for BasicBlockNode ----------

impl Arbitrary for BasicBlockNode {
    type Parameters = BasicBlockNodeParams;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(p: Self::Parameters) -> Self::Strategy {
        let ops_strategy: BoxedStrategy<Vec<Operation>> = if p.infallible_ops_only {
            op_infallible_sequence_strategy(p.max_ops_len).boxed()
        } else {
            op_non_control_sequence_strategy(p.max_ops_len).boxed()
        };
        // ensure at least 1 op to satisfy BasicBlockNode::new
        ops_strategy
            .prop_filter_map("non-empty ops", |ops| if ops.is_empty() { None } else { Some(ops) })
            .prop_map(|ops| BasicBlockNode::new(ops).expect("non-empty ops"))
            .boxed()
    }
}

// ---------- Optional: MastForest strategy (behind feature gate) ----------

/// Controls the generation mode for `MastForest` samples.
///
/// `Executable` enforces the structural closure invariants required for the Miden VM to
/// resolve every callee at run time (no dyn nodes, externals resolve to a local procedure
/// root, external graph is acyclic, every syscall callee is in the paired kernel) and
/// restricts basic blocks to operations that cannot fault at runtime.
///
/// `StructureOnly` exercises the full structural surface (dyn nodes, unresolved externals,
/// syscalls whose callee is not in any kernel, fallible operations) without enforcing the
/// closure invariants. It is the right mode for serialization, merging, pretty-printing,
/// and other non-execution code paths that benefit from broad structural coverage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GenerationMode {
    /// Forests that satisfy the structural closure invariants below.
    #[default]
    Executable,
    /// Forests that exercise the full structural surface without enforcing closure
    /// invariants.
    StructureOnly,
}

/// Parameters for generating `MastForest` instances via proptest.
///
/// # Defaults
///
/// `MastForestParams::default()` selects [`GenerationMode::Executable`] and sets every
/// `max_*` to a small non-zero number, so default samples exercise syscalls and externals
/// under the closure invariants. The one exception is `max_dyns`, which defaults to `0`:
/// dyn nodes cannot be guaranteed executable at the MAST level (see *Future work* below)
/// and must be opted into explicitly via `StructureOnly` mode.
///
/// # Invariants in `Executable` mode
///
/// When `mode` is [`GenerationMode::Executable`], the generator enforces the
/// following invariants on every emitted sample:
///
/// 1. **No dyn nodes.** No `DynNode` instances are emitted, regardless of `max_dyns`. The
///    MAST-level generator cannot synthesise valid operand-stack preconditions for dyn targets (see
///    *Future work* below).
/// 2. **External resolution.** Every external node's digest equals the MAST root of a procedure
///    root already present in the same forest, so the VM can resolve the call locally without
///    additional forest registration.
/// 3. **External acyclicity.** The directed graph induced by `external -> resolved root` is a DAG.
///    Because externals are emitted in topological order and reference only roots that already
///    exist at emission time, this is automatic; the property test `externals_form_a_dag` verifies
///    the invariant on every sample.
/// 4. **Kernel closure.** Every syscall's callee is a procedure root whose MAST root is a member of
///    the paired kernel's procedure hashes; the generator never falls back to a plain `Call` when a
///    kernel-eligible callee is unavailable.
/// 5. **Infallible basic blocks.** Basic blocks contain only operations satisfying
///    [`is_infallible_op`], i.e. operations that cannot fault whatever the operand stack, advice
///    provider, or memory contain. Fallible operations (`Inv`, `U32*`, memory and advice access,
///    binary-operand ops, ...) are excluded so a generated block never traps.
///
/// Additionally, generated forests (in both modes) are **pruned**: every node is reachable
/// from at least one procedure root, so any node can be exercised by walking the roots.
///
/// # Remaining executability gap
///
/// Invariants 1-5 guarantee that the MAST resolver accepts the forest and that no basic
/// block can fault. Control-flow condition values are not yet synthesised: a `Split` or
/// `Loop` node still pops its condition from whatever the stack happens to hold, so
/// run-to-completion on arbitrary entrypoints additionally requires generating suitable
/// stack inputs. That is planned as a follow-up (together with reintroducing fallible
/// operations behind generated stack preconditions).
///
/// # `StructureOnly` mode
///
/// Setting `mode = GenerationMode::StructureOnly` keeps the permissive behaviour:
/// syscalls may reference arbitrary callees, external digests are drawn at random and do
/// not have to resolve inside the forest, basic blocks draw from the full operation pool,
/// and a mix of `DynNode::new_dyn` and `DynNode::new_dyncall` instances may be emitted. Use
/// this mode for tests that exercise serialization, merging, or other non-execution code
/// paths where broad structural coverage is valuable and executability is not required.
///
/// # Future work — MASM-level dyn generation
///
/// Dyn nodes are intentionally unsupported in `Executable` mode because the generator
/// cannot synthesise valid operand-stack preconditions: each dyn/dyncall reads its callee
/// digest off the operand stack at runtime, and producing a semantically valid stack state
/// requires program-synthesis-level reasoning. The intended extension is an assembly-level
/// (MASM) generator that can emit instruction sequences which push a valid callee digest
/// before each dyn/dyncall; until such a generator exists, callers who need executable dyn
/// coverage should rely on hand-written fixtures or opt into `StructureOnly` mode.
#[derive(Clone, Debug)]
pub struct MastForestParams {
    /// Range of number of blocks to generate
    pub blocks: RangeInclusive<usize>,
    /// Maximum number of join nodes to generate
    pub max_joins: usize,
    /// Maximum number of split nodes to generate
    pub max_splits: usize,
    /// Maximum number of loop nodes to generate
    pub max_loops: usize,
    /// Maximum number of call nodes to generate
    pub max_calls: usize,
    /// Maximum number of syscall nodes to generate.
    ///
    /// Defaults to `1`. In [`GenerationMode::Executable`], each emitted syscall
    /// targets a procedure root whose digest is a member of the paired kernel
    /// (kernel-closure invariant). In [`GenerationMode::StructureOnly`], syscalls
    /// point at arbitrary nodes and the paired kernel is empty, so such forests will not
    /// execute.
    pub max_syscalls: usize,
    /// Maximum number of external nodes to generate.
    ///
    /// Defaults to `1`. In [`GenerationMode::Executable`], each emitted external's
    /// digest equals the MAST root of a procedure root already present in the same forest
    /// (external-resolution invariant) and the resulting external call graph is acyclic
    /// (external-acyclicity invariant). In [`GenerationMode::StructureOnly`],
    /// externals use random digests and forests containing them will not execute.
    pub max_externals: usize,
    /// Maximum number of dyn/dyncall nodes to generate.
    ///
    /// Defaults to `0`. In [`GenerationMode::Executable`] this field is treated as
    /// `0` and no dyn nodes are emitted (see the *Future work* note on the struct doc). In
    /// [`GenerationMode::StructureOnly`], a mix of `DynNode::new_dyn` and
    /// `DynNode::new_dyncall` instances may be emitted up to this bound; such forests are
    /// intended for structural tests and are not guaranteed to execute.
    pub max_dyns: usize,
    /// Controls whether the generator emits forests with the closure invariants enforced
    /// ([`GenerationMode::Executable`]) or structure-only forests
    /// ([`GenerationMode::StructureOnly`]).
    pub mode: GenerationMode,
    /// Optional user-supplied kernel procedure hashes.
    ///
    /// When `Some(hs)`, the strategy validates `hs` once at construction time and panics if
    /// it contains duplicates or more than [`KernelDescriptor::MAX_NUM_PROCEDURES`] entries. The
    /// generator then freezes the kernel to exactly `hs` and only emits syscalls whose
    /// callee digest is in this set; it will not emit a syscall when no procedure root in
    /// the forest matches a kernel hash. When `None`, the generator derives the kernel from
    /// procedure roots selected during generation.
    pub kernel_procedures: Option<Vec<Word>>,
}

impl Default for MastForestParams {
    fn default() -> Self {
        // Syscalls and externals are safe to emit by default: in Executable mode they are
        // generated under the closure invariants. Only dyn nodes stay opt-in (they cannot
        // be guaranteed executable at the MAST level), so `max_dyns` defaults to 0.
        Self {
            blocks: 1..=3,
            max_joins: 1,
            max_splits: 1,
            max_loops: 1,
            max_calls: 1,
            max_syscalls: 1,
            max_externals: 1,
            max_dyns: 0,
            mode: GenerationMode::Executable,
            kernel_procedures: None,
        }
    }
}

// ---------- Internal helpers for executable pipeline ----------

/// Counts of each node type to be generated in a single sample.
///
/// Used internally by [`ForestSeeds`] to drive the executable pipeline. All counts are upper
/// bounds; the generator may emit fewer nodes of a given type when the [`RootPool`] or
/// [`KernelPool`] is empty at emission time.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NodeCounts {
    pub num_joins: usize,
    pub num_splits: usize,
    pub num_loops: usize,
    pub num_calls: usize,
    pub num_syscalls: usize,
    pub num_externals: usize,
    pub num_dyns: usize,
}

/// Selects how an external node's digest is chosen during generation.
///
/// In `Executable` mode, external nodes must resolve to procedure roots already present in
/// the same forest, so the generator uses [`ExternalPick::FromRoot`] to pick from the
/// current [`RootPool`]. In `StructureOnly` mode, externals use randomly generated digests
/// via [`ExternalPick::Random`] that will not resolve and are intended for structural tests
/// only.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ExternalPick {
    /// Executable mode: index into the current [`RootPool`] at the moment the external is
    /// emitted. The generator will modulo this index by the pool's length to select a valid
    /// target.
    FromRoot(usize),
    /// StructureOnly mode: digest bytes sampled directly from proptest. The resulting
    /// external will not resolve to any procedure in the forest and is not executable.
    Random([u64; 4]),
}

/// Collection of primitive samples drawn from proptest for a single `MastForest` generation.
///
/// This struct is computed once per sample and consumed by either [`build_executable_forest`]
/// or [`build_structure_only_forest`] depending on the selected
/// [`GenerationMode`]. The field layout is frozen per the strategy composition
/// order to ensure deterministic shrinking: basic blocks are sampled first,
/// then counts, then pair/index vectors sized by those counts, and finally the selection
/// bits for roots and kernel inclusion.
///
/// # Field layout invariants
///
/// - `join_pairs.len() == counts.num_joins`
/// - `split_pairs.len() == counts.num_splits`
/// - `loop_indices.len() == counts.num_loops`
/// - `call_indices.len() == counts.num_calls`
/// - `syscall_picks.len() == counts.num_syscalls`
/// - `external_picks.len() == counts.num_externals`
/// - `dyn_selectors.len() == counts.num_dyns`
/// - `root_selection.len() >= basic_blocks.len() + counts.num_joins + counts.num_splits
///   + counts.num_loops + counts.num_calls`
/// - `kernel_inclusion.len()` is sized to cover all procedure roots that may be committed during
///   generation
#[derive(Clone, Debug)]
pub(crate) struct ForestSeeds {
    /// Basic block nodes to be added in Phase 1.
    pub basic_blocks: Vec<BasicBlockNode>,
    /// Counts of each control-flow node type to be generated.
    pub counts: NodeCounts,
    /// Child index pairs for join nodes (Phase 2).
    pub join_pairs: Vec<(usize, usize)>,
    /// Child index pairs for split nodes (Phase 2).
    pub split_pairs: Vec<(usize, usize)>,
    /// Child indices for loop nodes (Phase 2).
    pub loop_indices: Vec<usize>,
    /// Child indices for call nodes (Phase 2).
    pub call_indices: Vec<usize>,
    /// Each entry is a child index into the set of nodes already added at the moment the
    /// syscall is emitted. Used only in Executable mode via [`KernelPool`].
    pub syscall_picks: Vec<usize>,
    /// Each entry is a pick into the current [`RootPool`] (Executable mode) or a random
    /// digest (StructureOnly mode).
    pub external_picks: Vec<ExternalPick>,
    /// Bit for each dyn node selecting `new_dyn` (false) or `new_dyncall` (true).
    pub dyn_selectors: Vec<bool>,
    /// Used only when `kernel_procedures` is `None` in Executable mode. Each bit says
    /// whether the i-th committed procedure root is included in the minted kernel.
    pub kernel_inclusion: Vec<bool>,
    /// Bits controlling root seeding (which non-block nodes become roots before externals
    /// and syscalls are added).
    pub root_selection: Vec<bool>,
}

/// Ordered list of `MastNodeId`s that the generator has already committed as procedure
/// roots.
///
/// The pool exposes only insertion (`push`) and an iteration view (`iter`). Acyclicity of
/// the external call graph is automatic from insertion order: externals are appended only
/// after their target root has been committed, so the directed `external -> resolved root`
/// graph cannot contain a cycle. The dedicated `externals_form_a_dag` property test
/// verifies the invariant on every sample.
#[derive(Debug)]
pub(crate) struct RootPool {
    roots: Vec<MastNodeId>,
}

impl RootPool {
    /// Creates a new empty `RootPool`.
    pub fn new() -> Self {
        Self { roots: Vec::new() }
    }

    /// Adds a procedure root to the pool.
    pub fn push(&mut self, id: MastNodeId) {
        self.roots.push(id);
    }

    /// Returns `true` if the pool contains no roots.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Returns an iterator of all procedure roots in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = MastNodeId> + '_ {
        self.roots.iter().copied()
    }
}

/// Mutable view of the kernel pool during generation.
///
/// In Executable mode with `kernel_procedures = None`, this grows monotonically as syscalls
/// are added. With `kernel_procedures = Some(hs)`, it is initialised with `hs` and never
/// mutates (frozen).
///
/// The `frozen` flag controls whether new hashes can be inserted: when `true`, `insert` is a
/// no-op. This allows the generator to use a single code path for both user-supplied and
/// co-generated kernels.
#[derive(Debug)]
pub(crate) struct KernelPool {
    hashes: Vec<Word>,
    frozen: bool,
}

impl KernelPool {
    /// Creates a new empty `KernelPool` that accepts insertions.
    pub fn new() -> Self {
        Self { hashes: Vec::new(), frozen: false }
    }

    /// Creates a new `KernelPool` initialised with the given hashes and frozen so no further
    /// insertions are allowed.
    ///
    /// Used when the caller supplies `kernel_procedures = Some(hs)` to lock the kernel to
    /// exactly those hashes.
    pub fn new_frozen(hashes: Vec<Word>) -> Self {
        Self { hashes, frozen: true }
    }

    /// Inserts a hash into the pool if the pool is not frozen and the hash is not already
    /// present.
    ///
    /// When `frozen` is `true`, this is a no-op. This allows the generator to call `insert`
    /// unconditionally during syscall emission without branching on whether the kernel is
    /// user-supplied or co-generated. The dedup behaviour mirrors the [`KernelDescriptor`]
    /// invariant (`KernelDescriptor::from_hashes` rejects duplicates) so callers cannot
    /// accidentally produce a kernel that fails to construct.
    pub fn insert(&mut self, h: Word) {
        if !self.frozen && !self.hashes.contains(&h) {
            self.hashes.push(h);
        }
    }

    /// Returns `true` if the pool contains the given hash.
    pub fn contains(&self, h: Word) -> bool {
        self.hashes.contains(&h)
    }

    /// Returns a slice of all hashes in the pool.
    pub fn hashes(&self) -> &[Word] {
        &self.hashes
    }

    /// Returns `true` if the pool is frozen.
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }
}

// ---------- ForestSeeds sampling strategy ----------

/// Composes the proptest strategies that produce a [`ForestSeeds`] for a single
/// `MastForest` sample.
///
/// The composition order is fixed per the design to keep proptest shrinking effective:
///
/// 1. Basic blocks are sampled first (independent of everything else).
/// 2. Control-flow node counts (`num_joins`, `num_splits`, `num_loops`, `num_calls`,
///    `num_syscalls`, `num_externals`, `num_dyns`) are sampled next.
/// 3. Pair / index vectors (`join_pairs`, `split_pairs`, `loop_indices`, `call_indices`) are sized
///    by those counts.
/// 4. Finally, the selection vectors (`syscall_picks`, `external_picks`, `dyn_selectors`,
///    `root_selection`, `kernel_inclusion`) are sampled with lengths derived from the counts and
///    the total number of nodes that may be committed.
///
/// Later choices depend on earlier samples only through length invariants, so each
/// individual sample can be shrunk independently once the counts have been minimised.
///
/// The `external_picks` strategy branches on [`MastForestParams::mode`]: in
/// [`GenerationMode::Executable`] it yields [`ExternalPick::FromRoot`] indices
/// (into the generator's `RootPool` at emission time), while in
/// [`GenerationMode::StructureOnly`] it yields [`ExternalPick::Random`] digest
/// seeds.
pub(crate) fn forest_seeds_strategy(params: &MastForestParams) -> BoxedStrategy<ForestSeeds> {
    // In Executable mode, restrict blocks to infallible operations so generated blocks
    // never trap at runtime (invariant 5 on `MastForestParams`).
    let bb_params = BasicBlockNodeParams {
        infallible_ops_only: matches!(params.mode, GenerationMode::Executable),
        ..Default::default()
    };
    let max_joins = params.max_joins;
    let max_splits = params.max_splits;
    let max_loops = params.max_loops;
    let max_calls = params.max_calls;
    let max_syscalls = params.max_syscalls;
    let max_externals = params.max_externals;
    let max_dyns = params.max_dyns;
    let mode = params.mode;

    // Stage 1: basic blocks (independent of everything else). Respect the caller's full
    // `blocks` range, including its lower bound (e.g. `128..=128` for fixed-size samples).
    // The build phases need at least one block (fallback root, index arithmetic), so a
    // degenerate lower/upper bound of 0 is clamped to 1.
    let blocks_range = (*params.blocks.start()).max(1)..=(*params.blocks.end()).max(1);
    prop::collection::vec(any_with::<BasicBlockNode>(bb_params), blocks_range)
        // Stage 2: control-flow counts, each bounded by the corresponding `max_*`.
        .prop_flat_map(move |basic_blocks| {
            (
                Just(basic_blocks),
                (
                    0..=max_joins,
                    0..=max_splits,
                    0..=max_loops,
                    0..=max_calls,
                    0..=max_syscalls,
                    0..=max_externals,
                    0..=max_dyns,
                ),
            )
        })
        // Stage 3 + 4: pair/index vectors sized by counts, then selection vectors.
        .prop_flat_map(move |(basic_blocks, counts_tuple)| {
            let (
                num_joins,
                num_splits,
                num_loops,
                num_calls,
                num_syscalls,
                num_externals,
                num_dyns,
            ) = counts_tuple;

            // Upper bound on the number of nodes that can end up in the forest. Sizes the
            // `root_selection` and `kernel_inclusion` bit vectors so the build functions
            // always have a selection bit available per committed node / root.
            let max_nodes_total = basic_blocks.len()
                + num_joins
                + num_splits
                + num_loops
                + num_calls
                + num_syscalls
                + num_externals
                + num_dyns;

            // Branch on mode: Executable picks an index into the current RootPool;
            // StructureOnly samples a random digest seed.
            let external_picks_strategy: BoxedStrategy<Vec<ExternalPick>> = match mode {
                GenerationMode::Executable => {
                    prop::collection::vec(any::<usize>(), num_externals)
                        .prop_map(|picks| {
                            picks.into_iter().map(ExternalPick::FromRoot).collect()
                        })
                        .boxed()
                },
                GenerationMode::StructureOnly => {
                    prop::collection::vec(any::<[u64; 4]>(), num_externals)
                        .prop_map(|seeds| seeds.into_iter().map(ExternalPick::Random).collect())
                        .boxed()
                },
            };

            let counts = NodeCounts {
                num_joins,
                num_splits,
                num_loops,
                num_calls,
                num_syscalls,
                num_externals,
                num_dyns,
            };

            (
                Just(basic_blocks),
                Just(counts),
                // Pair / index vectors, sized exactly by the counts above.
                (
                    prop::collection::vec(any::<(usize, usize)>(), num_joins),
                    prop::collection::vec(any::<(usize, usize)>(), num_splits),
                    prop::collection::vec(any::<usize>(), num_loops),
                    prop::collection::vec(any::<usize>(), num_calls),
                ),
                // Selection vectors: picks/selectors consumed by the per-mode tails.
                (
                    prop::collection::vec(any::<usize>(), num_syscalls),
                    external_picks_strategy,
                    prop::collection::vec(any::<bool>(), num_dyns),
                    prop::collection::vec(any::<bool>(), max_nodes_total),
                    prop::collection::vec(any::<bool>(), max_nodes_total),
                ),
            )
        })
        .prop_map(
            |(
                basic_blocks,
                counts,
                (join_pairs, split_pairs, loop_indices, call_indices),
                (syscall_picks, external_picks, dyn_selectors, root_selection, kernel_inclusion),
            )| {
                ForestSeeds {
                    basic_blocks,
                    counts,
                    join_pairs,
                    split_pairs,
                    loop_indices,
                    call_indices,
                    syscall_picks,
                    external_picks,
                    dyn_selectors,
                    kernel_inclusion,
                    root_selection,
                }
            },
        )
        .boxed()
}

// ---------- (MastForest, KernelDescriptor) strategy ----------

/// Validates a caller-supplied `kernel_procedures` slice using the same rules as
/// [`KernelDescriptor::from_hashes`].
///
/// Returns `Ok(())` if the slice is `None` or accepted by `KernelDescriptor::from_hashes`;
/// otherwise returns the underlying [`KernelError`].
fn validate_kernel_procedures(kernel_procedures: &Option<Vec<Word>>) -> Result<(), KernelError> {
    match kernel_procedures.as_ref() {
        None => Ok(()),
        Some(hs) => KernelDescriptor::from_hashes(hs.clone()).map(|_| ()),
    }
}

/// Strategy yielding `(MastForest, KernelDescriptor)` pairs for proptest.
///
/// Dispatches to either `build_executable_forest` or `build_structure_only_forest`
/// depending on `params.mode`.
///
/// # Panics
///
/// Panics at construction time if `params.kernel_procedures` is `Some(hs)` and `hs` would be
/// rejected by [`KernelDescriptor::from_hashes`] (duplicates or more than
/// [`KernelDescriptor::MAX_NUM_PROCEDURES`] entries). The validity check is independent of the
/// proptest seed, so this is treated as a caller bug rather than a per-sample rejection —
/// validating once at construction time avoids burning the proptest reject budget on every sample.
///
/// See the module-level docs on [`MastForestParams`] for the full list of structural
/// closure invariants this strategy enforces in `Executable` mode.
pub fn forest_kernel_strategy(
    params: MastForestParams,
) -> BoxedStrategy<(MastForest, KernelDescriptor)> {
    if let Err(err) = validate_kernel_procedures(&params.kernel_procedures) {
        panic!("MastForestParams::kernel_procedures is invalid: {err}");
    }

    forest_seeds_strategy(&params)
        .prop_map(move |seeds| match params.mode {
            GenerationMode::Executable => build_executable_forest(seeds, &params),
            GenerationMode::StructureOnly => build_structure_only_forest(seeds, &params),
        })
        .boxed()
}

// ---------- Shared skeleton (Phases 1, 2, 2.5) ----------

/// Result of building the shared portion of a `MastForest` sample: basic
/// blocks, control-flow nodes (joins/splits/loops/calls), and an initial root selection.
///
/// The skeleton is identical for both [`GenerationMode::Executable`] and
/// [`GenerationMode::StructureOnly`]; the modes diverge only when adding
/// externals, syscalls, dyns, and finalising the kernel.
struct ForestSkeleton {
    forest: DenseMastForestBuilder,
    /// All node IDs in insertion (topological) order. Used by the structure-only tail to
    /// pick syscall callees from the full set of committed nodes.
    all_node_ids: Vec<MastNodeId>,
    /// Procedure roots seeded in Phase 2.5.
    root_pool: RootPool,
}

/// Builds the shared skeleton for a single sample.
///
/// Performs three phases identically for both generation modes:
///
/// 1. **Basic blocks.** Appends every block in `seeds.basic_blocks` and records its ID.
/// 2. **Control-flow nodes.** Appends joins, splits, loops, and calls using the index vectors in
///    `seeds`. Each count is clamped against the number of basic blocks so the generator emits a
///    contiguous prefix even when proptest samples a count that exceeds the available children.
/// 3. **Initial roots.** Marks a subset of the committed nodes as procedure roots according to
///    `seeds.root_selection`. If no node was selected and at least one basic block exists, the
///    first basic block becomes the fallback root so externals and syscalls have something to
///    target.
fn build_skeleton(seeds: &SkeletonInput<'_>) -> ForestSkeleton {
    let SkeletonInput {
        basic_blocks,
        counts,
        join_pairs,
        split_pairs,
        loop_indices,
        call_indices,
        root_selection,
    } = *seeds;

    // Build through `DenseMastForestBuilder` so that `finish()` emits the final dense node
    // order (externals sorted by digest, then blocks, then internal nodes) that the rest of
    // the crate, serialization included, requires.
    let mut forest = DenseMastForestBuilder::new();
    let empty_forest = MastForest::new();

    let num_basic_blocks = basic_blocks.len();
    let mut basic_block_ids: Vec<MastNodeId> = Vec::with_capacity(num_basic_blocks);
    for block in basic_blocks {
        let builder = block.clone().to_builder(&empty_forest);
        let node_id = forest.push_node(builder).expect("Failed to add block");
        basic_block_ids.push(node_id);
    }

    // Track all node IDs in insertion (topological) order so children referenced by
    // control-flow nodes are guaranteed to already exist in the forest.
    let mut all_node_ids: Vec<MastNodeId> = basic_block_ids.clone();

    // Joins and splits need at least two distinct children; loops and calls need one. Clamp
    // the per-sample counts against the available basic blocks so the strategy yields a
    // contiguous prefix when proptest oversamples.
    let max_parent_nodes = num_basic_blocks.saturating_sub(1);
    let num_joins = counts.num_joins.min(max_parent_nodes);
    let num_splits = counts.num_splits.min(max_parent_nodes);
    let num_loops = counts.num_loops.min(num_basic_blocks);
    let num_calls = counts.num_calls.min(num_basic_blocks);

    for &(left_raw, right_raw) in join_pairs.iter().take(num_joins) {
        let left_idx = left_raw % num_basic_blocks;
        let right_idx = right_raw % num_basic_blocks;
        if left_idx < all_node_ids.len() && right_idx < all_node_ids.len() {
            let left_id = all_node_ids[left_idx];
            let right_id = all_node_ids[right_idx];
            if let Ok(join_id) = forest.push_node(JoinNodeBuilder::new([left_id, right_id])) {
                all_node_ids.push(join_id);
            }
        }
    }

    for &(true_raw, false_raw) in split_pairs.iter().take(num_splits) {
        let true_idx = true_raw % num_basic_blocks;
        let false_idx = false_raw % num_basic_blocks;
        if true_idx < all_node_ids.len() && false_idx < all_node_ids.len() {
            let true_id = all_node_ids[true_idx];
            let false_id = all_node_ids[false_idx];
            if let Ok(split_id) = forest.push_node(SplitNodeBuilder::new([true_id, false_id])) {
                all_node_ids.push(split_id);
            }
        }
    }

    for &body_raw in loop_indices.iter().take(num_loops) {
        let body_idx = body_raw % num_basic_blocks;
        if body_idx < all_node_ids.len() {
            let body_id = all_node_ids[body_idx];
            if let Ok(loop_id) = forest.push_node(LoopNodeBuilder::new(body_id)) {
                all_node_ids.push(loop_id);
            }
        }
    }

    for &callee_raw in call_indices.iter().take(num_calls) {
        let callee_idx = callee_raw % num_basic_blocks;
        if callee_idx < all_node_ids.len() {
            let callee_id = all_node_ids[callee_idx];
            let call_id = forest
                .push_node(CallNodeBuilder::new(callee_id))
                .expect("Failed to add call node");
            all_node_ids.push(call_id);
        }
    }

    // Phase 2.5: select initial procedure roots so externals and syscalls have targets.
    let mut root_pool = RootPool::new();
    for (i, &id) in all_node_ids.iter().enumerate() {
        if root_selection.get(i).copied().unwrap_or(false) {
            forest.mark_root(id);
            root_pool.push(id);
        }
    }

    // Externals and syscalls need at least one procedure root to target.
    if root_pool.is_empty()
        && let Some(&fallback) = basic_block_ids.first()
    {
        forest.mark_root(fallback);
        root_pool.push(fallback);
    }

    ForestSkeleton { forest, all_node_ids, root_pool }
}

/// Borrowed view of the subset of [`ForestSeeds`] consumed by [`build_skeleton`].
#[derive(Clone, Copy)]
struct SkeletonInput<'a> {
    basic_blocks: &'a [BasicBlockNode],
    counts: NodeCounts,
    join_pairs: &'a [(usize, usize)],
    split_pairs: &'a [(usize, usize)],
    loop_indices: &'a [usize],
    call_indices: &'a [usize],
    root_selection: &'a [bool],
}

impl<'a> From<&'a ForestSeeds> for SkeletonInput<'a> {
    fn from(seeds: &'a ForestSeeds) -> Self {
        Self {
            basic_blocks: &seeds.basic_blocks,
            counts: seeds.counts,
            join_pairs: &seeds.join_pairs,
            split_pairs: &seeds.split_pairs,
            loop_indices: &seeds.loop_indices,
            call_indices: &seeds.call_indices,
            root_selection: &seeds.root_selection,
        }
    }
}

// ---------- Executable build (mode-specific tail) ----------

/// Builds an executable `(MastForest, KernelDescriptor)` pair from the provided seeds.
///
/// After [`build_skeleton`] produces the shared portion of the forest, this function appends
/// externals and syscalls under the closure invariants and finalises the paired kernel. Dyn
/// nodes are not emitted in this mode (see [`MastForestParams`] for the rationale).
fn build_executable_forest(
    seeds: ForestSeeds,
    params: &MastForestParams,
) -> (MastForest, KernelDescriptor) {
    let mut kernel_pool = match params.kernel_procedures.as_ref() {
        Some(hs) => KernelPool::new_frozen(hs.clone()),
        None => KernelPool::new(),
    };

    let input = SkeletonInput::from(&seeds);
    let ForestSkeleton { mut forest, mut root_pool, .. } = build_skeleton(&input);

    let ForestSeeds {
        syscall_picks,
        external_picks,
        kernel_inclusion,
        ..
    } = seeds;

    add_executable_externals(&mut forest, &mut root_pool, &external_picks);
    add_executable_syscalls(&mut forest, &mut root_pool, &mut kernel_pool, &syscall_picks);

    // Promote any node left unreachable by the seeded root selection, so the emitted
    // forest is fully pruned (every node reachable from a procedure root).
    let current_roots: Vec<MastNodeId> = root_pool.iter().collect();
    for id in mark_unreachable_nodes_as_roots(&mut forest, &current_roots) {
        root_pool.push(id);
    }

    // The kernel is derived from node digests, which are stable across the id remapping
    // performed by `finish()`, so it can be computed on the builder.
    let kernel = finalise_kernel(&forest, &root_pool, &kernel_pool, &kernel_inclusion, params);

    let forest = forest.finish().expect("generated forest must be valid in dense order");
    (forest, kernel)
}

/// Appends external nodes under the external-resolution and external-acyclicity invariants.
///
/// Each external's digest equals the digest of a procedure root already present in the
/// forest; the new external is then made a root itself (so subsequent externals can target
/// it). Acyclicity is automatic from the topological ordering: an external can only
/// reference roots committed before it, so it cannot transitively reach itself.
fn add_executable_externals(
    forest: &mut DenseMastForestBuilder,
    root_pool: &mut RootPool,
    external_picks: &[ExternalPick],
) {
    // External nodes are identified by digest alone, so a forest may contain at most one
    // external per digest (the dense order requires strictly increasing digests). Skip a
    // pick whose target digest is already used by an emitted external.
    let mut external_digests = BTreeSet::new();
    for pick in external_picks {
        let raw_idx = match *pick {
            ExternalPick::FromRoot(idx) => idx,
            ExternalPick::Random(_) => continue,
        };

        // External nodes are leaves and reference only roots committed before them, so all
        // current roots are eligible targets.
        let eligible: Vec<MastNodeId> = root_pool.iter().collect();
        if eligible.is_empty() {
            break;
        }

        let target_id = eligible[raw_idx % eligible.len()];
        let target_digest = forest.get_node_by_id(target_id).expect("root id is valid").digest();
        if !external_digests.insert(target_digest) {
            continue;
        }

        let ext_id = forest
            .push_node(ExternalNodeBuilder::new(target_digest))
            .expect("Failed to add external node");

        // Roots so subsequent externals can chain to them; acyclicity is guaranteed by
        // insertion order since an external can only target roots committed before it.
        forest.mark_root(ext_id);
        root_pool.push(ext_id);
    }
}

/// Appends syscall nodes under the kernel-closure invariant.
///
/// When the kernel pool is frozen, only roots whose digest is already in the pool are
/// eligible. When the kernel pool is free, any current root is eligible and its digest is
/// added to the pool when the syscall is emitted.
fn add_executable_syscalls(
    forest: &mut DenseMastForestBuilder,
    root_pool: &mut RootPool,
    kernel_pool: &mut KernelPool,
    syscall_picks: &[usize],
) {
    for &raw_pick in syscall_picks {
        // Once the free pool reaches `KernelDescriptor::MAX_NUM_PROCEDURES`, restrict
        // eligibility to roots whose digest is already in the pool, exactly as in the
        // frozen case. This caps kernel growth at emission time, so no later step ever
        // has to drop a digest that an already-emitted syscall targets.
        let pool_full = kernel_pool.hashes().len() >= KernelDescriptor::MAX_NUM_PROCEDURES;
        let eligible: Vec<MastNodeId> = if kernel_pool.is_frozen() || pool_full {
            root_pool
                .iter()
                .filter(|&id| {
                    forest
                        .get_node_by_id(id)
                        .map(|node| kernel_pool.contains(node.digest()))
                        .unwrap_or(false)
                })
                .collect()
        } else {
            root_pool.iter().collect()
        };

        if eligible.is_empty() {
            continue;
        }

        let callee_id = eligible[raw_pick % eligible.len()];
        let callee_digest = forest.get_node_by_id(callee_id).expect("callee id is valid").digest();

        let sc_id = forest
            .push_node(CallNodeBuilder::new_syscall(callee_id))
            .expect("Failed to add syscall node");

        forest.mark_root(sc_id);
        root_pool.push(sc_id);

        kernel_pool.insert(callee_digest);
    }
}

/// Builds the paired kernel from the user-supplied hashes (when frozen) or from the
/// generator's accumulated state (when free).
fn finalise_kernel(
    forest: &DenseMastForestBuilder,
    root_pool: &RootPool,
    kernel_pool: &KernelPool,
    kernel_inclusion: &[bool],
    params: &MastForestParams,
) -> KernelDescriptor {
    if let Some(hs) = params.kernel_procedures.as_ref() {
        return KernelDescriptor::from_hashes(hs.clone())
            .expect("kernel_procedures validated at entry");
    }

    let root_ids: Vec<MastNodeId> = root_pool.iter().collect();
    let mut hashes: Vec<Word> = kernel_pool.hashes().to_vec();

    // Syscall emission already caps the pool at `MAX_NUM_PROCEDURES` (see
    // `add_executable_syscalls`), so every syscall-targeted digest is retained here.
    // Inclusion-selected roots only fill whatever capacity remains; they are never allowed
    // to displace a digest an emitted syscall depends on.
    for (i, &root_id) in root_ids.iter().enumerate() {
        if hashes.len() >= KernelDescriptor::MAX_NUM_PROCEDURES {
            break;
        }
        if kernel_inclusion.get(i).copied().unwrap_or(false) {
            let digest = forest.get_node_by_id(root_id).expect("root id is valid").digest();
            if !hashes.contains(&digest) {
                hashes.push(digest);
            }
        }
    }

    // The co-generated kernel must be non-empty. Fall back to the first committed root when
    // no syscalls fired and no inclusion bits were set.
    if hashes.is_empty()
        && let Some(&first) = root_ids.first()
    {
        hashes.push(forest.get_node_by_id(first).expect("root id is valid").digest());
    }

    debug_assert!(hashes.len() <= KernelDescriptor::MAX_NUM_PROCEDURES);
    KernelDescriptor::from_hashes(hashes).expect("bounded and deduplicated")
}

/// Marks every node that is not reachable from `current_roots` as a procedure root itself,
/// and returns the newly promoted roots in the order they were marked.
///
/// Nodes are visited in reverse insertion order, so the top-most node of each unreachable
/// subtree is promoted (which makes its whole subtree reachable in one step). After this
/// sweep the forest is fully pruned: every node is reachable from at least one procedure
/// root.
fn mark_unreachable_nodes_as_roots(
    forest: &mut DenseMastForestBuilder,
    current_roots: &[MastNodeId],
) -> Vec<MastNodeId> {
    fn children(node: &MastNode) -> Vec<MastNodeId> {
        match node {
            MastNode::Join(join) => alloc::vec![join.first(), join.second()],
            MastNode::Split(split) => alloc::vec![split.on_true(), split.on_false()],
            MastNode::Loop(loop_node) => alloc::vec![loop_node.body()],
            MastNode::Call(call) => alloc::vec![call.callee()],
            MastNode::Block(_) | MastNode::External(_) | MastNode::Dyn(_) => Vec::new(),
        }
    }

    fn mark_reachable(
        forest: &DenseMastForestBuilder,
        from: MastNodeId,
        reachable: &mut BTreeSet<MastNodeId>,
    ) {
        let mut stack = alloc::vec![from];
        while let Some(current) = stack.pop() {
            if !reachable.insert(current) {
                continue;
            }
            if let Some(node) = forest.get_node_by_id(current) {
                stack.extend(children(node));
            }
        }
    }

    let mut reachable = BTreeSet::new();
    for &root in current_roots {
        mark_reachable(forest, root, &mut reachable);
    }

    let num_nodes = MastNodeContext::node_count(forest) as u32;
    let mut promoted = Vec::new();
    for idx in (0..num_nodes).rev() {
        let id = MastNodeId::new_unchecked(idx);
        if !reachable.contains(&id) {
            forest.mark_root(id);
            promoted.push(id);
            mark_reachable(forest, id, &mut reachable);
        }
    }
    promoted
}

// ---------- Structure-only build (mode-specific tail) ----------

/// Builds a structure-only `(MastForest, KernelDescriptor)` pair from the provided seeds.
///
/// Structure-only behaviour: externals use randomly generated digests via
/// [`ExternalPick::Random`] (and so will not resolve inside the forest), syscalls target
/// arbitrary entries of `all_node_ids` without any kernel-closure check, and dyn nodes are
/// emitted using [`ForestSeeds::dyn_selectors`] to pick between `DynNodeBuilder::new_dyn`
/// and `DynNodeBuilder::new_dyncall`.
///
/// The shared phases (basic blocks, control-flow nodes, initial root seeding) are produced
/// by [`build_skeleton`]; the modes then diverge in their operation pools (executable
/// blocks are restricted to infallible operations) and in how externals, syscalls, and dyn
/// nodes are emitted.
fn build_structure_only_forest(
    seeds: ForestSeeds,
    params: &MastForestParams,
) -> (MastForest, KernelDescriptor) {
    let input = SkeletonInput::from(&seeds);
    let ForestSkeleton { mut forest, mut all_node_ids, root_pool } = build_skeleton(&input);

    let ForestSeeds {
        counts,
        syscall_picks,
        external_picks,
        dyn_selectors,
        ..
    } = seeds;

    // Structure-only: syscalls pick from the full `all_node_ids` set (not just roots) with
    // no kernel-closure check — broad structural coverage is the goal, not executability.
    for &raw_pick in syscall_picks.iter().take(counts.num_syscalls) {
        if all_node_ids.is_empty() {
            break;
        }
        let callee_id = all_node_ids[raw_pick % all_node_ids.len()];
        let syscall_id = forest
            .push_node(CallNodeBuilder::new_syscall(callee_id))
            .expect("Failed to add syscall node");
        all_node_ids.push(syscall_id);
    }

    // Structure-only: externals use randomly sampled digests. Picks sampled via
    // `ExternalPick::FromRoot` are ignored here — the structure-only path only honours
    // `ExternalPick::Random`. Duplicate digests are skipped: a forest may contain at most
    // one external per digest.
    let mut external_digests = BTreeSet::new();
    for pick in external_picks.iter().take(counts.num_externals) {
        if let ExternalPick::Random([a, b, c, d]) = *pick {
            let digest = Word::from([
                Felt::new_unchecked(a),
                Felt::new_unchecked(b),
                Felt::new_unchecked(c),
                Felt::new_unchecked(d),
            ]);
            if !external_digests.insert(digest) {
                continue;
            }
            if let Ok(ext_id) = forest.push_node(ExternalNodeBuilder::new(digest)) {
                all_node_ids.push(ext_id);
            }
        }
    }

    for &is_dyncall in dyn_selectors.iter().take(counts.num_dyns) {
        let dyn_id = if is_dyncall {
            forest
                .push_node(DynNodeBuilder::new_dyncall())
                .expect("Failed to add dyncall node")
        } else {
            forest.push_node(DynNodeBuilder::new_dyn()).expect("Failed to add dyn node")
        };
        all_node_ids.push(dyn_id);
    }

    // Structure-only forests are pruned too: promote unreachable nodes to roots so every
    // node can be reached by walking the procedure roots.
    let current_roots: Vec<MastNodeId> = root_pool.iter().collect();
    let _ = mark_unreachable_nodes_as_roots(&mut forest, &current_roots);

    let kernel = match params.kernel_procedures.as_ref() {
        Some(hs) => {
            KernelDescriptor::from_hashes(hs.clone()).expect("kernel_procedures validated at entry")
        },
        None => KernelDescriptor::default(),
    };

    let forest = forest.finish().expect("generated forest must be valid in dense order");
    (forest, kernel)
}

impl Arbitrary for MastForest {
    type Parameters = MastForestParams;
    type Strategy = BoxedStrategy<Self>;

    /// Generates a `MastForest` by delegating to [`forest_kernel_strategy`] and
    /// dropping the paired kernel.
    ///
    /// See [`MastForestParams`] for the full set of structural closure invariants enforced
    /// in [`GenerationMode::Executable`] (the default) and the permissive,
    /// structure-focused behaviour in [`GenerationMode::StructureOnly`].
    /// Callers that also need the paired [`KernelDescriptor`] should use
    /// [`forest_kernel_strategy`] directly.
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        forest_kernel_strategy(params).prop_map(|(forest, _kernel)| forest).boxed()
    }
}

// ---------- Arbitrary implementations for missing types ----------

impl Arbitrary for AssemblyOp {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<bool>(),
            prop::collection::vec(any::<char>(), 1..=20)
                .prop_map(|chars| chars.into_iter().collect()),
            prop::collection::vec(any::<char>(), 1..=20)
                .prop_map(|chars| chars.into_iter().collect()),
            any::<u8>(),
        )
            .prop_map(|(has_location, context_name, op, num_cycles)| {
                use miden_debug_types::{ByteIndex, Location, Uri};

                let location = if has_location {
                    Some(Location::new(Uri::new("dummy.rs"), ByteIndex(0), ByteIndex(0)))
                } else {
                    None
                };

                AssemblyOp::new(location, context_name, num_cycles, op)
            })
            .boxed()
    }
}

impl Arbitrary for AdviceMap {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Strategy for generating Word keys
        let word_strategy = prop_oneof![
            Just(Word::default()),
            any::<[u64; 4]>().prop_map(|[a, b, c, d]| Word::new([
                Felt::new_unchecked(a),
                Felt::new_unchecked(b),
                Felt::new_unchecked(c),
                Felt::new_unchecked(d)
            ])),
        ];

        // Strategy for generating Arc<[Felt]> values
        let felt_array_strategy = prop::collection::vec(any::<u64>(), 1..=4).prop_map(|vals| {
            let felts: Arc<[Felt]> = vals.into_iter().map(Felt::new_unchecked).collect();
            felts
        });

        // Strategy for generating map entries
        let entry_strategy = (word_strategy, felt_array_strategy);

        // Strategy for generating the map itself (0 to 10 entries)
        prop::collection::vec(entry_strategy, 0..=10)
            .prop_map(|entries| {
                let mut map = BTreeMap::new();
                for (key, value) in entries {
                    map.insert(key, value);
                }
                AdviceMap::from(map)
            })
            .boxed()
    }
}

impl Arbitrary for Program {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Create a simple strategy that generates a basic block and creates a program from it
        any_with::<BasicBlockNode>(BasicBlockNodeParams {
            max_ops_len: 4, // Keep it small
            ..Default::default()
        })
        .prop_map(|node| {
            // Create a new MastForest
            let mut builder = DenseMastForestBuilder::new();
            let empty_forest = MastForest::new();

            // Add the node to the forest using builder
            let node_builder = node.to_builder(&empty_forest);
            let node_id = builder.push_node(node_builder).expect("Failed to add node");
            builder.mark_root(node_id);
            let (forest, remapping) =
                builder.finish_with_id_map().expect("generated program forest should be valid");
            let entrypoint = remapping.get(node_id).expect("entrypoint should be retained");

            Program::new(Arc::new(forest), entrypoint)
        })
        .prop_filter("valid entrypoint", |program| {
            // Ensure the generated program has a valid procedure entrypoint
            program.mast_forest().is_procedure_root(program.entrypoint())
        })
        .boxed()
    }
}

impl Arbitrary for KernelDescriptor {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Strategy for generating Word vectors
        let word_strategy = any::<[u64; 4]>().prop_map(|[a, b, c, d]| {
            Word::new([
                Felt::new_unchecked(a),
                Felt::new_unchecked(b),
                Felt::new_unchecked(c),
                Felt::new_unchecked(d),
            ])
        });

        // Strategy for generating kernel (0 to 3 words to avoid hitting MAX_NUM_PROCEDURES limit)
        prop::collection::vec(word_strategy, 0..=3)
            .prop_map(|words: Vec<Word>| {
                KernelDescriptor::new(&words).expect("Generated kernel should be valid")
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use proptest::{
        strategy::{BoxedStrategy, Strategy},
        test_runner::TestRunner,
    };

    use super::{GenerationMode, MastForestParams, forest_kernel_strategy};
    use crate::{
        Felt, Word,
        mast::{MastForest, MastNode},
        program::KernelDescriptor,
    };

    /// Returns a deterministic [`Word`] built from `seed`.
    fn word(seed: u64) -> Word {
        Word::new([
            Felt::new_unchecked(seed),
            Felt::new_unchecked(seed.wrapping_add(1)),
            Felt::new_unchecked(seed.wrapping_add(2)),
            Felt::new_unchecked(seed.wrapping_add(3)),
        ])
    }

    /// Draws one concrete sample from `strategy`, advancing `runner`'s RNG state so that
    /// repeated calls yield distinct samples.
    fn sample(
        strategy: &BoxedStrategy<(MastForest, KernelDescriptor)>,
        runner: &mut TestRunner,
    ) -> (MastForest, KernelDescriptor) {
        strategy
            .new_tree(runner)
            .expect("strategy must not reject a default seed")
            .current()
    }

    // --- compile-time surface check -------------------------------------------------------------

    /// Fails to compile if any field of [`MastForestParams`] or the signature of
    /// [`forest_kernel_strategy`] changes without a corresponding update here.
    #[allow(dead_code, clippy::no_effect_underscore_binding)]
    fn _compile_test_api_shape() {
        let MastForestParams {
            blocks,
            max_joins,
            max_splits,
            max_loops,
            max_calls,
            max_syscalls,
            max_externals,
            max_dyns,
            mode,
            kernel_procedures,
        } = MastForestParams::default();

        let _strategy: BoxedStrategy<(MastForest, KernelDescriptor)> =
            forest_kernel_strategy(MastForestParams::default());

        let _: GenerationMode = mode;
        let _ = (
            &blocks,
            max_joins,
            max_splits,
            max_loops,
            max_calls,
            max_syscalls,
            max_externals,
            max_dyns,
            &kernel_procedures,
        );
    }

    // --- unit tests -----------------------------------------------------------------------------

    /// Verifies that [`MastForestParams::default()`] produces the expected field values.
    #[test]
    fn mast_forest_params_default_values() {
        let p = MastForestParams::default();

        assert_eq!(p.mode, GenerationMode::Executable);
        assert_eq!(p.kernel_procedures, None);
        // Syscalls and externals are on by default (safe under the closure invariants);
        // only dyn nodes stay opt-in because they cannot be guaranteed executable.
        assert_eq!(p.max_dyns, 0);
        assert_eq!(p.max_syscalls, 1);
        assert_eq!(p.max_externals, 1);
        assert_eq!(p.blocks, 1..=3);
        assert_eq!(p.max_joins, 1);
        assert_eq!(p.max_splits, 1);
        assert_eq!(p.max_loops, 1);
        assert_eq!(p.max_calls, 1);
    }

    /// Verifies that duplicate `kernel_procedures` entries are rejected at strategy
    /// construction time (not per-sample).
    #[test]
    #[should_panic(expected = "MastForestParams::kernel_procedures is invalid")]
    fn kernel_procedures_with_duplicates_panics_at_construction() {
        let dup = word(0);
        let params = MastForestParams {
            kernel_procedures: Some(vec![dup, dup]),
            ..Default::default()
        };
        let _ = forest_kernel_strategy(params);
    }

    /// Verifies that a `kernel_procedures` list longer than
    /// [`KernelDescriptor::MAX_NUM_PROCEDURES`] panics at strategy construction time.
    #[test]
    #[should_panic(expected = "MastForestParams::kernel_procedures is invalid")]
    fn kernel_procedures_over_max_panics_at_construction() {
        let params = MastForestParams {
            kernel_procedures: Some(
                (0u64..=KernelDescriptor::MAX_NUM_PROCEDURES as u64).map(word).collect(),
            ),
            ..Default::default()
        };
        let _ = forest_kernel_strategy(params);
    }

    /// Verifies that a `kernel_procedures` list that is both too long and contains a
    /// duplicate panics at strategy construction time.
    #[test]
    #[should_panic(expected = "MastForestParams::kernel_procedures is invalid")]
    fn kernel_procedures_with_duplicates_and_over_max_panics_at_construction() {
        let params = MastForestParams {
            kernel_procedures: Some(
                (0u64..KernelDescriptor::MAX_NUM_PROCEDURES as u64)
                    .map(word)
                    .chain(core::iter::once(word(0)))
                    .collect(),
            ),
            ..Default::default()
        };
        let _ = forest_kernel_strategy(params);
    }

    /// Verifies that [`GenerationMode::StructureOnly`] emits dyn, external, and
    /// syscall nodes when their caps are non-zero.
    #[test]
    fn structure_only_generates_dyn_external_and_syscall_nodes() {
        let params = MastForestParams {
            mode: GenerationMode::StructureOnly,
            max_syscalls: 3,
            max_externals: 3,
            max_dyns: 3,
            ..Default::default()
        };
        let strategy = forest_kernel_strategy(params);

        let (mut saw_dyn, mut saw_external, mut saw_syscall) = (false, false, false);
        let mut runner = TestRunner::default();
        for _ in 0..256 {
            let (forest, _) = sample(&strategy, &mut runner);
            for node in forest.nodes() {
                match node {
                    MastNode::Dyn(_) => saw_dyn = true,
                    MastNode::External(_) => saw_external = true,
                    MastNode::Call(c) if c.is_syscall() => saw_syscall = true,
                    _ => {},
                }
            }
            if saw_dyn && saw_external && saw_syscall {
                break;
            }
        }

        assert!(saw_dyn, "no Dyn node observed across 256 samples");
        assert!(saw_external, "no External node observed across 256 samples");
        assert!(saw_syscall, "no syscall node observed across 256 samples");
    }

    /// Verifies that [`GenerationMode::StructureOnly`] emits both `new_dyn` and
    /// `new_dyncall` variants when `max_dyns` is non-zero.
    #[test]
    fn structure_only_emits_both_dyn_variants() {
        let params = MastForestParams {
            mode: GenerationMode::StructureOnly,
            max_dyns: 6,
            ..Default::default()
        };
        let strategy = forest_kernel_strategy(params);

        let (mut saw_dynexec, mut saw_dyncall) = (false, false);
        let mut runner = TestRunner::default();
        for _ in 0..256 {
            let (forest, _) = sample(&strategy, &mut runner);
            for node in forest.nodes() {
                if let MastNode::Dyn(d) = node {
                    if d.is_dyncall() {
                        saw_dyncall = true;
                    } else {
                        saw_dynexec = true;
                    }
                }
            }
            if saw_dynexec && saw_dyncall {
                break;
            }
        }

        assert!(saw_dynexec, "no dynexec node observed across 256 samples");
        assert!(saw_dyncall, "no dyncall node observed across 256 samples");
    }

    /// Verifies that an empty user supplied kernel causes all syscalls to be skipped and
    /// no `Call` nodes are emitted when `max_calls = 0`.
    #[test]
    fn empty_user_kernel_skips_syscalls_without_call_fallback() {
        let params = MastForestParams {
            kernel_procedures: Some(Vec::new()),
            max_syscalls: 5,
            max_calls: 0,
            ..Default::default()
        };
        let strategy = forest_kernel_strategy(params);

        let mut runner = TestRunner::default();
        for _ in 0..64 {
            let (forest, kernel) = sample(&strategy, &mut runner);
            assert!(kernel.proc_hashes().is_empty());
            for node in forest.nodes() {
                assert!(
                    !matches!(node, MastNode::Call(_)),
                    "unexpected Call node with empty kernel and max_calls=0"
                );
            }
        }
    }

    /// The caller's `blocks` range is respected in full, including its lower bound, so
    /// fixed-size requests like `4..=4` always yield exactly that many basic blocks.
    #[test]
    fn blocks_range_lower_bound_is_respected() {
        let params = MastForestParams {
            blocks: 4..=4,
            max_joins: 0,
            max_splits: 0,
            max_loops: 0,
            max_calls: 0,
            max_syscalls: 0,
            max_externals: 0,
            ..Default::default()
        };
        let strategy = forest_kernel_strategy(params);

        let mut runner = TestRunner::default();
        for _ in 0..16 {
            let (forest, _) = sample(&strategy, &mut runner);
            let num_blocks =
                forest.nodes().iter().filter(|node| matches!(node, MastNode::Block(_))).count();
            assert_eq!(num_blocks, 4, "requested exactly 4 basic blocks");
        }
    }
}

#[cfg(test)]
mod proptests {
    use alloc::{collections::BTreeSet, vec, vec::Vec};

    use proptest::prelude::*;

    use super::{MastForestParams, forest_kernel_strategy};
    use crate::mast::{MastForest, MastNode, MastNodeExt, MastNodeId};

    /// Returns the IDs of the immediate children of `id` in `forest`.
    ///
    /// Mirrors the child layout used by [`super::RootPool::roots_not_reaching`]: structural
    /// children for control-flow nodes, the callee for `Call`, and no children for leaves
    /// (`Block`, `External`, `Dyn`).
    fn children_of(forest: &MastForest, id: MastNodeId) -> Vec<MastNodeId> {
        match &forest[id] {
            MastNode::Block(_) | MastNode::External(_) | MastNode::Dyn(_) => Vec::new(),
            MastNode::Join(j) => vec![j.first(), j.second()],
            MastNode::Split(s) => vec![s.on_true(), s.on_false()],
            MastNode::Loop(l) => vec![l.body()],
            MastNode::Call(c) => vec![c.callee()],
        }
    }

    /// Returns the procedure root that contains `id` in its reachable subtree, or `None` if
    /// no root reaches it.
    fn containing_root(forest: &MastForest, id: MastNodeId) -> Option<MastNodeId> {
        forest.procedure_roots().iter().copied().find(|&root| {
            let mut stack = vec![root];
            let mut seen = BTreeSet::new();
            while let Some(n) = stack.pop() {
                if n == id {
                    return true;
                }
                if !seen.insert(n) {
                    continue;
                }
                stack.extend(children_of(forest, n));
            }
            false
        })
    }

    // --- property tests -------------------------------------------------------------------------

    /// Returns parameter set that opts into syscalls and externals at non-zero caps so the
    /// closure invariants are actually exercised. The defaults set these to 0 to preserve
    /// the pre-feature distribution; tests that want to verify executable-mode behaviour
    /// must opt in explicitly.
    fn executable_params_with_syscalls_and_externals() -> MastForestParams {
        MastForestParams {
            max_syscalls: 3,
            max_externals: 3,
            ..Default::default()
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

        /// In `Executable` mode the generator must never emit a Dyn node, even when
        /// `max_dyns` is non-zero.
        #[test]
        fn no_dyn_nodes_in_executable_mode(
            forest in any_with::<MastForest>(MastForestParams {
                max_dyns: 6,
                ..Default::default()
            })
        ) {
            for node in forest.nodes() {
                prop_assert!(!matches!(node, MastNode::Dyn(_)), "Executable forest contains a Dyn node");
            }
        }

        /// Every external node must have its digest match the digest of some procedure root
        /// in the same forest, so the VM can resolve the call locally.
        #[test]
        fn externals_resolve_to_a_local_root(
            forest in any_with::<MastForest>(executable_params_with_syscalls_and_externals())
        ) {
            let root_digests: BTreeSet<_> = forest
                .procedure_roots()
                .iter()
                .map(|&root| forest[root].digest())
                .collect();
            for node in forest.nodes() {
                if let MastNode::External(ext) = node {
                    prop_assert!(
                        root_digests.contains(&ext.digest()),
                        "external digest does not match any procedure root in the forest",
                    );
                }
            }
        }

        /// The directed graph induced by `external -> resolved root` must be acyclic across
        /// procedure roots, so external chains cannot loop back on themselves.
        #[test]
        fn externals_form_a_dag(
            forest in any_with::<MastForest>(MastForestParams {
                max_externals: 6,
                ..Default::default()
            })
        ) {
            // Build adjacency: for each external, the source procedure root that contains it
            // points to the target procedure root whose digest the external matches. Both
            // roots must exist: generated forests are pruned (every node belongs to some
            // root's subtree) and externals resolve locally (invariant 2), so a missing
            // root here is a generator bug, not a case to skip.
            let mut edges: Vec<(MastNodeId, MastNodeId)> = Vec::new();
            for (idx, node) in forest.nodes().iter().enumerate() {
                let MastNode::External(ext) = node else { continue };
                let id = MastNodeId::new_unchecked(idx as u32);
                let src_root = containing_root(&forest, id)
                    .expect("pruned forest: every external must be reachable from a root");
                let target_digest = ext.digest();
                let tgt_root = forest
                    .procedure_roots()
                    .iter()
                    .copied()
                    .find(|&r| forest[r].digest() == target_digest)
                    .expect("external-resolution: target digest must match a procedure root");
                edges.push((src_root, tgt_root));
            }

            // DFS with white/gray/black coloring to detect a back-edge.
            #[derive(Clone, Copy, PartialEq, Eq)]
            enum Color { White, Gray, Black }
            let mut color: alloc::collections::BTreeMap<MastNodeId, Color> =
                forest.procedure_roots().iter().map(|&r| (r, Color::White)).collect();

            fn visit(
                node: MastNodeId,
                edges: &[(MastNodeId, MastNodeId)],
                color: &mut alloc::collections::BTreeMap<MastNodeId, Color>,
            ) -> bool {
                color.insert(node, Color::Gray);
                for &(src, tgt) in edges.iter().filter(|(s, _)| *s == node) {
                    let _ = src;
                    match color.get(&tgt).copied().unwrap_or(Color::White) {
                        Color::Gray => return false,
                        Color::White => {
                            if !visit(tgt, edges, color) {
                                return false;
                            }
                        },
                        Color::Black => {},
                    }
                }
                color.insert(node, Color::Black);
                true
            }

            let roots: Vec<MastNodeId> = forest.procedure_roots().to_vec();
            for r in roots {
                if color.get(&r).copied().unwrap_or(Color::White) == Color::White {
                    prop_assert!(visit(r, &edges, &mut color), "external graph contains a cycle");
                }
            }
        }

        /// Every syscall's callee digest must be present in the paired kernel.
        #[test]
        fn syscalls_target_a_kernel_procedure(
            (forest, kernel) in forest_kernel_strategy(executable_params_with_syscalls_and_externals())
        ) {
            for node in forest.nodes() {
                let MastNode::Call(call) = node else { continue };
                if !call.is_syscall() {
                    continue;
                }
                let callee_digest = forest[call.callee()].digest();
                prop_assert!(
                    kernel.contains_proc(callee_digest),
                    "syscall callee digest is not present in the paired kernel",
                );
            }
        }

        /// In the free kernel case (`kernel_procedures = None`) the co-generated kernel must
        /// be non-empty and every entry must equal the digest of some procedure root in the
        /// same forest.
        #[test]
        fn free_kernel_is_derived_from_forest_roots(
            (forest, kernel) in forest_kernel_strategy(executable_params_with_syscalls_and_externals())
        ) {
            let root_digests: BTreeSet<_> = forest
                .procedure_roots()
                .iter()
                .map(|&root| forest[root].digest())
                .collect();
            prop_assert!(!kernel.proc_hashes().is_empty(), "free kernel must be non-empty");
            for h in kernel.proc_hashes() {
                prop_assert!(
                    root_digests.contains(h),
                    "kernel hash does not match any procedure root in the forest",
                );
            }
        }

        /// Every emitted `(forest, kernel)` pair must accept its first procedure root as a
        /// valid `Program` entrypoint. This is the structural-executability smoke test:
        /// passing this property means the VM's structural validation of the program (as
        /// implemented in `Program::with_kernel`) succeeds without requiring any external
        /// forest registration.
        #[test]
        fn forest_kernel_pair_constructs_a_valid_program(
            (forest, kernel) in forest_kernel_strategy(executable_params_with_syscalls_and_externals())
        ) {
            use alloc::sync::Arc;
            use crate::program::Program;

            let root = forest.procedure_roots().first().copied();
            prop_assert!(root.is_some(), "forest must expose at least one procedure root");
            let root = root.unwrap();

            let program = Program::with_kernel(Arc::new(forest), root, kernel);
            prop_assert!(
                program.mast_forest().is_procedure_root(program.entrypoint()),
                "Program entrypoint is not a procedure root",
            );
        }

        /// In `Executable` mode every basic block must consist solely of operations that
        /// cannot fault at runtime (invariant 5 on `MastForestParams`).
        #[test]
        fn executable_blocks_contain_only_infallible_ops(
            forest in any_with::<MastForest>(MastForestParams {
                blocks: 1..=6,
                ..Default::default()
            })
        ) {
            for node in forest.nodes() {
                let MastNode::Block(block) = node else { continue };
                for op_or_dec in block.op_batches().iter().flat_map(|batch| batch.ops()) {
                    prop_assert!(
                        super::is_infallible_op(op_or_dec),
                        "executable block contains fallible operation {op_or_dec:?}",
                    );
                }
            }
        }

        /// Generated forests are pruned in `Executable` mode: every node is reachable from
        /// at least one procedure root.
        #[test]
        fn executable_forests_are_pruned(
            forest in any_with::<MastForest>(executable_params_with_syscalls_and_externals())
        ) {
            let mut reachable: BTreeSet<MastNodeId> = BTreeSet::new();
            let mut stack: Vec<MastNodeId> = forest.procedure_roots().to_vec();
            while let Some(id) = stack.pop() {
                if reachable.insert(id) {
                    stack.extend(children_of(&forest, id));
                }
            }
            prop_assert_eq!(
                reachable.len(),
                forest.num_nodes() as usize,
                "every node must be reachable from a procedure root",
            );
        }

        /// Generated forests are pruned in `StructureOnly` mode as well.
        #[test]
        fn structure_only_forests_are_pruned(
            forest in any_with::<MastForest>(MastForestParams {
                mode: super::GenerationMode::StructureOnly,
                max_syscalls: 3,
                max_externals: 3,
                max_dyns: 3,
                ..Default::default()
            })
        ) {
            let mut reachable: BTreeSet<MastNodeId> = BTreeSet::new();
            let mut stack: Vec<MastNodeId> = forest.procedure_roots().to_vec();
            while let Some(id) = stack.pop() {
                if reachable.insert(id) {
                    stack.extend(children_of(&forest, id));
                }
            }
            prop_assert_eq!(
                reachable.len(),
                forest.num_nodes() as usize,
                "every node must be reachable from a procedure root",
            );
        }
    }
}
