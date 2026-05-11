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
    program::{KernelDescriptor, Program},
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

// ---------- Parameters ----------

/// Parameters for generating BasicBlockNode instances
#[derive(Clone, Debug)]
pub struct BasicBlockNodeParams {
    /// Maximum number of operations in a generated basic block
    pub max_ops_len: usize,
}

impl Default for BasicBlockNodeParams {
    fn default() -> Self {
        Self { max_ops_len: 8 }
    }
}

// ---------- Arbitrary for BasicBlockNode ----------

impl Arbitrary for BasicBlockNode {
    type Parameters = BasicBlockNodeParams;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(p: Self::Parameters) -> Self::Strategy {
        // ensure at least 1 op to satisfy BasicBlockNode::new
        op_non_control_sequence_strategy(p.max_ops_len)
            .prop_filter_map("non-empty ops", |ops| if ops.is_empty() { None } else { Some(ops) })
            .prop_map(|ops| BasicBlockNode::new(ops).expect("non-empty ops"))
            .boxed()
    }
}

// ---------- Optional: MastForest strategy (behind feature gate) ----------

/// Controls the generation mode for `MastForest` samples.
///
/// The default mode (`Executable`) emits forests that satisfy the four executability closure
/// invariants required by the Miden VM (dyn-suppression, external-resolution,
/// external-acyclicity, and kernel-closure). The `StructureOnly` mode preserves the
/// pre-existing, structure-focused generator behaviour used by serialization and merging
/// tests and does not enforce those invariants.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MastForestGenerationMode {
    /// Generate forests that are guaranteed to be executable by the Miden VM.
    #[default]
    Executable,
    /// Generate forests that exercise the full structural surface (including dyn, unresolved
    /// externals, and free-form syscalls) without enforcing executability invariants.
    StructureOnly,
}

/// Parameters for generating `MastForest` instances via proptest.
///
/// # Default behaviour: executable forests
///
/// `MastForestParams::default()` selects [`MastForestGenerationMode::Executable`], so every
/// sample is executable by the Miden VM against a co-generated (or caller-supplied)
/// [`Kernel`]. Callers that only need the forest can keep using
/// `<MastForest as Arbitrary>::arbitrary_with`; callers that also need the paired kernel
/// should use the `(MastForest, Kernel)` strategy exposed alongside this struct.
///
/// # Executability guarantees
///
/// When `mode` is [`MastForestGenerationMode::Executable`], the generator enforces the
/// following four closure invariants on every emitted sample:
///
/// 1. **No dyn nodes.** No `DynNode` instances are emitted, regardless of `max_dyns`. The
///    MAST-level generator cannot synthesise valid operand-stack preconditions for dyn
///    targets (see *Future work* below).
/// 2. **External-resolution.** Every external node's digest equals the MAST root of a
///    procedure root already present in the same forest, so the VM can resolve the call
///    without additional forest registration.
/// 3. **External-acyclicity.** The directed graph induced by external nodes on the forest's
///    procedure roots is a DAG; no external resolves, transitively, back to the procedure
///    root that contains it.
/// 4. **Kernel-closure.** Every syscall's callee is a procedure root whose MAST root is a
///    member of the paired kernel's procedure hashes; the generator never falls back to a
///    plain `Call` when a kernel-eligible callee is unavailable.
///
/// Together, these invariants guarantee that any procedure root in the emitted forest can be
/// selected as an entrypoint and executed to completion by the VM on empty inputs.
///
/// # `StructureOnly` mode
///
/// Setting `mode = MastForestGenerationMode::StructureOnly` retains the pre-feature,
/// permissive behaviour: syscalls may reference arbitrary callees, external digests are drawn
/// at random and do not have to resolve inside the forest, and a mix of `DynNode::new_dyn`
/// and `DynNode::new_dyncall` instances may be emitted. Use this mode for tests that
/// exercise serialization, merging, or other non-execution code paths where broad structural
/// coverage is valuable and executability is not required.
///
/// # Future work — MASM-level dyn generation
///
/// Dyn nodes are intentionally unsupported in `Executable` mode because the generator cannot
/// synthesise valid operand-stack preconditions: each dyn/dyncall reads its callee digest off
/// the operand stack at runtime, and producing a semantically valid stack state requires
/// program-synthesis-level reasoning that the MAST-level generator does not perform. The
/// intended extension is an assembly-level (MASM) generator that can emit instruction
/// sequences which push a valid callee digest before each dyn/dyncall; until such a generator
/// exists, callers who need executable dyn coverage should rely on hand-written fixtures or
/// opt into `StructureOnly` mode.
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
    /// In [`MastForestGenerationMode::Executable`] (the default), each emitted syscall targets a
    /// procedure root whose MAST root is a member of the paired kernel, satisfying the
    /// kernel-closure invariant. In [`MastForestGenerationMode::StructureOnly`], syscalls retain
    /// the legacy behaviour of pointing at arbitrary local node IDs with unresolvable digests
    /// and will not execute.
    pub max_syscalls: usize,
    /// Maximum number of external nodes to generate.
    ///
    /// In [`MastForestGenerationMode::Executable`] (the default), each emitted external's digest
    /// equals the MAST root of a procedure root already present in the same forest and the
    /// resulting external call graph is acyclic, so the VM can resolve every external locally.
    /// In [`MastForestGenerationMode::StructureOnly`], externals use randomly generated digests
    /// that will not resolve and forests containing them will fail to execute.
    pub max_externals: usize,
    /// Maximum number of dyn/dyncall nodes to generate.
    ///
    /// In [`MastForestGenerationMode::Executable`] (the default), this field is treated as `0`
    /// and no dyn nodes are emitted (see the *Future work* note on the struct doc). In
    /// [`MastForestGenerationMode::StructureOnly`], a mix of `DynNode::new_dyn` and
    /// `DynNode::new_dyncall` instances may be emitted up to this bound; such forests are
    /// intended for structural tests (serialization, merging, pretty-printing) and are not
    /// guaranteed to execute.
    pub max_dyns: usize,
    /// Controls whether the generator emits executable forests (with the closure invariants
    /// enforced) or legacy, structure-only forests.
    pub mode: MastForestGenerationMode,
    /// Optional user-supplied kernel procedure hashes.
    ///
    /// When `Some`, the generator freezes the kernel to exactly these hashes (after validation
    /// for uniqueness and `Kernel::MAX_NUM_PROCEDURES`) and will only emit syscalls whose
    /// callee digest is present in this set. When `None`, the generator derives the kernel
    /// from procedure roots selected during generation.
    pub kernel_procedures: Option<Vec<Word>>,
}

impl Default for MastForestParams {
    fn default() -> Self {
        Self {
            blocks: 1..=3,
            max_joins: 1,
            max_splits: 1,
            max_loops: 1,
            max_calls: 1,
            max_syscalls: 1,
            max_externals: 1,
            max_dyns: 0,
            mode: MastForestGenerationMode::Executable,
            kernel_procedures: None,
        }
    }
}

// ---------- Internal helpers for executable pipeline ----------

/// Counts of each node type to be generated in a single sample.
///
/// Used internally by the `ForestSeeds` container to drive the four-phase executable
/// pipeline. All counts are upper bounds; the generator may emit fewer nodes of a given type
/// when the `RootPool` or `KernelPool` is empty at emission time.
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
/// the same forest, so the generator uses `FromRoot(index)` to pick from the current
/// `RootPool`. In `StructureOnly` mode, externals use randomly generated digests via
/// `Random([u64; 4])` that will not resolve and are intended for structural tests only.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ExternalPick {
    /// Executable mode: index into the current `RootPool` at the moment the external is
    /// emitted. The generator will modulo this index by the pool's length to select a valid
    /// target.
    FromRoot(usize),
    /// StructureOnly mode: digest bytes sampled directly from proptest. The resulting external
    /// will not resolve to any procedure in the forest and is not executable.
    Random([u64; 4]),
}

/// Collection of primitive samples drawn from proptest for a single `MastForest` generation.
///
/// This struct is computed once per sample and consumed by either `build_executable_forest`
/// or `build_structure_only_forest` depending on the selected [`MastForestGenerationMode`].
/// The field layout is frozen per the strategy composition order to ensure deterministic
/// shrinking: basic blocks and decorators are sampled first, then counts, then pair/index
/// vectors sized by those counts, and finally the selection bits for roots and kernel
/// inclusion.
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
/// - `root_selection.len() >= basic_blocks.len() + counts.num_joins + counts.num_splits + counts.num_loops + counts.num_calls`
/// - `kernel_inclusion.len()` is sized to cover all procedure roots that may be committed
///   during generation
#[derive(Clone, Debug)]
pub(crate) struct ForestSeeds {
    /// Basic block nodes to be added in Phase 1.
    pub basic_blocks: Vec<BasicBlockNode>,
    /// Decorators to be registered before any nodes are added.
    pub decorators: Vec<Decorator>,
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
    /// syscall is emitted. Used only in Executable mode via `KernelPool::pick`.
    pub syscall_picks: Vec<usize>,
    /// Each entry is a pick into the current `RootPool` (Executable mode) or a random digest
    /// (StructureOnly mode).
    pub external_picks: Vec<ExternalPick>,
    /// Bit for each dyn node selecting `new_dyn` (false) or `new_dyncall` (true).
    pub dyn_selectors: Vec<bool>,
    /// Used only when `kernel_procedures` is `None` in Executable mode. Each bit says whether
    /// the i-th committed procedure root is included in the minted kernel.
    pub kernel_inclusion: Vec<bool>,
    /// Bits controlling Phase 2.5 root seeding (which non-block nodes become roots before
    /// Phase 3 externals/syscalls are added).
    pub root_selection: Vec<bool>,
}

/// Ordered multiset of `MastNodeId`s that the generator has already committed as procedure
/// roots.
///
/// Supports filtering by "roots that do not transitively reach a given subtree" so that
/// external-node additions stay acyclic. For proptest-scale forests (single-digit counts per
/// node type), a simple on-demand DFS is sufficient; no caching is required.
#[derive(Debug)]
pub(crate) struct RootPool<'a> {
    forest: &'a MastForest,
    roots: Vec<MastNodeId>,
}

impl<'a> RootPool<'a> {
    /// Creates a new empty `RootPool` for the given forest.
    pub fn new(forest: &'a MastForest) -> Self {
        Self { forest, roots: Vec::new() }
    }

    /// Adds a procedure root to the pool.
    pub fn push(&mut self, id: MastNodeId) {
        self.roots.push(id);
    }

    /// Returns `true` if the pool contains no roots.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Returns the number of roots in the pool.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Returns an iterator of procedure roots whose transitive descendants do not include
    /// `excluded`.
    ///
    /// The iterator is ordered by insertion order so the generator is deterministic for a
    /// given seed. Uses an on-demand DFS to check reachability.
    pub fn roots_not_reaching(
        &self,
        excluded: MastNodeId,
    ) -> impl Iterator<Item = MastNodeId> + '_ {
        self.roots.iter().copied().filter(move |&root| !self.reaches(root, excluded))
    }

    /// Returns `true` if `from` transitively reaches `to` through the forest's child edges.
    ///
    /// Uses a simple DFS with a visited set to detect cycles and avoid infinite loops.
    fn reaches(&self, from: MastNodeId, to: MastNodeId) -> bool {
        use alloc::collections::BTreeSet;

        if from == to {
            return true;
        }

        let mut visited = BTreeSet::new();
        let mut stack = alloc::vec![from];

        while let Some(current) = stack.pop() {
            if current == to {
                return true;
            }

            if !visited.insert(current) {
                // Already visited this node, skip to avoid cycles
                continue;
            }

            // Get the node and push its children onto the stack
            if let Some(node) = self.forest.get_node_by_id(current) {
                match node {
                    MastNode::Join(join) => {
                        stack.push(join.first());
                        stack.push(join.second());
                    }
                    MastNode::Split(split) => {
                        stack.push(split.on_true());
                        stack.push(split.on_false());
                    }
                    MastNode::Loop(loop_node) => {
                        stack.push(loop_node.body());
                    }
                    MastNode::Call(call) => {
                        stack.push(call.callee());
                    }
                    // Basic blocks, external nodes, and dyn nodes have no children
                    MastNode::Block(_) | MastNode::External(_) | MastNode::Dyn(_) => {}
                }
            }
        }

        false
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

    /// Inserts a hash into the pool if the pool is not frozen.
    ///
    /// When `frozen` is `true`, this is a no-op. This allows the generator to call `insert`
    /// unconditionally during syscall emission without branching on whether the kernel is
    /// user-supplied or co-generated.
    pub fn insert(&mut self, h: Word) {
        if !self.frozen {
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

    /// Returns `true` if at least one procedure root in `roots` has a digest that is a member
    /// of this pool.
    ///
    /// Used by Phase 3 to decide whether a syscall node can be emitted: if the kernel is
    /// frozen (user-supplied) and no existing root matches any kernel hash, the generator
    /// skips the syscall rather than emitting an invalid one.
    pub fn has_candidate_in(&self, roots: &[MastNodeId], forest: &MastForest) -> bool {
        roots.iter().any(|&root| {
            forest
                .get_node_by_id(root)
                .map(|node| self.contains(node.digest()))
                .unwrap_or(false)
        })
    }
}

// ---------- ForestSeeds sampling strategy ----------

/// Composes the proptest strategies that produce a [`ForestSeeds`] for a single
/// `MastForest` sample.
///
/// The composition order is fixed per the design to keep proptest shrinking effective:
///
/// 1. Basic blocks and decorators are sampled first (independent of everything else).
/// 2. Control-flow node counts (`num_joins`, `num_splits`, `num_loops`, `num_calls`,
///    `num_syscalls`, `num_externals`, `num_dyns`) are sampled next.
/// 3. Pair / index vectors (`join_pairs`, `split_pairs`, `loop_indices`, `call_indices`) are
///    sized by those counts.
/// 4. Finally, the selection vectors (`syscall_picks`, `external_picks`, `dyn_selectors`,
///    `root_selection`, `kernel_inclusion`) are sampled with lengths derived from the counts
///    and the total number of nodes that may be committed.
///
/// Later choices depend on earlier samples only through length invariants, so each
/// individual sample can be shrunk independently once the counts have been minimised.
///
/// The `external_picks` strategy branches on [`MastForestParams::mode`]: in
/// [`MastForestGenerationMode::Executable`] it yields [`ExternalPick::FromRoot`] indices
/// (into the generator's `RootPool` at emission time), while in
/// [`MastForestGenerationMode::StructureOnly`] it yields [`ExternalPick::Random`] digest
/// seeds.
pub(crate) fn forest_seeds_strategy(params: &MastForestParams) -> BoxedStrategy<ForestSeeds> {
    let bb_params = BasicBlockNodeParams {
        max_decorator_id_u32: params.decorators,
        ..Default::default()
    };
    let blocks_end = *params.blocks.end();
    let decorators_count = params.decorators as usize;
    let max_joins = params.max_joins;
    let max_splits = params.max_splits;
    let max_loops = params.max_loops;
    let max_calls = params.max_calls;
    let max_syscalls = params.max_syscalls;
    let max_externals = params.max_externals;
    let max_dyns = params.max_dyns;
    let mode = params.mode;

    // Stage 1: basic blocks + decorators (independent of everything else).
    (
        prop::collection::vec(any_with::<BasicBlockNode>(bb_params), 1..=blocks_end),
        prop::collection::vec(any::<Decorator>(), decorators_count..=decorators_count),
    )
        // Stage 2: control-flow counts, each bounded by the corresponding `max_*`.
        .prop_flat_map(move |(basic_blocks, decorators)| {
            (
                Just(basic_blocks),
                Just(decorators),
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
        .prop_flat_map(move |(basic_blocks, decorators, counts_tuple)| {
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
                MastForestGenerationMode::Executable => prop::collection::vec(
                    any::<usize>(),
                    num_externals..=num_externals,
                )
                .prop_map(|picks| picks.into_iter().map(ExternalPick::FromRoot).collect())
                .boxed(),
                MastForestGenerationMode::StructureOnly => prop::collection::vec(
                    any::<[u64; 4]>(),
                    num_externals..=num_externals,
                )
                .prop_map(|seeds| seeds.into_iter().map(ExternalPick::Random).collect())
                .boxed(),
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
                Just(decorators),
                Just(counts),
                // Pair / index vectors, sized exactly by the counts above.
                (
                    prop::collection::vec(any::<(usize, usize)>(), num_joins..=num_joins),
                    prop::collection::vec(any::<(usize, usize)>(), num_splits..=num_splits),
                    prop::collection::vec(any::<usize>(), num_loops..=num_loops),
                    prop::collection::vec(any::<usize>(), num_calls..=num_calls),
                ),
                // Selection vectors: picks/selectors consumed during Phases 2.5/3/4.
                (
                    prop::collection::vec(any::<usize>(), num_syscalls..=num_syscalls),
                    external_picks_strategy,
                    prop::collection::vec(any::<bool>(), num_dyns..=num_dyns),
                    prop::collection::vec(any::<bool>(), max_nodes_total..=max_nodes_total),
                    prop::collection::vec(any::<bool>(), max_nodes_total..=max_nodes_total),
                ),
            )
        })
        .prop_map(
            |(
                basic_blocks,
                decorators,
                counts,
                (join_pairs, split_pairs, loop_indices, call_indices),
                (syscall_picks, external_picks, dyn_selectors, root_selection, kernel_inclusion),
            )| {
                ForestSeeds {
                    basic_blocks,
                    decorators,
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

// ---------- (MastForest, Kernel) strategy ----------

/// Validates a caller supplied `kernel_procedures` slice.
///
/// Returns `true` iff the slice is `None` or contains no duplicates and at most
/// [`Kernel::MAX_NUM_PROCEDURES`] entries. Used by
/// [`mast_forest_and_kernel_strategy`] to reject malformed parameter configurations via
/// `prop_filter_map` rather than panicking downstream when [`Kernel::from_hashes`] would
/// otherwise fail.
fn kernel_procedures_are_valid(kernel_procedures: &Option<Vec<Word>>) -> bool {
    let Some(hs) = kernel_procedures.as_ref() else {
        return true;
    };
    if hs.len() > Kernel::MAX_NUM_PROCEDURES {
        return false;
    }
    // Check for duplicates: sort a copy by canonical byte order and scan consecutive pairs.
    let mut sorted: Vec<&Word> = hs.iter().collect();
    sorted.sort_by_key(|w| w.as_bytes());
    !sorted.windows(2).any(|pair| pair[0] == pair[1])
}

/// Strategy yielding executable `(MastForest, Kernel)` pairs, or structure-only pairs when
/// [`MastForestParams::mode`] is [`MastForestGenerationMode::StructureOnly`].
///
/// The strategy first samples a [`ForestSeeds`] via [`forest_seeds_strategy`] and then
/// dispatches to either [`build_executable_forest`] or [`build_structure_only_forest`]
/// depending on `params.mode`.
///
/// # Precondition rejection
///
/// The sampler is wrapped in a `prop_filter_map("valid kernel_procedures", ...)` so that a
/// `Some(hs)` with duplicates or with `hs.len() > Kernel::MAX_NUM_PROCEDURES` rejects the
/// precondition rather than panicking downstream. The validity check is invariant in the
/// seed, so either every sample passes the filter (when `kernel_procedures` is well-formed
/// or `None`) or every sample is rejected (surfacing as a proptest "too many rejects"
/// error, which signals a misconfigured caller rather than a generator bug).
///
/// See the module-level docs on [`MastForestParams`] for the full list of invariants this
/// strategy guarantees in `Executable` mode.
pub fn mast_forest_and_kernel_strategy(
    params: MastForestParams,
) -> BoxedStrategy<(MastForest, Kernel)> {
    forest_seeds_strategy(&params)
        .prop_filter_map("valid kernel_procedures", move |seeds| {
            if !kernel_procedures_are_valid(&params.kernel_procedures) {
                return None;
            }
            let result = match params.mode {
                MastForestGenerationMode::Executable => build_executable_forest(seeds, &params),
                MastForestGenerationMode::StructureOnly => {
                    build_structure_only_forest(seeds, &params)
                },
            };
            Some(result)
        })
        .boxed()
}

/// Builds an executable `(MastForest, Kernel)` pair from the provided seeds.
///
/// TODO: externals + syscalls, and kernel finalisation.
fn build_executable_forest(
    seeds: ForestSeeds,
    params: &MastForestParams,
) -> (MastForest, Kernel) {
    let _ = params;

    let ForestSeeds {
        basic_blocks,
        decorators,
        counts,
        join_pairs,
        split_pairs,
        loop_indices,
        call_indices,
        syscall_picks: _,
        external_picks: _,
        dyn_selectors: _,
        kernel_inclusion: _,
        root_selection,
    } = seeds;

    let mut forest = MastForest::new();

    for decorator in decorators {
        forest.add_decorator(decorator).expect("Failed to add decorator");
    }

    let num_basic_blocks = basic_blocks.len();
    let mut basic_block_ids: Vec<MastNodeId> = Vec::with_capacity(num_basic_blocks);
    for block in basic_blocks {
        let builder = block.to_builder(&forest);
        let node_id = builder.add_to_forest(&mut forest).expect("Failed to add block");
        basic_block_ids.push(node_id);
    }

    // Track all node IDs in insertion (topological) order so children referenced by
    // control-flow nodes are guaranteed to already exist in the forest.
    let mut all_node_ids: Vec<MastNodeId> = basic_block_ids.clone();

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
            if let Ok(join_id) =
                JoinNodeBuilder::new([left_id, right_id]).add_to_forest(&mut forest)
            {
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
            if let Ok(split_id) =
                SplitNodeBuilder::new([true_id, false_id]).add_to_forest(&mut forest)
            {
                all_node_ids.push(split_id);
            }
        }
    }

    for &body_raw in loop_indices.iter().take(num_loops) {
        let body_idx = body_raw % num_basic_blocks;
        if body_idx < all_node_ids.len() {
            let body_id = all_node_ids[body_idx];
            if let Ok(loop_id) = LoopNodeBuilder::new(body_id).add_to_forest(&mut forest) {
                all_node_ids.push(loop_id);
            }
        }
    }

    for &callee_raw in call_indices.iter().take(num_calls) {
        let callee_idx = callee_raw % num_basic_blocks;
        if callee_idx < all_node_ids.len() {
            let callee_id = all_node_ids[callee_idx];
            let call_id = CallNodeBuilder::new(callee_id)
                .add_to_forest(&mut forest)
                .expect("Failed to add call node");
            all_node_ids.push(call_id);
        }
    }

    // TODO: wire RootPool to support acyclicity filtering for externals.
    let mut root_ids: Vec<MastNodeId> = Vec::new();
    for (i, &id) in all_node_ids.iter().enumerate() {
        if root_selection.get(i).copied().unwrap_or(false) {
            forest.make_root(id);
            root_ids.push(id);
        }
    }

    // Externals and syscalls need at least one procedure root to target.
    if root_ids.is_empty() && !basic_block_ids.is_empty() {
        let fallback = basic_block_ids[0];
        forest.make_root(fallback);
        root_ids.push(fallback);
    }

    (forest, Kernel::default())
}

/// Builds a structure-only `(MastForest, Kernel)` pair from the provided seeds.
#[allow(unused_variables)]
fn build_structure_only_forest(
    seeds: ForestSeeds,
    params: &MastForestParams,
) -> (MastForest, Kernel) {
    unimplemented!("will be implemented later!")
}

impl Arbitrary for MastForest {
    type Parameters = MastForestParams;
    type Strategy = BoxedStrategy<Self>;

    /// Generates a `MastForest` by delegating to [`mast_forest_and_kernel_strategy`] and
    /// dropping the paired kernel.
    ///
    /// See [`MastForestParams`] for the full set of guarantees: the four executability
    /// closure invariants in [`MastForestGenerationMode::Executable`] (the default) and the
    /// permissive, structure-focused behaviour in [`MastForestGenerationMode::StructureOnly`].
    /// Callers that also need the paired [`Kernel`] — required to actually execute the
    /// forest on the VM in `Executable` mode — should use [`mast_forest_and_kernel_strategy`]
    /// directly.
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        mast_forest_and_kernel_strategy(params)
            .prop_map(|(forest, _kernel)| forest)
            .boxed()
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
