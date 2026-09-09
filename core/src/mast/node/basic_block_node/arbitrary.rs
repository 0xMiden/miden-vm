use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec,
};
use core::{iter::repeat_n, ops::RangeInclusive};

use proptest::{arbitrary::Arbitrary, prelude::*};

use super::*;
use crate::{
    Felt, ONE, Word,
    advice::AdviceMap,
    mast::{
        CallNodeBuilder, DenseMastForestBuilder, DynNodeBuilder, ExternalNodeBuilder,
        JoinNodeBuilder, LoopNodeBuilder, SplitNodeBuilder,
    },
    operations::Operation,
    program::{KernelDescriptor, Program},
};

// OPERATIONS
// ================================================================================================

/// Non-control-flow operations without an immediate value.
const OPS_NO_IMM: &[Operation] = &[
    Operation::Add,
    Operation::Mul,
    Operation::Neg,
    Operation::Inv,
    Operation::Incr,
    Operation::And,
    Operation::Or,
    Operation::Not,
    Operation::Eq,
    Operation::Eqz,
    Operation::Drop,
    Operation::Pad,
    Operation::Swap,
    Operation::SwapW,
    Operation::SwapW2,
    Operation::SwapW3,
    Operation::SwapDW,
    Operation::MovUp2,
    Operation::MovUp3,
    Operation::MovUp4,
    Operation::MovUp5,
    Operation::MovUp6,
    Operation::MovUp7,
    Operation::MovUp8,
    Operation::MovDn2,
    Operation::MovDn3,
    Operation::MovDn4,
    Operation::MovDn5,
    Operation::MovDn6,
    Operation::MovDn7,
    Operation::MovDn8,
    Operation::CSwap,
    Operation::CSwapW,
    Operation::Dup0,
    Operation::Dup1,
    Operation::Dup2,
    Operation::Dup3,
    Operation::Dup4,
    Operation::Dup5,
    Operation::Dup6,
    Operation::Dup7,
    Operation::Dup9,
    Operation::Dup11,
    Operation::Dup13,
    Operation::Dup15,
    Operation::MLoad,
    Operation::MStore,
    Operation::MLoadW,
    Operation::MStoreW,
    Operation::MStream,
    Operation::Pipe,
    Operation::AdvPop,
    Operation::AdvPopW,
    Operation::U32split,
    Operation::U32add,
    Operation::U32sub,
    Operation::U32mul,
    Operation::U32div,
    Operation::U32and,
    Operation::U32xor,
    Operation::U32add3,
    Operation::U32madd,
    Operation::SDepth,
    Operation::Caller,
    Operation::Clk,
    Operation::Emit,
    Operation::Ext2Mul,
    Operation::Expacc,
    Operation::HPerm,
];

/// Operations that cannot fail whatever the stack, advice provider, or memory hold, paired with
/// the change each one makes to the stack depth.
///
/// Left out: `Inv` (traps on zero), `And`, `Or`, `Not`, `CSwap` and `CSwapW` (binary operands),
/// the `U32*` family (u32-range operands), memory and advice operations, `Caller`, `Emit`,
/// `Assert`, and the crypto/STARK helpers.
const INFALLIBLE_OPS: &[(Operation, i8)] = &[
    (Operation::Add, -1),
    (Operation::Mul, -1),
    (Operation::Neg, 0),
    (Operation::Incr, 0),
    (Operation::Eq, -1),
    (Operation::Eqz, 0),
    (Operation::Ext2Mul, 0),
    (Operation::Expacc, 0),
    (Operation::Drop, -1),
    (Operation::Pad, 1),
    (Operation::Swap, 0),
    (Operation::SwapW, 0),
    (Operation::SwapW2, 0),
    (Operation::SwapW3, 0),
    (Operation::SwapDW, 0),
    (Operation::MovUp2, 0),
    (Operation::MovUp3, 0),
    (Operation::MovUp4, 0),
    (Operation::MovUp5, 0),
    (Operation::MovUp6, 0),
    (Operation::MovUp7, 0),
    (Operation::MovUp8, 0),
    (Operation::MovDn2, 0),
    (Operation::MovDn3, 0),
    (Operation::MovDn4, 0),
    (Operation::MovDn5, 0),
    (Operation::MovDn6, 0),
    (Operation::MovDn7, 0),
    (Operation::MovDn8, 0),
    (Operation::Dup0, 1),
    (Operation::Dup1, 1),
    (Operation::Dup2, 1),
    (Operation::Dup3, 1),
    (Operation::Dup4, 1),
    (Operation::Dup5, 1),
    (Operation::Dup6, 1),
    (Operation::Dup7, 1),
    (Operation::Dup9, 1),
    (Operation::Dup11, 1),
    (Operation::Dup13, 1),
    (Operation::Dup15, 1),
    (Operation::SDepth, 1),
    (Operation::Clk, 1),
];

/// Strategy for operations without immediate values (non-control flow).
pub fn op_no_imm_strategy() -> impl Strategy<Value = Operation> {
    prop::sample::select(OPS_NO_IMM)
}

/// Strategy for operations with immediate values.
pub fn op_with_imm_strategy() -> impl Strategy<Value = Operation> {
    any::<u64>().prop_map(Felt::new_unchecked).prop_map(Operation::Push)
}

/// Strategy for all non-control flow operations.
pub fn op_non_control_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![op_no_imm_strategy(), op_with_imm_strategy()]
}

/// Strategy for sequences of non-control flow operations.
pub fn op_non_control_sequence_strategy(
    max_length: usize,
) -> impl Strategy<Value = Vec<Operation>> {
    prop::collection::vec(op_non_control_strategy(), 1..=max_length)
}

/// Returns true if `op` cannot fail during execution, whatever the VM state.
pub fn is_infallible_op(op: &Operation) -> bool {
    stack_delta(op).is_some()
}

/// Change `op` makes to the stack depth, or `None` if `op` can fail.
fn stack_delta(op: &Operation) -> Option<i8> {
    match op {
        Operation::Noop => Some(0),
        Operation::Push(_) => Some(1),
        _ => INFALLIBLE_OPS
            .iter()
            .find(|(candidate, _)| candidate == op)
            .map(|&(_, delta)| delta),
    }
}

fn op_infallible_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![
        prop::sample::select(INFALLIBLE_OPS).prop_map(|(op, _)| op),
        op_with_imm_strategy(),
    ]
}

/// Drops operations that would take the stack below its depth on entry and appends `Drop`s so
/// the block leaves the depth as it found it. Every operation in `ops` must be infallible.
fn balance_ops(ops: Vec<Operation>) -> Vec<Operation> {
    let mut depth = 0i32;
    let mut balanced = Vec::with_capacity(ops.len() * 2);
    for op in ops {
        let delta = i32::from(stack_delta(&op).expect("infallible operation"));
        if depth + delta >= 0 {
            depth += delta;
            balanced.push(op);
        }
    }
    balanced.extend(repeat_n(Operation::Drop, depth as usize));
    if balanced.is_empty() {
        balanced.push(Operation::Noop);
    }
    balanced
}

// BASIC BLOCKS
// ================================================================================================

/// Parameters for generating `BasicBlockNode` instances.
#[derive(Clone, Debug)]
pub struct BasicBlockNodeParams {
    /// Maximum number of operations in a generated basic block.
    pub max_ops_len: usize,
    /// Restricts blocks to infallible operations that leave the stack depth unchanged, so a block
    /// runs on any operand stack.
    pub executable: bool,
}

impl Default for BasicBlockNodeParams {
    fn default() -> Self {
        Self { max_ops_len: 8, executable: false }
    }
}

/// Strategy for the operations of a basic block described by `params`.
pub fn block_ops_strategy(params: &BasicBlockNodeParams) -> BoxedStrategy<Vec<Operation>> {
    if params.executable {
        prop::collection::vec(op_infallible_strategy(), 1..=params.max_ops_len)
            .prop_map(balance_ops)
            .boxed()
    } else {
        op_non_control_sequence_strategy(params.max_ops_len).boxed()
    }
}

impl Arbitrary for BasicBlockNode {
    type Parameters = BasicBlockNodeParams;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        block_ops_strategy(&params)
            .prop_map(|ops| BasicBlockNode::new(ops).expect("non-empty operations"))
            .boxed()
    }
}

// FOREST PARAMETERS
// ================================================================================================

/// What a `MastForest` sample guarantees.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GenerationMode {
    /// Every procedure root runs to completion on any operand stack. See [`MastForestParams`].
    #[default]
    Executable,
    /// Broad structural coverage without execution guarantees: fallible operations, dyn nodes,
    /// externals with random digests, and syscalls to arbitrary nodes.
    StructureOnly,
}

/// Parameters for generating `MastForest` instances via proptest.
///
/// In [`GenerationMode::Executable`] every procedure root of a sample executes to completion on
/// any operand stack once the forest is loaded into the host:
///
/// - basic blocks hold only infallible operations and leave the stack depth unchanged;
/// - each split sits behind a block that pushes its condition, and each loop body ends by pushing
///   `0`, so conditions are binary and loops run exactly once;
/// - each external resolves to a procedure root of the same forest, and the graph of externals is
///   acyclic;
/// - each syscall callee is a member of the paired kernel;
/// - dyn nodes are never emitted (issue #3397 tracks a MASM-level generator for them).
///
/// The `MastForest` `Arbitrary` impl drops the kernel, so in this mode it emits no syscalls and
/// its samples run under the empty kernel of `Program::new`; [`forest_kernel_strategy`] keeps the
/// kernel and the syscalls.
///
/// With `kernel_procedures` set, syscall callees are external nodes carrying the supplied hashes,
/// so running them requires the matching kernel forest in the host.
///
/// Samples of both modes are pruned: every node is reachable from a procedure root.
#[derive(Clone, Debug)]
pub struct MastForestParams {
    /// Number of basic blocks to generate; a bound of `0` is raised to `1`.
    pub blocks: RangeInclusive<usize>,
    /// Maximum number of join nodes.
    pub max_joins: usize,
    /// Maximum number of split nodes.
    pub max_splits: usize,
    /// Maximum number of loop nodes.
    pub max_loops: usize,
    /// Maximum number of call nodes.
    pub max_calls: usize,
    /// Maximum number of syscall nodes. Forced to `0` by the `MastForest` `Arbitrary` impl in
    /// [`GenerationMode::Executable`].
    pub max_syscalls: usize,
    /// Maximum number of external nodes.
    pub max_externals: usize,
    /// Maximum number of dyn and dyncall nodes. Ignored in [`GenerationMode::Executable`].
    pub max_dyns: usize,
    /// Guarantees the samples provide.
    pub mode: GenerationMode,
    /// Procedure hashes of a caller-supplied kernel. When `None`, the kernel is derived from the
    /// generated procedure roots. Duplicate hashes or more than
    /// [`KernelDescriptor::MAX_NUM_PROCEDURES`] entries make [`forest_kernel_strategy`] panic.
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
            mode: GenerationMode::Executable,
            kernel_procedures: None,
        }
    }
}

// SEEDS
// ================================================================================================

/// How an external node picks its digest.
#[derive(Clone, Copy, Debug)]
enum ExternalPick {
    /// Executable mode: indices into the current roots (target) and nodes (join sibling).
    Local { root: usize, sibling: usize },
    /// Structure-only mode: a random digest.
    Random([u32; 4]),
}

/// Raw samples for one forest. Index vectors are reduced modulo the number of candidates when
/// they are consumed.
#[derive(Clone, Debug)]
struct ForestSeeds {
    basic_blocks: Vec<BasicBlockNode>,
    join_pairs: Vec<(usize, usize)>,
    split_pairs: Vec<(usize, usize)>,
    loop_indices: Vec<usize>,
    call_indices: Vec<usize>,
    /// Condition pushed before each split (executable mode).
    cond_bits: Vec<bool>,
    syscall_picks: Vec<usize>,
    external_picks: Vec<ExternalPick>,
    /// `true` selects `dyncall`, `false` selects `dyn`.
    dyn_selectors: Vec<bool>,
    /// Which skeleton nodes become procedure roots.
    root_selection: Vec<bool>,
    /// Which roots join the generated kernel besides syscall targets.
    kernel_inclusion: Vec<bool>,
}

fn forest_seeds_strategy(params: &MastForestParams) -> BoxedStrategy<ForestSeeds> {
    let executable = params.mode == GenerationMode::Executable;
    let block_params = BasicBlockNodeParams { executable, ..Default::default() };
    let blocks = (*params.blocks.start()).max(1)..=(*params.blocks.end()).max(1);
    let caps = params.clone();

    prop::collection::vec(any_with::<BasicBlockNode>(block_params), blocks)
        .prop_flat_map(move |basic_blocks| {
            (
                Just(basic_blocks),
                (
                    0..=caps.max_joins,
                    0..=caps.max_splits,
                    0..=caps.max_loops,
                    0..=caps.max_calls,
                    0..=caps.max_syscalls,
                    0..=caps.max_externals,
                    0..=if executable { 0 } else { caps.max_dyns },
                ),
            )
        })
        .prop_flat_map(
            move |(basic_blocks, (joins, splits, loops, calls, syscalls, externals, dyns))| {
                // Upper bound on the node count, used to size the selection bit vectors.
                let max_nodes = basic_blocks.len()
                    + joins
                    + 2 * splits
                    + 2 * loops
                    + calls
                    + syscalls
                    + 2 * externals
                    + dyns
                    + 2;
                let external_picks: BoxedStrategy<Vec<ExternalPick>> = if executable {
                    prop::collection::vec(any::<(usize, usize)>(), externals)
                        .prop_map(|picks| {
                            picks
                                .into_iter()
                                .map(|(root, sibling)| ExternalPick::Local { root, sibling })
                                .collect()
                        })
                        .boxed()
                } else {
                    prop::collection::vec(any::<[u32; 4]>(), externals)
                        .prop_map(|seeds| seeds.into_iter().map(ExternalPick::Random).collect())
                        .boxed()
                };
                (
                    Just(basic_blocks),
                    (
                        prop::collection::vec(any::<(usize, usize)>(), joins),
                        prop::collection::vec(any::<(usize, usize)>(), splits),
                        prop::collection::vec(any::<usize>(), loops),
                        prop::collection::vec(any::<usize>(), calls),
                        prop::collection::vec(any::<bool>(), splits),
                    ),
                    (
                        prop::collection::vec(any::<usize>(), syscalls),
                        external_picks,
                        prop::collection::vec(any::<bool>(), dyns),
                        prop::collection::vec(any::<bool>(), max_nodes),
                        prop::collection::vec(any::<bool>(), max_nodes),
                    ),
                )
            },
        )
        .prop_map(
            |(
                basic_blocks,
                (join_pairs, split_pairs, loop_indices, call_indices, cond_bits),
                (syscall_picks, external_picks, dyn_selectors, root_selection, kernel_inclusion),
            )| {
                ForestSeeds {
                    basic_blocks,
                    join_pairs,
                    split_pairs,
                    loop_indices,
                    call_indices,
                    cond_bits,
                    syscall_picks,
                    external_picks,
                    dyn_selectors,
                    root_selection,
                    kernel_inclusion,
                }
            },
        )
        .boxed()
}

// SKELETON
// ================================================================================================

/// Shared part of a sample: basic blocks, control flow, and the initial procedure roots.
struct Skeleton {
    forest: DenseMastForestBuilder,
    /// Nodes that later nodes may reference and that root selection draws from.
    node_ids: Vec<MastNodeId>,
    roots: Vec<MastNodeId>,
}

/// Single-operation blocks pushing `0` or `1`, created on first use. `0` also ends every loop
/// body, since a loop inspects its condition only after each iteration.
#[derive(Default)]
struct ConditionBlocks {
    zero: Option<MastNodeId>,
    one: Option<MastNodeId>,
}

impl ConditionBlocks {
    fn get(&mut self, forest: &mut DenseMastForestBuilder, bit: bool) -> MastNodeId {
        let (slot, op) = if bit {
            (&mut self.one, Operation::Push(ONE))
        } else {
            (&mut self.zero, Operation::Pad)
        };
        *slot.get_or_insert_with(|| {
            forest.push_node(BasicBlockNodeBuilder::new(vec![op])).expect("condition block")
        })
    }
}

fn choose(ids: &[MastNodeId], index: usize) -> MastNodeId {
    ids[index % ids.len()]
}

fn digest_of(forest: &DenseMastForestBuilder, id: MastNodeId) -> Word {
    forest.get_node_by_id(id).expect("node id from this builder").digest()
}

/// Joins a block pushing `bit` in front of `node`, which consumes it as its condition.
fn with_condition(
    forest: &mut DenseMastForestBuilder,
    conditions: &mut ConditionBlocks,
    bit: bool,
    node: MastNodeId,
) -> MastNodeId {
    let condition = conditions.get(forest, bit);
    forest
        .push_node(JoinNodeBuilder::new([condition, node]))
        .expect("condition join")
}

fn build_skeleton(seeds: &ForestSeeds, executable: bool) -> Skeleton {
    let mut forest = DenseMastForestBuilder::new();
    let empty_forest = MastForest::new();
    let mut node_ids: Vec<MastNodeId> = seeds
        .basic_blocks
        .iter()
        .map(|block| {
            forest.push_node(block.clone().to_builder(&empty_forest)).expect("basic block")
        })
        .collect();
    let mut conditions = ConditionBlocks::default();
    let mut cond_bits = seeds.cond_bits.iter().copied();

    for &(first, second) in &seeds.join_pairs {
        let join = JoinNodeBuilder::new([choose(&node_ids, first), choose(&node_ids, second)]);
        node_ids.push(forest.push_node(join).expect("join"));
    }

    for &(on_true, on_false) in &seeds.split_pairs {
        let split =
            SplitNodeBuilder::new([choose(&node_ids, on_true), choose(&node_ids, on_false)]);
        let mut id = forest.push_node(split).expect("split");
        if executable {
            let bit = cond_bits.next().unwrap_or(false);
            id = with_condition(&mut forest, &mut conditions, bit, id);
        }
        node_ids.push(id);
    }

    for &body in &seeds.loop_indices {
        let mut body = choose(&node_ids, body);
        if executable {
            let exit = conditions.get(&mut forest, false);
            body = forest.push_node(JoinNodeBuilder::new([body, exit])).expect("loop body");
        }
        node_ids.push(forest.push_node(LoopNodeBuilder::new(body)).expect("loop"));
    }

    for &callee in &seeds.call_indices {
        let call = CallNodeBuilder::new(choose(&node_ids, callee));
        node_ids.push(forest.push_node(call).expect("call"));
    }

    let mut roots: Vec<MastNodeId> = node_ids
        .iter()
        .copied()
        .zip(&seeds.root_selection)
        .filter_map(|(id, &selected)| selected.then_some(id))
        .collect();
    if roots.is_empty() {
        roots.push(node_ids[0]);
    }
    for &root in &roots {
        forest.mark_root(root);
    }

    Skeleton { forest, node_ids, roots }
}

/// Marks every node unreachable from `roots` as a root, top-most nodes first.
fn promote_unreachable(forest: &mut DenseMastForestBuilder, roots: &mut Vec<MastNodeId>) {
    let mut reachable = BTreeSet::new();
    for &root in roots.iter() {
        mark_reachable(forest, root, &mut reachable);
    }
    for index in (0..MastNodeContext::node_count(forest) as u32).rev() {
        let id = MastNodeId::new_unchecked(index);
        if !reachable.contains(&id) {
            forest.mark_root(id);
            roots.push(id);
            mark_reachable(forest, id, &mut reachable);
        }
    }
}

fn mark_reachable(
    forest: &DenseMastForestBuilder,
    from: MastNodeId,
    reachable: &mut BTreeSet<MastNodeId>,
) {
    let mut stack = vec![from];
    while let Some(id) = stack.pop() {
        if reachable.insert(id) {
            forest
                .get_node_by_id(id)
                .expect("node id from this builder")
                .append_children_to(&mut stack);
        }
    }
}

// EXECUTABLE MODE
// ================================================================================================

fn build_executable_forest(
    seeds: &ForestSeeds,
    kernel: Option<&KernelDescriptor>,
) -> (MastForest, KernelDescriptor) {
    let Skeleton { mut forest, node_ids, mut roots } = build_skeleton(seeds, true);
    let mut externals = BTreeMap::new();

    add_local_externals(&mut forest, &node_ids, &mut roots, &mut externals, &seeds.external_picks);
    let syscall_hashes = match kernel {
        Some(kernel) => {
            let hashes = kernel.proc_hashes();
            add_kernel_syscalls(
                &mut forest,
                &mut roots,
                &mut externals,
                hashes,
                &seeds.syscall_picks,
            );
            Vec::new()
        },
        None => add_local_syscalls(&mut forest, &mut roots, &seeds.syscall_picks),
    };
    promote_unreachable(&mut forest, &mut roots);

    let kernel = kernel.cloned().unwrap_or_else(|| {
        generated_kernel(&forest, &roots, syscall_hashes, &seeds.kernel_inclusion)
    });
    let forest = forest.build().expect("generated forest is valid");
    (forest, kernel)
}

/// Adds externals resolving to a root of the same forest. Each one is joined with an existing
/// node, so the external is used by a procedure instead of being a root itself.
fn add_local_externals(
    forest: &mut DenseMastForestBuilder,
    node_ids: &[MastNodeId],
    roots: &mut Vec<MastNodeId>,
    externals: &mut BTreeMap<Word, MastNodeId>,
    picks: &[ExternalPick],
) {
    for pick in picks {
        let ExternalPick::Local { root, sibling } = *pick else {
            continue;
        };
        let digest = digest_of(forest, choose(roots, root));
        // Dense forests hold at most one external per digest.
        if externals.contains_key(&digest) {
            continue;
        }
        let external = forest.push_node(ExternalNodeBuilder::new(digest)).expect("external");
        externals.insert(digest, external);
        let join = JoinNodeBuilder::new([external, choose(node_ids, sibling)]);
        let wrapper = forest.push_node(join).expect("external join");
        forest.mark_root(wrapper);
        roots.push(wrapper);
    }
}

/// Adds syscalls to existing roots and returns the callee digests, which stay within the kernel
/// size limit.
fn add_local_syscalls(
    forest: &mut DenseMastForestBuilder,
    roots: &mut Vec<MastNodeId>,
    picks: &[usize],
) -> Vec<Word> {
    let mut hashes: Vec<Word> = Vec::new();
    for &index in picks {
        // Once the kernel is full, only roots already in it can be called.
        let full = hashes.len() >= KernelDescriptor::MAX_NUM_PROCEDURES;
        let callable: Vec<MastNodeId> = roots
            .iter()
            .copied()
            .filter(|&id| !full || hashes.contains(&digest_of(forest, id)))
            .collect();
        if callable.is_empty() {
            continue;
        }
        let callee = choose(&callable, index);
        let digest = digest_of(forest, callee);
        let syscall = forest.push_node(CallNodeBuilder::new_syscall(callee)).expect("syscall");
        forest.mark_root(syscall);
        roots.push(syscall);
        if !hashes.contains(&digest) {
            hashes.push(digest);
        }
    }
    hashes
}

/// Adds syscalls whose callees are externals carrying the supplied kernel hashes.
fn add_kernel_syscalls(
    forest: &mut DenseMastForestBuilder,
    roots: &mut Vec<MastNodeId>,
    externals: &mut BTreeMap<Word, MastNodeId>,
    hashes: &[Word],
    picks: &[usize],
) {
    if hashes.is_empty() {
        return;
    }
    for &index in picks {
        let hash = hashes[index % hashes.len()];
        let callee = *externals.entry(hash).or_insert_with(|| {
            forest.push_node(ExternalNodeBuilder::new(hash)).expect("kernel external")
        });
        let syscall = forest.push_node(CallNodeBuilder::new_syscall(callee)).expect("syscall");
        forest.mark_root(syscall);
        roots.push(syscall);
    }
}

/// Builds the kernel from the syscall targets, then from roots selected by `inclusion` while
/// room remains. Falls back to the first root, so the kernel is never empty.
fn generated_kernel(
    forest: &DenseMastForestBuilder,
    roots: &[MastNodeId],
    mut hashes: Vec<Word>,
    inclusion: &[bool],
) -> KernelDescriptor {
    for (&root, &included) in roots.iter().zip(inclusion) {
        if hashes.len() >= KernelDescriptor::MAX_NUM_PROCEDURES {
            break;
        }
        let digest = digest_of(forest, root);
        if included && !hashes.contains(&digest) {
            hashes.push(digest);
        }
    }
    if hashes.is_empty() {
        hashes.push(digest_of(forest, roots[0]));
    }
    KernelDescriptor::from_hashes(hashes).expect("unique hashes within the size limit")
}

// STRUCTURE-ONLY MODE
// ================================================================================================

fn build_structure_only_forest(
    seeds: &ForestSeeds,
    kernel: Option<&KernelDescriptor>,
) -> (MastForest, KernelDescriptor) {
    let Skeleton { mut forest, mut node_ids, mut roots } = build_skeleton(seeds, false);

    for &index in &seeds.syscall_picks {
        let syscall = CallNodeBuilder::new_syscall(choose(&node_ids, index));
        node_ids.push(forest.push_node(syscall).expect("syscall"));
    }

    let mut digests = BTreeSet::new();
    for pick in &seeds.external_picks {
        let ExternalPick::Random(seed) = *pick else { continue };
        let digest = Word::from(seed);
        if digests.insert(digest) {
            node_ids.push(forest.push_node(ExternalNodeBuilder::new(digest)).expect("external"));
        }
    }

    for &dyncall in &seeds.dyn_selectors {
        let node = if dyncall {
            DynNodeBuilder::new_dyncall()
        } else {
            DynNodeBuilder::new_dyn()
        };
        node_ids.push(forest.push_node(node).expect("dyn"));
    }

    promote_unreachable(&mut forest, &mut roots);
    let forest = forest.build().expect("generated forest is valid");
    (forest, kernel.cloned().unwrap_or_default())
}

// STRATEGIES
// ================================================================================================

/// Strategy yielding `(MastForest, KernelDescriptor)` pairs. See [`MastForestParams`] for what
/// each [`GenerationMode`] guarantees.
///
/// # Panics
///
/// Panics if `params.kernel_procedures` is rejected by [`KernelDescriptor::from_hashes`]. The
/// check does not depend on the sample, so it runs once here instead of rejecting every sample.
pub fn forest_kernel_strategy(
    params: MastForestParams,
) -> BoxedStrategy<(MastForest, KernelDescriptor)> {
    let kernel = params.kernel_procedures.clone().map(|hashes| {
        KernelDescriptor::from_hashes(hashes)
            .unwrap_or_else(|err| panic!("MastForestParams::kernel_procedures is invalid: {err}"))
    });
    let mode = params.mode;

    forest_seeds_strategy(&params)
        .prop_map(move |seeds| match mode {
            GenerationMode::Executable => build_executable_forest(&seeds, kernel.as_ref()),
            GenerationMode::StructureOnly => build_structure_only_forest(&seeds, kernel.as_ref()),
        })
        .boxed()
}

impl Arbitrary for MastForest {
    type Parameters = MastForestParams;
    type Strategy = BoxedStrategy<Self>;

    /// Samples forests that need no kernel: in [`GenerationMode::Executable`] no syscalls are
    /// emitted, so every root runs under the empty kernel of `Program::new`. Use
    /// [`forest_kernel_strategy`] to sample syscalls together with their kernel.
    fn arbitrary_with(mut params: Self::Parameters) -> Self::Strategy {
        if params.mode == GenerationMode::Executable {
            params.max_syscalls = 0;
        }
        forest_kernel_strategy(params).prop_map(|(forest, _)| forest).boxed()
    }
}

// OTHER ARBITRARY IMPLEMENTATIONS
// ================================================================================================

fn word_strategy() -> impl Strategy<Value = Word> {
    any::<[u32; 4]>().prop_map(Word::from)
}

impl Arbitrary for AdviceMap {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let key = prop_oneof![Just(Word::default()), word_strategy()];
        let value = prop::collection::vec(any::<u64>(), 1..=4).prop_map(|values| {
            values.into_iter().map(Felt::new_unchecked).collect::<Arc<[Felt]>>()
        });

        prop::collection::vec((key, value), 0..=10)
            .prop_map(|entries| AdviceMap::from(entries.into_iter().collect::<BTreeMap<_, _>>()))
            .boxed()
    }
}

impl Arbitrary for Program {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    /// Generates a program whose entrypoint is a single basic block.
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any_with::<BasicBlockNode>(BasicBlockNodeParams { max_ops_len: 4, ..Default::default() })
            .prop_map(|node| {
                let mut builder = DenseMastForestBuilder::new();
                let node_id = builder
                    .push_node(node.to_builder(&MastForest::new()))
                    .expect("Failed to add node");
                builder.mark_root(node_id);
                let (forest, remapping) =
                    builder.build_with_id_map().expect("generated program forest should be valid");
                let entrypoint = remapping.get(node_id).expect("entrypoint should be retained");

                Program::new(Arc::new(forest), entrypoint)
            })
            .boxed()
    }
}

impl Arbitrary for KernelDescriptor {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Distinct random words, well below `MAX_NUM_PROCEDURES`.
        prop::collection::btree_set(word_strategy(), 0..=3)
            .prop_map(|words| {
                KernelDescriptor::from_hashes(words.into_iter().collect())
                    .expect("Generated kernel should be valid")
            })
            .boxed()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::fmt::Debug;

    use proptest::{strategy::ValueTree, test_runner::TestRunner};

    use super::*;
    use crate::mast::{CallNode, MastNode, OpBatch, SubtreeIterator};

    fn word(seed: u32) -> Word {
        Word::from([seed, seed + 1, seed + 2, seed + 3])
    }

    fn sample<T: Debug>(strategy: &BoxedStrategy<T>, runner: &mut TestRunner) -> T {
        strategy.new_tree(runner).expect("strategy does not reject").current()
    }

    fn syscalls(forest: &MastForest) -> impl Iterator<Item = &CallNode> {
        forest.nodes().iter().filter_map(|node| match node {
            MastNode::Call(call) if call.is_syscall() => Some(call),
            _ => None,
        })
    }

    fn assert_pruned(forest: &MastForest) {
        let reachable: BTreeSet<MastNodeId> = forest
            .procedure_roots()
            .iter()
            .flat_map(|root| SubtreeIterator::new(root, forest))
            .collect();
        assert_eq!(reachable.len(), forest.num_nodes() as usize);
    }

    fn executable_params() -> MastForestParams {
        MastForestParams {
            blocks: 1..=4,
            max_syscalls: 3,
            max_externals: 3,
            ..Default::default()
        }
    }

    #[test]
    fn default_params_select_executable_mode() {
        let params = MastForestParams::default();
        assert_eq!(params.mode, GenerationMode::Executable);
        assert_eq!(params.kernel_procedures, None);
        assert_eq!((params.max_syscalls, params.max_externals, params.max_dyns), (1, 1, 0));
    }

    #[test]
    #[should_panic(expected = "kernel_procedures is invalid")]
    fn duplicate_kernel_procedures_panic() {
        let _ = forest_kernel_strategy(MastForestParams {
            kernel_procedures: Some(vec![word(0), word(0)]),
            ..Default::default()
        });
    }

    #[test]
    #[should_panic(expected = "kernel_procedures is invalid")]
    fn oversized_kernel_procedures_panic() {
        let hashes = (0..=KernelDescriptor::MAX_NUM_PROCEDURES as u32).map(word).collect();
        let _ = forest_kernel_strategy(MastForestParams {
            kernel_procedures: Some(hashes),
            ..Default::default()
        });
    }

    #[test]
    fn structure_only_emits_every_node_kind() {
        let strategy = forest_kernel_strategy(MastForestParams {
            mode: GenerationMode::StructureOnly,
            max_syscalls: 3,
            max_externals: 3,
            max_dyns: 4,
            ..Default::default()
        });
        let mut runner = TestRunner::default();
        // dyn, dyncall, external, syscall
        let mut seen = [false; 4];
        for _ in 0..256 {
            let (forest, _) = sample(&strategy, &mut runner);
            for node in forest.nodes() {
                match node {
                    MastNode::Dyn(dyn_node) => seen[usize::from(dyn_node.is_dyncall())] = true,
                    MastNode::External(_) => seen[2] = true,
                    MastNode::Call(call) if call.is_syscall() => seen[3] = true,
                    _ => {},
                }
            }
            if seen.iter().all(|&kind| kind) {
                return;
            }
        }
        panic!("missing node kinds: {seen:?}");
    }

    #[test]
    fn supplied_kernel_syscalls_target_its_hashes() {
        let hashes = vec![word(1), word(10)];
        let strategy = forest_kernel_strategy(MastForestParams {
            kernel_procedures: Some(hashes.clone()),
            max_syscalls: 3,
            ..Default::default()
        });
        let mut runner = TestRunner::default();
        let (forest, kernel) = (0..64)
            .map(|_| sample(&strategy, &mut runner))
            .find(|(forest, _)| syscalls(forest).next().is_some())
            .expect("a sample with syscalls");

        assert_eq!(kernel.proc_hashes().len(), hashes.len());
        for call in syscalls(&forest) {
            let callee = &forest[call.callee()];
            assert!(callee.is_external());
            assert!(kernel.contains_proc(callee.digest()));
        }
    }

    #[test]
    fn empty_supplied_kernel_emits_no_syscalls() {
        let strategy = forest_kernel_strategy(MastForestParams {
            kernel_procedures: Some(Vec::new()),
            max_syscalls: 4,
            max_calls: 0,
            ..Default::default()
        });
        let mut runner = TestRunner::default();
        for _ in 0..64 {
            let (forest, kernel) = sample(&strategy, &mut runner);
            assert!(kernel.is_empty());
            assert!(!forest.nodes().iter().any(|node| matches!(node, MastNode::Call(_))));
        }
    }

    #[test]
    fn blocks_range_lower_bound_is_respected() {
        let strategy = forest_kernel_strategy(MastForestParams {
            blocks: 4..=4,
            max_joins: 0,
            max_splits: 0,
            max_loops: 0,
            max_calls: 0,
            max_syscalls: 0,
            max_externals: 0,
            ..Default::default()
        });
        let mut runner = TestRunner::default();
        for _ in 0..16 {
            let (forest, _) = sample(&strategy, &mut runner);
            assert_eq!(forest.nodes().iter().filter(|node| node.is_basic_block()).count(), 4);
        }
    }

    proptest! {
        #[test]
        fn executable_forests_have_no_dyn_nodes(
            forest in any_with::<MastForest>(MastForestParams { max_dyns: 6, ..Default::default() })
        ) {
            prop_assert!(!forest.nodes().iter().any(MastNode::is_dyn));
        }

        /// Without a paired kernel there is nothing a syscall could target.
        #[test]
        fn plain_executable_forests_have_no_syscalls(
            forest in any_with::<MastForest>(MastForestParams { max_syscalls: 3, ..Default::default() })
        ) {
            prop_assert!(syscalls(&forest).next().is_none());
        }

        /// Blocks hold only infallible operations and leave the stack depth unchanged, except for
        /// the single-operation blocks that push a split or loop condition.
        #[test]
        fn executable_blocks_are_infallible_and_balanced(
            forest in any_with::<MastForest>(executable_params())
        ) {
            for node in forest.nodes() {
                let Some(block) = node.get_basic_block() else { continue };
                let ops: Vec<Operation> =
                    block.op_batches().iter().flat_map(OpBatch::ops).copied().collect();
                let mut depth = 0i32;
                for op in &ops {
                    let delta = stack_delta(op);
                    prop_assert!(delta.is_some(), "fallible operation {op:?}");
                    depth += i32::from(delta.unwrap_or_default());
                    prop_assert!(depth >= 0, "block underflows its entry depth: {ops:?}");
                }
                let real: Vec<Operation> =
                    ops.iter().copied().filter(|op| *op != Operation::Noop).collect();
                let pushes_condition = matches!(real[..], [Operation::Pad])
                    || matches!(real[..], [Operation::Push(value)] if value == ONE);
                prop_assert!(depth == 0 || (depth == 1 && pushes_condition), "unbalanced block {ops:?}");
            }
        }

        #[test]
        fn externals_resolve_to_a_local_root(
            forest in any_with::<MastForest>(executable_params())
        ) {
            for node in forest.nodes().iter().filter(|node| node.is_external()) {
                let target = forest.find_procedure_root(node.digest());
                prop_assert!(
                    target.is_some_and(|target| !forest[target].is_external()),
                    "external does not resolve to a local root",
                );
            }
        }

        /// Edges lead from the root containing an external to the root it resolves to.
        #[test]
        fn externals_form_a_dag(
            forest in any_with::<MastForest>(MastForestParams { max_externals: 6, ..Default::default() })
        ) {
            fn acyclic(
                node: MastNodeId,
                edges: &[(MastNodeId, MastNodeId)],
                path: &mut BTreeSet<MastNodeId>,
                done: &mut BTreeSet<MastNodeId>,
            ) -> bool {
                if done.contains(&node) {
                    return true;
                }
                if !path.insert(node) {
                    return false;
                }
                let ok = edges
                    .iter()
                    .filter(|(source, _)| *source == node)
                    .all(|&(_, target)| acyclic(target, edges, path, done));
                path.remove(&node);
                done.insert(node);
                ok
            }

            let roots = forest.procedure_roots();
            let mut edges = Vec::new();
            for (index, node) in forest.nodes().iter().enumerate() {
                if !node.is_external() {
                    continue;
                }
                let id = MastNodeId::new_unchecked(index as u32);
                let source = roots
                    .iter()
                    .copied()
                    .find(|root| SubtreeIterator::new(root, &forest).any(|reached| reached == id))
                    .expect("pruned forest");
                let target = forest.find_procedure_root(node.digest()).expect("resolvable external");
                edges.push((source, target));
            }

            let (mut path, mut done) = (BTreeSet::new(), BTreeSet::new());
            for &root in roots {
                prop_assert!(acyclic(root, &edges, &mut path, &mut done), "cycle through externals");
            }
        }

        #[test]
        fn syscalls_target_kernel_procedures(
            (forest, kernel) in forest_kernel_strategy(executable_params())
        ) {
            for call in syscalls(&forest) {
                prop_assert!(kernel.contains_proc(forest[call.callee()].digest()));
            }
        }

        #[test]
        fn generated_kernel_holds_forest_roots(
            (forest, kernel) in forest_kernel_strategy(executable_params())
        ) {
            prop_assert!(!kernel.is_empty());
            for hash in kernel.proc_hashes() {
                prop_assert!(forest.find_procedure_root(*hash).is_some(), "kernel hash is not a root");
            }
        }

        #[test]
        fn executable_forests_are_pruned(forest in any_with::<MastForest>(executable_params())) {
            assert_pruned(&forest);
        }

        #[test]
        fn structure_only_forests_are_pruned(
            forest in any_with::<MastForest>(MastForestParams {
                mode: GenerationMode::StructureOnly,
                max_syscalls: 3,
                max_externals: 3,
                max_dyns: 3,
                ..Default::default()
            })
        ) {
            assert_pruned(&forest);
        }
    }
}
