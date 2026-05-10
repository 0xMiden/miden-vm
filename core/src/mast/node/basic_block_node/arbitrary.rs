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

impl Arbitrary for MastForest {
    type Parameters = MastForestParams;
    type Strategy = BoxedStrategy<Self>;

    /// Generates a `MastForest` with the specified parameters.
    ///
    /// # Generated forest properties
    ///
    /// - **Basic blocks**: always generated (`1..=blocks.end()`) with operations.
    /// - **Control flow nodes**: generated according to the `max_*` parameters; any given count
    ///   may be `0` for a particular sample.
    /// - **Root nodes**: a non-empty subset of the generated nodes is marked as procedure roots,
    ///   so downstream externals and syscalls always have at least one valid callee to target.
    ///
    /// # Executability guarantees
    ///
    /// When `params.mode` is [`MastForestGenerationMode::Executable`] (the default), every
    /// emitted sample satisfies the four closure invariants documented on
    /// [`MastForestParams`]:
    ///
    /// 1. No dyn nodes are emitted (regardless of `max_dyns`).
    /// 2. Every external's digest equals a procedure root already present in the forest
    ///    (external-resolution).
    /// 3. The external call graph over procedure roots is acyclic (external-acyclicity).
    /// 4. Every syscall callee is a procedure root whose MAST root is a member of the paired
    ///    kernel (kernel-closure).
    ///
    /// This `arbitrary_with` strategy yields only the forest. Callers that need the paired
    /// kernel — required to actually execute the forest on the VM — should use the
    /// `(MastForest, Kernel)` strategy exposed alongside [`MastForestParams`] in this module.
    ///
    /// When `params.mode` is [`MastForestGenerationMode::StructureOnly`], none of the
    /// closure invariants are enforced: syscalls may target arbitrary callees with random
    /// digests, externals use randomly generated digests, and both `DynNode::new_dyn` and
    /// `DynNode::new_dyncall` variants may be emitted up to `max_dyns`. Forests produced in
    /// this mode are appropriate for serialization, merging, and pretty-printing tests but are
    /// not guaranteed to execute.
    ///
    /// # Future work — MASM-level dyn generation
    ///
    /// Dyn nodes remain unsupported in `Executable` mode because the MAST-level generator
    /// cannot synthesise valid operand-stack preconditions for the callee digest that each
    /// dyn/dyncall reads off the stack at runtime. An assembly-level (MASM) generator — which
    /// can emit instruction sequences that push a valid digest before each dyn/dyncall — is
    /// the intended future extension for producing executable forests with dyn coverage.
    /// Until then, callers should keep `max_dyns = 0` in `Executable` mode or opt into
    /// `StructureOnly` mode for structural (non-executing) tests.
    ///
    /// # Example usage
    ///
    /// ```rust
    /// use miden_core::mast::{MastForest, arbitrary::MastForestParams};
    /// use proptest::arbitrary::Arbitrary;
    ///
    /// // Executable forest (default mode).
    /// let forest = MastForest::arbitrary_with(MastForestParams::default());
    ///
    /// // Structure-only forest, e.g. for serialization tests.
    /// let params = MastForestParams {
    ///     mode: miden_core::mast::arbitrary::MastForestGenerationMode::StructureOnly,
    ///     max_syscalls: 2,
    ///     max_externals: 1,
    ///     max_dyns: 1,
    ///     ..Default::default()
    /// };
    /// let forest = MastForest::arbitrary_with(params);
    /// ```
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        let bb_params = BasicBlockNodeParams { ..Default::default() };

        // Generate nodes in a way that respects topological ordering
        (
            // Generate basic blocks first (they have no dependencies)
            prop::collection::vec(any_with::<BasicBlockNode>(bb_params), 1..=*params.blocks.end()),
            // Generate control flow node counts within the specified limits
            (
                // Generate number of join nodes (0 to max_joins)
                0..=params.max_joins,
                // Generate number of split nodes (0 to max_splits)
                0..=params.max_splits,
                // Generate number of loop nodes (0 to max_loops)
                0..=params.max_loops,
                // Generate number of call nodes (0 to max_calls)
                0..=params.max_calls,
                // Generate number of syscall nodes (0 to max_syscalls)
                0..=params.max_syscalls,
                // Generate number of external nodes (0 to max_externals)
                0..=params.max_externals,
                // Generate number of dyn nodes (0 to max_dyns)
                0..=params.max_dyns,
            ),
        )
            .prop_flat_map(
                move |(
                    basic_blocks,
                    (
                        num_joins,
                        num_splits,
                        num_loops,
                        num_calls,
                        num_syscalls,
                        num_externals,
                        num_dyns,
                    ),
                )| {
                    let num_basic_blocks = basic_blocks.len();

                    // Ensure we have enough basic blocks for parents to reference
                    let max_parent_nodes = num_basic_blocks.saturating_sub(1);
                    let num_joins = num_joins.min(max_parent_nodes);
                    let num_splits = num_splits.min(max_parent_nodes);
                    let num_loops = num_loops.min(num_basic_blocks);
                    let num_calls = num_calls.min(num_basic_blocks);
                    let num_syscalls = num_syscalls.min(num_basic_blocks);

                    // Generate indices for creating parent nodes
                    (
                        Just(basic_blocks),
                        Just((
                            num_joins,
                            num_splits,
                            num_loops,
                            num_calls,
                            num_syscalls,
                            num_externals,
                            num_dyns,
                        )),
                        // Generate indices for join nodes (need 2 children each)
                        prop::collection::vec(any::<(usize, usize)>(), num_joins..=num_joins)
                            .prop_map(move |pairs| {
                                pairs
                                    .into_iter()
                                    .map(|(a, b)| (a % num_basic_blocks, b % num_basic_blocks))
                                    .collect::<Vec<_>>()
                            }),
                        // Generate indices for split nodes (need 2 children each)
                        prop::collection::vec(any::<(usize, usize)>(), num_splits..=num_splits)
                            .prop_map(move |pairs| {
                                pairs
                                    .into_iter()
                                    .map(|(a, b)| (a % num_basic_blocks, b % num_basic_blocks))
                                    .collect::<Vec<_>>()
                            }),
                        // Generate indices for loop nodes (need 1 child each)
                        prop::collection::vec(any::<usize>(), num_loops..=num_loops).prop_map(
                            move |indices| {
                                indices
                                    .into_iter()
                                    .map(|i| i % num_basic_blocks)
                                    .collect::<Vec<_>>()
                            },
                        ),
                        // Generate indices for call nodes (need 1 child each)
                        prop::collection::vec(any::<usize>(), num_calls..=num_calls).prop_map(
                            move |indices| {
                                indices
                                    .into_iter()
                                    .map(|i| i % num_basic_blocks)
                                    .collect::<Vec<_>>()
                            },
                        ),
                        // Generate indices for syscall nodes (need 1 child each)
                        prop::collection::vec(any::<usize>(), num_syscalls..=num_syscalls)
                            .prop_map(move |indices| {
                                indices
                                    .into_iter()
                                    .map(|i| i % num_basic_blocks)
                                    .collect::<Vec<_>>()
                            }),
                        // Generate digests for external nodes
                        prop::collection::vec(any::<[u64; 4]>(), num_externals..=num_externals)
                            .prop_map(move |digests| {
                                digests
                                    .into_iter()
                                    .map(|[a, b, c, d]| {
                                        Word::from([
                                            Felt::new_unchecked(a),
                                            Felt::new_unchecked(b),
                                            Felt::new_unchecked(c),
                                            Felt::new_unchecked(d),
                                        ])
                                    })
                                    .collect::<Vec<_>>()
                            }),
                    )
                },
            )
            .prop_map(
                move |(
                    basic_blocks,
                    (
                        _num_joins,
                        _num_splits,
                        _num_loops,
                        _num_calls,
                        _num_syscalls,
                        _num_externals,
                        num_dyns,
                    ),
                    join_pairs,
                    split_pairs,
                    loop_indices,
                    call_indices,
                    syscall_indices,
                    external_digests,
                )| {
                    let mut forest = DenseMastForestBuilder::new();
                    let empty_forest = MastForest::new();

                    // 2) Add basic blocks and collect their IDs
                    let mut basic_block_ids = Vec::new();
                    for block in basic_blocks {
                        let builder = block.to_builder(&empty_forest);
                        let node_id = forest.push_node(builder).expect("Failed to add block");
                        basic_block_ids.push(node_id);
                    }

                    // 3) Add control flow nodes in topological order (children already exist)
                    let mut all_node_ids = basic_block_ids.clone();

                    // Add join nodes
                    for &(left_idx, right_idx) in &join_pairs {
                        if left_idx < all_node_ids.len() && right_idx < all_node_ids.len() {
                            let left_id = all_node_ids[left_idx];
                            let right_id = all_node_ids[right_idx];
                            if let Ok(join_id) =
                                forest.push_node(JoinNodeBuilder::new([left_id, right_id]))
                            {
                                all_node_ids.push(join_id);
                            }
                        }
                    }

                    // Add split nodes
                    for &(true_idx, false_idx) in &split_pairs {
                        if true_idx < all_node_ids.len() && false_idx < all_node_ids.len() {
                            let true_id = all_node_ids[true_idx];
                            let false_id = all_node_ids[false_idx];
                            if let Ok(split_id) =
                                forest.push_node(SplitNodeBuilder::new([true_id, false_id]))
                            {
                                all_node_ids.push(split_id);
                            }
                        }
                    }

                    // Add loop nodes
                    for &body_idx in &loop_indices {
                        if body_idx < all_node_ids.len() {
                            let body_id = all_node_ids[body_idx];
                            if let Ok(loop_id) = forest.push_node(LoopNodeBuilder::new(body_id)) {
                                all_node_ids.push(loop_id);
                            }
                        }
                    }

                    // Add call nodes
                    for &callee_idx in &call_indices {
                        if callee_idx < all_node_ids.len() {
                            let callee_id = all_node_ids[callee_idx];
                            let call_id =
                                forest.push_node(CallNodeBuilder::new(callee_id)).unwrap();
                            all_node_ids.push(call_id);
                        }
                    }

                    // Add syscall nodes
                    // WARNING: These use random procedure digests and will not execute without a
                    // matching kernel
                    for &callee_idx in &syscall_indices {
                        if callee_idx < all_node_ids.len() {
                            let callee_id = all_node_ids[callee_idx];
                            let syscall_id =
                                forest.push_node(CallNodeBuilder::new_syscall(callee_id)).unwrap();
                            all_node_ids.push(syscall_id);
                        }
                    }

                    // Add external nodes
                    // WARNING: These use random digests that won't match any valid procedures
                    let mut external_digest_set = BTreeSet::new();
                    for digest in external_digests {
                        if !external_digest_set.insert(digest) {
                            continue;
                        }

                        if let Ok(external_id) = forest.push_node(ExternalNodeBuilder::new(digest))
                        {
                            all_node_ids.push(external_id);
                        }
                    }

                    // Add dyn nodes (mix of dyn and dyncall)
                    // WARNING: These leave junk on the stack and cannot execute properly
                    for i in 0..num_dyns {
                        let dyn_id = if i % 2 == 0 {
                            forest.push_node(DynNodeBuilder::new_dyn()).unwrap()
                        } else {
                            forest.push_node(DynNodeBuilder::new_dyncall()).unwrap()
                        };
                        all_node_ids.push(dyn_id);
                    }

                    // 4) Make some nodes roots (but not all, to test internal nodes)
                    let num_roots = (all_node_ids.len() / 3).max(1); // Make roughly 1/3 of nodes roots
                    let mut root_digest_set = BTreeSet::new();
                    for (i, &node_id) in all_node_ids.iter().enumerate() {
                        if i % (all_node_ids.len() / num_roots.max(1)) == 0
                            && root_digest_set
                                .insert(forest.get_node_by_id(node_id).unwrap().digest())
                        {
                            forest.mark_root(node_id);
                        }
                    }

                    forest.finish().expect("generated MAST forest should be valid")
                },
            )
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
