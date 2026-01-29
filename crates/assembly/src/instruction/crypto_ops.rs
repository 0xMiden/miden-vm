use miden_core::{
    Felt, Operation::*, ZERO, field::PrimeCharacteristicRing, sys_events::SystemEvent,
};

use super::BasicBlockBuilder;
use crate::Report;

// HASHING
// ================================================================================================

/// Appends HPERM and stack manipulation operations to compute a 1-to-1 Poseidon2 hash.
///
/// - Input:   the top 4 elements are the word `A` to be hashed.
/// - Output:  the middle 4 elements are the digest word.
///
/// Internally, this prepares the top 12 elements as a Poseidon2 state in `[RATE0, RATE1, CAPACITY]`
/// layout, calls `hperm`, and then extracts the digest using squeeze_digest pattern.
///
/// This operation takes 19 VM cycles.
pub(super) fn hash(block_builder: &mut BasicBlockBuilder) {
    #[rustfmt::skip]
    let ops = [
        // Add a zero word to serve as RATE1.
        // => [0, A, ...]
        Pad, Pad, Pad, Pad,

        // Add capacity word [4, 0, 0, 0] on top.
        // => [[4,0,0,0], 0, A, ...]  i.e. [CAP, RATE1, RATE0]
        Pad, Pad, Pad, Push(Felt::from_u32(4_u32)),

        // Reorder to [RATE0, RATE1, CAP] required by hperm:
        // => [A, 0, [4,0,0,0], ...]
        SwapW2,

        // Apply hperm.
        // => [RATE0', RATE1', CAP', ...]
        HPerm,

        // Extract digest (RATE0')
        // => [CAP', RATE1', RATE0', ...]
        SwapW2,
        // => [RATE1', RATE0', ...]
        Drop, Drop, Drop, Drop,
        // => [RATE0', ...]  (the digest)
        Drop, Drop, Drop, Drop,
    ];
    block_builder.push_ops(ops);
}

/// Appends HPERM and stack manipulation operations to the span block as required to compute a
/// 2-to-1 Poseidon2 hash using the canonical `[RATE0, RATE1, CAPACITY]` state layout.
///
/// - Input:   the top 8 elements form the 2-word preimage `[A, B]` in stack order (A on top).
/// - Output:  the middle 4 elements are the digest word, which is `hash(A, B)`.
///
/// Internally, this:
/// 1. Pads a zero capacity word so the top 12 elements are `[CAP, A, B]`.
/// 2. Reorders words to `[A, B, CAP]` required by `hperm`.
/// 3. Applies `hperm` (Poseidon2 permutation) on the top 12 elements.
/// 4. Extracts the digest.
///
/// This operation takes 16 VM cycles.
pub(super) fn hmerge(block_builder: &mut BasicBlockBuilder) {
    #[rustfmt::skip]
    let ops = [
        // Add a zero word to serve as CAPACITY.
        // => [0, A, B, ...]
        Pad, Pad, Pad, Pad,

        // Reorder [CAP, A, B] to [A, B, CAP] required by hperm:
        // => [B, A, 0, ...]
        SwapW2,
        // => [A, B, 0, ...]
        SwapW,

        // Apply hperm.
        // => [A', B', CAP', ...]  where A' contains the digest
        HPerm,

        // Extract digest (A')
        // => [CAP', B', A', ...]
        SwapW2,
        // => [B', A', ...]
        Drop, Drop, Drop, Drop,
        // => [A', ...]  (the digest)
        Drop, Drop, Drop, Drop,
    ];
    block_builder.push_ops(ops);
}

// MERKLE TREES
// ================================================================================================

/// Appends the MPVERIFY op and stack manipulations to the span block as required to verify that a
/// Merkle tree with root R opens to node V at depth d and index i. The stack is expected to be
/// arranged as follows (from the top):
/// - depth of the node, 1 element
/// - index of the node, 1 element
/// - current root of the tree, 4 elements
///
/// After the operations are executed, the stack will be arranged as follows:
/// - node V, 4 elements
/// - root of the tree, 4 elements.
///
/// This operation takes 10 VM cycles.
pub(super) fn mtree_get(block_builder: &mut BasicBlockBuilder) {
    // stack: [d, i, R, ...]
    // pops the value of the node we are looking for from the advice stack
    read_mtree_node(block_builder);
    #[rustfmt::skip]
    let ops = [
        // verify the node V for root R with depth d and index i
        // => [V, d, i, R, ...]
        MpVerify(ZERO),

        // move d, i back to the top of the stack and are dropped since they are
        // no longer needed => [V, R, ...]
        MovUp4, Drop, MovUp4, Drop,
    ];
    block_builder.push_ops(ops);
}

/// Appends the MRUPDATE op with a parameter of "false" and stack manipulations to the span block
/// as required to update a node in the Merkle tree with root R at depth d and index i to value V.
/// The stack is expected to be arranged as follows (from the top):
/// - depth of the node, 1 element
/// - index of the node, 1 element
/// - current root of the tree, 4 elements
/// - new value of the node, 4 element
///
/// After the operations are executed, the stack will be arranged as follows:
/// - old value of the node, 4 elements
/// - new root of the tree after the update, 4 elements
///
/// This operation takes 30 VM cycles.
pub(super) fn mtree_set(block_builder: &mut BasicBlockBuilder) -> Result<(), Report> {
    // stack: [d, i, R_old, V_new, ...]

    // stack: [V_old, R_new, ...] (30 cycles)
    update_mtree(block_builder)
}

/// Creates a new Merkle tree in the advice provider by combining trees with the specified roots.
/// The stack is expected to be arranged as follows (from the top):
/// - root of the right tree, 4 elements
/// - root of the left tree, 4 elements
///
/// The operation will merge the Merkle trees with the provided roots, producing a new merged root
/// with incremented depth. After the operations are executed, the stack will be arranged as
/// follows:
/// - merged root, 4 elements
///
/// It is not checked whether the provided roots exist as Merkle trees in the advide providers.
///
/// This operation takes 16 VM cycles.
pub(super) fn mtree_merge(block_builder: &mut BasicBlockBuilder) {
    // stack input:  [R_rhs, R_lhs, ...]
    // stack output: [R_merged, ...]

    // invoke the advice provider function to merge 2 Merkle trees defined by the roots on the top
    // of the operand stack
    block_builder.push_system_event(SystemEvent::MerkleNodeMerge);

    // perform the `hmerge`, updating the operand stack
    hmerge(block_builder)
}

// MERKLE TREES - HELPERS
// ================================================================================================

/// This is a helper function for assembly operations that fetches the node value from the
/// Merkle tree using decorators and pushes it onto the stack. It prepares the stack with the
/// elements expected by the VM's MPVERIFY & MRUPDATE operations.
/// The stack is expected to be arranged as follows (from the top):
/// - depth of the node, 1 element
/// - index of the node, 1 element
/// - root of the Merkle tree, 4 elements
/// - new value of the node, 4 elements (only in the case of mtree_set)
///
/// After the operations are executed, the stack will be arranged as follows:
/// - old value of the node, 4 elements
/// - depth of the node, 1 element
/// - index of the node, 1 element
/// - root of the Merkle tree, 4 elements
/// - new value of the node, 4 elements (only in the case of mtree_set)
///
/// This operation takes 5 VM cycles.
fn read_mtree_node(block_builder: &mut BasicBlockBuilder) {
    // The stack should be arranged in the following way: [d, i, R, ...] so that the decorator
    // can fetch the node value from the root. In the `mtree.get` operation we have the stack in
    // the following format: [d, i, R], whereas in the case of `mtree.set` we would also have the
    // new node value post the tree root: [d, i, R, V_new]
    //
    // Push the value of the node we are looking for onto the advice stack
    block_builder.push_system_event(SystemEvent::MerkleNodeToStack);

    // Allocate space for the word and pop from advice stack
    // => MPVERIFY: [V_old, d, i, R, ...]
    // => MRUPDATE: [V_old, d, i, R, V_new, ...]
    block_builder.push_op_many(Pad, 4);
    block_builder.push_op(AdvPopW);
}

/// Update a node in the merkle tree. This operation will always copy the tree into a new instance,
/// and perform the mutation on the copied tree.
///
/// This operation takes 30 VM cycles.
fn update_mtree(block_builder: &mut BasicBlockBuilder) -> Result<(), Report> {
    // stack: [d, i, R_old, V_new, ...]
    // output: [R_new, R_old, V_new, V_old, ...]

    // Inject the old node value onto the stack for the call to MRUPDATE.
    // stack: [V_old, d, i, R_old, V_new, ...] (5 cycles)
    read_mtree_node(block_builder);

    #[rustfmt::skip]
    let ops = [
        // NOTE: The stack is 14 elements deep already. The existing ops manipulate up to depth 16,
        // so it's only possible to copy 2-elements at a time.
        //
        // We conceptually treat each 4‑FELT block as a structural / little‑endian word:
        //   - V_old  = o = [o0, o1, o2, o3]
        //   - R_old  = r = [r0, r1, r2, r3]
        //   - V_new  = n = [n0, n1, n2, n3]
        //
        // After `read_mtree_node`, the stack (top-first, grouped in words) is:
        //   stack: [[o0, o1, o2, o3], [d, i, r0, r1], [r2, r3, n0, n1], n2, n3, ...]
        //
        // The sequence below:
        //   - duplicates V_old so it is available both for `MrUpdate` and for the final
        //     `[V_old, R_new, ...]` result,
        //   - rearranges the stack to match `MrUpdate`'s expected inputs,
        //   - then drops intermediate values to leave `[V_old, R_new, ...]`.

        // Move i then d up
        // stack: [[d, i, o0, o1], [o2, o3, r0, r1], [r2, r3, n0, n1], n2, n3, ...]
        MovUp5, MovUp5,

        // Copy half of the word, o0 then o1 (using structural indexing)
        // stack: [[o2, o3, d, i], [o0, o1, o2, o3], [r0, r1, r2, r3], [n0, n1, n2, n3], ...]
        Dup5, Dup5,

        // Move the data down
        // stack: [[o2, o3, d, i], [r0, r1, r2, r3], [n0, n1, n2, n3], [o0, o1, o2, o3], ...]
        SwapDW, SwapW, SwapW2,

        // Copy the other half of the word, o2 then o3
        // stack: [[o0, o1, o2, o3], [d, i, r0, r1], [r2, r3, n0, n1,] [n2, n3, o0, o1], o2, o3, ...]
        Dup13, Dup13,

        // Update the Merkle tree
        // ========================================================================================

        // Update the node at depth `d` and position `i`. It will always copy the Merkle tree.
        // stack: [R_new, d, i, R_old, V_new, V_old, ...]
        MrUpdate,

        // Drop unecessary values
        // ========================================================================================

        // drop d and i since they are no longer needed
        // stack: [R_new, R_old, V_new, V_old, ...]
        MovUp4, Drop, MovUp4, Drop,

        // drop old Merkle root from the stack
        // stack: [R_new, V_new, V_old, ...]
        SwapW, Drop, Drop, Drop, Drop,

        // drop new value from stack
        // stack: [R_new, V_old, ...]
        SwapW, Drop, Drop, Drop, Drop,

        // move the V_old to the front
        // stack: [V_old, R_new, ...]
        SwapW
    ];

    // stack: [V_old, R_new, ...] (25 cycles)
    block_builder.push_ops(ops);

    Ok(())
}
