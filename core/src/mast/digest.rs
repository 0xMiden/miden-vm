use alloc::vec::Vec;

use crate::{
    Word,
    chiplets::hasher,
    mast::{CallNode, DynNode, JoinNode, LoopNode, OpBatch, SplitNode},
};

pub(super) fn basic_block_digest(op_batches: &[OpBatch]) -> Word {
    let op_groups = op_batches.iter().flat_map(|batch| *batch.groups()).collect::<Vec<_>>();
    hasher::hash_elements(&op_groups)
}

pub(super) fn join_digest(left: Word, right: Word) -> Word {
    hasher::merge_in_domain(&[left, right], JoinNode::DOMAIN)
}

pub(super) fn split_digest(on_true: Word, on_false: Word) -> Word {
    hasher::merge_in_domain(&[on_true, on_false], SplitNode::DOMAIN)
}

pub(super) fn loop_digest(body: Word) -> Word {
    hasher::merge_in_domain(&[body, Word::default()], LoopNode::DOMAIN)
}

pub(super) fn call_digest(callee: Word, is_syscall: bool) -> Word {
    let domain = if is_syscall {
        CallNode::SYSCALL_DOMAIN
    } else {
        CallNode::CALL_DOMAIN
    };
    hasher::merge_in_domain(&[callee, Word::default()], domain)
}

pub(super) fn dyn_digest(is_dyncall: bool) -> Word {
    if is_dyncall {
        DynNode::DYNCALL_DEFAULT_DIGEST
    } else {
        DynNode::DYN_DEFAULT_DIGEST
    }
}
