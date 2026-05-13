use crate::Felt;

/// A 4-felt opaque tag identifying a deferred node. Tags are not interpreted by `miden-core` or
/// by the processor — the installed [`crate::deferred::Schema`](crate::deferred) imposes any
/// structure (type prefix, op suffix, kind, …) it needs.
pub type Tag = [Felt; 4];
