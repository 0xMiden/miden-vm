use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use super::{
    DeferredError, DeferredStateWire, Digest, IntegrityError, Node, NodeType, Payload,
    PrecompileError, PrecompileRegistry, TRUE_DIGEST, Tag,
};

/// In-memory deferred-DAG state — the verifier's witness.
///
/// State fields:
/// - `nodes`: in-memory node store, written by `register`/`register_chunk`/`log` (user-declared),
///   by [`WitnessBuilder::intern`] (precompile-minted children), and by evaluation (computed
///   canonicals). Not every node is necessarily reachable from `root`. [`Self::to_wire`] emits only
///   the root-reachable closure.
/// - `evals`: host-side evaluation memo mapping `input_digest -> canonical`. Seeded with
///   `TRUE_DIGEST -> Node::TRUE` (terminal sentinel) and reused across evaluate calls. Not
///   serialized to wire.
/// - `root`: the transcript root pointer. Initial value [`super::TRUE_DIGEST`]; advanced by
///   [`Self::log`], which interns an AND-node `{tag: Tag::TRUE, payload: prev_root || stmnt}` and
///   updates the root pointer. Reducing root to TRUE is the verifier's single check.
///
/// This in-memory form does **not** travel in the proof. [`Self::to_wire`] lowers it to the
/// passive [`DeferredStateWire`] (index-encoded, root derived from the last entry); that wire is
/// what ships, and the verifier reconstructs a validated `DeferredState` from it via
/// [`Self::rehydrate`]. Untrusted bytes therefore only ever become a state through the
/// schema-checked, chain-walked rehydrate path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredState {
    nodes: BTreeMap<Digest, Node>,
    root: Digest,
    evals: BTreeMap<Digest, Node>,
}

impl Default for DeferredState {
    fn default() -> Self {
        let mut evals = BTreeMap::new();
        evals.insert(TRUE_DIGEST, Node::TRUE);
        Self {
            nodes: BTreeMap::new(),
            root: TRUE_DIGEST,
            evals,
        }
    }
}

impl DeferredState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the node stored under `digest`, or [`PrecompileError::MissingNode`] if no such
    /// node has been registered. Returning a `Result` lets precompile reducers propagate the
    /// missing-node case with `?` instead of unwrapping an `Option`.
    pub fn get(&self, digest: &Digest) -> Result<&Node, PrecompileError> {
        self.nodes.get(digest).ok_or(PrecompileError::MissingNode)
    }

    /// Returns whether `digest` names a wire-committed node — i.e. one that ships in `to_wire`.
    /// [`TRUE_DIGEST`] is the framework sentinel and is never materialized in `nodes`, so this
    /// returns `false` for it; call sites that need to treat TRUE as a virtual member explicitly
    /// short-circuit on `d == TRUE_DIGEST` first.
    pub fn contains(&self, digest: &Digest) -> bool {
        self.nodes.contains_key(digest)
    }

    /// Inserts `node` into the wire-committed DAG keyed by its Poseidon2 digest. Returns the
    /// digest. Idempotent on identical `(digest, node)` pairs.
    ///
    /// Internal: external callers go through the schema-aware [`Self::register`] /
    /// [`Self::evaluate`] / [`Self::log`] entry points, which preserve the type invariants. Raw
    /// `intern` bypasses tag-validation and root-shape checks.
    pub(crate) fn intern(&mut self, node: Node) -> Digest {
        let digest = node.digest();
        self.nodes.insert(digest, node);
        digest
    }

    pub fn nodes(&self) -> &BTreeMap<Digest, Node> {
        &self.nodes
    }

    fn get_eval(&self, digest: &Digest) -> Option<&Node> {
        self.evals.get(digest)
    }

    /// Memoize `input_digest -> canonical` in `evals` and intern the canonical into `nodes` so it
    /// is addressable as a child. Orphan canonicals are trimmed by [`Self::to_wire`].
    fn record_eval(&mut self, input_digest: Digest, canonical: Node) {
        self.evals.insert(input_digest, canonical.clone());
        self.intern(canonical);
    }

    /// Returns the current transcript root pointer. Initial value is [`super::TRUE_DIGEST`].
    /// Advanced exclusively by [`Self::log`] — no external API mutates this field directly.
    pub fn root(&self) -> Digest {
        self.root
    }

    /// Advance the transcript root by one AND-step.
    ///
    /// Interns `AND(self.root, stmt_digest)` and updates `root` to its digest. The caller passes
    /// `expected_new_root` so the host-side and in-circuit hashers can be cross-checked: if they
    /// disagree the call fails with [`super::DeferredError::InvalidPayload`] and the state is
    /// left untouched (no node interned, root unchanged).
    ///
    /// The caller is responsible for having previously `evaluate`-d the statement (the prover does
    /// this via `DeferredEvaluate`); this method does not re-run reduce. Statement-validity is
    /// re-established on the verifier side by `DeferredState::rehydrate` (introduced in a later
    /// step), which walks the chain and evaluates each statement.
    pub fn log(
        &mut self,
        stmt_digest: Digest,
        expected_new_root: Digest,
    ) -> Result<(), DeferredError> {
        let and_node = Node::and(self.root, stmt_digest);
        let actual = and_node.digest();
        if actual != expected_new_root {
            return Err(DeferredError::InvalidPayload);
        }
        self.nodes.insert(actual, and_node);
        self.root = actual;
        Ok(())
    }

    /// Register an opaque node, asking `precompiles` to decode its tag.
    ///
    /// The node's payload variant must match `decode(tag).body`, otherwise
    /// [`PrecompileError::InvalidNode`] is surfaced. The node is interned into the DAG by its
    /// Poseidon2 digest. Re-registering an identical `(digest, node)` pair is silently
    /// idempotent.
    ///
    /// Paired with [`Self::evaluate`] — together they back the `DeferredRegister` and
    /// `DeferredEvaluate` system events. `register` is the cheap "commit this node to the wire"
    /// step that returns a digest the caller can chain into downstream nodes (as an operand of
    /// a Join op, or as a statement passed to [`Self::log`]); `evaluate` is the recursive
    /// reduce on an already-registered node. Splitting them lets the caller declare children
    /// without forcing a reduce, and lets the verifier re-run identical paths during rehydrate.
    ///
    /// Predicate tags are *not* verified at registration — register is a pure host hint that
    /// only populates the DAG. Verification is explicit: either host-side via [`Self::evaluate`],
    /// or constrained via [`Self::log`].
    pub fn register(
        &mut self,
        precompiles: &PrecompileRegistry,
        node: Node,
    ) -> Result<Digest, PrecompileError> {
        let node_type = precompiles.decode(node.tag)?;
        if !payload_matches_type(node_type, &node.payload) {
            return Err(PrecompileError::InvalidNode);
        }
        let digest = node.digest();
        self.nodes.insert(digest, node);
        Ok(digest)
    }

    /// Evaluate an opaque node via the precompile registry.
    ///
    /// Reduces to canonical form per `PrecompileRegistry::reduce`. Computed canonicals are
    /// memoized in `evals` and interned into `nodes` (see `record_eval`).
    ///
    /// For a predicate tag, success returns [`Node::TRUE`] (detectable via
    /// [`Node::is_true_node`]) and a mismatch surfaces as [`PrecompileError::AssertionFailed`].
    ///
    /// Transitively-referenced child digests must resolve through `nodes` (registered upstream)
    /// or the state `evals` memo (cached from this or earlier evaluate calls) — an unknown
    /// child digest surfaces as [`PrecompileError::MissingNode`]. The processor-side handler
    /// returns the canonical's `tag || payload` felts on the advice stack for the caller to
    /// re-hash in-circuit.
    pub fn evaluate(
        &mut self,
        precompiles: &PrecompileRegistry,
        node: Node,
    ) -> Result<Node, PrecompileError> {
        let node_type = precompiles.decode(node.tag)?;
        if !payload_matches_type(node_type, &node.payload) {
            return Err(PrecompileError::InvalidNode);
        }
        WitnessBuilder::new(self, precompiles).eval(node)
    }

    /// Evaluate a node addressed by digest.
    ///
    /// Lookup order is `evals` first, then `nodes`:
    /// - if `digest` exists in `evals`, returns the cached canonical directly;
    /// - otherwise, loads the input node from `nodes` and reduces it via [`Self::evaluate`].
    ///
    /// Returns [`PrecompileError::MissingNode`] when the digest is unknown to both stores.
    pub fn evaluate_digest(
        &mut self,
        precompiles: &PrecompileRegistry,
        digest: Digest,
    ) -> Result<Node, PrecompileError> {
        if let Some(canonical) = self.get_eval(&digest) {
            return Ok(canonical.clone());
        }
        let node = self.get(&digest)?.clone();
        self.evaluate(precompiles, node)
    }

    /// Serialize this state to its wire form. Walks reachable nodes from `root` in DFS
    /// post-order, assigning each visited node a `u32` index in emission order. `Join`-shape
    /// entries encode their children as indices into the earlier wire entries (or
    /// [`crate::deferred::TRUE_INDEX`] for the [`TRUE_DIGEST`] terminal). Any nodes outside the
    /// root-reachable closure (e.g. registered or evaluation-interned orphans) are dropped.
    ///
    /// Reachability is computed *structurally*, without consulting the schema: for any node
    /// with an `Expression` payload, interpret the 8 felts as `(lhs_digest, rhs_digest)`. If
    /// both digests resolve in `self.nodes` (or are [`TRUE_DIGEST`]), the encoder treats the
    /// node as Join and emits indices; otherwise it falls back to `Value` (raw felts). Real
    /// Join children are always registered (the user pre-registers operands before logging),
    /// so the heuristic never misses one. False positives — a `Value` leaf whose 8 payload felts
    /// happen to coincide with the digests of two registered nodes — round-trip safely because
    /// the reconstructed payload bytes are byte-identical.
    pub fn to_wire(&self) -> DeferredStateWire {
        let mut by_digest = BTreeMap::<Digest, u32>::new();
        let mut entries = Vec::<super::WireEntry>::new();
        self.dfs_post_order(self.root, &mut by_digest, &mut entries);
        // DFS post-order from `self.root` emits the AND-node digesting to `self.root` last (or
        // emits nothing when root is `TRUE_DIGEST`). The deferred commitment is therefore
        // recoverable as `entries.last().digest()` — no need to ship it as a field.
        DeferredStateWire { entries }
    }

    /// Internal DFS post-order helper for [`Self::to_wire`]. Recursive; for the DAG shapes
    /// produced by `register`/`evaluate`/`log` this is bounded by the depth of the expression
    /// tree, which is well within Rust's default stack budget.
    fn dfs_post_order(
        &self,
        d: Digest,
        by_digest: &mut BTreeMap<Digest, u32>,
        entries: &mut Vec<super::WireEntry>,
    ) {
        if d == TRUE_DIGEST || by_digest.contains_key(&d) {
            return;
        }
        let Some(node) = self.nodes.get(&d) else {
            // Reachable digest with no interned node — bare statement commitment in the
            // production precompile-transcript model. The wire doesn't carry it; the precompile
            // verifier registry validates it externally.
            return;
        };

        // Determine whether this is a real Join node (children resolve) or a Value-shaped
        // node. For Chunk bodies, no children to recurse into.
        let mut binary_indices: Option<(Digest, Digest)> = None;
        if let Ok((lhs, rhs)) = node.payload.join_children() {
            let lhs_ok = lhs == TRUE_DIGEST || self.nodes.contains_key(&lhs);
            let rhs_ok = rhs == TRUE_DIGEST || self.nodes.contains_key(&rhs);
            if lhs_ok && rhs_ok {
                // Recurse into children first so they receive lower indices.
                self.dfs_post_order(lhs, by_digest, entries);
                self.dfs_post_order(rhs, by_digest, entries);
                binary_indices = Some((lhs, rhs));
            }
        }

        let idx = entries.len() as u32;
        by_digest.insert(d, idx);

        let body = match (&node.payload, binary_indices) {
            (Payload::Chunk(chunks), _) => super::WireBody::Chunks(chunks.clone()),
            (Payload::Expression(felts), None) => super::WireBody::Value(*felts),
            (Payload::Expression(_), Some((lhs, rhs))) => {
                let lhs_idx = if lhs == TRUE_DIGEST {
                    super::TRUE_INDEX
                } else {
                    by_digest[&lhs]
                };
                let rhs_idx = if rhs == TRUE_DIGEST {
                    super::TRUE_INDEX
                } else {
                    by_digest[&rhs]
                };
                super::WireBody::Join { lhs: lhs_idx, rhs: rhs_idx }
            },
        };
        entries.push(super::WireEntry { tag: node.tag, body });
    }

    /// Construct a verified [`DeferredState`] from a wire-format value under the supplied
    /// `precompiles`. Re-runs the prover's validation, content-addressing, and AND-chain walk;
    /// the returned state therefore satisfies the invariants documented at the top of this
    /// module.
    ///
    /// The two phases:
    /// - **Phase 1 (structural):** read each wire entry in order, reconstruct the digest-form
    ///   [`Node`] (translating `Join` indices to the digests of earlier entries),
    ///   `precompiles.decode` the tag, and intern. Index bounds and chunk arities are validated;
    ///   `payload_matches_type` confirms the decoded [`NodeType`] is compatible with the in-memory
    ///   shape.
    /// - **Reachability:** between the phases, reject any interned entry that is not in the
    ///   structural closure of the root ([`IntegrityError::DanglingNode`]). `to_wire` emits exactly
    ///   that closure, so a faithful wire passes; this rejects bloat / hidden-data entries an
    ///   adversarial wire might smuggle in. Phase 2 may extend state `evals` only, so the `nodes`
    ///   set checked here matches the post-rehydrate state exactly.
    /// - **Phase 2 (semantic):** walk the AND-chain from `wire.root` down to
    ///   [`super::TRUE_DIGEST`], asserting each step has `tag == Tag::TRUE` and re-evaluating each
    ///   predicate statement via [`Self::evaluate`]. The walk surfaces tampered AND-payloads,
    ///   missing statements, non-predicate statements, and failed equalities.
    pub fn rehydrate(
        wire: &DeferredStateWire,
        precompiles: &PrecompileRegistry,
    ) -> Result<Self, IntegrityError> {
        let mut state = Self::new();
        // Parallel to `wire.entries`: the recomputed digest at each index. `Join` entries at
        // position `i` reconstruct their payload by reading earlier `digests[lhs/rhs]` (or
        // `TRUE_DIGEST` when the index is `TRUE_INDEX`).
        let mut digests: Vec<Digest> = Vec::with_capacity(wire.entries.len());

        for (i, entry) in wire.entries.iter().enumerate() {
            let node = match &entry.body {
                super::WireBody::Value(felts) => Node::leaf(entry.tag, *felts),
                super::WireBody::Chunks(chunks) => {
                    // The wire is untrusted: the deserializer accepts a zero-length chunk body,
                    // but empty chunk bodies are forbidden. Reject here, before `Node::chunk`
                    // (whose non-empty precondition would otherwise panic in debug builds);
                    // `payload_matches_type` below would also reject it, but only after
                    // construction.
                    if chunks.is_empty() {
                        return Err(IntegrityError::ShapeMismatch);
                    }
                    Node::chunk(entry.tag, chunks.clone())
                },
                super::WireBody::Join { lhs, rhs } => {
                    let lhs_d = resolve_index(*lhs, i, &digests)?;
                    let rhs_d = resolve_index(*rhs, i, &digests)?;
                    Node::join(entry.tag, lhs_d, rhs_d)
                },
            };

            // Validate. `decode_node_type` handles AND-nodes (framework-owned `Tag::TRUE`)
            // without invoking a precompile, then defers to `precompiles.decode` for everything
            // else. `payload_matches_type` enforces the Expression-vs-Chunk distinction (and the
            // exact chunk count for Chunks tags, which is ≥ 1 — empty chunk bodies are rejected).
            let node_type = decode_node_type(precompiles, &node)?;
            if !payload_matches_type(node_type, &node.payload) {
                return Err(IntegrityError::ShapeMismatch);
            }

            let d = state.intern(node);
            digests.push(d);
        }

        // Derive the deferred commitment from phase 1's last digest. DFS post-order from the
        // prover's `self.root` puts the topmost AND-node at the end of `entries`, so its digest
        // is the chain's head. Empty entries → trivial-empty transcript (`TRUE_DIGEST`).
        state.root = digests.last().copied().unwrap_or(TRUE_DIGEST);

        // Reachability — every interned entry must lie in the structural closure of `root`.
        // `to_wire` emits exactly that closure (DFS post-order from root), so a faithful wire
        // passes; an entry outside it is bloat or hidden data and is rejected. Done here, before
        // phase 2's evaluate re-mints canonical intermediates into `state.nodes`.
        if reachable_closure(&state.nodes, state.root).len() != state.nodes.len() {
            return Err(IntegrityError::DanglingNode);
        }

        // Phase 2 — chain walk + per-statement re-evaluation. AND-nodes share Tag::TRUE and a
        // `(prev_root, stmt_digest)` payload; statements must reduce to `Node::TRUE` under the
        // precompiles. An interior AND-node whose `prev_root` doesn't resolve in `state.nodes` (and
        // isn't `TRUE_DIGEST`) surfaces as `BrokenChain` — a tampered or corrupt transcript.
        let mut cur = state.root;
        while cur != TRUE_DIGEST {
            let and_node = state.nodes.get(&cur).ok_or(IntegrityError::BrokenChain)?.clone();
            if and_node.tag != Tag::TRUE {
                return Err(IntegrityError::NonAndNode);
            }
            let (prev_root, stmt_digest) =
                and_node.payload.join_children().map_err(|_| IntegrityError::BadAndPayload)?;
            let stmt =
                state.nodes.get(&stmt_digest).ok_or(IntegrityError::MissingStatement)?.clone();
            let canonical = state.evaluate(precompiles, stmt)?;
            if !canonical.is_true_node() {
                return Err(IntegrityError::PredicateNotTrue);
            }
            cur = prev_root;
        }

        Ok(state)
    }

    /// Walk the AND-chain from `self.root` down to [`super::TRUE_DIGEST`] and return each
    /// statement digest in execution order (oldest first). Assumes the state's chain integrity
    /// has already been established (e.g. by `rehydrate`); panics on a missing or non-AND node
    /// because that situation can't arise on a value produced by the supported constructors.
    ///
    /// Test-only: the chain walk currently has no production caller (the verifier consumes the
    /// rehydrated state directly). Gated so it isn't dead public surface.
    #[cfg(test)]
    pub fn statements(&self) -> Vec<Digest> {
        let mut out = Vec::new();
        let mut cur = self.root;
        while cur != TRUE_DIGEST {
            let and_node = self
                .nodes
                .get(&cur)
                .expect("statements(): AND-chain references a node not in state");
            debug_assert_eq!(
                and_node.tag,
                Tag::TRUE,
                "statements(): AND-chain step is not tagged Tag::TRUE"
            );
            let (prev_root, stmt_digest) = and_node
                .payload
                .join_children()
                .expect("statements(): AND-node has non-expression body");
            out.push(stmt_digest);
            cur = prev_root;
        }
        out.reverse();
        out
    }
}

// SERIALIZATION
// ================================================================================================
// `DeferredState` is intentionally NOT `Serializable` / `Deserializable`. Wire-level transit
// goes through [`DeferredStateWire`]; in-memory construction from bytes goes through
// `DeferredState::rehydrate(&wire, schema)`. This keeps the only path from untrusted bytes to
// an in-memory state through the schema-validated, chain-walked rehydrate constructor.

/// Resolve a wire `Join` child index against the digest table built so far during phase 1 of
/// rehydrate. [`super::TRUE_INDEX`] maps to [`TRUE_DIGEST`]; any other value must be a valid
/// position strictly less than the current entry (topological invariant).
fn resolve_index(idx: u32, current: usize, digests: &[Digest]) -> Result<Digest, IntegrityError> {
    if idx == super::TRUE_INDEX {
        return Ok(TRUE_DIGEST);
    }
    let i = idx as usize;
    if i >= current || i >= digests.len() {
        return Err(IntegrityError::BadIndex);
    }
    Ok(digests[i])
}

/// Decode a node's [`NodeType`] for `rehydrate`. Framework-owned `Tag::TRUE` AND-nodes are
/// classified as `Join` directly (no precompile claims id `ZERO`); everything else routes
/// through `precompiles.decode`.
fn decode_node_type(
    precompiles: &PrecompileRegistry,
    node: &Node,
) -> Result<NodeType, IntegrityError> {
    if node.tag == Tag::TRUE {
        return Ok(NodeType::Join);
    }
    precompiles.decode(node.tag).map_err(|_| IntegrityError::UnknownTag)
}

/// Returns `true` when the variant of `payload` agrees with the [`NodeType`] the schema decoded
/// for the node's tag. Construction-time invariant — handlers always build the matching variant,
/// but a hand-constructed `Node` may disagree.
///
/// `Value` and `Join` both map to `Payload::Expression` at the in-memory level — the tag is
/// the source of truth for whether the 8 felts encode raw data or two child digests, and the
/// precompile rejects payload-semantic violations inside `reduce`.
fn payload_matches_type(nt: NodeType, payload: &Payload) -> bool {
    match (nt, payload) {
        (NodeType::Value | NodeType::Join, Payload::Expression(_)) => true,
        (NodeType::Chunks(n), Payload::Chunk(chunks)) => chunks.len() == n.get() as usize,
        _ => false,
    }
}

/// Digests structurally reachable from `root` in `nodes`, using the *same* heuristic as
/// [`DeferredState::to_wire`]'s `dfs_post_order`: an Expression payload is treated as
/// `(lhs, rhs)` child digests iff both resolve in `nodes` (or are [`TRUE_DIGEST`]). AND-chain
/// links (`prev_root || stmt`) fall out of this since AND-nodes are Expression-bodied. Used by
/// [`DeferredState::rehydrate`] to reject wire entries outside the root's closure.
///
/// [`TRUE_DIGEST`] is treated as a virtual edge terminal — reachable but not materialized — so
/// the closure size matches `nodes.len()` for a faithful wire (no TRUE entry is ever emitted by
/// `to_wire`, so rehydrate must not require one in `nodes`).
fn reachable_closure(nodes: &BTreeMap<Digest, Node>, root: Digest) -> BTreeSet<Digest> {
    let mut seen = BTreeSet::new();
    let mut stack = alloc::vec![root];
    while let Some(d) = stack.pop() {
        if d == TRUE_DIGEST || !seen.insert(d) {
            continue;
        }
        let Some(node) = nodes.get(&d) else { continue };
        if let Ok((lhs, rhs)) = node.payload.join_children() {
            let lhs_ok = lhs == TRUE_DIGEST || nodes.contains_key(&lhs);
            let rhs_ok = rhs == TRUE_DIGEST || nodes.contains_key(&rhs);
            if lhs_ok && rhs_ok {
                stack.push(lhs);
                stack.push(rhs);
            }
        }
    }
    seen.remove(&TRUE_DIGEST);
    seen
}

// WITNESS BUILDER
// ================================================================================================

/// Drives the recursive reduce of a node while a
/// [`Precompile::reduce`](crate::deferred::Precompile::reduce) runs.
///
/// A precompile only supplies *per-node* semantics; it does not own the DAG. This handle is what
/// threads the [`DeferredState`] and the [`PrecompileRegistry`] registry through that call — the
/// registry by shared reference, the state by exclusive reference, bundled together so
/// [`resolve`](Self::resolve) can recurse back through `PrecompileRegistry::reduce` without an
/// aliasing-borrow problem. A precompile's `reduce` therefore reads as a depth-first recursive
/// function: "resolve lhs, resolve rhs, combine."
///
/// Three capabilities:
///
/// - [`eval`](Self::eval) reduces a concrete input node (top-level entrypoint).
/// - [`resolve`](Self::resolve) reduces a child by digest, memo-first via `state.evals`.
/// - [`intern`](Self::intern) writes a node straight to `state.nodes`.
///
/// `eval` and `resolve` go through `record_eval`, which both memoizes in
/// `evals` and interns the canonical into `nodes`. `intern` is the nodes-only primitive
/// precompiles use to mint canonical children.
///
/// The verifier re-runs the same code path during [`DeferredState::rehydrate`]'s phase 2.
/// `evals` is host-side only and never serialized.
///
/// There is exactly one of these: the prover builds the witness through it, and the verifier's
/// [`DeferredState::rehydrate`] re-runs the identical path to re-establish it — so no trait
/// abstraction over "kinds of builder" is warranted. Construction is crate-private; a precompile
/// only ever receives a `&mut WitnessBuilder` from the framework and cannot fabricate one.
pub struct WitnessBuilder<'a> {
    state: &'a mut DeferredState,
    precompiles: &'a PrecompileRegistry,
}

impl<'a> WitnessBuilder<'a> {
    /// Bind a state and the precompile registry into a witness builder. Crate-private; the
    /// public entry point is [`DeferredState::evaluate`], which hands the resulting
    /// `&mut WitnessBuilder` to `PrecompileRegistry::reduce`.
    pub(crate) fn new(state: &'a mut DeferredState, precompiles: &'a PrecompileRegistry) -> Self {
        Self { state, precompiles }
    }

    /// Top-level evaluation path for a concrete input node.
    ///
    /// Reduces `node` to canonical form via the precompile registry and records
    /// `input_digest -> canonical` in state `evals` for cross-call reuse.
    pub fn eval(&mut self, node: Node) -> Result<Node, PrecompileError> {
        let input_digest = node.digest();
        self.reduce_and_record_eval(node, input_digest)
    }

    /// Walk `digest` to its canonical form, recursively reducing it via the precompile registry.
    /// Errors with [`PrecompileError::MissingNode`] if the digest is unknown to both state `evals`
    /// and `nodes`.
    ///
    /// Memo-first: a hit in `state.evals` returns the canonical directly. On miss, looks up the
    /// input in `state.nodes`, reduces it, and records the result (see `record_eval`).
    pub fn resolve(&mut self, digest: Digest) -> Result<Node, PrecompileError> {
        if let Some(canonical) = self.state.get_eval(&digest) {
            return Ok(canonical.clone());
        }
        let child = self.state.get(&digest)?.clone();
        self.reduce_and_record_eval(child, digest)
    }

    /// Register a freshly-minted canonical child and return its digest. Used by compound
    /// canonicals whose payload references just-computed child digests (e.g. `Group::Add`
    /// minting coordinate leaves).
    ///
    /// Writes only to `state.nodes` — the `nodes` entry makes the child wire-committed so a
    /// later registered node whose payload references this child's digest will resolve cleanly
    /// on the verifier side, regardless of evaluation order across statements. The memo fills
    /// lazily on first `resolve(digest)`.
    pub fn intern(&mut self, node: Node) -> Digest {
        let digest = node.digest();
        self.state.nodes.insert(digest, node);
        digest
    }

    /// Reduce `node` to canonical form, write `input_digest → canonical` into state `evals`,
    /// and intern the canonical node into `state.nodes`.
    ///
    /// The `input_digest` is passed by the caller (rather than recomputed via `node.digest()`)
    /// so the memo write skips a redundant Poseidon2 — `resolve` already has the digest as its
    /// argument, and `evaluate` computes it once at the top of the call.
    pub(crate) fn reduce_and_record_eval(
        &mut self,
        node: Node,
        input_digest: Digest,
    ) -> Result<Node, PrecompileError> {
        let precompiles = self.precompiles;
        let canonical = precompiles.reduce(&node, self)?;
        self.state.record_eval(input_digest, canonical.clone());
        Ok(canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Felt, Word, ZERO,
        deferred::{Payload, PrecompileRegistry, TRUE_DIGEST, Tag},
        testing::precompile::Uint,
    };

    /// The single-precompile registry every engine test runs against.
    fn precompiles() -> PrecompileRegistry {
        PrecompileRegistry::default().with_precompile(Uint)
    }

    fn test_leaf(value: u32) -> Node {
        let mut limbs = [0u32; 8];
        limbs[0] = value;
        Uint::leaf_node(limbs)
    }

    fn dummy_digest(seed: u64) -> Word {
        Word::new(core::array::from_fn(|i| Felt::new_unchecked(seed + i as u64)))
    }

    #[test]
    fn empty_state_has_no_nodes_and_root_is_true() {
        let state = DeferredState::new();
        assert!(state.nodes().is_empty());
        assert_eq!(state.root(), TRUE_DIGEST);
    }

    #[test]
    fn log_advances_root_with_and_node() {
        // Logging interns AND(prev_root, stmt) and sets root to its digest.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(7)).unwrap();
        let pred = Node::join(Uint::eq_tag(), a, a);
        let stmt = state.evaluate(&schema, pred).unwrap();
        // The canonical of an `eq` predicate is `Node::TRUE`. Use the predicate's *digest* —
        // which we recover from the original node — as `stmt_digest`.
        let _ = stmt; // canonical, discarded
        let stmt_digest = Node::join(Uint::eq_tag(), a, a).digest();

        let expected = Node::and(TRUE_DIGEST, stmt_digest).digest();
        state.log(stmt_digest, expected).unwrap();
        assert_eq!(state.root(), expected);
        // The newly-minted AND-node must be in the map keyed by its digest.
        assert!(state.contains(&expected));
    }

    #[test]
    fn log_rejects_wrong_expected_root() {
        // A wrong `expected_new_root` makes `log` fail without mutating the state.
        let mut state = DeferredState::new();
        let stmt_digest = dummy_digest(7);
        let bogus_root = dummy_digest(42);
        let pre_root = state.root();
        let pre_node_count = state.nodes().len();
        let err = state.log(stmt_digest, bogus_root);
        assert!(matches!(err, Err(DeferredError::InvalidPayload)));
        assert_eq!(state.root(), pre_root, "root must remain unchanged on failure");
        assert_eq!(state.nodes().len(), pre_node_count, "no node interned on failure");
    }

    #[test]
    fn missing_node_get_returns_error() {
        let state = DeferredState::new();
        let err = state.get(&dummy_digest(1)).unwrap_err();
        assert!(matches!(err, PrecompileError::MissingNode));
    }

    #[test]
    fn register_leaf_stores_it() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let node = test_leaf(7);
        let digest = state.register(&schema, node.clone()).unwrap();
        assert_eq!(digest, node.digest());
        assert_eq!(state.get(&digest).unwrap(), &node);
    }

    #[test]
    fn idempotent_reinsert_succeeds() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let node = test_leaf(7);
        let d1 = state.register(&schema, node.clone()).unwrap();
        let d2 = state.register(&schema, node).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(state.nodes().len(), 1);
    }

    #[test]
    fn register_with_unhandled_tag_errors() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        // Uint id + unknown discriminant: schema decode returns Err.
        let bad_tag = Tag {
            id: Uint::id(),
            args: [Felt::from_u32(99), ZERO, ZERO],
        };
        let bad = Node::leaf(bad_tag, [Felt::from_u32(0); 8]);
        let err = state.register(&schema, bad);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::InvalidNode));
    }

    #[test]
    fn register_op_stores_op_node() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let op = Node::join(Uint::add_tag(), a, b);
        let digest = state.register(&schema, op).unwrap();
        assert!(state.contains(&digest));
    }

    #[test]
    fn register_predicate_does_not_verify_eagerly() {
        // `register` is a pure host hint — it interns the predicate node without driving reduce.
        // Programs that want host-side verification call `evaluate`; programs that want
        // constrained verification call `log`.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        // A mismatched predicate — would fail if eagerly verified.
        let bad = Node::join(Uint::eq_tag(), a, b);
        let bad_digest = state.register(&schema, bad.clone()).unwrap();
        assert!(state.contains(&bad_digest), "predicate interned even when it doesn't hold");
        // Verification surfaces the mismatch only when explicitly invoked.
        let err = state.evaluate(&schema, bad);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
    }

    #[test]
    fn evaluate_predicate_succeeds_returns_true_node() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(7)).unwrap();
        let assertion = Node::join(Uint::eq_tag(), a, a);
        let result = state.evaluate(&schema, assertion).unwrap();
        assert!(result.is_true_node(), "predicate success returns the canonical TRUE node");
    }

    #[test]
    fn evaluate_predicate_mismatch_errors() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let mismatch = Node::join(Uint::eq_tag(), a, b);
        let err = state.evaluate(&schema, mismatch);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
    }

    #[test]
    fn evaluate_predicate_missing_node_errors() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(1)).unwrap();
        let dangling = Word::new([Felt::from_u32(0xdead); 4]);
        let assertion = Node::join(Uint::eq_tag(), a, dangling);
        let err = state.evaluate(&schema, assertion);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::MissingNode));
    }

    #[test]
    fn nested_evaluation_reduces_through_op_tree() {
        // Build (a + b) * c, then verify equal to a pre-computed leaf via evaluate.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let c = state.register(&schema, test_leaf(5)).unwrap();
        let expected = state.register(&schema, test_leaf(35)).unwrap();
        let add = state.register(&schema, Node::join(Uint::add_tag(), a, b)).unwrap();
        let mul = state.register(&schema, Node::join(Uint::mul_tag(), add, c)).unwrap();
        let assertion = Node::join(Uint::eq_tag(), mul, expected);
        let result = state.evaluate(&schema, assertion).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn evaluate_interns_canonicals_into_nodes() {
        // Register the full op tree (a + b) * c == 35 plus an orphan leaf, evaluate the
        // predicate, and assert evaluate interns computed canonicals into `state.nodes`.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let c = state.register(&schema, test_leaf(5)).unwrap();
        let expected = state.register(&schema, test_leaf(35)).unwrap();
        let _orphan = state.register(&schema, test_leaf(99)).unwrap();
        let add = state.register(&schema, Node::join(Uint::add_tag(), a, b)).unwrap();
        let mul = state.register(&schema, Node::join(Uint::mul_tag(), add, c)).unwrap();
        let assertion = Node::join(Uint::eq_tag(), mul, expected);
        let assertion_digest = assertion.digest();
        state.evaluate(&schema, assertion).unwrap();

        // Newly interned canonicals: leaf(7) for add, and TRUE for the predicate result.
        assert_eq!(state.nodes().len(), 9);
        assert!(!state.contains(&assertion_digest), "evaluate does not auto-register input node");
        assert!(state.contains(&test_leaf(7).digest()), "canonical(add) is interned into nodes");
        assert!(state.contains(&Node::TRUE.digest()), "canonical(TRUE) is interned into nodes");
        assert_eq!(state.root(), TRUE_DIGEST, "no log called, root is still TRUE");
    }

    #[test]
    fn evaluate_does_not_intern_unregistered_input() {
        // Build (a+b)*c, pre-register only the leaves and `add`. The outer `mul` is handed
        // directly to `evaluate` — input stays out of `nodes`, but computed canonicals are
        // interned.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let c = state.register(&schema, test_leaf(5)).unwrap();
        let add = Node::join(Uint::add_tag(), a, b);
        let add_digest = state.register(&schema, add).unwrap();
        let mul = Node::join(Uint::mul_tag(), add_digest, c);
        let mul_digest = mul.digest();

        let canonical = state.evaluate(&schema, mul).unwrap();
        assert_eq!(canonical, test_leaf(35));
        assert!(!state.contains(&mul_digest), "input op stays out of nodes");
        assert!(state.contains(&test_leaf(35).digest()), "computed canonical is interned");
    }

    #[test]
    fn resolve_of_true_digest_returns_true_node() {
        // TRUE is never interned; the seeded `evals` entry is what lets `resolve` return it
        // instead of erroring on `state.get(&TRUE_DIGEST)`.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let mut witness = WitnessBuilder::new(&mut state, &schema);
        let resolved = witness.resolve(TRUE_DIGEST).unwrap();
        assert!(resolved.is_true_node());
    }

    // REHYDRATE TESTS
    // ============================================================================================

    /// Assert that `state` survives a `to_wire` → `rehydrate` round-trip: the root matches and
    /// every reproduced node agrees with the source. `rehydrate` already rejects danglers and
    /// re-evaluates each predicate, so a dropped reachable node fails inside it before we compare.
    fn assert_round_trips(state: &DeferredState, precompiles: &PrecompileRegistry) {
        let rehydrated = DeferredState::rehydrate(&state.to_wire(), precompiles).unwrap();
        assert_eq!(rehydrated.root(), state.root());
        assert!(
            rehydrated.nodes().iter().all(|(d, n)| state.nodes().get(d) == Some(n)),
            "wire round-trip changed a reachable node",
        );
    }

    /// Build a fresh state that logs `(a+b)*c == 35` as a transcript step. Returns the populated
    /// state for round-trip tests.
    fn built_state_with_logged_predicate() -> DeferredState {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let c = state.register(&schema, test_leaf(5)).unwrap();
        let expected = state.register(&schema, test_leaf(35)).unwrap();
        let add = state.register(&schema, Node::join(Uint::add_tag(), a, b)).unwrap();
        let mul = state.register(&schema, Node::join(Uint::mul_tag(), add, c)).unwrap();
        let assertion = Node::join(Uint::eq_tag(), mul, expected);
        // `log` references the predicate node by digest; pre-register so the wire embeds it as
        // a Join entry rather than a bare-commitment Value.
        let stmt_digest = state.register(&schema, assertion.clone()).unwrap();
        state.evaluate(&schema, assertion).unwrap();
        let new_root = Node::and(state.root(), stmt_digest).digest();
        state.log(stmt_digest, new_root).unwrap();
        // Defense-in-depth: every fixture consumer inherits a wire round-trip self-check, so any
        // future change that breaks `to_wire`/`rehydrate` consistency fails loudly here.
        assert_round_trips(&state, &precompiles());
        state
    }

    #[test]
    fn rehydrate_round_trips_simple_chain() {
        let original = built_state_with_logged_predicate();
        let wire = original.to_wire();
        let rehydrated = DeferredState::rehydrate(&wire, &precompiles()).unwrap();
        assert_eq!(rehydrated.root(), original.root());
        assert_eq!(rehydrated.statements(), original.statements());
    }

    #[test]
    fn rehydrate_empty_state_succeeds() {
        let wire = DeferredStateWire::default();
        let state = DeferredState::rehydrate(&wire, &precompiles()).unwrap();
        assert_eq!(state.root(), TRUE_DIGEST);
        assert!(state.nodes().is_empty());
    }

    #[test]
    fn rehydrate_rejects_bad_index() {
        // A Join entry whose lhs index points past the (empty) digest table: index 0 is not
        // < its own position 0 → BadIndex.
        let wire = DeferredStateWire {
            entries: alloc::vec![crate::deferred::WireEntry {
                tag: Uint::add_tag(),
                body: crate::deferred::WireBody::Join { lhs: 0, rhs: 0 },
            }],
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(matches!(err, Err(IntegrityError::BadIndex)));
    }

    #[test]
    fn rehydrate_rejects_unknown_tag() {
        // A tag the schema rejects — its id doesn't match Uint.
        let bogus_tag = Tag {
            id: Felt::new_unchecked(0xdead),
            args: [ZERO; 3],
        };
        let wire = DeferredStateWire {
            entries: alloc::vec![crate::deferred::WireEntry {
                tag: bogus_tag,
                body: crate::deferred::WireBody::Value([ZERO; 8]),
            }],
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(matches!(err, Err(IntegrityError::UnknownTag)));
    }

    #[test]
    fn rehydrate_rejects_empty_chunk_body() {
        // The deserializer accepts a zero-length chunk body, but empty chunk bodies are forbidden.
        // Rehydrate must reject one with `ShapeMismatch`, not panic in `Node::chunk`'s non-empty
        // precondition — the wire is untrusted. The guard fires before tag decode, so the tag is
        // irrelevant.
        let wire = DeferredStateWire {
            entries: alloc::vec![crate::deferred::WireEntry {
                tag: test_leaf(0).tag,
                body: crate::deferred::WireBody::Chunks(alloc::sync::Arc::from(
                    alloc::vec![[ZERO; 8]; 0]
                )),
            }],
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(matches!(err, Err(IntegrityError::ShapeMismatch)));
    }

    #[test]
    fn to_wire_drops_unreachable_orphan_leaves() {
        // Register an orphan that no one references; build a logged-predicate chain. The wire
        // must contain the chain's reachable closure but NOT the orphan.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let _orphan = state.register(&schema, test_leaf(99)).unwrap();
        let a = state.register(&schema, test_leaf(7)).unwrap();
        let pred = Node::join(Uint::eq_tag(), a, a);
        let stmt_digest = state.register(&schema, pred.clone()).unwrap();
        state.evaluate(&schema, pred).unwrap();
        let new_root = Node::and(state.root(), stmt_digest).digest();
        state.log(stmt_digest, new_root).unwrap();
        // Defense-in-depth: orphan-trimmed wire must still round-trip cleanly.
        assert_round_trips(&state, &schema);

        let wire = state.to_wire();
        // Rehydrate and read back the digest set — the wire's bytes don't carry digests, but
        // rehydration recomputes them, so we exercise the round-trip identity here.
        let rehydrated = DeferredState::rehydrate(&wire, &precompiles()).unwrap();
        let orphan_digest = test_leaf(99).digest();
        assert!(
            !rehydrated.contains(&orphan_digest),
            "orphan must be trimmed from wire and absent after rehydrate"
        );
        // The chain and its closure must still ship and rehydrate.
        assert!(rehydrated.contains(&new_root), "AND-node must be in rehydrated state");
        assert!(rehydrated.contains(&stmt_digest), "stmt predicate must be in rehydrated state");
        assert!(rehydrated.contains(&a), "stmt's operand must be in rehydrated state");
    }

    #[test]
    fn to_wire_trimmed_round_trips_through_rehydrate() {
        // Orphans dropped by `to_wire` must still round-trip via rehydrate.
        let original = built_state_with_logged_predicate();
        let wire = original.to_wire();
        let rehydrated = DeferredState::rehydrate(&wire, &precompiles()).unwrap();
        assert_eq!(rehydrated.root(), original.root());
        assert_eq!(rehydrated.statements(), original.statements());
    }

    #[test]
    fn rehydrate_rejects_failed_predicate() {
        // Build a chain whose statement is `eq(leaf(3), leaf(4))` — disagreeing leaves.
        // Phase 2's evaluate returns AssertionFailed, surfaced as `PredicateFailed`.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        // Hand-roll a chain that points to a failing predicate without going through `log`'s
        // schema gate (which evaluate-rejects ahead of time).
        let bad_pred = Node::join(Uint::eq_tag(), a, b);
        let bad_digest = bad_pred.digest();
        state.intern(bad_pred);
        let and_node = Node::and(TRUE_DIGEST, bad_digest);
        let and_digest = and_node.digest();
        state.intern(and_node);
        state.root = and_digest;

        let wire = state.to_wire();
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(
            matches!(err, Err(IntegrityError::PredicateFailed(_))),
            "expected PredicateFailed, got {err:?}"
        );
    }

    #[test]
    fn rehydrate_rejects_broken_chain() {
        // An AND-node whose `prev_root` references a digest not present in the wire entries.
        // Because the structural heuristic only follows a node's `(lhs, rhs)` when *both*
        // resolve, the missing `prev_root` makes the AND-node opaque, leaving `a`/`pred`
        // outside the root's closure — so the reachability gate (before phase 2) rejects this
        // with `DanglingNode`, preempting the phase-2 `BrokenChain` backstop. Both are valid
        // rejections of the same malformed wire.
        //
        // Entries (DFS post-order):
        //   [0] leaf `a` = test_leaf(7)                              — Value
        //   [1] predicate eq(a, a)                                   — Join (lhs=rhs=0)
        //   [2] AND-node { Tag::TRUE, payload: (bogus_prev, pred) }   — Value (raw felts; the
        //       AND-node's `prev_root` can't be encoded as a wire index because it intentionally
        //       doesn't appear in the entries)
        let a = test_leaf(7);
        let a_payload = *a.payload.as_felts().expect("leaf is expression-bodied");
        let pred = Node::join(Uint::eq_tag(), a.digest(), a.digest());
        let pred_digest = pred.digest();
        let bogus_prev = dummy_digest(42);
        let and_payload = *Payload::join(bogus_prev, pred_digest)
            .as_felts()
            .expect("join is expression-bodied");

        let wire = DeferredStateWire {
            entries: alloc::vec![
                crate::deferred::WireEntry {
                    tag: a.tag,
                    body: crate::deferred::WireBody::Value(a_payload),
                },
                crate::deferred::WireEntry {
                    tag: pred.tag,
                    body: crate::deferred::WireBody::Join { lhs: 0, rhs: 0 },
                },
                crate::deferred::WireEntry {
                    tag: Tag::TRUE,
                    body: crate::deferred::WireBody::Value(and_payload),
                },
            ],
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(
            matches!(err, Err(IntegrityError::DanglingNode)),
            "expected DanglingNode (reachability gate preempts BrokenChain), got {err:?}"
        );
    }

    #[test]
    fn rehydrate_rejects_dangling_entry() {
        // A faithful chain (leaf a → eq(a, a) predicate → AND-node) plus an orphan leaf that
        // nothing references. Phase 1 interns all four; the reachability check (before phase 2)
        // finds the orphan outside the root's structural closure and rejects it.
        //
        // Entries:
        //   [0] leaf a = test_leaf(7)            — Value
        //   [1] orphan = test_leaf(99)           — Value (dangling: unreferenced)
        //   [2] predicate eq(a, a)               — Join { lhs: 0, rhs: 0 }
        //   [3] AND { Tag::TRUE, (TRUE, pred) }   — Join { lhs: TRUE_INDEX, rhs: 2 }
        let a = test_leaf(7);
        let a_payload = *a.payload.as_felts().expect("leaf is expression-bodied");
        let orphan = test_leaf(99);
        let orphan_payload = *orphan.payload.as_felts().expect("leaf is expression-bodied");
        let pred = Node::join(Uint::eq_tag(), a.digest(), a.digest());

        let wire = DeferredStateWire {
            entries: alloc::vec![
                crate::deferred::WireEntry {
                    tag: a.tag,
                    body: crate::deferred::WireBody::Value(a_payload),
                },
                crate::deferred::WireEntry {
                    tag: orphan.tag,
                    body: crate::deferred::WireBody::Value(orphan_payload),
                },
                crate::deferred::WireEntry {
                    tag: pred.tag,
                    body: crate::deferred::WireBody::Join { lhs: 0, rhs: 0 },
                },
                crate::deferred::WireEntry {
                    tag: Tag::TRUE,
                    body: crate::deferred::WireBody::Join {
                        lhs: crate::deferred::TRUE_INDEX,
                        rhs: 2,
                    },
                },
            ],
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(
            matches!(err, Err(IntegrityError::DanglingNode)),
            "expected DanglingNode, got {err:?}"
        );
    }
}
