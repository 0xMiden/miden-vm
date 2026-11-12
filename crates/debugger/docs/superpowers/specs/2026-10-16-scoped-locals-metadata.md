# Package debug metadata for inline-frame and lexical-scope locals

Status: proposed upstream contract; field names below are illustrative, semantics are requirements.

Tracking issues: [compiler #1468](https://github.com/0xMiden/compiler/issues/1468) and [debugger #165](https://github.com/0xMiden/miden-debug/issues/165). The debugger issue also contains a shareable copy of the proposed package contract for the upstream discussion.

## Outcome and scope

Enable a debugger to inspect each source-level inline frame and resolve local names according to lexical shadowing, without guessing ownership from names, source lines, storage slots, or executable hashes. Preserve the physical-invocation isolation already implemented in the debugger.

This requires a coordinated VM/package change, compiler producer change, and debugger consumer change. This document specifies the VM-facing contract and the acceptance criteria for those follow-ups. It does not require a new expression evaluator, complete DWARF support, cross-language closure lookup, or support for every optimized location expression. Unsupported storage must remain explicitly unavailable.

## Current limitations

The v0.36.1 package debug format is version 4. `DebugSourceVar` repeats a name/type/declaration location alongside each location update, but has no binding identity or scope owner. `DebugSourceInlineCall` identifies a callee and call-site range, but cannot connect that inline instance to variable declarations. `DebugVarLocation::Unavailable` currently acts as a name-based kill in the debugger.

The compiler discards inline-subroutine variable children, merges some declarations by Wasm local slot, and does not preserve lexical-block boundaries. Its HIR variable attribute has no declaration identity or scope. It also drops inline frames with unknown call-site lines. These losses cannot be repaired by a consumer.

## Recommended data model

Use two new package-local indexed tables and reuse the existing source-occurrence graph. A scope tree also represents inline ownership; a separate parallel inline-identity graph is unnecessary.

```rust
DebugScope {
    parent: Option<DebugScopeIdx>,
    kind: Function { function: DebugFunctionIdx }
        | Inline { callee: DebugFunctionIdx, call_site: Option<DebugLocIdx> }
        | Lexical,
    location: Option<DebugLocIdx>, // presentation only
}

DebugVariable {
    scope: DebugScopeIdx,
    name: DebugStringIdx,
    type_id: Option<DebugTypeIdx>,
    arg_index: Option<NonZeroU32>,
    declaration: Option<DebugLocIdx>,
}

DebugScopedVarUpdate {
    op_idx: u32,
    variable: DebugVariableIdx,
    value_location: DebugVarLocation,
}

DebugScopeRange {
    op_start: u32,
    op_end: u32,
    scope: DebugScopeIdx, // innermost scope; ancestors define the context
}
```

Scope ranges and variable updates belong to a particular `DebugSourceNodeId`, not just a reduced `MastNodeId`. A procedure/source root must explicitly identify its function scope or declare that scoped metadata is absent. This capability is per procedure, so scoped and unscoped dependencies can coexist.

The new scoped update is an alternative to the current unscoped variable row, not a second independent declaration copy. Preserve an explicit unscoped representation for existing assembly producers; it retains invocation-only behavior. The assembler must not invent lexical ownership for it. An opted-in scoped procedure must not silently mix unscoped and scoped updates for its source locals.

### Identity and ownership

- A function scope has no parent. A lexical scope belongs to its parent. An inline scope's parent is the caller's lexical scope at the call site; its callee is a source-level function, which need not have an executable procedure body or MAST root.
- Each concrete static inline expansion receives a distinct scope subtree and variable records. Its inline scope index is also its static inline-instance ID. Repeated dynamic execution of that expansion reuses static IDs but creates fresh runtime activations.
- A function-root scope activation belongs to one recovered physical/source invocation. Entry/exit actions below concern its lexical and inline descendants; physical invocation entry/return establishes/retires the root. An exit targets the matching activation under that owner, never every activation of the same static scope index.
- IDs identify declaration/expansion instances, not structurally interned display records. Equal names, types, source locations, storage slots, or MAST roots do not justify combining them. Optional abstract-origin sharing is not required for the initial format.
- The existing inline presentation rows must refer to this same inline scope identity when scoped metadata is present. Do not require a consumer to reconcile two identities using callee names or call-site coordinates. Assembler `exec` recovery boundaries and source-language inline instances remain distinguishable; an inline scope does not manufacture a new physical VM invocation.
- All source locations are optional presentation metadata. Missing source files or unknown lines must not erase binding or inline ownership.

### Visibility and shadowing

Scopes represent name-resolution regions, not necessarily a one-to-one copy of DWARF lexical blocks. Producers introduce nested binding scopes where needed for declaration points and same-block shadowing, such as successive Rust `let x` statements. At most one directly owned binding with a given name is visible in a scope; names resolve from the current innermost scope outward.

Variable records exist independently of updates. Entering a scope makes its bindings visible with unavailable values until a usable update is observed. `Unavailable` invalidates only that binding's storage/value; it does not remove the binding. Exiting a scope changes visibility and reveals any outer binding without re-emitting its declaration.

For example, while an unavailable inner `x` is in scope, lookup returns that `x` as unavailable, never the outer `x`. Selection of an inline frame searches its lexical ancestors up to that inline root; it does not expose the caller's locals as callee locals. Selecting the inline caller starts from the call-site parent scope instead.

The producer must not invent a shadow order when input debug metadata does not establish one. Preserve an explicit unsupported/absent scoped capability or report a diagnostic rather than assigning precedence by DIE order, line number, or latest value update.

### Coverage and dynamic activation boundaries

Scope ranges are half-open in executable operation coordinates. Multiple discontiguous ranges can refer to the same scope. Ranges describe the selected lexical context; a change of range fragment does not imply a new inline or lexical activation.

Boundary actions establish and retire activation generations; ranges select visibility within those activations. A known range must identify an active scope in the owning invocation's scope ancestry. A mismatch is invalid metadata, not permission to synthesize a missing entry. Unknown coverage retains activation state but suppresses claims of exact lexical lookup; it does not reset captures or borrow another frame's scope.

Ranges alone are insufficient. The contract also requires explicit logical scope entry/exit boundaries, executed on each traversal. This is necessary when a loop leaves and re-enters the same inline site or lexical scope and consecutive observable operations have the same scope chain. A consumer must be able to invalidate captures from the previous activation in that case.

Recommended representation: ordered `Enter(scope)` / `Exit(scope)` metadata events anchored to source-occurrence operation boundaries and source-graph traversal boundaries. Anchors must distinguish `BeforeOperation(op_idx)` from occurrence/edge entry and exit. A traversal event fires only when its corresponding source occurrence or edge is traversed; it is not inferred from monotonic operation offsets. Edge qualification is needed where the same operation can be reached both from inside an activation and from outside it.

The assembler may lower traversal anchors to operation-boundary events where equivalent, but must retain the original distinction when merging, deduplication, empty blocks, or external boundaries would erase it. The exact wire layout can follow the existing source-graph representation; support for these traversal semantics is a prerequisite, not a debugger follow-up.

Boundary rules:

1. Events are ordered within a boundary. Exits unwind inner-to-outer; entries establish outer-to-inner scope activations. `Exit(S), Enter(S)` is a real fresh activation even if the before/after lexical chain is identical.
2. Entry initializes bindings to unavailable. Variable updates at the boundary execute after the relevant entries and evaluate against the pre-operation VM state, preserving current transient stack capture timing.
3. Updates to an existing caller binding can occur before entry to a callee scope. Therefore lowering must preserve the producer's ordered boundary actions; it must not independently sort all scope events and all variable updates and thereby reverse their order. An explicit ordinal or a unified boundary-action stream is required when they share an anchor.
   Updates may target an active ancestor binding, including an inline caller's binding, but not a binding whose scope has not entered or has already exited. Re-entry creates a fresh generation under its own parent activation, independent of copies under recursive physical invocations.
4. Generated prologues, epilogues, control operations, and padding preserve the current logical context unless there is an explicit transition. Coverage gaps must be marked unknown/unscoped, not interpreted as scope exit or silently attributed to another owner.
5. Empty, terminal, and zero-width external occurrences retain ordered transitions even when there is no instruction to attach them to. The processor must deliver them at the next pre-operation observation or final completion, preserving their owning debug package and source invocation. Any location update must be evaluated/captured at its actual anchor, before subsequent stack, memory-context, or frame-base changes; delayed delivery cannot recapture it from the next operation's state. The processor can expose an anchor-time observation or evaluate the relevant transient values/anchors before queuing it. No executable `nop`, trace, or event is required solely to expose debug scope transitions.
6. A physical call suspends the caller's logical context; it is not a lexical exit. Returning resumes that context. Explicit exit/re-entry changes an activation; moving between discontiguous fragments without those actions does not.

A producer whose source metadata cannot identify logical re-entry must not claim complete activation metadata. Membership and location validity cannot repair missing lifetime evidence.

### Storage evaluation

Retain `DebugVarLocation` and its Miden execution-coordinate expressions. An inline scope does not create a new VM memory context or FMP. Its variable updates use the owning physical invocation's execution state and the binding's own emitted location expression/frame-base anchor. Suspended logical callers retain their anchors and captured stack values while ordinary memory reads remain live in the owning memory context.

No separate serialized dynamic activation IDs or runtime values are needed. The debugger combines static scope/binding IDs with physical invocation and scope-entry generations.

## Required VM/assembly API changes

- Add table builders, accessors, scoped declaration/update inputs, scope-context inputs, and ordered traversal-boundary inputs to the assembly pipeline. Thread identifiers through AST/HIR-facing assembly interfaces and lowering; adding package tables only is insufficient.
- Preserve scopes, references, ordered actions, and range endpoints through block merging, rebatching, source graph reduction, imports, and executable deduplication. Update ownership at generated instructions without deriving it from sparse assembly source rows.
- Expose the current scoped context and ordered boundary actions from the processor's shared source-context inspection API, with their source/debug package and owning source-invocation identity, consistent with recovered call-frame identities. Preserve anchor-time evaluation as described above. Local execution, DAP, replay, and final completion must receive equivalent observations exactly once.
- Retain binding identity in the consumer-facing variable API. Flattening scoped updates back into today's name-only `DebugVarInfo` would lose the new information.
- Expose enough scope ancestry for a debugger to retain the lexical context of every inline caller when execution enters a nested inline or physical call.

## Serialization, validation, and merging

- Bump `DEBUG_INFO_VERSION` from 4 to the next allocated version. Existing readers reject incompatible versions; keep that explicit diagnostic. Reading v4 into a legacy invocation-only adapter is optional separate work, not an automatic compatibility promise. New-version packages with explicit unscoped metadata retain invocation-only inspection.
- Remap scope parents, function references, variable owners, scoped update references, inline links, range contexts, and boundary-action references during table/source-graph import. Reserve index mappings before resolving forward references. Return complete remapping APIs for the new IDs.
- Do not structurally intern concrete scope or variable instances across input packages or inline copies. Intentional reuse of one imported instance uses its remapping, not equality of display fields. Dynamic ownership also includes the loaded debug package.
- Validate all indices; acyclic, well-formed scope ancestry; function/inline ownership; range bounds and unambiguous membership; inline-link consistency; legal action anchors and ordering; and scoped updates targeting a binding in the appropriate physical/source context. Reject detectable unbalanced transitions and make invalid runtime transitions diagnostic rather than silently repairing ownership.
- Keep allocations, row counts, ancestry depth, and encoded payload bounded. Use range/change-point encoding, not a complete scope chain copied to every operation. Include size/indexing stress tests to avoid repeating the earlier inline-table growth problem.
- Scope metadata must not change executable MAST roots, program outputs, or VM cycle counts.

## Acceptance fixtures for the upstream contract

1. Two same-named bindings in nested scopes; inner unavailable; exit restores the outer binding.
2. Same-block shadowing represented by binding scopes, including distinct declarations sharing a source line or a Wasm storage slot.
3. Two inline expansions with identical callee/call-site display metadata remain distinct; one inline activation spans multiple source nodes and discontiguous ranges.
4. Re-entry to the same inline/lexical scope on a loop back-edge, with no intervening observable outer-scope operation, clears stale captures. A branch between fragments of one activation does not clear them.
5. Inline caller invokes a physical callee, resumes, and retains the caller's lexical context and frame-base anchors; physical recursion isolates all corresponding scopes.
6. Multiple ordered scope actions and variable updates share a boundary; empty/terminal/external boundaries deliver actions once, including completion.
7. Generated locals prologues, epilogues, control nodes, and batch padding do not lose ownership. Merged/deduplicated code keeps separate source-instance identities.
8. Missing declaration/call-site locations and variables with no supported location still preserve valid ownership and shadowing.
9. Serialization, dependency merging, malformed-input validation, and replay preserve these semantics. A large nested-inline fixture stays within the bounded reader and uses ranges rather than per-operation chain expansion.

At least one compiler-produced fixture must run through the complete pipeline. Hand-built package fixtures establish the VM contract but cannot detect producer losses.

## Division of follow-up work

VM/package: implement and publish the contract above, including assembler and processor exposure.

Compiler: import DWARF lexical/inline/binding identities and visibility, preserve unavailable bindings, resolve abstract-origin attributes without merging concrete instances, replace slot-based declaration ownership, retain identities through HIR transformations, and emit the new assembly metadata. When cloning an inline expansion, clone its concrete scope/binding subtree and remap updates. Follow the input language's actual binding semantics; do not guess missing visibility.

Debugger: extend invocation state with dynamic scope activations, use binding IDs instead of names, implement nearest-scope lookup separately from value availability, and reuse one resolver in local UI, DAP, and Python. Scope changes without variable updates must affect visibility. Retain suspended logical caller state, use the explicit source context rather than line heuristics, and preserve stale-handle/reset/termination guarantees.

Related existing work: compiler [#1284](https://github.com/0xMiden/compiler/issues/1284) covers inline call debugging broadly; compiler [#1430](https://github.com/0xMiden/compiler/issues/1430) documents the earlier inline metadata size problem; debugger [#94](https://github.com/0xMiden/miden-debug/issues/94) tracks broader debugging usability.
