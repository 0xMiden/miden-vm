# Invocation-specific locals implementation plan

**Goal:** Inspect each live invocation's own locals in local and DAP sessions, including recursion and suspended callers.

**Approved design:** The conversation's invocation-specific locals design, approved for implementation on 2026-10-16. Full inline-frame and lexical-scope ownership are deferred.

**Architecture:** Recovered invocations receive debugger-owned identities. A shared engine tracker retains each invocation's declarations, captured transient values, and evaluation context. Frontends select an invocation and use the same value resolver; they never resolve a caller's locals against the callee's context.

**Constraints:** Use VM 0.36.1 APIs with the authorized temporary upstream recovery patch, preserve no-std feature support and replay semantics, use jj for commits, and leave ambiguous or unobserved ownership unavailable. Inline frames have no separately inspectable locals in this pass.

## Tasks

- [x] Engine ownership and resolution. Add failing tests for caller/callee name collisions and kills, recursion, restoration after return, and memory/frame-relative reads. Give recovered frames stable IDs, record pre-step context and frame bases, retain transient snapshots, and expose a frame-variable view and shared resolver. Preserve current-variable access for entry breakpoint logic.
- [x] DAP integration. Add protocol regressions for scopes and evaluation using distinct frames, stale handles after resume, and unavailable inline frames. Map frame IDs and scope handles to the engine identities, invalidate stop-specific handles, and use the engine value resolver. Extend the bundled client to request scopes and frame-specific evaluation.
- [x] Local integration. Make selected physical frames drive local variable inspection and source filtering. Keep scripting current-frame APIs consistent and add explicit frame selection/inspection where needed. Route remote inspection through the frame-aware DAP API.
- [x] Regression matrix. Exercise exec/call/dynamic calls, cross-package and partial metadata, stack snapshots, changed frame bases, live memory mutations, replay parity, termination/reload, and local/DAP parity.
- [x] Independent review, validation, changelog, and jj commits. Run targeted tests, workspace tests with default/all features, docs, formatting, strict Clippy, lit, and the feature matrix. Resolve review findings before committing.

## Review focus

Invocation entry/return timing must match the source event's pre-step ownership. Caller FMP must be refreshed after prologues, not captured only on entry. Frame-base anchors must not follow a callee's overwritten shared base, while ordinary memory reads stay live. Missing metadata must not assign callee variables to a recovered ancestor. Repeated visits and reset must not reuse stale invocation or DAP handles.

## Coordination

Engine owns `debug/variables*`, `debug/stacktrace*`, `exec/state*`, and public exports. DAP owns `exec/dap*` and `exec/dap_client*`. Local integration owns `src/ui`, `src/script`, and frontend tests. The engine API is confirmed between implementers before frontend code depends on it. Root owns final validation and commits.

## Upstream prerequisite

VM v0.36.1 loses recovered invocation ranges across generated locals instructions and padding in merged blocks. The authorized sibling patch validates explicit inline boundaries against complete ordered instruction signatures, allowing padding offsets to differ only at those boundaries. Generic source slices retain exact-offset matching. Inline depth is derived from the selected source occurrence using a cached endpoint index, preserving physical frame ownership without duplicate inline rows.

The temporary workspace dependency patch uses the sibling checkout until the fix is published. Full inline-frame and lexical-scope locals remain outside this change.

## Validation

Independent review is complete. Debugger validation passed: 481 all-feature tests, 469 default-feature tests, 28 lit tests, documentation tests, all 101 feature configurations, strict Clippy, and formatting. Upstream validation passed: 1,679 processor tests (one existing ignored test), strict processor Clippy, and formatting. Regression cases were observed failing before their corresponding fixes, including final frame-base writes, external memory contexts, typed remote raw values, and merged generated-local invocation recovery.

Upstream commit: `11e280bd`. The temporary dependency patch is isolated in debugger commit `13a61fb2`.
