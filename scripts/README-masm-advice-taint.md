# Compiler advice analysis for core MASM

This branch starts from VM `origin/main`. Existing VM dependency declarations
and lockfiles must remain unchanged. The user allows a separate unpublished
CLI workspace in `tools/midenc-masm-lint` with its own dependencies and lockfile.
The compiler fixes start from `origin/next` and retain VM 0.35 dependencies.

Run the compiler analysis on the original core manifest. Show compact findings
and grouped skip totals by default, with full detail behind `--verbose`.
Both modes must preserve diagnostic counts and exit status. Findings, skipped
procedures, and an incomplete run remain failures.

Begin CI as manually dispatched evidence, with both reports uploaded on failure.
A required core check waits until coverage and blocking findings are resolved.
No branch publication or dependency migration is part of this local preparation.
