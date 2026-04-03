---
title: Unused dependency check failed
labels: ci, dependencies
---

The scheduled unused dependency check reported one or more dependencies that are not used in the
feature and target combinations covered by `.github/workflows/unused-deps.yml`.

Please review the failing workflow run in the Actions tab and either:

- remove the dependency if it is genuinely unused, or
- add a documented `cargo-udeps` ignore entry if the dependency is only used by cfg-gated code,
  generated code, or doctests that `cargo-udeps` cannot see.
