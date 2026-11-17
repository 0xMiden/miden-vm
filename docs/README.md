# Docs preview dependencies

This package builds the local VM docs preview. The published site imports
`src/` through the separate `miden-docs` repository. With Node.js 22, run from
the repository root:

```sh
make check-docs-site
```

`.npmrc` disables install scripts. Dependencies still execute during the build.

The audit prints all findings. Its only active exception is
[GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf) for
`picomatch` 2.3.2, expiring **November 24, 2026**. It covers repository-controlled
build patterns. The exception requires registry latest `4.0.7` and advisory range
`<=4.0.7`. It ignores only the search-plugin 0.11.0 downgrade suggestion, which
requires Docusaurus 2 instead of this preview's Docusaurus 3.
[The audit script](scripts/audit.mjs) enforces these limits and rejects other
advisories or fix recommendations. Remove the exception when a patch is available.

Use the docs plugin and classic theme directly. Keep local search and live Mermaid
rendering, including its required `@mermaid-js/layout-elk` package. KaTeX assets
come from the locked npm package. Remove security overrides in `package.json`
when parent dependencies accept patched versions.

Refresh dependencies with `npm --prefix docs update --ignore-scripts`, then rerun
the check. Commit manifest and lockfile changes together. Dependabot scans `next`,
so dependency fixes on `main` must also reach `next`.
