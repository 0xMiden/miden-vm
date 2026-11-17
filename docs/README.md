# Docs preview dependencies

This Docusaurus package builds the local VM docs preview. The published site
imports the Markdown from `src/` through the separate `miden-docs` repository.
Use Node.js 22 to install and build the preview:

```sh
cd docs
npm ci
npm run build:dev
npm run test:audit
npm run audit:ci
```

The `.npmrc` disables dependency install scripts. The docs build works without
them. Package code still runs during the build, so dependency review remains
necessary.

The CI audit temporarily accepts
[GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf) for the
locked `picomatch` 2.3.2 dependency. The exception expires on November 24, 2026.
As of November 17, the advisory covers every published version through 4.0.7
and lists no patched release. It reports excessive regular-expression
backtracking for crafted repeated extglob patterns. The dependency is used by
the build tooling, whose patterns come from repository configuration. This
preview generates static files and accepts no file patterns from site visitors.
The exception covers this docs preview only.

The earlier `braces` 3.0.3 exception expired on November 3, 2026.
[GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) remains
rejected by the audit after that cutoff.

The lockfile uses `http-cache-semantics` 4.3.0 to address
[GHSA-ch52-4w7c-c8xp](https://github.com/advisories/GHSA-ch52-4w7c-c8xp).
The audit no longer accepts an exception for that advisory.

`scripts/audit.mjs` checks the advisory ID and every affected locked version.
It also accepts findings inherited solely from reviewed advisories, prints the
full npm report, and fails when an exception expires or an applicable fix is
reported. Other advisories still fail CI. Run `npm audit` to see the raw report
and remove the exception when upstream publishes a fix.

npm sometimes suggests downgrading `@cmfcmf/docusaurus-search-local` to 0.11.0
to address `picomatch`. That plugin version requires Docusaurus 2, which conflicts
with this preview's Docusaurus 3 dependencies. The audit excludes only that exact
recommendation from its available-fix check. A separate registry lookup must still
report `picomatch` 4.0.7 as the latest release, and the advisory range must remain
`<=4.0.7`. A changed registry result or advisory range fails the audit, as does any
other fix recommendation. The locked-version and expiry checks still apply.

The preview uses the docs plugin and classic theme directly. Installing the
classic preset also pulls in unused analytics and Algolia search integrations,
along with SVG transformation tooling. The classic theme still depends on the
blog and pages plugins even though this preview does not enable them.

Keep live Mermaid rendering. The current Docusaurus build also requires
`@mermaid-js/layout-elk` to resolve its optional layout import, even though the
existing diagram uses the default layout. Local search remains enabled.

KaTeX CSS and fonts come from the locked npm package. Mermaid resolves to the
direct dependency's version range through the `$mermaid` override. The remaining
security overrides update `serialize-javascript` and the `uuid` dependency of
`sockjs` beyond the vulnerable major versions required by their parents. Remove
these overrides when upstream dependency ranges include patched versions.

To refresh compatible versions, run `npm update --ignore-scripts`, then repeat
the build and audit. Commit both `package.json` and `package-lock.json` when the
manifest changes. Dependabot alerts track the default branch, currently `next`,
so fixes merged into `main` also need to reach `next` to clear those alerts.
