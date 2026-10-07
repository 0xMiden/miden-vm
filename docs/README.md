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

The CI audit temporarily accepts one unpatched advisory until November 3,
2026. [GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm)
affects `braces` 3.0.3, which handles file patterns in the build tooling.
This preview generates static files and does not accept file patterns from site
visitors. The exception covers this docs preview only. It does not make `braces`
safe for other uses.

The lockfile uses `http-cache-semantics` 4.3.0 to address
[GHSA-ch52-4w7c-c8xp](https://github.com/advisories/GHSA-ch52-4w7c-c8xp).
The audit no longer accepts an exception for that advisory.

`scripts/audit.mjs` checks the advisory ID and every affected locked version.
It also accepts findings inherited solely from that advisory, prints the
full npm report, and fails when the exception expires or a patched release is
reported. Other advisories still fail CI. Run `npm audit` to see the raw report
and remove the exception when upstream publishes a fix.

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
