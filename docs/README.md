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
[GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249)
for the locked `minimatch` 3.1.5 until December 3, 2026. The advisory describes
`firstPhasePreProcess()` amplification with `optimizationLevel >= 2` in version
10.2.6. Version 3.1.5 has neither that preprocessing pass nor that option.
`serve-handler` 6.1.7 still pins version 3.1.5 and calls its CommonJS function
export. Forcing the patched version 11 would break that API. The exception
covers this exact advisory and version in the local docs preview only.

The former `braces` exception has been removed because
[GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm)
was withdrawn. The lockfile also updates `follow-redirects` to 1.16.2 and `joi`
to 17.13.9 to address their redirect-header and email-validation advisories.

The lockfile uses `http-cache-semantics` 4.3.0 to address
[GHSA-ch52-4w7c-c8xp](https://github.com/advisories/GHSA-ch52-4w7c-c8xp).
The audit no longer accepts an exception for that advisory.

`scripts/audit.mjs` checks the advisory ID and every affected locked version.
It also accepts findings inherited solely from that advisory, prints the
full npm report, and fails when the exception expires or a patched release is
reported. Other advisories still fail CI. Run `npm audit` to see the raw report
and remove the exception when the advisory range is corrected or a compatible
fix is available.

The preview uses the docs plugin and classic theme directly. Installing the
classic preset also pulls in unused analytics and Algolia search integrations,
along with SVG transformation tooling. The classic theme still depends on the
blog and pages plugins even though this preview does not enable them.

Keep live Mermaid rendering. The current Docusaurus build also requires
`@mermaid-js/layout-elk` to resolve its optional layout import, even though the
existing diagram uses the default layout. The `$@mermaid-js/layout-elk` override
keeps Docusaurus on the direct dependency's version because its optional peer
range still requests ELK 0.1.9. Local search remains enabled.

KaTeX CSS and fonts come from the locked npm package. The `$katex` override also
keeps Mermaid and `rehype-katex` on the patched KaTeX 0.19 release line. Mermaid
resolves to the direct dependency's version range through the `$mermaid`
override.

The security overrides require `postcss-selector-parser` 7.1.6 or newer and
Tinypool 2.1.2 or newer because the build dependencies still request older major
versions. They require DOMPurify 3.4.17 or newer to address
[GHSA-cg2g-xh64-v4q7](https://github.com/advisories/GHSA-cg2g-xh64-v4q7).
They also update `serialize-javascript` and the `uuid` dependency of
`sockjs` beyond the vulnerable versions required by their parents. Remove these
overrides when upstream dependency ranges include patched versions.

To refresh compatible versions, run `npm update --ignore-scripts`, then repeat
the build and audit. Commit both `package.json` and `package-lock.json` when the
manifest changes. Dependabot alerts track the default branch, currently `next`,
so fixes merged into `main` also need to reach `next` to clear those alerts.
