# Security Policy

Miden VM is currently in alpha, has not been audited, and is not ready for production use.
Security reports are still valuable, especially when they identify issues that could affect proof
soundness, verification correctness, cryptographic assumptions, release integrity, or unsafe use of
the VM and its crates.

## Supported Versions

Security fixes are prioritized for the current active development branch and the most recent release
line.

| Version | Supported |
| ------- | --------- |
| `next` | Yes |
| Latest published `0.x` release | Best effort |
| Older releases | No guarantee |

Because the project is in alpha, APIs and internals may change between releases. Users should plan
to upgrade to the latest release after a security fix is published.

## Reporting a Vulnerability

Please do not open a public issue, discussion, or pull request for an undisclosed vulnerability.
Report vulnerabilities through GitHub's private vulnerability reporting flow:

<https://github.com/0xMiden/miden-vm/security/advisories/new>

Use a public GitHub issue only for ordinary bugs that do not create a security risk.

## What to Include

Please set a high bar for security submissions. Reports are most actionable when they include:

- A clear description of the vulnerability and its security impact.
- The affected crate, component, version, commit, or branch.
- A minimal proof of concept or reproducible test case.
- A proposed fix patch, where possible.
- A regression test that fails before the fix and passes after it, where possible.
- Any relevant environment details, configuration, feature flags, inputs, or assumptions.
- Whether the issue has been disclosed anywhere else.

Incomplete reports may still be useful, but maintainers may ask for a proof of concept, a patch, or
a regression test before triage can be completed.

## Scope

Security-relevant reports include, but are not limited to:

- Proof soundness, verifier acceptance, or constraint-system issues.
- Bugs that let invalid programs, proofs, or package artifacts be accepted as valid.
- Vulnerabilities in assembly parsing, serialization, deserialization, or package handling.
- Memory-safety issues, panics, or resource exhaustion with a plausible security impact.
- Supply-chain, release, CI, or signing issues that could affect published artifacts.

General correctness bugs, documentation issues, feature requests, and performance problems without a
plausible security impact should be reported through the normal public issue tracker.

## Disclosure

Maintainers will use GitHub security advisories to coordinate investigation, fixes, credits, and
public disclosure. Please give maintainers a reasonable opportunity to investigate and release a fix
before disclosing the issue publicly.

When testing, act in good faith: do not access data that is not yours, do not disrupt services, and
do not use the vulnerability beyond what is necessary to demonstrate impact.
