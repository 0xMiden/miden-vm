# Security Policy

Miden Crypto is currently pre-1.0, has not been independently audited as a whole,
and should be evaluated carefully before production use. Security reports are
valuable, especially when they identify issues that could affect cryptographic
assumptions, proof soundness, verification correctness, serialization
canonicality, release integrity, or unsafe use of the crates in this workspace.

## Supported Versions

Security fixes are prioritized for the current active development branch and the
most recent release line.

| Version | Supported |
| ------- | --------- |
| `next` | Yes |
| Latest published `0.x` release | Best effort |
| Older releases | No guarantee |

Because the project is pre-1.0, APIs and internals may change between releases.
Users should plan to upgrade to the latest release after a security fix is
published.

## Reporting a Vulnerability

Please do not open a public issue, discussion, or pull request for an
undisclosed vulnerability. Report vulnerabilities through GitHub's private
vulnerability reporting flow:

<https://github.com/0xMiden/crypto/security/advisories/new>

Use a public GitHub issue only for ordinary bugs that do not create a security
risk.

## What to Include

Please set a high bar for security submissions. Reports are most actionable when
they include:

- A clear description of the vulnerability and its security impact.
- The affected crate, component, version, commit, or branch.
- A minimal proof of concept or reproducible test case.
- A proposed fix patch, where possible.
- A regression test that fails before the fix and passes after it, where
  possible.
- Any relevant environment details, configuration, feature flags, inputs, or
  assumptions.
- Whether the issue has been disclosed anywhere else.

Incomplete reports may still be useful, but maintainers may ask for a proof of
concept, a patch, or a regression test before triage can be completed.

## Scope

Security-relevant reports include, but are not limited to:

- Cryptographic assumption, domain-separation, transcript, or randomness issues.
- Bugs that allow invalid signatures, proofs, openings, ciphertexts, or package
  artifacts to be accepted as valid.
- Vulnerabilities in hashing, authenticated encryption, key exchange, digital
  signatures, Merkle structures, serialization, deserialization, or package
  handling.
- Proof soundness, verifier acceptance, or constraint-system issues in the STARK
  crates.
- Memory-safety issues, panics, timing leaks, or resource exhaustion with a
  plausible security impact.
- Supply-chain, release, CI, or signing issues that could affect published
  artifacts.

General correctness bugs, documentation issues, feature requests, and
performance problems without a plausible security impact should be reported
through the normal public issue tracker.

## Disclosure

Maintainers will use GitHub security advisories to coordinate investigation,
fixes, credits, and public disclosure. Please give maintainers a reasonable
opportunity to investigate and release a fix before disclosing the issue
publicly.

When testing, act in good faith: do not access data that is not yours, do not
disrupt services, and do not use the vulnerability beyond what is necessary to
demonstrate impact.
