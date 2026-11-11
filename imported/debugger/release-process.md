# Release Process

The operational guide for releasing `miden-debug` from *this* repository.

> For the tool itself, its commands, and the full `.release/config.toml` schema,
> see [release-tool](https://github.com/0xMiden/release-tool). This document
> covers only what is specific to this repository.

Three things are true throughout and explain most of the procedure:

- **Publication to crates.io cannot be undone.** There is no rollback, and a
  version can never be reused. Everything reversible therefore happens before
  anything irreversible, and the approval gate sits exactly on that boundary.
- **A release is resumable.** Every attempt reconciles against live state first,
  so a run that dies partway through can be re-run and will do only what is
  missing. A first attempt and a resume are the same run.
- **Versions are chosen by a person.** The tooling validates a version; it never
  picks one.

| I want to… | Go to | Touches production? |
| --- | --- | --- |
| Release for real | [§4](#4-production-release) | Yes, after the approval gate |
| Try the publish path with no risk, on my machine | [§5](#5-local-rehearsal) | No |
| Try the real workflow on real runners first | [§6](#6-hosted-rehearsal) | No crates, no tags — but real drafts and real attestations |
| Ship something consumers cannot accidentally pick up | [§7](#7-prereleases) | Yes, but invisible to default requirements |
| Fix a release that went wrong | [§8](#8-recovery) | — |

---

## 1. Branches

| Branch | Role |
| --- | --- |
| `next` | Development. All ordinary work merges here. |
| `main` | Releases. Only ever released from here. |

Releases happen from `main`, and `main` lags `next`. A release therefore starts
by promoting `next` into `main`, and the release candidate is branched from and
merged into **`main`** — not `next`. The workflow enforces this: the commit it
releases must be `main`'s tip *and* the most recent commit to have changed
`.release/release.toml`.

---

## 2. What this repository releases

Three releasable units, declared in
[`.release/config.toml`](../.release/config.toml), plus a `private` unit holding
the infrastructure crates that are never published.

| Unit | Kind | Version lives in | Tag | Changelog |
| --- | --- | --- | --- | --- |
| `debugger` | crates | its own manifests | `v{version}` | `CHANGELOG.md` |

Publication order is `debugger`. Any unit may be released alone, and any combination together. Only a stable `debugger` release claims the repository's "Latest release" slot.

---

## 3. Prerequisites

One-time setup, requiring repository-admin and crates.io-owner access. None of it
can be performed by the tooling.

### 3.1 crates.io

| What | Detail |
| --- | --- |
| Trusted Publisher, per crate | Repository `0xMiden/miden-debug`, workflow `release.yml`, environment `release` |
| Trusted-Publishing-only mode | Enable per crate **after** its publisher is verified working |
| New crates | crates.io cannot configure a publisher for a crate that does not exist. Bootstrap a brand-new crate once with a short-lived, narrowly scoped token, then switch it |
| Long-lived tokens | Remove `CARGO_REGISTRY_TOKEN` from repository secrets once Trusted Publishing works |

`cargo make release package-order` lists the publishable crates; each needs its
own publisher entry. A crate whose publisher is missing or misconfigured cannot
be detected in advance — the token carries no list of the crates it authorizes —
so the failure surfaces mid-publication as a 403. It is survivable
([R6](#r6-403-from-cratesio-during-publication)).

### 3.2 GitHub repository settings

| What | Detail |
| --- | --- |
| Immutable releases | Enable for the repository |
| Environment `release` | Required reviewers; self-review disabled; admin bypass disabled where supported; deployment restricted to protected `main` |
| Tag ruleset for `v*` | **Restrict deletions and updates only. Do not restrict creations.** |
| Required status check | `release / gate` |
| CODEOWNERS | Release infrastructure paths reviewed by a release owner |

> **Why creations are not restricted.** Ruleset bypass actors are roles, teams,
> apps, and deploy keys — there is no workflow-level actor, and `GITHUB_TOKEN`
> acts as the repository-wide Actions app. A creation bypass would therefore let
> *every* workflow create release tags, which is worse than not restricting
> creation at all. What matters is that a published tag can never be moved or
> removed, and deletion/update restrictions give exactly that.

### 3.3 Repository state

- Every workspace package classified in `.release/config.toml`
  (`cargo make release lint` enforces this).
- No active `[patch]` entries in the root manifest.
- All first-party external dependencies (miden-vm, protocol, and related
  repositories) published at the versions the workspace requires.

---

## 4. Production release

### Phase A — Prepare the candidate

Entirely on a branch and in pull requests. Nothing here touches crates.io,
creates a tag, or publishes anything.

1. **Promote `next` into `main`.** A pull request titled for the release, merged
   once CI passes. Skip if `main` is already at the commit you intend to release.
2. **Freeze `main`.** Nothing may merge until the release completes; anything
   landing after your candidate invalidates it
   ([R4](#r4-subject-is-not-mains-tip)).
3. **Branch from `main`,** not `next`:
   `git switch --detach origin/main && git switch -c release/v0.10.0`.
4. **Choose the units and versions.** A judgement call. See
   [§2](#2-what-this-repository-releases) for what forces what — in particular an
   SDK minor bump or prerelease requires the templates to move with it, as does a
   compiler change that needs a template change.
5. **Move the versions,** once per unit:
   ```bash
   cargo make release set-version --unit debugger 1.0.1
   ```
   Omit the version to bump to the next minor; `--dry-run` first to review.
   Expect edits to the crate manifests, every requirement naming them,
   `Cargo.lock`, `.release/release.toml`, and — for an SDK bump — the template
   manifests and `extra/templates/bundle.toml`.
   ([R1](#r1-set-version-reports-disagreeing-versions))
6. **Write the changelog** for each unit being released:
   ```bash
   cargo make release changelog-prompt debugger --version 1.0.1
   ```
   This emits a *prompt*; it never writes entries. Review and edit what comes
   back. The range defaults to the unit's last release tag through `HEAD`,
   filtered to that unit's paths — but if there is no baseline, pass a range
   explicitly for the unit (`cargo make release changelog-prompt debugger v1.0.0..HEAD --version 1.0.1`).
7. **Lint locally:** `cargo make release lint`. Expect
   `release lint: 42 packages classified, no findings`.
   ([R2](#r2-the-embedded-template-bundle-is-stale),
   [R3](#r3-release-lint-findings),
   [R11](#r11-the-templates-cannot-resolve-the-sdk-being-released))
8. **Open the release-candidate pull request into `main`,** containing the
   version, lockfile, changelog, `.release/release.toml`, and any template bundle
   changes. Expect `release / gate` to run — roughly 8 minutes, since the package
   closure is in scope for any candidate.
   ([R3](#r3-release-lint-findings),
   [R5](#r5-package-closure-verification-fails))
9. **Review and merge** with a merge that leaves the candidate as `main`'s tip
    and as the last commit to have touched `.release/release.toml`. The workflow
    checks both.

> **You must click "Approve and run" on the candidate pull request.** GitHub does
> not start workflow runs for pull requests opened by `GITHUB_TOKEN`, and pushes
> to such a branch create no runs at all. Since `release / gate` is required, the
> candidate cannot merge until you do.

### The pull-request gate

`release-ci.yml` runs on every pull request and exposes one required check,
`release / gate`. It calls `release-verify.yml`, which holds the substantive
checks, carries no credentials, and can reach no production service — the same
workflow production calls, so pull requests and releases run identical logic
rather than two approximations of it.

| Job | What it does |
| --- | --- |
| `impact` | Classifies the diff. Touching `tools/release/`, `.release/`, `Makefile.toml`, `.github/workflows/`, `Cargo.lock`, or any `Cargo.toml` escalates to the full tier. |
| `release lint` | Lints the configuration, checks the publication order is derivable, runs the release-tool tests, checks formatting. |
| `package closure` | Packages every publishable crate and builds a consumer against them. Full tier only. |
| `workflow policy` | Asserts the release workflow's invariants; runs `actionlint`. |
| `gate` | The single required check. Runs unconditionally and fails if any required job failed *or was unexpectedly skipped*, so a misconfigured dependency cannot turn a red build green. |

---

### Phase B — Plan

**B1. Dispatch the release workflow from `main`:** `gh workflow run release.yml
--ref main`, or **Actions** → **release** → **Run workflow** with *Use workflow
from* set to **main**. There are no inputs; the scope comes from the reviewed
`.release/release.toml` and nothing else.

```bash
gh run watch "$(gh run list --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

*If the `plan` job fails immediately:* [R4](#r4-subject-is-not-mains-tip),
[R12](#r12-the-release-declaration-was-changed-in-a-different-commit).

**B2. Review the intent.** The run → the **plan** job → the **Generate the
intent** step prints it in full: units, versions, prerelease flags, the crates in
each stage, the tags to be created, and which release claims the "latest" slot.
The same content is attached as the `release-intent` artifact. Confirm it matches
what you decided in A4. If anything is unexpected, cancel the run — nothing
irreversible has happened — and start again from A3.

---

### Phase C — Build and stage

Fully automated. Nothing to do but watch.

| Job | What it does |
| --- | --- |
| `plan` | Validates the subject against `main`, lints the candidate, generates the intent. |
| `verify` | Calls `release-verify.yml` at the full tier. |
| `seal and stage` | Seals the intent into a plan; builds the template bundle. |
| `build <binary> (<target>)` | A 3 × 2 matrix — `midenc`, `cargo-miden`, `miden-objtool` × Linux, macOS — building, smoke-testing, and archiving each executable. |
| `attest artifacts` | Records build provenance for the six executables. |
| `stage drafts` | Creates the draft releases, routes every artifact to a unit by its `assets` globs, uploads, and reads each one back. |

*Expect:* draft releases under **Releases** — not visible to anyone without
write access, and deletable. No tag exists and no crate is published, so
everything here is reversible.

> **One exception: attestations are permanent.** They are recorded in a public
> transparency log during this phase, so a cancelled release leaves provenance
> for artifacts that were never released. Harmless — nothing consumes an
> attestation for an artifact with no release — but it cannot be undone.

*If a job fails:* [R7](#r7-an-asset-does-not-match-what-was-uploaded),
[R13](#r13-an-artifact-is-routed-nowhere-or-to-two-units), or treat it as an
ordinary build failure. Either way nothing is published; fix it in a new
candidate.

---

### Phase D — Approve and publish

**D1. Approve the deployment. This is the point of no return.** The `publish` job
runs in the `release` environment and pauses; the run shows a yellow **Review
deployments** button, and required reviewers are notified.

Before approving, check on the run page that the intent from B2 is still what you
want, that the drafts exist and carry the expected assets, and that no earlier job
reported a warning you have not read. Then: **Review deployments** → tick
**release** → **Approve and deploy**.

> **Who approves.** A required reviewer on the `release` environment, and not the
> person who dispatched the run — self-review is disabled, so another maintainer
> with the reviewer role must click it. This is the only human approval in the
> pipeline and it is the entire reversibility boundary. The `finalize` job runs in
> the same environment and inherits the same approval, so approving here approves
> Phase E too.

*If you decide not to proceed:* do not approve. Cancel the run and follow
[§8.1](#81-discarding-drafts). Nothing will have been published.

**D2. Publication runs.** Per unit, in order (`sdk` → `templates` → `compiler`):
create that unit's tag, obtain a short-lived Trusted Publishing token, reconcile
against crates.io, publish only what is absent, and verify the result from the
registry. The `release-journal` artifact records every decision.

> **The token lives 30 minutes.** Cargo publishes in dependency waves and waits
> for index confirmation between them — roughly a dozen waves for the compiler
> stage.

*If it fails:* [R6](#r6-403-from-cratesio-during-publication),
[R8](#r8-a-tag-already-exists-at-a-different-commit),
[R9](#r9-a-planned-version-conflicts-or-is-yanked),
[R10](#r10-the-publishing-token-expired-mid-stage).

---

### Phase E — Finalize

**E1. Finalization runs** in the same `release` environment, under the same
approval. It verifies every staged draft and then publishes them, in order.
Publication makes a release immutable, so *all* units are verified before *any*
is published. Per unit:

- The tag exists and points at the released commit — read from the tag **ref**,
  not the release's `target_commitish`, which GitHub stops honouring once the tag
  exists and which therefore reports what was requested rather than what is true.
- The draft carries this run's sealed plan, compared by bytes, so finalizing
  another run's draft is caught.
- Every asset still hashes to what `SHA256SUMS` recorded at staging.
- Nothing unplanned is attached, because after publication it can never be
  removed.

The "latest" decision was sealed into the plan at intent time and is not taken
here; the SDK, the template bundle, and every prerelease publish with
`make_latest=false`.

*If it fails:* [R7](#r7-an-asset-does-not-match-what-was-uploaded),
[R8](#r8-a-tag-already-exists-at-a-different-commit),
[R14](#r14-finalization-reports-an-unplanned-asset).

**E2. Review the final report** in the **finalize** job's **Verify and publish the
drafts** step: each tag, whether it was newly published or already published, and
which claimed the "latest" slot. Then confirm outside the tooling that the
releases are no longer drafts, the crates appear on crates.io at the expected
versions, and `cargo install miden-debug` (or the equivalent) resolves the new
version.

**E3. Unfreeze `main`** and handle announcements and downstream coordination.

---

## 5. Local rehearsal

Exercises packaging and the publish path on your machine against a local registry
that serves crates published to it and proxies crates.io for everything else.
Nothing reaches crates.io or GitHub.

**Requires versions that are not already published.** The registry proxies
crates.io, so an already-published version is visible and Cargo will refuse to
republish it. Do this on a candidate branch after A5.

```bash
# 1. Start the local registry. Leave this running in its own terminal.
#    --cache-dir keeps upstream index lookups between runs; without it, every
#    rehearsal re-fetches the third-party closure.
cargo make release fake-registry --port 8732 --cache-dir /tmp/rehearsal-cache
```

It prints the two pieces of configuration a rehearsal needs. Put the source
replacement in `$CARGO_HOME/config.toml` so resolution finds unpublished crates;
`--index` alone redirects only the upload target and cannot resolve
interdependent crates that are not yet on crates.io.

In a second terminal, from the candidate workspace:

```bash
# 2. Prove the packaged crates are usable: packages every selected crate,
#    publishes it to a throwaway registry, and builds a consumer that resolves
#    ONLY through that registry. Production publishes with --no-verify, so this
#    is the only thing that checks it. Takes several minutes.
cargo make release verify-closure

# 3. Generate the intent from .release/release.toml.
cargo make release plan --subject "$(git rev-parse HEAD)" --output intent.json

# 4. Seal it: package every crate and pin the plan to their exact bytes.
cargo make release seal --intent intent.json --output plan.json \
    --cache-dir /tmp/rehearsal-cache

# 5. Publish stage by stage, reconciling and verifying each from the registry.
cargo make release publish --plan plan.json \
    --rehearsal-index sparse+http://127.0.0.1:8732/
```

Step 2 is separate on purpose: `seal` packages the crates but does not build a
consumer against them. `verify-closure` is what proves they are usable, and it is
what the pull-request gate runs.

**A local rehearsal creates no tags.** There is no throwaway GitHub, so a tag
created here would be a real, permanent tag naming a version that was never
released. The publish path is given a GitHub client that refuses every call, so
tagging is the one part of Phase D a local rehearsal cannot exercise.

*If it fails:* [R5](#r5-package-closure-verification-fails),
[R15](#r15-crate-already-exists-during-a-local-rehearsal).

---

## 6. Hosted rehearsal

**A hosted rehearsal is a production run that you stop at the approval gate.**
There is no separate rehearsal workflow: everything reversible happens before the
gate, so every step up to it *is* the rehearsal.

| Phase | Runs? | Reversible? |
| --- | --- | --- |
| A — candidate | Yes | Yes |
| B — plan | Yes | Yes |
| C — build, attest, stage drafts | Yes | Yes, except attestations |
| **approval gate** | **You do not approve** | — |
| D — tag and publish | No | — |
| E — finalize | No | — |

Follow Phase A and Phase B exactly as written in §4, let Phase C run, and at D1
**do not approve**. That is the only difference from a production release. Clean
up with [§8.1](#81-discarding-drafts).

*Expect:* draft releases carrying the executables, the template bundle,
`SHA256SUMS`, and the sealed plan; build attestations for the six executables;
**no tags**, and **nothing on crates.io**.

This is the only way to exercise the real GitHub path — draft creation, asset
upload and readback, real runners, real artifacts. It still does not prove that
crates.io accepts the upload, that Trusted Publishing is configured per crate,
production rate limits, tag creation, or immutable finalization. The first three
are only provable by a real publish, the last two by a real release; a prerelease
(§7) is the intended way to get there.

---

## 7. Prereleases

A prerelease is selected by giving a version with a prerelease identifier, e.g.
`0.10.0-rc.1`, at step A5. It is the intended first exercise of the full
production path, because **a prerelease cannot disturb existing consumers**: a
default requirement such as `midenc = "0.9"` never matches one.

Follow §4 unchanged. The differences are automatic:

- GitHub releases are marked prerelease and never become "Latest", whatever the
  configuration says.
- **Templates can be part of a prerelease,** and must be when the SDK is
  prereleased ([§2.2](#22-co-release-is-decided-from-content)). The bundle takes
  a prerelease version, and only a prerelease `cargo-miden` will resolve it — a
  stable build accepts only stable bundles in its own minor series, so stable
  users never see it.

---

## 8. Recovery

### 8.1 Discarding drafts

All of Phase C is undone by deleting the drafts. Cancel the run first — one
waiting for approval will sit there indefinitely — then either delete each draft
in the **Releases** UI, or download the sealed plan from the run's artifacts and:

```bash
GITHUB_TOKEN=$(gh auth token) cargo make release discard --plan plan.json
```

`discard` deletes only *still-draft* releases and never touches a published one.
The attestations are left behind and cannot be withdrawn; this is expected and
harmless.

### 8.2 Resuming a partial publish

A publish that dies partway through — an expired token, a 403, a runner failure —
is resumed by **re-dispatching the workflow from `main` (B1)**. There is no
separate resume command and nothing to clean up first.

This works because every attempt reconciles against live registry state before
publishing anything: crates already on the registry at the planned version and
digest are skipped, and only what is missing goes out. A tag that already exists
at the released commit is accepted; one at a *different* commit is a hard stop
([R8](#r8-a-tag-already-exists-at-a-different-commit)).

**Do not change versions to resume.** Everything already published stays
published, and a plan whose versions moved is a different release. Re-dispatch
the same candidate. To see what a resume would do first:

```bash
GITHUB_TOKEN=$(gh auth token) cargo make release reconcile --plan plan.json
```

It prints `publish`, `skip`, or `CONFLICT` per crate. With the sealed plan in
hand it compares digests, so an existing version whose content differs is a
conflict rather than a skip.

### 8.3 What cannot be undone

| Once this has happened | Why it is permanent |
| --- | --- |
| A crate version reached crates.io | It can never be republished and never reused, even after a yank. A yanked version is permanently unavailable. |
| A tag was created | Tag rulesets restrict deletion and updates, by design. The version it names is burnt. |
| A GitHub release was finalized | Immutable releases: the assets and body can never change, and nothing can be added or removed. |
| An attestation was recorded | It is in a public transparency log. |

In every case the recovery is the same: **abandon that version and release a new
one.** Leftover tags and drafts are accepted as debris.

---

### R1: `set-version` reports disagreeing versions

Every crate in a version domain shares one version and one has drifted, usually
hand-edited. Set them all to the same version manually, then re-run
`set-version`; `cargo make release lint` will confirm.

### R2: The embedded template bundle is stale

`lint` reports `the embedded archive for unit 'templates' is stale`.
`tools/cargo-miden/templates.tar.gz` no longer matches the sources under
`extra/templates`. Regenerate and commit:

```bash
cargo make release bundle --output tools/cargo-miden/templates.tar.gz
```

**If the error also lists untracked files,** those are in your working tree but
not in git, so they are not in the bundle and your local archive will differ from
CI's. Commit them (`git add -f` if something is ignoring them) or delete them.
The bundle is built from tracked files precisely so it depends on the commit and
not on your checkout.

### R3: `release lint` findings

| Finding | Remedy |
| --- | --- |
| `package '…' is not classified` | A new workspace member. Add it to `.release/config.toml` under an explicit unit |
| `… is publishable in its manifest but classified as private` (or the reverse) | Make them agree. The config is the policy; the manifest is what Cargo obeys |
| `private package '…' is at X but private packages are frozen at 0.1.0` | Set it back. Private crates are never published, so a version tracking a release domain is misleading |
| `publishable package '…' depends on private package '…'` | Publish the dependency or remove it; otherwise the published crate is unresolvable for consumers |
| `active [patch] entry` | Comment it out. This is the most likely way to publish a broken crate: the workspace builds, the manifest looks right, and the published crate resolves to a registry version without the patched behaviour |

### R4: Subject is not `main`'s tip

`subject … is not main's tip (…); refresh the candidate`. Something merged to
`main` after your candidate, so this commit cannot be released. Open a fresh
candidate from the current `main` (A3) and re-dispatch, and make sure the freeze
from A2 is actually being observed.

### R5: Package closure verification fails

A packaging failure, `the packaged crates do not build when resolved from a
registry`, or `the release scope is not self-contained`. A packaged crate is
missing something it needs — a file excluded from the archive, a dependency that
only resolves by workspace path, or an active `[patch]`. The self-containment
variant means a unit in the candidate depends on a crate that is neither being
released nor already published; usually the fix is to add the unit that owns it
to the candidate.

Reproduce with `cargo make release verify-closure` and read the build error.
Common causes: a file needed at build time that the package's `include` does not
cover, or a dependency without a version requirement — path-only dependencies are
stripped when packaging.

### R6: 403 from crates.io during publication

The named crate has no Trusted Publisher, or its configuration does not match this
repository, workflow, and the `release` environment. This cannot be detected in
advance. Fix the publisher entry ([§3.1](#31-cratesio)) and re-dispatch (B1); see
[§8.2](#82-resuming-a-partial-publish). **Do not change versions** — everything
already published stays.

### R7: An asset does not match what was uploaded

`does not match what was uploaded`, or `hashes to … but was staged as …`. An
asset's bytes changed between upload and readback, or between staging and
finalization. Do not publish: cancel the run, delete the drafts
([§8.1](#81-discarding-drafts)), and re-dispatch. If it recurs with the same
asset, treat it as an integrity incident and investigate before releasing
anything.

### R8: A tag already exists at a different commit

`tag '…' already exists at <sha>, not <sha>`, or during finalization `points at …
not at the subject`. The tag was created by an earlier attempt at a different
commit, or by something else. Rulesets prevent moving or deleting it, by design,
so **that version is burnt**. Do not try to move the tag; delete any still-draft
releases ([§8.1](#81-discarding-drafts)) and release a **new version** from a new
candidate. The leftover tag is accepted as debris.

### R9: A planned version conflicts or is yanked

`stage '…' has N conflict(s)`. A planned version already exists on crates.io with
*different* bytes, or has been yanked — and a yanked version can never be
republished. Open a new candidate with new versions. If you need to yank
something during an incident, finish or abandon the in-flight release first:
yanking a planned version mid-release strands it, because versions cannot change
during a resume.

### R10: The publishing token expired mid-stage

An authentication error roughly 30 minutes into a stage. Trusted Publishing
tokens live 30 minutes and Cargo waits for index confirmation between dependency
waves. Re-dispatch (B1): a fresh token is obtained per stage and reconciliation
resumes from what is already published. If one stage repeatedly cannot finish
inside the budget it needs splitting — raise it rather than retrying
indefinitely.

### R11: The templates cannot resolve the SDK being released

`lint` reports that `sdk-requirement` cannot resolve the version this release
publishes for `sdk`. Almost always a hand-edited version; see the table in
[§2.2](#22-co-release-is-decided-from-content). Nothing else catches this —
`bundle.toml` and the template manifests agree with each other, so they look
consistent, while a generated project cannot resolve `miden` at all. Re-run the
bump rather than editing by hand, then regenerate the bundle because its contents
changed:

```bash
cargo make release set-version --unit sdk 0.14.0-rc.1 --force
cargo make release bundle --output tools/cargo-miden/templates.tar.gz
```

`--force` is needed whenever the version is not moving forward, which includes
re-applying the version already in place.

### R12: The release declaration was changed in a different commit

`the release declaration was last changed in <sha>, not <sha>`.
`.release/release.toml` was not last modified by the commit being released:
either something landed afterwards, or the candidate did not actually change the
declaration. Confirm `set-version` ran and its change was committed, then open a
fresh candidate from the current `main`.

### R13: An artifact is routed nowhere, or to two units

`matches no unit's assets globs`, `matches more than one unit`, `belongs to unit
'…', which this release does not include`, or `requires an asset matching '…',
and none was staged`. The build matrix and the `assets` globs in
`.release/config.toml` disagree — a new binary with no pattern, overlapping
patterns, an artifact built for a unit not in this candidate, or a matrix job
that did not run.

All four are refused rather than defaulted, because an unrouted asset would be
silently dropped from a release nobody can add it to afterwards. Fix the globs or
the matrix and re-dispatch; nothing has been published.

### R14: Finalization reports an unplanned asset

`the draft for '…' carries N asset(s) the plan does not describe`. Do not publish
— after publication an asset can never be removed. Establish where it came from;
if it was attached by hand, remove it and re-dispatch. If you cannot account for
it, treat it as an intrusion and stop.

### R15: `crate already exists` during a local rehearsal

The version you are rehearsing is already published on crates.io, and the local
registry proxies crates.io for anything it has not been told it owns. Rehearse
with unpublished versions: run A5 first.

---

## 9. What is not yet exercised

**Nothing here has run against real GitHub.** Tag creation, draft creation, asset
upload and readback, and finalization are exercised only against an in-memory
double and a local stub HTTP server. The wire format has been tested; GitHub's
acceptance of it has not. A hosted rehearsal (§6) is what validates this, and it
should be treated as the point of the exercise rather than a formality. The same
applies to crates.io: Trusted Publishing is configured, but no upload has been
attempted through it.

Not implemented:

- **Template resolution robustness** (design §12.3–12.4). `cargo miden new`
  resolves the bundle at runtime and falls back to the embedded copy, but makes a
  *single* attempt with no caching, so every invocation queries GitHub, and it
  does not walk down to an older candidate when the newest tag has no release
  behind it — which happens routinely, since tags are created before a release is
  finalized. Also absent: `--template-version`, `--offline`, and the `deny.json`
  retraction list, so withdrawing a bad template bundle means releasing a newer
  one.
- **`audit-publishers`.** Trusted Publishing configuration cannot be
  preflighted, so a missing publisher surfaces mid-publication as
  [R6](#r6-403-from-cratesio-during-publication).
- **An abandon command.** Recovering from a stuck release means deleting drafts
  ([§8.1](#81-discarding-drafts)) and releasing a new version.
- **Consumer smoke tests in Phase E.** The design calls for resolving
  representative consumers from crates.io before the drafts are published.
  Finalization verifies assets, tags, and the plan, but installs nothing;
  `verify-closure` covers the equivalent question before publication, against
  packaged rather than published crates.
- **A dedicated rehearsal workflow.** §6 uses the production workflow stopped at
  the gate, which exercises the same code.

Everything else — every command in
[tools/release/README.md](../tools/release/README.md), plus the production
workflow and the pull-request gate — is implemented and tested end to end against
the rehearsal registry and the GitHub double, which is as close to production as
anything gets without publishing for real.
