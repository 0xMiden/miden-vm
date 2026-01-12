# Contributing to Miden

#### First off, thanks for taking the time to contribute!

You can find a detailed explanation of main project concepts in [docs](https://docs.miden.xyz/miden-vm/).

We want to make contributing to this project as easy and transparent as possible, whether it's:

- Reporting a [bug](https://github.com/0xMiden/miden-vm/issues/new)
- Taking part in [discussions](https://github.com/0xMiden/miden-vm/discussions)
- Submitting a [fix](https://github.com/0xMiden/miden-vm/pulls)
- Proposing new [features](https://github.com/0xMiden/miden-vm/issues/new)

&nbsp;

## Contribution Quality

To keep review time focused on meaningful improvements, we generally do not accept:
- Trivial typo fixes
- Minor code or documentation changes that don't materially improve clarity or completeness

Contributions should:
- Include clear reasoning for the change
- Be linked to an issue the author has been assigned to
- Be testable / reviewable without unnecessary overhead
- Pass all CI tests

**We reserve the right to close PRs at our discretion, or batch trivial valid fixes into internal commits.**

## Flow
We are using [Github Flow](https://docs.github.com/en/get-started/quickstart/github-flow), so all code changes happen through pull requests from a [forked repo](https://docs.github.com/en/get-started/quickstart/fork-a-repo).

### Branching
- The current active branch is `next`. Every branch with a fix/feature must be forked from `next`.

- The branch name should contain a short issue/feature description separated with hyphens [(kebab-case)](https://en.wikipedia.org/wiki/Letter_case#Kebab_case).

    For example, if the issue title is `Fix functionality X in component Y` then the branch name will be something like: `fix-x-in-y`.

- New branch should be rebased from `next` before submitting a PR in case there have been changes to avoid merge commits.
i.e. this branches state:
  ```
          A---B---C fix-x-in-y
         /
    D---E---F---G next
            |   |
         (F, G) changes happened after `fix-x-in-y` forked
  ```

  should become this after rebase:


  ```
                  A'--B'--C' fix-x-in-y
                 /
    D---E---F---G next
  ```


  More about rebase [here](https://git-scm.com/docs/git-rebase) and [here](https://www.atlassian.com/git/tutorials/rewriting-history/git-rebase#:~:text=What%20is%20git%20rebase%3F,of%20a%20feature%20branching%20workflow.)

### Signing commits

We require all commits to be [signed](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#ssh-commit-signature-verification).


### Commit messages
- Commit messages should be written in a short, descriptive manner and be prefixed with tags for the change type and scope (if possible) according to the [semantic commit](https://gist.github.com/joshbuchea/6f47e86d2510bce28f8e7f42ae84c716) scheme.
For example, a new change to the AIR crate might have the following message: `feat(air): add constraints for the decoder`

- Also squash commits to logically separated, distinguishable stages to keep git log clean:
    ```
    7hgf8978g9... Added A to X \
                                \  (squash)
    gh354354gh... oops, typo --- * ---------> 9fh1f51gh7... feat(X): add A && B
                                /
    85493g2458... Added B to X /


    789fdfffdf... Fixed D in Y \
                                \  (squash)
    787g8fgf78... blah  blah --- * ---------> 4070df6f00... fix(Y): fixed D && C
                                /
    9080gf6567... Fixed C in Y /
    ```

### Code Style and Documentation
- For documentation in the codebase, we follow the [rustdoc](https://doc.rust-lang.org/rust-by-example/meta/doc.html) convention with no more than 100 characters per line.
- For code sections, we use code separators like the following to a width of 100 characters::
    ```
    // CODE SECTION HEADER
    // ================================================================================
    ```

- [Rustfmt](https://github.com/rust-lang/rustfmt) and [Clippy](https://github.com/rust-lang/rust-clippy) linting is included in CI pipeline. Anyways it's preferable to run linting locally before push:
    ```
    cargo fix --allow-staged --allow-dirty --all-targets --all-features; cargo fmt; cargo clippy --workspace --all-targets --all-features -- -D warnings
    ```

### Versioning
We use [semver](https://semver.org/) naming convention.

&nbsp;

## Pre-PR checklist
1. Repo forked and branch created from `next` according to the naming convention.
2. Every commit is [signed](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#ssh-commit-signature-verification).
3. Commit messages and code style follow conventions.
4. Tests added for new functionality.
5. Documentation/comments updated for all changes according to our documentation convention.
6. Clippy and Rustfmt linting passed.
7. New branch rebased from `next`.

&nbsp;

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

&nbsp;

## Any contributions you make will be under the MIT Software License
In short, when you submit code changes, your submissions are understood to be under the dual [MIT](./LICENSE-MIT) and [Apache 2.0](./LICENSE-APACHE) license that covers the project. Feel free to contact the maintainers if that's a concern.
