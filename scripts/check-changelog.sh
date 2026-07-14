#!/bin/bash
set -uo pipefail

VM_CHANGELOG_FILE="CHANGELOG.md"
CRYPTO_CHANGELOG_FILE="CHANGELOG.crypto.md"

usage() {
    cat <<EOF
Usage: BASE_REF=<base> NO_CHANGELOG_LABEL=<true|false> $0 [CHANGELOG_FILE...]

When no changelog file is passed, the script routes changes to the right changelog:
  - VM and shared workspace changes require ${VM_CHANGELOG_FILE}
  - crypto crate changes require ${CRYPTO_CHANGELOG_FILE}
  - PRs touching both areas require both files
EOF
}

require_changelog() {
    local changelog_file="$1"

    if git diff --quiet "origin/${BASE_REF}" -- "${changelog_file}"; then
        >&2 echo "Changes should come with an entry in the \"${changelog_file}\" file. This behavior
can be overridden by using the \"no changelog\" label, which is used for changes
that are trivial / explicitly stated not to require a changelog entry."
        exit 1
    fi

    echo "The \"${changelog_file}\" file has been updated."
}

has_crypto_change() {
    grep -Eq '^(crates/(crypto|crypto-derive|field|serde-utils|lifted-air|lifted-stark|stark-transcript|stateful-hasher)/|tests/wycheproof/|benches/(miden-bench|smt-codspeed)/|tools/(miden-crypto-fuzz|miden-serde-utils-fuzz)/)'
}

has_vm_change() {
    grep -Eq '^(air/|core/|processor/|prover/|verifier/|miden-vm/|crates/(ace-codegen|assembly|assembly-syntax|assembly-syntax-cst|debug-types|lib/core|mast-package|midenc-hir-type|package-registry|package-registry-local|miden-format|project|test-serde-macros|test-utils|utils-core-derive|utils-diagnostics|utils-indexing|utils-sync)/|benches/(blake3-bench|synthetic-bench)/|tools/miden-core-fuzz/)'
}

changed_files() {
    git diff --name-only "origin/${BASE_REF}"
}

if [ "${NO_CHANGELOG_LABEL:-false}" = "true" ]; then
    # 'no changelog' set, so finish successfully
    echo "\"no changelog\" label has been set"
    exit 0
fi

if [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

: "${BASE_REF:?BASE_REF is not set}"

if [ "$#" -gt 0 ]; then
    for changelog_file in "$@"; do
        require_changelog "${changelog_file}"
    done
    exit 0
fi

changed="$(changed_files)"
required_changelogs=()

if printf '%s\n' "${changed}" | has_crypto_change; then
    required_changelogs+=("${CRYPTO_CHANGELOG_FILE}")
fi

if printf '%s\n' "${changed}" | has_vm_change; then
    required_changelogs+=("${VM_CHANGELOG_FILE}")
fi

if [ "${#required_changelogs[@]}" -eq 0 ]; then
    required_changelogs=("${VM_CHANGELOG_FILE}")
fi

for changelog_file in "${required_changelogs[@]}"; do
    require_changelog "${changelog_file}"
done
