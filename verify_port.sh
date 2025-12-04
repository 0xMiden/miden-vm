#!/bin/bash
# Verify EdDSA port by comparing file contents with normalization
#
# This script compares the 8 NEW files introduced in the EdDSA branch:
#   - 2 MASM files (eddsa_ed25519.masm, sha512.masm)
#   - 2 Handler files (eddsa_ed25519.rs, sha512.rs)
#   - 2 Test files (eddsa_ed25519.rs, sha512.rs)
#   - 2 Documentation files (eddsa_ed25519.md, sha512.md)
#
# NOT VERIFIED by this script (integration changes to existing files):
#   - lib.rs: Handler registrations, verifier registrations, helper functions
#   - mod.rs: Module declarations
#   - Cargo.toml: Dependency additions (sha2)
#   - CHANGELOG.md: Release notes
#   - docs/index.md: Index updates
#
# NOT PORTED (independent refactoring change on original branch):
#   - hmerge → exec.rpo::merge in secp256k1.masm and keccak256.masm
#
# This was an unrelated refactoring that happened to be on the EdDSA branch.

ORIGINAL_BRANCH="adr1anh/eddsa"

# Normalization function - converts old conventions to new
# Order matters - more specific patterns first
normalize() {
    sed \
        -e 's|stdlib/|libcore/|g' \
        -e 's|miden_stdlib|miden_libcore|g' \
        -e 's|stdlib::crypto::dsa::eddsa25519|miden::core::dsa::eddsa_ed25519|g' \
        -e 's|stdlib::hash::sha512|miden::core::hash::sha512|g' \
        -e 's|std::crypto::dsa::eddsa::ed25519|miden::core::crypto::dsa::eddsa_ed25519|g' \
        -e 's|std::crypto::hashes::sha512|miden::core::crypto::hashes::sha512|g' \
        -e 's|use\.std::crypto::dsa::eddsa::ed25519|use.miden::core::crypto::dsa::eddsa_ed25519|g' \
        -e 's|use std::crypto::dsa::eddsa::ed25519|use miden::core::crypto::dsa::eddsa_ed25519|g' \
        -e 's|exec\.ed25519::|exec.eddsa_ed25519::|g' \
        -e 's|use\.std::crypto::hashes::sha512|use.miden::core::crypto::hashes::sha512|g' \
        -e 's|use std::crypto::hashes::sha512|use miden::core::crypto::hashes::sha512|g' \
        -e 's|use\.std::|use.miden::core::|g' \
        -e 's|use std::|use miden::core::|g' \
        -e 's|crypto::hashes::rpo$|crypto::hashes::rpo256|g' \
        -e 's|exec\.rpo::|exec.rpo256::|g' \
        -e 's|handlers/eddsa25519|handlers/eddsa_ed25519|g' \
        -e 's|eddsa25519::|eddsa_ed25519::|g'
}

compare_file() {
    local orig_path="$1"
    local ported_path="$2"

    echo "--- Comparing: $orig_path -> $ported_path"

    # Get original file content (normalized)
    ORIG=$(git show "$ORIGINAL_BRANCH:$orig_path" 2>/dev/null | normalize)

    # Get ported file content (normalized)
    if [[ -f "$ported_path" ]]; then
        PORT=$(cat "$ported_path" | normalize)
    else
        echo "  ERROR: Ported file not found!"
        return 1
    fi

    # Compare
    DIFF=$(diff <(echo "$ORIG") <(echo "$PORT") 2>/dev/null)

    if [[ -n "$DIFF" ]]; then
        echo "  DIFFERENCES FOUND:"
        echo "$DIFF" | head -30
        return 1
    else
        echo "  OK (identical after normalization)"
        return 0
    fi
}

echo "=== Comparing EdDSA file contents ==="
echo ""

TOTAL=0
PASS=0

# MASM files
compare_file "stdlib/asm/crypto/dsa/eddsa/ed25519.masm" "libcore/asm/crypto/dsa/eddsa_ed25519.masm"
[[ $? -eq 0 ]] && ((PASS++)); ((TOTAL++)); echo ""

compare_file "stdlib/asm/crypto/hashes/sha512.masm" "libcore/asm/crypto/hashes/sha512.masm"
[[ $? -eq 0 ]] && ((PASS++)); ((TOTAL++)); echo ""

# Handler files
compare_file "stdlib/src/handlers/eddsa25519.rs" "libcore/src/handlers/eddsa_ed25519.rs"
[[ $? -eq 0 ]] && ((PASS++)); ((TOTAL++)); echo ""

compare_file "stdlib/src/handlers/sha512.rs" "libcore/src/handlers/sha512.rs"
[[ $? -eq 0 ]] && ((PASS++)); ((TOTAL++)); echo ""

# Test files
compare_file "stdlib/tests/crypto/eddsa_ed25519.rs" "libcore/tests/crypto/eddsa_ed25519.rs"
[[ $? -eq 0 ]] && ((PASS++)); ((TOTAL++)); echo ""

compare_file "stdlib/tests/crypto/sha512.rs" "libcore/tests/crypto/sha512.rs"
[[ $? -eq 0 ]] && ((PASS++)); ((TOTAL++)); echo ""

# Documentation files
compare_file "stdlib/docs/crypto/dsa/eddsa/ed25519.md" "libcore/docs/crypto/dsa/eddsa_ed25519.md"
[[ $? -eq 0 ]] && ((PASS++)); ((TOTAL++)); echo ""

compare_file "stdlib/docs/crypto/hashes/sha512.md" "libcore/docs/crypto/hashes/sha512.md"
[[ $? -eq 0 ]] && ((PASS++)); ((TOTAL++)); echo ""

echo "=== Summary ==="
echo "Passed: $PASS / $TOTAL"

if [[ $PASS -eq $TOTAL ]]; then
    echo "All EdDSA files successfully ported!"
else
    echo "Review the differences above."
fi
