#!/usr/bin/env bash
set -euo pipefail

report_dir="${RUNNER_TEMP}/coverage-comment"
mkdir -p "$report_dir"
report_path="$report_dir/coverage-comment.md"
# Octocov only writes a summary if its destination already exists.
: > "$report_path"
status=0
GITHUB_STEP_SUMMARY="$report_path" octocov || status=$?
cat "$report_path" >> "$GITHUB_STEP_SUMMARY"

# A threshold failure still produces a useful report. Pushes only need the summary
# and Octocov's baseline datastore, not a pull request comment artifact.
if [[ -s "$report_path" && -n "${PR_NUMBER:-}" ]]; then
    printf '%s\n%s\n%s\n' "$PR_NUMBER" "$PR_HEAD_SHA" "$PR_HEAD_REPO" > "$report_dir/coverage-pr-context.txt"
    echo 'has_report=true' >> "$GITHUB_OUTPUT"
fi
exit "$status"
