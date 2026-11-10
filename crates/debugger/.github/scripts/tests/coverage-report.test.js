const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

for (const [code, number, report] of [
  [0, '150', '## Code Metrics Report\n\n| Coverage | 75% | 80% (+5%) |\n'],
  [1, '150', '## Code Metrics Report\n\nCoverage below threshold\n'],
  [0, '', '## Code Metrics Report\n\nPush baseline\n'],
  [1, '150', ''],
]) {
  test(`captures native octocov output and preserves its exit status ${code} (PR=${number}, report=${Boolean(report)})`, (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'octocov-capture-'));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    fs.writeFileSync(path.join(directory, 'octocov'), '#!/bin/sh\ntest -f "$GITHUB_STEP_SUMMARY" || exit 2\nprintf "%s" "$TEST_REPORT" >> "$GITHUB_STEP_SUMMARY"\nexit "$TEST_EXIT"\n', { mode: 0o755 });
    const summary = path.join(directory, 'job-summary');
    const output = path.join(directory, 'output');
    fs.writeFileSync(summary, 'Earlier summary\n');
    fs.writeFileSync(output, '');
    const result = spawnSync('bash', [path.join(__dirname, '../coverage-report.sh')], {
      env: { ...process.env, PATH: `${directory}:${process.env.PATH}`, RUNNER_TEMP: directory,
        GITHUB_STEP_SUMMARY: summary, GITHUB_OUTPUT: output, TEST_REPORT: report, TEST_EXIT: String(code),
        PR_NUMBER: number, PR_HEAD_SHA: 'a'.repeat(40), PR_HEAD_REPO: 'contributor/repo' }, encoding: 'utf8',
    });
    assert.equal(result.status, code, result.stderr);
    assert.equal(fs.readFileSync(path.join(directory, 'coverage-comment/coverage-comment.md'), 'utf8'), report);
    assert.equal(fs.readFileSync(summary, 'utf8'), `Earlier summary\n${report}`);
    if (!number || !report) {
      assert.equal(fs.readFileSync(output, 'utf8'), '');
      assert.equal(fs.existsSync(path.join(directory, 'coverage-comment/coverage-pr-context.txt')), false);
      return;
    }
    assert.match(fs.readFileSync(output, 'utf8'), /has_report=true/);
    assert.equal(fs.readFileSync(path.join(directory, 'coverage-comment/coverage-pr-context.txt'), 'utf8'),
      `150\n${'a'.repeat(40)}\ncontributor/repo\n`);
  });
}
