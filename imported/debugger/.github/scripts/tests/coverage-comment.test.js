const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { test } = require('node:test');
const coverage = require('../coverage-comment.js');

const repo = { owner: '0xMiden', repo: 'miden-debug' };
const fork = 'contributor/miden-debug';
const sha = 'a'.repeat(40);
const pull = { number: 150, state: 'open', head: { sha, ref: 'feature', repo: { full_name: fork } } };
const run = {
  id: 100, workflow_id: 7, event: 'pull_request', status: 'completed',
  head_sha: sha, head_branch: 'feature', head_repository: { full_name: fork },
  pull_requests: [], created_at: '2026-10-07T12:00:00Z',
};
const artifact = { id: 200, name: 'coverage-comment', expired: false, size_in_bytes: 1000 };
const report = '## Code Metrics Report\n\n| | next | PR |\n| Coverage | 75% | 80% (+5%) |\n\n<details><summary>Files</summary>src/main.rs: 80%</details>\n\n---\nReported by [octocov](https://github.com/k1LoW/octocov)\n';
const prContext = `150\n${sha}\n${fork}\n`;
function zip(entries = { 'coverage-comment.md': report, 'coverage-pr-context.txt': prContext }) {
  return execFileSync('python3', ['-c', [
    'import io, json, sys, zipfile',
    'out = io.BytesIO()',
    'with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:',
    '    for name, value in json.load(sys.stdin).items(): archive.writestr(name, value)',
    'sys.stdout.buffer.write(out.getvalue())',
  ].join('\n')], { input: JSON.stringify(entries) });
}
const archive = zip();

function fixture(options = {}) {
  const writes = [];
  const warnings = [];
  const comments = options.comments ?? [];
  let downloads = 0;
  const github = {
    rest: {
      pulls: { list: 'pulls', get: async () => ({ data: options.currentPull ?? pull }) },
      actions: {
        getWorkflow: async (args) => {
          assert.equal(args.workflow_id, 'ci.yml');
          return { data: { id: 7 } };
        },
        listWorkflowRuns: 'runs', listWorkflowRunArtifacts: 'artifacts',
        downloadArtifact: async (args) => {
          downloads++;
          assert.equal(args.artifact_id, 200);
          if (options.downloadError) throw options.downloadError;
          return { data: options.archive ?? archive };
        },
      },
      issues: {
        listComments: 'comments',
        createComment: async (args) => { writes.push({ kind: 'create', ...args }); },
        updateComment: async (args) => { writes.push({ kind: 'update', ...args }); },
      },
    },
    paginate: async (method, args) => {
      assert.equal(args.owner, repo.owner);
      assert.equal(args.repo, repo.repo);
      switch (method) {
        case 'pulls': assert.equal(args.state, 'open'); return options.pulls ?? [pull];
        case 'runs':
          assert.equal(args.workflow_id, 7);
          assert.equal(args.head_sha, sha);
          assert.equal(args.event, 'pull_request');
          return options.runs ?? [run];
        case 'artifacts': return options.artifacts ?? [artifact];
        case 'comments': return comments;
        default: throw new Error(`Unexpected API ${method}`);
      }
    },
  };
  return {
    github, context: { repo, serverUrl: 'https://github.com' },
    core: { info() {}, warning(message) { warnings.push(message); }, setFailed(message) { throw new Error(message); } },
    writes, warnings, get downloads() { return downloads; },
  };
}

test('scheduled publisher creates a current fork PR comment from its CI artifact', async () => {
  const f = fixture();
  await coverage.publishForkCoverage(f);
  assert.equal(f.writes.length, 1);
  assert.equal(f.writes[0].kind, 'create');
  assert.equal(f.writes[0].issue_number, 150);
  assert.ok(f.writes[0].body.includes(report.trim()), 'preserves native comparison and per-file details');
  assert.match(f.writes[0].body, /actions\/runs\/100/);
  assert.ok(f.writes[0].body.includes(sha));
});

test('a current comment causes no write; an outdated bot comment is updated', async () => {
  const initial = fixture();
  await coverage.publishForkCoverage(initial);
  const comment = { id: 300, user: { login: 'github-actions[bot]', type: 'Bot' }, body: initial.writes[0].body };
  const current = fixture({ comments: [comment] });
  await coverage.publishForkCoverage(current);
  assert.deepEqual(current.writes, []);
  const stale = fixture({ comments: [{ ...comment, body: '<!-- octocov -->\nold' }] });
  await coverage.publishForkCoverage(stale);
  assert.equal(stale.writes[0].kind, 'update');
  assert.equal(stale.writes[0].comment_id, 300);
});

test('same-repository PRs and missing fork repositories are skipped', async () => {
  const f = fixture({ pulls: [
    { ...pull, head: { ...pull.head, repo: { full_name: '0xMiden/miden-debug' } } },
    { ...pull, head: { ...pull.head, repo: null } },
  ] });
  await coverage.publishForkCoverage(f);
  assert.equal(f.downloads, 0);
  assert.deepEqual(f.writes, []);
});

for (const [name, options] of Object.entries({
  'missing artifact': { artifacts: [] },
  'expired artifact': { artifacts: [{ ...artifact, expired: true }] },
  'missing Markdown': { archive: zip({ 'coverage-pr-context.txt': prContext }) },
  'expired during download': { downloadError: { status: 410 } },
  'wrong run SHA': { runs: [{ ...run, head_sha: 'b'.repeat(40) }] },
  'wrong head repository': { runs: [{ ...run, head_repository: { full_name: 'other/repo' } }] },
  'wrong branch': { runs: [{ ...run, head_branch: 'other' }] },
  'wrong workflow': { runs: [{ ...run, workflow_id: 8 }] },
  'wrong event': { runs: [{ ...run, event: 'push' }] },
  'wrong PR association': { runs: [{ ...run, pull_requests: [{ number: 151 }] }] },
  'PR changed during processing': { currentPull: { ...pull, head: { ...pull.head, sha: 'b'.repeat(40) } } },
  'PR closed during processing': { currentPull: { ...pull, state: 'closed' } },
})) {
  test(`skips ${name}`, async () => {
    const f = fixture(options);
    await coverage.publishForkCoverage(f);
    assert.deepEqual(f.writes, []);
  });
}

test('artifact context cannot redirect a comment to another PR', async () => {
  const f = fixture({ archive: zip({ 'coverage-comment.md': report, 'coverage-pr-context.txt': `151\n${sha}\n${fork}\n` }) });
  await coverage.publishForkCoverage(f);
  assert.deepEqual(f.writes, []);
  assert.equal(f.warnings.length, 1);
});

test('invalid coverage is rejected without posting artifact content', async () => {
  const f = fixture({ archive: zip({ 'coverage-comment.md': '', 'coverage-pr-context.txt': prContext }) });
  await coverage.publishForkCoverage(f);
  assert.deepEqual(f.writes, []);
  assert.equal(f.warnings.length, 1);
});

test('newest report is selected even when CI failed in an unrelated job', async () => {
  const f = fixture({ runs: [{ ...run, id: 99, created_at: '2026-10-06T00:00:00Z' }, { ...run, conclusion: 'failure' }] });
  await coverage.publishForkCoverage(f);
  assert.match(f.writes[0].body, /actions\/runs\/100/);
});

test('API authorization errors are not silently treated as missing coverage', async () => {
  const f = fixture({ downloadError: { status: 403 } });
  await assert.rejects(() => coverage.publishForkCoverage(f));
});

test('ZIP reader reads fixed members without extracting unrelated paths', () => {
  assert.equal(typeof coverage.readCoverageArchive, 'function');
  const result = coverage.readCoverageArchive(zip({
    'coverage-comment.md': report, 'coverage-pr-context.txt': prContext,
    '../../payload': 'do not extract',
  }));
  assert.equal(result.report, report);
  assert.equal(result.context, prContext);
});

test('a newer artifact on the same commit updates the existing comment', async () => {
  const initial = fixture();
  await coverage.publishForkCoverage(initial);
  const f = fixture({ comments: [{ id: 300, user: { login: 'github-actions[bot]', type: 'Bot' },
    body: initial.writes[0].body.replace(`${sha}:200`, `${sha}:199`) }] });
  await coverage.publishForkCoverage(f);
  assert.equal(f.writes[0].kind, 'update');
});

test('a marker in a human comment is not overwritten', async () => {
  const f = fixture({ comments: [{ id: 300, user: { login: 'contributor', type: 'User' }, body: '<!-- octocov -->' }] });
  await coverage.publishForkCoverage(f);
  assert.equal(f.writes[0].kind, 'create');
});

test('same-repository Dependabot coverage is handled by the scheduled publisher', async () => {
  const botPull = { ...pull, user: { login: 'dependabot[bot]' },
    head: { ...pull.head, repo: { full_name: '0xMiden/miden-debug' } } };
  const f = fixture({ pulls: [botPull], currentPull: botPull,
    runs: [{ ...run, head_repository: botPull.head.repo }],
    archive: zip({ 'coverage-comment.md': report, 'coverage-pr-context.txt': `150\n${sha}\n0xMiden/miden-debug\n` }),
  });
  await coverage.publishForkCoverage(f);
  assert.equal(f.writes[0].kind, 'create');
});

test('all open fork PRs are reconciled, including after a malformed report', async () => {
  const second = { ...pull, number: 151 };
  const f = fixture({ pulls: [pull, second], currentPull: second,
    archive: zip({ 'coverage-comment.md': report, 'coverage-pr-context.txt': `151\n${sha}\n${fork}\n` }),
  });
  await coverage.publishForkCoverage(f);
  assert.equal(f.warnings.length, 1);
  assert.equal(f.writes.length, 1);
  assert.equal(f.writes[0].issue_number, 151);
});

for (const [label, entries] of Object.entries({
  'oversized context': { 'coverage-pr-context.txt': 'a'.repeat(1025), 'coverage-comment.md': report },
  'oversized expanded report': { 'coverage-pr-context.txt': prContext, 'coverage-comment.md': 'a'.repeat(60 * 1024 + 1) },
})) {
  test(`ZIP reader rejects ${label}`, () => {
    assert.throws(() => coverage.readCoverageArchive(zip(entries)));
  });
}

test('ZIP reader rejects duplicate coverage members', () => {
  const duplicate = execFileSync('python3', ['-c', [
    'import io, sys, zipfile',
    'out = io.BytesIO()',
    'with zipfile.ZipFile(out, "w") as archive:',
    '    archive.writestr("coverage-pr-context.txt", "x")',
    '    archive.writestr("coverage-pr-context.txt", "y")',
    '    archive.writestr("coverage-comment.md", "z")',
    'sys.stdout.buffer.write(out.getvalue())',
  ].join('\n')], { stdio: ['pipe', 'pipe', 'pipe'] });
  assert.throws(() => coverage.readCoverageArchive(duplicate));
});

test('direct reusable commenter skips forks and publishes same-repository reports', async (t) => {
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'coverage-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const previousDirectory = process.env.COVERAGE_ARTIFACT;
  process.env.COVERAGE_ARTIFACT = directory;
  t.after(() => {
    if (previousDirectory === undefined) delete process.env.COVERAGE_ARTIFACT;
    else process.env.COVERAGE_ARTIFACT = previousDirectory;
  });
  const direct = fixture();
  direct.context.payload = { pull_request: pull };
  await coverage(direct);
  assert.deepEqual(direct.writes, []);
  const localPull = { ...pull, head: { ...pull.head, repo: { full_name: '0xMiden/miden-debug' } } };
  const local = fixture({ currentPull: localPull });
  local.context.payload = { pull_request: localPull };
  local.context.runId = 100;
  fs.writeFileSync(path.join(directory, 'coverage-comment.md'), report);
  fs.writeFileSync(path.join(directory, 'coverage-pr-context.txt'), `150\n${sha}\n0xMiden/miden-debug\n`);
  await coverage(local);
  assert.equal(local.writes[0].kind, 'create');
  assert.match(local.writes[0].body, /80%/);
});

test('publisher surfaces a missing Python runtime instead of blaming the artifact', async (t) => {
  const previousPath = process.env.PATH;
  process.env.PATH = '';
  t.after(() => { process.env.PATH = previousPath; });
  const f = fixture();
  await assert.rejects(() => coverage.publishForkCoverage(f), { code: 'ENOENT' });
});
