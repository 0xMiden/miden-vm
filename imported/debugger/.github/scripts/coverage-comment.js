const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const MARKER = '<!-- octocov -->';
const MAX_ARCHIVE = 10 * 1024 * 1024;

// Rendered by octocov in the read-only report job. Preserve its comparisons and
// file tables; publishing must never run the PR's octocov configuration.
function summary(report) {
  if (!report.trim().startsWith('## Code Metrics Report') ||
      Buffer.byteLength(report, 'utf8') > 60 * 1024) {
    throw new Error('Missing or oversized octocov report');
  }
  return report.trim();
}

function artifactMatchesPull(text, pull) {
  const [number, sha, repository, ...extra] = text.trim().split('\n');
  return extra.length === 0 && Number(number) === pull.number &&
    sha === pull.head.sha && repository === pull.head.repo?.full_name;
}

function sameHead(left, right) {
  return right.state === 'open' && left.head.sha === right.head.sha &&
    left.head.ref === right.head.ref &&
    left.head.repo?.full_name === right.head.repo?.full_name;
}

function readPrefix(filename, limit) {
  const descriptor = fs.openSync(filename, 'r');
  try {
    const buffer = Buffer.alloc(limit);
    return buffer.toString('utf8', 0, fs.readSync(descriptor, buffer, 0, limit, 0));
  } finally {
    fs.closeSync(descriptor);
  }
}

async function publishComment({ github, context, core }, pull, result, runId, revision) {
  const comments = await github.paginate(github.rest.issues.listComments, {
    ...context.repo, issue_number: pull.number, per_page: 100,
  });
  const previous = comments.find(comment => comment.user?.login === 'github-actions[bot]' &&
    comment.user?.type === 'Bot' && comment.body?.includes(MARKER));
  const runUrl = `${context.serverUrl || 'https://github.com'}/${context.repo.owner}/${context.repo.repo}/actions/runs/${runId}`;
  const body = `${MARKER}\n${result}\n\n[Coverage CI run](${runUrl})\n\n` +
    `<!-- coverage-revision: ${pull.head.sha}:${revision} -->`;
  if (previous?.body === body) return;

  // The PR can change while fetching runs, artifacts, or comments.
  const { data: current } = await github.rest.pulls.get({
    ...context.repo, pull_number: pull.number,
  });
  if (!sameHead(pull, current)) {
    core.info(`Skipping changed or closed PR #${pull.number}`);
    return;
  }
  if (previous) {
    await github.rest.issues.updateComment({ ...context.repo, comment_id: previous.id, body });
  } else {
    await github.rest.issues.createComment({ ...context.repo, issue_number: pull.number, body });
  }
}

async function commentOnCoverage(options) {
  const { github, context, core } = options;
  const eventPull = context.payload.pull_request;
  const repository = `${context.repo.owner}/${context.repo.repo}`;
  // This entry point must never try to publish from a fork's read-only token.
  if (!eventPull || eventPull.head.repo?.full_name !== repository) return;
  const { data: pull } = await github.rest.pulls.get({
    ...context.repo, pull_number: eventPull.number,
  });
  if (!sameHead(eventPull, pull)) return;
  const directory = process.env.COVERAGE_ARTIFACT;
  const report = path.join(directory, 'coverage-comment.md');
  if (!fs.existsSync(report)) return;
  const artifactContext = readPrefix(path.join(directory, 'coverage-pr-context.txt'), 1025);
  if (artifactContext.length > 1024 || !artifactMatchesPull(artifactContext, pull)) {
    core.warning(`Ignoring mismatched coverage for PR #${pull.number}`);
    return;
  }
  await publishComment(options, pull, summary(readPrefix(report, 60 * 1024 + 1)), context.runId,
    `${context.runId}:${process.env.GITHUB_RUN_ATTEMPT || '1'}`);
}

function readCoverageArchive(data) {
  const input = Buffer.from(data);
  if (input.length > MAX_ARCHIVE) throw new Error('Coverage archive exceeds size limit');
  // Only this trusted helper is executed. ZIP entries are read in memory, never extracted.
  return JSON.parse(execFileSync('python3', [path.join(__dirname, 'coverage-archive.py')], {
    input, encoding: 'utf8', timeout: 10000, maxBuffer: 512 * 1024,
    stdio: ['pipe', 'pipe', 'pipe'],
  }));
}

async function findReport({ github, context, core }, pull, workflowId) {
  const runs = await github.paginate(github.rest.actions.listWorkflowRuns, {
    ...context.repo, workflow_id: workflowId, event: 'pull_request',
    head_sha: pull.head.sha, status: 'completed', per_page: 100,
  });
  runs.sort((left, right) => right.id - left.id);
  for (const run of runs) {
    if (run.workflow_id !== workflowId || run.event !== 'pull_request' ||
        run.status !== 'completed' || run.head_sha !== pull.head.sha ||
        run.head_branch !== pull.head.ref ||
        run.head_repository?.full_name !== pull.head.repo.full_name ||
        (run.pull_requests?.length && !run.pull_requests.some(pr => pr.number === pull.number))) continue;

    const artifacts = await github.paginate(github.rest.actions.listWorkflowRunArtifacts, {
      ...context.repo, run_id: run.id, per_page: 100,
    });
    const artifact = artifacts.filter(item => item.name === 'coverage-comment' && !item.expired)
      .sort((left, right) => right.id - left.id)[0];
    if (!artifact) continue;
    if (artifact.size_in_bytes > MAX_ARCHIVE) {
      core.warning(`Skipping oversized coverage artifact for PR #${pull.number}`);
      continue;
    }
    let data;
    try {
      ({ data } = await github.rest.actions.downloadArtifact({
        ...context.repo, artifact_id: artifact.id, archive_format: 'zip',
      }));
    } catch (error) {
      // Artifacts may expire or be deleted between listing and downloading.
      if (error.status === 404 || error.status === 410) continue;
      throw error;
    }
    try {
      const report = readCoverageArchive(data);
      if (!report) continue;
      if (!artifactMatchesPull(report.context, pull)) throw new Error('Mismatched artifact context');
      return { result: summary(report.report), runId: run.id, revision: artifact.id };
    } catch (error) {
      // Spawn failures and resource limits are operational errors, not bad reports.
      if (error.code) throw error;
      // Keep untrusted archive contents out of logs as well as commands and comments.
      core.warning(`Skipping malformed or mismatched coverage artifact ${artifact.id} for PR #${pull.number}`);
    }
  }
  return null;
}

async function publishForkCoverage(options) {
  const { github, context, core } = options;
  const repository = `${context.repo.owner}/${context.repo.repo}`;
  const pulls = await github.paginate(github.rest.pulls.list, {
    ...context.repo, state: 'open', per_page: 100,
  });
  const { data: workflow } = await github.rest.actions.getWorkflow({
    ...context.repo, workflow_id: 'ci.yml',
  });
  for (const pull of pulls) {
    // Dependabot also receives a read-only token, even for same-repository PRs.
    if (!pull.head.repo || (pull.head.repo.full_name === repository &&
        pull.user?.login !== 'dependabot[bot]')) continue;
    const report = await findReport(options, pull, workflow.id);
    if (!report) {
      core.info(`No current coverage artifact for PR #${pull.number}`);
      continue;
    }
    await publishComment(options, pull, report.result, report.runId, report.revision);
  }
}

module.exports = commentOnCoverage;
module.exports.publishForkCoverage = publishForkCoverage;
module.exports.readCoverageArchive = readCoverageArchive;
