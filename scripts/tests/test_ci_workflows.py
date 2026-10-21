"""Run CI path detection against real Git histories without building Rust."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


def workflow_script(filename, step_name):
    lines = (REPO / ".github/workflows" / filename).read_text().splitlines()
    start = lines.index(f"      - name: {step_name}")
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line == "        run: |":
            script = []
            for body in lines[index + 1 :]:
                if body and not body.startswith("          "):
                    break
                script.append(body[10:])
            return "\n".join(script) + "\n"
        if line.startswith("      - "):
            break
    raise AssertionError(f"No shell block found for {step_name}")


class PathDetectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ci-paths-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "CI fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "core.excludesFile", os.devnull)
        self.write("README.md", "initial documentation\n")
        self.write(".github/workflows/base.yml", "name: initial\n")
        self.base = self.commit()
        self.zizmor = workflow_script("zizmor.yml", "Check for CI changes")
        self.eidos = workflow_script("test.yml", "Check for Eidos-related changes")

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", *args],
            cwd=self.repo,
            text=True,
            stderr=subprocess.PIPE,
        ).strip()

    def write(self, name, content="changed\n"):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", "Fixture change")
        return self.git("rev-parse", "HEAD")

    def run_script(self, script, event, base, head, expected, **extra_env):
        output = self.root / "output"
        summary = self.root / "summary"
        output.write_text("")
        summary.write_text("")
        environment = dict(
            os.environ,
            EVENT_NAME=event,
            BASE_SHA=base,
            HEAD_SHA=head,
            GITHUB_OUTPUT=str(output),
            GITHUB_STEP_SUMMARY=str(summary),
        )
        environment.update(extra_env)
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
            cwd=self.repo,
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if expected is None:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(output.read_text(), "")
        else:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(output.read_text(), f"run={expected}\n")
        return summary.read_text()

    def test_zizmor_audits_each_ci_path_for_prs_and_merge_groups(self):
        paths = (
            ".github/workflows/new.yml",
            ".github/actions/setup/action.yml",
            ".github/actionlint.yaml",
            "zizmor.yml",
        )
        for path in paths:
            self.git("checkout", "--quiet", "--detach", self.base)
            self.write(path)
            head = self.commit()
            for event in ("pull_request", "merge_group"):
                with self.subTest(path=path, event=event):
                    self.run_script(self.zizmor, event, self.base, head, "true")

    def test_zizmor_records_noop_for_unrelated_changes(self):
        self.write("README.md")
        head = self.commit()
        for event in ("pull_request", "merge_group"):
            with self.subTest(event=event):
                summary = self.run_script(self.zizmor, event, self.base, head, "false")
                self.assertIn("No CI changes detected", summary)

    def test_queue_diff_includes_earlier_queued_ci_changes(self):
        self.write(".github/workflows/base.yml")
        self.commit()
        self.write("README.md")
        head = self.commit()
        self.run_script(self.zizmor, "merge_group", self.base, head, "true")

    def test_pr_diff_excludes_changes_only_on_the_base_branch(self):
        self.write("README.md")
        head = self.commit()
        self.git("checkout", "--quiet", "--detach", self.base)
        self.write(".github/workflows/base.yml")
        base = self.commit()
        self.run_script(self.zizmor, "pull_request", base, head, "false")

    def test_ci_file_renamed_out_of_ci_still_runs_the_audit(self):
        self.git("mv", ".github/workflows/base.yml", "moved-outside-ci.yml")
        head = self.commit()
        self.run_script(self.zizmor, "pull_request", self.base, head, "true")

    def test_newline_in_filename_does_not_break_path_detection(self):
        self.write(".github/workflows/line\nbreak.yml")
        head = self.commit()
        self.run_script(self.zizmor, "pull_request", self.base, head, "true")

    def test_missing_or_unavailable_diff_endpoints_fail(self):
        scripts = (
            (self.zizmor, "pull_request"),
            (self.zizmor, "merge_group"),
            (self.eidos, "pull_request"),
        )
        for script, event in scripts:
            for base, head in (("", self.base), (self.base, ""), ("0" * 40, self.base)):
                with self.subTest(event=event, base=base, head=head):
                    self.run_script(script, event, base, head, None)

    def test_missing_pr_merge_base_fails(self):
        tree = self.git("rev-parse", self.base + "^{tree}")
        unrelated = self.git("commit-tree", tree, "-m", "Unrelated history")
        for script in (self.zizmor, self.eidos):
            self.run_script(script, "pull_request", unrelated, self.base, None)

    def test_failed_git_diff_fails_the_job(self):
        commands = self.root / "commands"
        commands.mkdir()
        git = commands / "git"
        git.write_text("#!/bin/sh\nexit 42\n")
        git.chmod(0o755)
        path = str(commands) + os.pathsep + os.environ["PATH"]
        for script, event in (
            (self.zizmor, "pull_request"),
            (self.zizmor, "merge_group"),
            (self.eidos, "pull_request"),
        ):
            with self.subTest(event=event):
                self.run_script(script, event, self.base, self.base, None, PATH=path)

    def test_eidos_runs_for_crypto_and_build_changes(self):
        for path in ("crates/crypto/src/lib.rs", "Makefile", ".cargo/config.toml"):
            self.git("checkout", "--quiet", "--detach", self.base)
            self.write(path)
            head = self.commit()
            with self.subTest(path=path):
                self.run_script(self.eidos, "pull_request", self.base, head, "true")

    def test_eidos_skips_unrelated_pr_changes(self):
        self.write("README.md")
        head = self.commit()
        self.run_script(self.eidos, "pull_request", self.base, head, "false")

    def test_eidos_runs_on_merge_groups_and_pushes(self):
        for event in ("merge_group", "push"):
            with self.subTest(event=event):
                self.run_script(self.eidos, event, "", "", "true")

    def test_zizmor_preserves_manual_and_push_audits(self):
        for event in ("workflow_dispatch", "push"):
            with self.subTest(event=event):
                self.run_script(self.zizmor, event, "", "", "true")


if __name__ == "__main__":
    unittest.main()
