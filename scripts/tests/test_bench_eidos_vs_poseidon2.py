"""Exercise benchmark preflight against simulated Linux host interfaces."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
MODES = ("scaling", "composition-scaling", "aws-campaign", "aws-profile")

# BASH_ENV also supplies these stand-ins to the AWS modes' child runners.
HOST_COMMANDS = r"""
unexpected_call() {
  printf '%s\n' "$*" >> "$BENCH_TEST_ROOT/unexpected-calls"
  return 99
}
command() {
  if [[ "$1" == -v && "$2" == "${BENCH_TEST_MISSING_COMMAND:-}" ]]; then
    return 1
  fi
  builtin command "$@"
}
git() {
  [[ "$1" != -C ]] || shift 2
  case "$1" in
    cat-file|merge-base) return 0 ;;
    rev-parse)
      [[ "$*" != *missing-revision* ]] || return 1
      printf '%040d\n' 1
      ;;
    *) unexpected_call git "$@" ;;
  esac
}
uname() {
  case "$1" in
    -s) echo "${BENCH_TEST_OS:-Linux}" ;;
    -m) echo "${BENCH_TEST_ARCH:-aarch64}" ;;
    *) unexpected_call uname "$@" ;;
  esac
}
ldd() { echo 'ldd (GNU libc) 2.40'; }
lscpu() {
  if [[ "${1:-}" == --parse=* ]]; then
    echo '0,0,0,0,0'
  else
    echo 'Model name: Test CPU'
  fi
}
taskset() { [[ "$*" == *' true' ]] || unexpected_call taskset "$@"; }
numactl() { [[ "$*" == *' true' ]] || unexpected_call numactl "$@"; }
rustc() {
  if [[ "$1" == --print && "$2" == cfg ]]; then
    echo "target_arch=\"$(uname -m)\""
    case "$*" in
      *target-cpu=x86-64-v3*) echo 'target_feature="avx2"' ;;
      *target-cpu=x86-64-v4*)
        printf 'target_feature="%s"\n' avx2 avx512f avx512dq avx512bw avx512cd avx512vl
        ;;
    esac
  else
    unexpected_call rustc "$@"
  fi
}
perf() {
  case "$1" in
    --version) echo 'perf version 6.8' ;;
    stat)
      case "${BENCH_TEST_PERF:-all}" in
        none) return 1 ;;
        software) [[ "$*" != *:u* ]] || return 1 ;;
        '<not supported>'|'<not counted>')
          printf '%s;;event;0;;\n' "$BENCH_TEST_PERF" >&2
          return 0
          ;;
      esac
      printf '1;;event;100;;\n' >&2
      ;;
    *) unexpected_call perf "$@" ;;
  esac
}
cargo() { unexpected_call cargo "$@"; }
mktemp() { unexpected_call mktemp "$@"; }
flock() { unexpected_call flock "$@"; }
tar() { unexpected_call tar "$@"; }
sudo() { unexpected_call sudo "$@"; }
sysctl() { unexpected_call sysctl "$@"; }
apt-get() { unexpected_call apt-get "$@"; }
dnf() { unexpected_call dnf "$@"; }
yum() { unexpected_call yum "$@"; }
"""


class BenchmarkPreflightTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="eidos-preflight-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.host = self.root / "host"
        self.thp = self.host / "sys/kernel/mm/transparent_hugepage/enabled"
        files = {
            "sys/kernel/mm/transparent_hugepage/enabled": "always [madvise] never\n",
            "proc/sys/kernel/perf_event_paranoid": "4\n",
            "proc/self/status": "Cpus_allowed_list:\t0\n",
            "proc/self/cgroup": "0::/\n",
            "proc/cpuinfo": (
                "flags : avx avx2 bmi1 bmi2 cx16 f16c fma lahf_lm lzcnt movbe popcnt pni "
                "sse4_1 sse4_2 ssse3 xsave avx512f avx512dq avx512bw avx512cd avx512vl\n"
            ),
            "sys/fs/cgroup/cgroup.controllers": "cpu\n",
            "sys/fs/cgroup/cpu.max": "max 100000\n",
            "sys/fs/cgroup/cpu.stat": "",
            "time": "#!/bin/sh\nexit 99\n",
        }
        for name, contents in files.items():
            path = self.host / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
        (self.host / "time").chmod(0o755)

        # Redirect only host file paths; execute the complete runner and its children.
        source = (REPO / "scripts/bench_eidos_vs_poseidon2.sh").read_text()
        for prefix in ("/sys/", "/proc/"):
            source = source.replace(prefix, str(self.host) + prefix)
        source = source.replace("/usr/bin/time", str(self.host / "time"))
        self.runner = self.root / "scripts/bench_eidos_vs_poseidon2.sh"
        self.runner.parent.mkdir()
        self.runner.write_text(source)
        self.runner.chmod(0o755)
        (self.root / "bench-baselines").symlink_to(REPO / "bench-baselines", target_is_directory=True)
        self.commands = self.root / "host-commands.sh"
        self.commands.write_text(HOST_COMMANDS)

    def run_runner(self, mode, *args, dry_run=True, **settings):
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("EIDOS_", "BENCH_TEST_"))
        }
        env.update(
            BASH_ENV=str(self.commands),
            BENCH_TEST_ROOT=str(self.root),
            GLIBC_TUNABLES="glibc.malloc.hugetlb=1",
        )
        env.update(settings)
        before = {p: p.read_bytes() for p in self.host.rglob("*") if p.is_file()}
        command = ["bash", str(self.runner), f"--{mode}", "--threads", "1", *args]
        if dry_run:
            command.append("--dry-run")
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        after = {p: p.read_bytes() for p in self.host.rglob("*") if p.is_file()}
        self.assertEqual(before, after, output)
        calls = self.root / "unexpected-calls"
        self.assertFalse(calls.exists(), calls.read_text() if calls.exists() else output)
        self.assertFalse((self.root / "target").exists(), output)
        return result.returncode, output

    def test_configured_dry_runs_finish_without_artifacts(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                code, output = self.run_runner(mode)
                self.assertEqual(code, 0, output)
                self.assertIn("kernel THP:       always [madvise] never", output)
                if mode == "aws-campaign":
                    self.assertIn("preflight passed for hugetlb0-native", output)
                    self.assertIn("preflight passed for hugetlb1-native", output)

    def test_wrong_thp_policy_reports_setup_without_writing(self):
        self.thp.write_text("always madvise [never]\n")
        for mode in MODES:
            for dry_run in (True, False):
                with self.subTest(mode=mode, dry_run=dry_run):
                    code, output = self.run_runner(mode, dry_run=dry_run)
                    self.assertNotEqual(code, 0, output)
                    self.assertIn("always madvise [never]", output)
                    self.assertIn(f"set {self.thp} to madvise", output)

    def test_x86_campaign_preflights_all_cpu_profiles(self):
        code, output = self.run_runner("aws-campaign", BENCH_TEST_ARCH="x86_64")
        self.assertEqual(code, 0, output)
        for arm in (
            "hugetlb0-native", "hugetlb1-native", "hugetlb1-x86-64-v3", "hugetlb1-x86-64-v4"
        ):
            self.assertIn(f"preflight passed for {arm}", output)

    def test_unavailable_thp_policy_is_reported(self):
        self.thp.unlink()
        for mode in MODES:
            with self.subTest(mode=mode):
                code, output = self.run_runner(mode)
                self.assertNotEqual(code, 0, output)
                self.assertIn("cannot read kernel THP policy", output)

    def test_invalid_revision_is_rejected_before_host_preflight(self):
        self.thp.write_text("[always] madvise never\n")
        for mode in MODES:
            with self.subTest(mode=mode):
                code, output = self.run_runner(mode, "--eidos-rev", "missing-revision")
                self.assertNotEqual(code, 0, output)
                self.assertIn("Eidos revision missing-revision is unavailable", output)

    def test_missing_profile_tools_are_reported_without_installing(self):
        for tool in ("perf", "numactl", "time"):
            with self.subTest(tool=tool):
                if tool == "time":
                    (self.host / "time").unlink()
                code, output = self.run_runner("aws-profile", BENCH_TEST_MISSING_COMMAND=tool)
                self.assertNotEqual(code, 0, output)
                self.assertIn("install", output)
                self.assertIn(tool, output)

    def test_aws_dry_runs_propagate_child_preflight_failures(self):
        for mode in ("aws-campaign", "aws-profile"):
            with self.subTest(mode=mode):
                code, output = self.run_runner(mode, BENCH_TEST_MISSING_COMMAND="rustc")
                self.assertNotEqual(code, 0, output)
                self.assertIn("missing required command: rustc", output)
                self.assertNotIn("preflight passed", output)

    def test_profile_uses_available_counters_without_changing_permissions(self):
        code, output = self.run_runner("aws-profile", BENCH_TEST_PERF="software")
        self.assertEqual(code, 0, output)
        self.assertIn("check perf permissions and kernel.perf_event_paranoid", output)
        self.assertRegex(
            output, r"perf events:\s+task-clock,context-switches,cpu-migrations,page-faults\n"
        )
        self.assertIn("[profile] preflight passed", output)

    def test_profile_fails_if_no_counters_are_available(self):
        for failure in ("none", "<not supported>", "<not counted>"):
            with self.subTest(failure=failure):
                code, output = self.run_runner("aws-profile", BENCH_TEST_PERF=failure)
                self.assertNotEqual(code, 0, output)
                self.assertIn("perf exposes none of the requested profiling events", output)

    def test_non_linux_scaling_reports_platform_requirement(self):
        self.thp.unlink()
        for mode in MODES:
            with self.subTest(mode=mode):
                code, output = self.run_runner(
                    mode, BENCH_TEST_OS="Darwin", BENCH_TEST_MISSING_COMMAND="flock"
                )
                self.assertNotEqual(code, 0, output)
                self.assertIn(f"--{mode} requires Linux", output)


if __name__ == "__main__":
    unittest.main()
