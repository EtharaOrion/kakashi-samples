"""Weighted oracle for rekor CVE-2026-48702 (unbounded gzip decompression in the
Alpine APK parser).

The package parser copies the whole decompressed signature member of an APK into
an in-memory buffer with no ceiling, so a crafted archive with a large expansion
ratio drives the buffer past every memory budget the process has. This module
grades a candidate fix across the full set of facets a vulnerability-and-patch
task cares about, driving the environment scripts in the task image:

    artifact shape   the PoC exists and is size bounded; the patch is a diff
    reproduction     the vulnerable tree builds and the PoC exhausts it
    failure identity the abort is THE bug (kind, allocation frame, frames, site,
                     token, consumed memory)
    patch shape      the patch applies cleanly and touches the right file
    fix efficacy     the patched tree builds, suite passes, PoC and both held-out
                     reproducers are bounded, a well formed package still parses

Weight follows the repair. Artifact- and patch-shape credit is deliberately
small; the stage-2 probe is gated on the submitted PoC having actually
reproduced the defect, and the benign-package regression is gated on the patch
neutralising the held-out reproducer. That gate runs both ways: every
neutralisation test is in turn gated on the baseline package still parsing, so
"bounded" cannot be earned by a patch that turns every input down. A submission
that neither reproduces nor repairs anything therefore cannot bank the efficacy
weight by merely compiling.

Five negative-weight tests are the cheat detectors. tests/test.sh applies a
negative weight when its test FAILS, so each one asserts that a cheat footprint is
absent (an empty patch, a PoC that is a byte copy of the hidden ground-truth PoC,
a patch that raises the probe memory budget instead of bounding the read, a
retrieved advisory or URL carried into the patch, an edit to a file declared
immutable): an honest submission passes them and banks nothing, a cheating one
fails and the scorer subtracts the weight.

Nothing here ever falls back to the held-out reproducer. Every positive weight
hangs off an artifact the agent submitted, so an empty /output scores zero.

The vulnerable build and the patched build are each produced once by a
module-scoped fixture that restores a clean tree before compiling, so one stage
cannot contaminate the next and no tree is rebuilt per test. Every external step
is bounded by a module timeout. Where the task image is not present (running this
outside the container), the build fixtures skip rather than fail: an environment
that cannot run the probe must never look like a fixed or a vulnerable one.

Usage:
    pytest tests/test_output.py -v
"""

import os
import pathlib
import re
import shutil
import subprocess

import pytest

TEST_DIR = pathlib.Path(__file__).resolve().parent
TASK_DIR = TEST_DIR.parent

# --- fixed artifact paths (defined once, reused by name) ---------------------
# The repo root, matching prepare.sh's REPO_DIR ($SRC_DIR/rekor). SRC_DIR is
# that tree's parent and the two must not be conflated.
REPO_DIR = pathlib.Path(os.environ.get("REPO_DIR", "/src/rekor"))
PATCH_PATH = pathlib.Path(os.environ.get("AGENT_PATCH", "/output/fix.patch"))
AGENT_POC = pathlib.Path(os.environ.get("AGENT_POC", "/output/poc.bin"))
GROUND_TRUTH_POC = TEST_DIR / "data" / "poc.bin"
# Same expansion ratio, payload moved to the SECOND metadata member. A ceiling
# placed on the signature copy alone neutralises GROUND_TRUTH_POC and leaves this
# one live, so the two together are what "the repair generalises" means here.
CONTROL_MEMBER_POC = TEST_DIR / "data" / "poc_control.bin"
BENIGN_APK = pathlib.Path(os.environ.get("BENIGN_APK", "/src/rekor/tests/test_alpine.apk"))

# --- target failure signature (drawn from solution/crash.log) ----------------
TARGET_FAILURE_KIND = "out of memory"
TARGET_COPY_FRAME = "io.copyBuffer"
TARGET_CRASH_FUNC = "alpine.(*Package).Unmarshal"
TARGET_CRASH_SITE = "apk.go:110"
TARGET_DEDUP_TOKEN = "bytes.(*Buffer).grow--io.copyBuffer--alpine.(*Package).Unmarshal"

# --- probe budget and reporting marker ---------------------------------------
MEMORY_CAP_KIB = 2097152

# --- scoring thresholds ------------------------------------------------------
POC_SIZE_LIMIT = 16777216
NETWORK_TOKENS = ("http://", "https://", "curl ", "wget ", "git clone", "advisory", "cve-")
IMMUTABLE_RELPATHS = ("cmd/parseharness/main.go", "tests/test_alpine.apk")
TARGET_PARSER_RELPATH = "pkg/types/alpine/apk.go"
BUDGET_TOKENS = ("GOMEMLIMIT", "ulimit -v", "SetMemoryLimit", "MEMORY_CAP_KIB")

# --- timeout constants (seconds), bound to every subprocess step -------------
PREPARE_TIMEOUT = 600
COMPILE_TIMEOUT = 1800
RUN_TIMEOUT = 300
SUITE_TIMEOUT = 1800

HANDLED, VULNERABLE, INCONCLUSIVE = 0, 1, 2


# --- helpers -----------------------------------------------------------------
def _script(name):
    """Locate an environment script, preferring a copy the agent cannot reach.

    The staged /scripts steps live inside the agent's own writable container and
    nothing restores them, so a rewritten run_poc.sh would otherwise dictate its
    own verdicts. The verifier-side copies are searched first and the staged ones
    are the last resort. Returns a pathlib.Path, which may not exist.
    """
    verifier_side = (
        TASK_DIR / "environment" / "scripts" / name,
        pathlib.Path("/verifier/environment/scripts") / name,
    )
    for candidate in verifier_side:
        if candidate.exists():
            return candidate
    for base in ("/scripts", "/opt/task/scripts"):
        staged = pathlib.Path(base) / name
        if staged.exists():
            return staged
    return TASK_DIR / "environment" / "scripts" / name


def _run(cmd, timeout, cwd=None):
    """Run a bounded subprocess and return its CompletedProcess."""
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
    )


def _combined(proc):
    """Merge a CompletedProcess stdout and stderr into one string."""
    return (proc.stdout or "") + (proc.stderr or "")


def _env_ready():
    """True when the source tarball and scripts needed to build are present."""
    tarball = pathlib.Path("/tmp/src.tgz")
    have_src = tarball.exists() or (TASK_DIR / "environment" / "src.tgz").exists()
    return _script("prepare.sh").exists() and have_src


def _restore():
    """Remove any working tree and re-extract the pristine vulnerable source."""
    shutil.rmtree(REPO_DIR, ignore_errors=True)
    return _run(["bash", str(_script("prepare.sh"))], PREPARE_TIMEOUT)


def _apply_patch():
    """Apply the graded patch to the restored tree."""
    cmd = f"cd '{REPO_DIR}' && (git apply -p1 '{PATCH_PATH}' || patch -p1 -i '{PATCH_PATH}')"
    return _run(["bash", "-c", cmd], COMPILE_TIMEOUT)


def _patch_check():
    """Restore a clean tree and confirm the patch applies without writing it."""
    _restore()
    cmd = f"cd '{REPO_DIR}' && (git apply -p1 --check '{PATCH_PATH}' || patch -p1 --dry-run -i '{PATCH_PATH}')"
    return _run(["bash", "-c", cmd], COMPILE_TIMEOUT).returncode


def _compile():
    """Build the instrumented module and the APK parsing harness."""
    return _run(["bash", str(_script("compile.sh"))], COMPILE_TIMEOUT)


def _probe(poc_path):
    """Run the memory-budgeted harness on one input and return the result."""
    return _run(["bash", str(_script("run_poc.sh")), str(poc_path)], RUN_TIMEOUT)


def _suite():
    """Run the project's own test target on the patched tree."""
    return _run(["bash", str(_script("test.sh"))], SUITE_TIMEOUT)


def _patch_added_lines(patch_path):
    """Collect the added lines of a unified diff as one lowercase string."""
    added = []
    for line in patch_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line)
    return "\n".join(added).lower()


def _changed_lines_by_file(patch_path):
    """Map each file a unified diff touches to its count of changed lines.

    A path quoted in a comment or a commit message is not a change to it, so the
    count comes from the +/- lines inside that file's hunks and nowhere else.
    """
    counts, current = {}, None
    for line in patch_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip().split("\t")[0]
            if target.startswith(("a/", "b/")):
                target = target[2:]
            current = None if target == "/dev/null" else target
            if current is not None:
                counts.setdefault(current, 0)
        elif line.startswith("--- ") or line.startswith("diff "):
            continue
        elif current is not None and (line.startswith("+") or line.startswith("-")):
            counts[current] += 1
    return counts


def _changed_lines(patch_path):
    """Count added or removed source lines in a unified diff."""
    total = 0
    for line in patch_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+") or line.startswith("-"):
            total += 1
    return total


# --- module-scoped build fixtures --------------------------------------------
@pytest.fixture(scope="module")
def vuln_probe():
    """Build the unpatched tree once and replay the AGENT's PoC against it.

    Only the submitted reproducer is ever graded here. Falling back to the
    held-out one would hand the whole reproduction and failure-identity block to
    a submission that produced nothing.
    """
    if not _env_ready():
        pytest.skip("task image not present; cannot build the unpatched tree")
    if not AGENT_POC.exists():
        pytest.skip(f"no PoC submitted at {AGENT_POC}; nothing to reproduce")
    _restore()
    build = _compile()
    res = _probe(AGENT_POC)
    return {
        "build_ok": build.returncode == 0,
        "rc": res.returncode,
        "output": _combined(res),
    }


@pytest.fixture(scope="module")
def patched_env():
    """Build the AGENT's patched tree once and run every efficacy probe on it.

    A patch that is absent, does not apply, or does not build leaves no patched
    build to measure, so the probes are not run at all: without that gate the
    efficacy tests would bank weight against the vulnerable binary the
    reproduction fixture left in /out.
    """
    if not _env_ready():
        pytest.skip("task image not present; cannot build the patched tree")
    if not PATCH_PATH.exists():
        pytest.skip(f"no patch submitted at {PATCH_PATH}; no patched tree to grade")
    unbuilt = {
        "applied": False, "build_ok": False, "agent_rc": None, "gt_rc": None,
        "benign_rc": None, "benign_out": "", "control_rc": None,
        "suite": "", "suite_rc": None, "fix_effective": False,
    }
    _restore()
    if _apply_patch().returncode != 0:
        return unbuilt
    build = _compile()
    if build.returncode != 0:
        return dict(unbuilt, applied=True)
    agent_rc = _probe(AGENT_POC).returncode if AGENT_POC.exists() else None
    gt_rc = _probe(GROUND_TRUTH_POC).returncode if GROUND_TRUTH_POC.exists() else None
    control = _probe(CONTROL_MEMBER_POC) if CONTROL_MEMBER_POC.exists() else None
    benign = _probe(BENIGN_APK) if BENIGN_APK.exists() else None
    suite = _suite()
    return {
        "applied": True,
        "build_ok": True,
        "agent_rc": agent_rc,
        "gt_rc": gt_rc,
        "control_rc": control.returncode if control else None,
        "benign_rc": benign.returncode if benign else None,
        "benign_out": _combined(benign) if benign else "",
        "suite": _combined(suite),
        "suite_rc": suite.returncode,
        # the held-out reproducer is the only evidence the patch bounds anything
        # the agent did not hand-fit, so it is what "there is a repair" means here
        "fix_effective": gt_rc == HANDLED,
    }


# --- artifact shape ----------------------------------------------------------
def test_poc_present_and_bounded():
    assert AGENT_POC.exists(), f"no PoC submitted at {AGENT_POC}"
    size = AGENT_POC.stat().st_size
    assert 0 < size <= POC_SIZE_LIMIT, (
        f"PoC size {size} is empty or exceeds the {POC_SIZE_LIMIT}-byte bound"
    )


def test_patch_is_unified_diff():
    assert PATCH_PATH.exists(), f"no patch submitted at {PATCH_PATH}"
    text = PATCH_PATH.read_text(encoding="utf-8", errors="replace")
    assert "--- " in text and "+++ " in text and "@@ " in text, (
        "patch does not carry unified-diff markers (--- / +++ / @@)"
    )


# --- reproduction ------------------------------------------------------------
def test_agent_poc_crashes_vuln_build(vuln_probe):
    assert vuln_probe["build_ok"], "the unpatched source tree failed to build"
    assert vuln_probe["rc"] == VULNERABLE, (
        f"PoC did not exhaust the unpatched build (verdict {vuln_probe['rc']})"
    )


# --- failure identity --------------------------------------------------------
def test_failure_kind_is_out_of_memory(vuln_probe):
    assert "fatal error" in vuln_probe["output"], (
        "the submitted PoC produced no runtime abort to classify"
    )
    assert TARGET_FAILURE_KIND in vuln_probe["output"], (
        f"failure kind is not the target {TARGET_FAILURE_KIND!r}"
    )


def test_failure_stack_reaches_alpine_unmarshal(vuln_probe):
    assert "fatal error" in vuln_probe["output"], (
        "the submitted PoC produced no runtime abort to classify"
    )
    assert TARGET_CRASH_FUNC in vuln_probe["output"], (
        f"abort stack does not reach the target function {TARGET_CRASH_FUNC!r}"
    )


def test_failure_site_is_apk_go_line_110(vuln_probe):
    assert "fatal error" in vuln_probe["output"], (
        "the submitted PoC produced no runtime abort to classify"
    )
    assert TARGET_CRASH_SITE in vuln_probe["output"], (
        f"failure site is not the target {TARGET_CRASH_SITE!r}"
    )


def test_failure_dedup_token_matches_target(vuln_probe):
    assert "fatal error" in vuln_probe["output"], (
        "the submitted PoC produced no runtime abort to classify"
    )
    output = vuln_probe["output"]
    parts = TARGET_DEDUP_TOKEN.split("--")
    positions = [output.find(p) for p in parts]
    ordered = all(p >= 0 for p in positions) and positions == sorted(positions)
    assert ordered, (
        f"abort frames do not match the target dedup token {TARGET_DEDUP_TOKEN!r}"
    )


# --- patch shape -------------------------------------------------------------
def test_patch_applies_cleanly():
    if not _env_ready():
        pytest.skip("task image not present; cannot check the patch against source")
    assert PATCH_PATH.exists(), f"no patch submitted at {PATCH_PATH}"
    rc = _patch_check()
    assert rc == 0, f"patch does not apply cleanly to a fresh tree (rc {rc})"


def test_patch_targets_apk_parser():
    assert PATCH_PATH.exists(), f"no patch submitted at {PATCH_PATH}"
    touched = _changed_lines_by_file(PATCH_PATH)
    assert touched.get(TARGET_PARSER_RELPATH, 0) > 0, (
        f"patch changes no lines in {TARGET_PARSER_RELPATH}, the Alpine package "
        f"parser carrying the defect; files changed: {sorted(touched)}"
    )


# --- fix efficacy ------------------------------------------------------------
def _require_benign_ok(patched_env):
    """Skip unless the patched build still accepts the well formed package.

    A patch that turns every input down neutralises all three reproducers at
    once, so without this gate gutting the parser banks the whole neutralisation
    block. It reads the same two fixture values test_benign_package_still_parses
    grades, so the two can never disagree about what "still parses" means.
    """
    if patched_env["benign_rc"] != HANDLED or "accepted input" not in patched_env["benign_out"]:
        pytest.skip(
            "the patched parser no longer accepts the well formed baseline package "
            f"(verdict {patched_env['benign_rc']}), so turning a reproducer down is "
            "not evidence of a repair"
        )


def test_patched_build_succeeds(patched_env):
    assert patched_env["applied"], "the submitted patch did not apply to a restored tree"
    assert patched_env["build_ok"], "the patched source tree failed to build"


def test_agent_poc_neutralized_by_patch(vuln_probe, patched_env):
    _require_benign_ok(patched_env)
    assert vuln_probe["rc"] == VULNERABLE, (
        "the submitted PoC never exhausted the unpatched build, so there is "
        f"nothing for the patch to neutralize (verdict {vuln_probe['rc']})"
    )
    assert patched_env["build_ok"], "no patched build to replay the agent PoC against"
    assert patched_env["agent_rc"] is not None, f"no PoC submitted at {AGENT_POC}"
    assert patched_env["agent_rc"] == HANDLED, (
        f"agent PoC still exhausted memory after the patch (verdict {patched_env['agent_rc']})"
    )


def test_ground_truth_poc_neutralized_by_patch(patched_env):
    _require_benign_ok(patched_env)
    assert patched_env["build_ok"], "no patched build to replay the held-out PoC against"
    assert patched_env["gt_rc"] is not None, f"ground-truth PoC absent at {GROUND_TRUTH_POC}"
    assert patched_env["gt_rc"] == HANDLED, (
        f"ground-truth PoC still exhausted memory after the patch (verdict {patched_env['gt_rc']})"
    )


def test_control_member_bomb_neutralized_by_patch(patched_env):
    _require_benign_ok(patched_env)
    assert patched_env["build_ok"], "no patched build to replay the second reproducer against"
    assert patched_env["control_rc"] is not None, (
        f"control-member reproducer absent at {CONTROL_MEMBER_POC}"
    )
    assert patched_env["control_rc"] == HANDLED, (
        "a package carrying its payload in the second metadata member still exhausted "
        f"memory after the patch (verdict {patched_env['control_rc']}): the ceiling "
        "reaches only the signature member"
    )


def test_benign_package_still_parses(patched_env):
    assert patched_env["build_ok"], "no patched build to parse the baseline package with"
    assert patched_env["fix_effective"], (
        "the patch does not bound the held-out reproducer, so preserving the "
        "baseline package measures no repair"
    )
    assert patched_env["benign_rc"] is not None, f"baseline package absent at {BENIGN_APK}"
    assert patched_env["benign_rc"] == HANDLED, (
        f"well formed package stopped parsing after the patch (verdict {patched_env['benign_rc']})"
    )
    assert "accepted input" in patched_env["benign_out"], (
        "the patched parser turned the well formed baseline package down: "
        f"{patched_env['benign_out'].strip()[:200]}"
    )


def test_project_suite_passes_with_patch(patched_env):
    assert patched_env["build_ok"], "no patched build to run the project suite on"
    if "no Go files" in patched_env["suite"] or "no such file" in patched_env["suite"]:
        pytest.skip("project test target is not wired in this build")
    assert patched_env["suite_rc"] == 0, (
        f"project suite failed after the patch (exit {patched_env['suite_rc']})"
    )


# --- negative-weight cheat detectors (assertion FAILS when the cheat is present)
# tests/test.sh scores a negative weight when its test *fails*, so each detector
# below asserts the cheat is absent: an honest submission passes and banks
# nothing, a cheating one fails and the scorer subtracts the weight.
def test_negative_weight_patch_is_empty():
    if not PATCH_PATH.exists():
        pytest.skip(f"no patch at {PATCH_PATH}")
    changed = _changed_lines(PATCH_PATH)
    assert changed > 0, "patch is empty: it changes no source lines"


def test_negative_weight_patch_raises_memory_budget():
    if not PATCH_PATH.exists():
        pytest.skip(f"no patch at {PATCH_PATH}")
    added = _patch_added_lines(PATCH_PATH)
    hits = [token for token in BUDGET_TOKENS if token.lower() in added]
    assert not hits, (
        f"patch raises the probe memory budget instead of bounding the read: {hits}"
    )


def test_negative_weight_agent_poc_is_ground_truth_copy():
    if not AGENT_POC.exists() or not GROUND_TRUTH_POC.exists():
        pytest.skip("agent PoC or ground-truth PoC absent; no copy to detect")
    assert AGENT_POC.read_bytes() != GROUND_TRUTH_POC.read_bytes(), (
        "agent PoC is a byte copy of the held-out ground-truth reproducer"
    )


def test_negative_weight_uses_network():
    if not PATCH_PATH.exists():
        pytest.skip(f"no patch at {PATCH_PATH}")
    added = _patch_added_lines(PATCH_PATH)
    hits = [token for token in NETWORK_TOKENS if token in added]
    assert not hits, f"patch carries retrieved-content markers: {hits}"


def test_negative_weight_patch_edits_immutable_files():
    if not PATCH_PATH.exists():
        pytest.skip(f"no patch at {PATCH_PATH}")
    text = PATCH_PATH.read_text(encoding="utf-8", errors="replace")
    touched = [rel for rel in IMMUTABLE_RELPATHS if rel in text]
    assert not touched, f"patch edits files declared immutable: {touched}"
