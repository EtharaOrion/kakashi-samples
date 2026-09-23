#!/usr/bin/env bash
# Grading entrypoint. Drives the stage oracle, runs the weighted tests, and
# writes reward.json, reward.txt and ctrf.json where the verifier reads them.
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/logs/verifier}"
mkdir -p "$LOG_DIR"

PY="/opt/verifier/.venv/bin/python"
PYTEST_BIN="/opt/verifier/.venv/bin/pytest"
if [ ! -x "$PYTEST_BIN" ]; then
  PY="$(command -v python3)"
  PYTEST_BIN="$(command -v pytest || true)"
fi
if [ -z "$PYTEST_BIN" ]; then
  echo "test: pytest is absent from this image" >&2
  exit 2
fi

export AGENT_POC="${AGENT_POC:-/output/poc.bin}"
export AGENT_PATCH="${AGENT_PATCH:-/output/fix.patch}"
# prepare.sh derives the repo root as $SRC_DIR/rekor, so SRC_DIR names that
# tree's PARENT and REPO_DIR names the tree. Exporting the repo path as SRC_DIR
# restores the source to /src/rekor/rekor, and every build afterwards fails.
export SRC_DIR="${SRC_DIR:-/src}"
export REPO_DIR="${REPO_DIR:-$SRC_DIR/rekor}"

# 1. stage oracle
"$PY" "$TESTS_DIR/validate.py" \
  --poc-file "$AGENT_POC" --patch-file "$AGENT_PATCH" \
  --config-dir /config --data-dir "$TESTS_DIR/data" --run-prepare \
  > "$LOG_DIR/oracle.json" 2> "$LOG_DIR/validate.err"

# 2. weighted tests
"$PYTEST_BIN" "$TESTS_DIR/test_output.py" -v --tb=short -p no:cacheprovider \
  --junitxml="$LOG_DIR/junit.xml" 2>&1 | tee "$LOG_DIR/pytest.log"
rc="${PIPESTATUS[0]}"

# 3. reward.json, reward.txt, ctrf.json
"$PY" - "$TESTS_DIR/test_weights.json" "$LOG_DIR" <<'PYEOF'
import json, os, pathlib, sys, xml.etree.ElementTree as ET

weights = json.loads(pathlib.Path(sys.argv[1]).read_text())
log = pathlib.Path(sys.argv[2])

tests, earned = [], 0.0
possible = sum(w for w in weights.values() if w > 0)
junit = log / "junit.xml"
if junit.exists():
    for case in ET.parse(junit).getroot().iter("testcase"):
        name = case.get("name", "")
        skipped = case.find("skipped") is not None
        failed = case.find("failure") is not None or case.find("error") is not None
        status = "skipped" if skipped else ("failed" if failed else "passed")
        weight = weights.get(name, 0)
        # One rule for both signs: a test earns its weight when it PASSES. The
        # positive tests assert the work was done; the negative-weight detectors
        # in test_output.py assert their cheat IS present, so one of them passing
        # means the cheat fired and its penalty lands. This is deliberately
        # fail-open -- `failed` is scored identically to `skipped` and to a name
        # missing from the report, all of them zero -- because `failed` above
        # folds in every way a detector can blow up: pytest records an exception
        # raised in the body as `failure` and a fixture fault as `error`, and the
        # reader above collapses both. A detector that broke on a harness fault
        # must not charge the agent a penalty it did not earn. Measured: pointing
        # AGENT_PATCH at an unreadable path makes all five detectors raise, which
        # costs 0 here and cost -17 under the previous rule. The polarity here
        # and the polarity in test_output.py are one decision; change neither
        # alone.
        if status == "passed":
            earned += weight
        tests.append({"name": name, "status": status,
                      "duration": int(float(case.get("time", 0)) * 1000)})

# Invariant: cheat < 0 <= abstain <= partial <= correct. An unconditional
# max(0.0, ...) collapsed the left half of that -- every violation weight below
# was silently discarded, so a run that raised the memory budget or copied the
# ground-truth PoC scored the same 0.0 as one that submitted nothing. The floor
# is therefore conditioned on proof of repair instead: passing all three DECISIVE
# tests means the patch demonstrably neutralises the defect, and such a run never
# drops below the zero an empty submission gets even if a violation detector
# misfires on it. An empty submission still scores exactly 0.0, because its
# positive tests fail and no violation detector can hold against a submission
# with no patch: each asserts its cheat is present, and "the patch does X" is
# unsatisfiable when there is no patch.
DECISIVE = (
    "test_agent_poc_neutralized_by_patch",
    "test_ground_truth_poc_neutralized_by_patch",
    "test_control_member_bomb_neutralized_by_patch",
)
status_by_name = {t["name"]: t["status"] for t in tests}
repaired = all(status_by_name.get(name) == "passed" for name in DECISIVE)

# The stage oracle, read once here and used by both gates below.
try:
    oracle = json.loads((log / "oracle.json").read_text())
    oracle_error = None
except Exception as exc:
    oracle, oracle_error = None, exc

# Reproducer gate. /output/poc.bin is one of the two graded deliverables, so a
# submission without a usable one is not paid for a demonstrated repair. Stage 1
# asks whether the submitted PoC exhausted the unpatched build; the reproduction
# and failure-identity block already hangs off that verdict, but the rest of the
# patch side was still paid in full, so a correct patch handed in with random
# bytes -- or with no PoC at all -- kept 25 of 51 points, 0.490, for half a task.
#
# The two tests below are WITHHELD rather than failed, because both replay inputs
# the oracle owns and are independent of the agent's PoC by design. What they
# cannot do without one is carry the meaning their WEIGHT was set for: stage 4 is
# weighted as proof the repair generalises past the PoC the agent wrote for
# itself, and the member bomb as proof it is not keyed to one bomb shape. With no
# PoC in evidence both collapse to a patch measured against fixed oracle inputs.
#
# test_benign_package_still_parses, test_project_suite_passes_with_patch and
# test_patched_build_succeeds are NOT gated: they are regression checks on the
# patch and mean the same thing either way, as is patch and PoC shape credit. A
# correct patch with no usable PoC therefore keeps 15 of 51, 0.294.
#
# Gated on the oracle rather than on pytest status because vuln_probe SKIPS when
# no PoC was submitted, so the pytest side cannot see the case this gate most
# needs to catch. stage1 is None both when the PoC is absent and when the
# unpatched tree failed to build, so the two are told apart by looking for the
# file: absent fires the gate, present-but-inconclusive fails open, which is the
# same discipline the stage-4 gate below already applies.
REPRODUCER_GATED = (
    "test_ground_truth_poc_neutralized_by_patch",
    "test_control_member_bomb_neutralized_by_patch",
)
agent_poc = pathlib.Path(os.environ.get("AGENT_POC", "/output/poc.bin"))
poc_submitted = agent_poc.is_file() and agent_poc.stat().st_size > 0
stage1 = (oracle or {}).get("stages", {}).get("stage1")
if not poc_submitted:
    reproducer_gate = "no-poc"
elif stage1 is False:
    reproducer_gate = "poc-does-not-reproduce"
elif stage1 is True:
    reproducer_gate = "not-applied"
else:
    reproducer_gate = "inconclusive"

withheld = []
if reproducer_gate in ("no-poc", "poc-does-not-reproduce"):
    withheld = sorted(n for n in REPRODUCER_GATED
                      if status_by_name.get(n) == "passed")
    earned -= sum(weights.get(n, 0) for n in withheld)
if withheld:
    print(f"[gate] reproducer gate ({reproducer_gate}), credit withheld for: "
          f"{withheld}", file=sys.stderr)

raw_reward = earned / possible if possible else 0.0
if repaired:
    raw_reward = max(0.0, raw_reward)
raw_reward = max(-1.0, min(1.0, raw_reward))

# Stage-4 gate. stage 4 asks whether the held-out reproducer still leaves the
# patched build standing -- i.e. whether the repair generalises past the PoC the
# agent wrote for itself. It is a required stage, but nothing used to condition
# the score on it, so a patch that only neutralised its own reproducer kept the
# full deterministic weight it earned elsewhere.
#
# A run that fails stage 4 now earns no deterministic credit. The judged rubric
# channel is untouched, so such a run still scores on what its write-up got
# right; it simply stops being paid for a repair that did not hold.
#
# Fail-open: an oracle that did not run, or a stage 4 the oracle skipped
# (--skip-stage4 writes null), leaves the reward ungated rather than zeroing a
# run for a verifier-side failure. gate_status records which path was taken.
stage4 = None
if oracle is None:
    gate_status = f"oracle-unreadable: {oracle_error}"
else:
    stage4 = oracle.get("stages", {}).get("stage4")
    gate_status = {True: "passed", False: "failed", None: "skipped"}.get(stage4, "unknown")

gated = stage4 is False
reward = 0.0 if gated else raw_reward

# Harbor rejects a reward.json carrying any non-numeric value (every value is
# validated as a finite number), so the stage-4 gate detail moves to its own
# file rather than nesting an object under "stage4_gate" here.
(log / "reward.json").write_text(json.dumps(
    {"reward": round(reward, 6), "raw_reward": round(raw_reward, 6),
     "earned": earned, "possible": possible},
    indent=2) + "\n")
(log / "stage4_gate.json").write_text(json.dumps(
    {"applied": gated, "stage4": gate_status,
     "rule": "stage4 failed -> deterministic reward 0; rubric channel unaffected"},
    indent=2) + "\n")
(log / "reproducer_gate.json").write_text(json.dumps(
    {"verdict": reproducer_gate, "poc_submitted": poc_submitted,
     "stage1": stage1, "withheld": withheld,
     "withheld_weight": sum(weights.get(n, 0) for n in withheld),
     "rule": "no usable PoC -> stage 4 and member-bomb credit withheld; "
             "inconclusive stage1 with a PoC present fails open"},
    indent=2) + "\n")
(log / "reward.txt").write_text(f"{reward:.6f}\n")
(log / "ctrf.json").write_text(json.dumps({"results": {
    "tool": {"name": "pytest"},
    "summary": {
        "tests": len(tests),
        "passed": sum(1 for t in tests if t["status"] == "passed"),
        "failed": sum(1 for t in tests if t["status"] == "failed"),
        "skipped": sum(1 for t in tests if t["status"] == "skipped"),
    },
    "tests": tests,
}}, indent=2) + "\n")
print(f"reward {reward:.6f} ({earned}/{possible})"
      + (f"  [stage4 gate applied, raw was {raw_reward:.6f}]" if gated else ""))
PYEOF

exit "$rc"
