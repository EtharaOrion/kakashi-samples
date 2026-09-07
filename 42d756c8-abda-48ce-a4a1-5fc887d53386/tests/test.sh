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
import json, pathlib, sys, xml.etree.ElementTree as ET

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
        if status == "passed" and weight > 0:
            earned += weight
        elif status == "failed" and weight < 0:
            earned += weight
        tests.append({"name": name, "status": status,
                      "duration": int(float(case.get("time", 0)) * 1000)})

raw_reward = max(0.0, earned / possible) if possible else 0.0

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
gate_status = "oracle-missing"
try:
    oracle = json.loads((log / "oracle.json").read_text())
    stage4 = oracle.get("stages", {}).get("stage4")
    gate_status = {True: "passed", False: "failed", None: "skipped"}.get(stage4, "unknown")
except Exception as exc:
    gate_status = f"oracle-unreadable: {exc}"

gated = stage4 is False
reward = 0.0 if gated else raw_reward

(log / "reward.json").write_text(json.dumps(
    {"reward": round(reward, 6), "raw_reward": round(raw_reward, 6),
     "earned": earned, "possible": possible,
     "stage4_gate": {"applied": gated, "stage4": gate_status,
                     "rule": "stage4 failed -> deterministic reward 0; rubric channel unaffected"}},
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
