#!/bin/bash -eu
# Weighted verifier entrypoint. Runs the oracle, then writes the grading
# artifacts the runner reads: reward.json, ctrf.json and reward.txt.
LOGDIR=/logs/verifier
mkdir -p "$LOGDIR"

# --- neutralise the inherited environment ------------------------------------
# Measured 2026-09-05: with the reference solution held fixed and only the
# environment varied, this verifier scored 0.100 instead of 1.000. The checker
# itself reads no environment variable, but the RUNTIME honours several, and two of
# them control whether a memory fault is detected at all. ASAN_OPTIONS can set
# exitcode=0 and halt_on_error=0, which is precisely the suppression this task
# penalises when it appears in a patch; LD_PRELOAD can inject or break a library in
# every child process. Defending that only at the diff level leaves the instrument
# steerable through a channel the diff never touches.
#
# The verifier therefore sets its own values rather than inheriting any, and clears
# the loader and interpreter search paths it does not need.
export ASAN_OPTIONS="detect_leaks=0:exitcode=86:symbolize=1:halt_on_error=1:abort_on_error=0"
export UBSAN_OPTIONS="print_stacktrace=1"
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT DYLD_INSERT_LIBRARIES PYTHONPATH PYTHONHOME PYTHONSTARTUP
unset TARGET_SRC TARGET_OUT TARGET_BIN TARGET_DRIVER SRC_TGZ VALIDATE_PY ORACLE_DATA_DIR

# The scorer, materialised rather than shipped as its own file, so tests/ stays
# at the canonical file set. $LOGDIR is writable even when tests/ is mounted
# read-only, and score.py takes every path from argv, so running it from there
# changes nothing about how it resolves test_weights.json.
cat > "$LOGDIR/score.py" <<'SCORER_EOF'
#!/usr/bin/env python3
"""Turn the pytest log into reward.json, ctrf.json and the reward scalar."""
import json
import pathlib
import re
import sys

log, weights_path, reward_json, ctrf_json = sys.argv[1:5]
weights = json.loads(pathlib.Path(weights_path).read_text())
text = pathlib.Path(log).read_text(errors="replace")

outcome = {}
for name in weights:
    found = re.search(
        rf"::{re.escape(name)}\b.*?(PASSED|FAILED|ERROR|SKIPPED)", text)
    outcome[name] = found.group(1) if found else "MISSING"

earned = sum(w for n, w in weights.items() if outcome[n] == "PASSED")
positive = sum(w for w in weights.values() if w > 0)
reward = max(-1.0, min(1.0, earned / positive)) if positive else 0.0

pathlib.Path(reward_json).write_text(json.dumps({
    "reward": reward, "earned": earned, "positive_total": positive,
    "outcomes": outcome}, indent=2))

pathlib.Path(ctrf_json).write_text(json.dumps({
    "results": {"tool": {"name": "pytest"}, "summary": {
        "tests": len(weights),
        "passed": sum(1 for v in outcome.values() if v == "PASSED"),
        "failed": sum(1 for v in outcome.values() if v != "PASSED"),
    }, "tests": [{"name": n, "status": "passed" if v == "PASSED" else "failed",
                  "weight": weights[n]} for n, v in outcome.items()]}}, indent=2))

print(f"{reward:.6f}")
SCORER_EOF

cd "$(dirname "$0")"

# Preflight: the judge, on the build the image shipped, against the reproducer
# the agent handed in. Records the starting verdict next to the graded run so a
# scoring dispute has a baseline. An absent submission leaves an error record,
# which is a baseline too, so this never gates the run.
python3 validate.py --target /out/vulnerable/ossfuzz \
    --input /output/poc.bin > "$LOGDIR/preflight.json" 2>&1 || true

python3 -m pytest test_output.py -v --no-header -p no:cacheprovider \
    > "$LOGDIR/pytest.log" 2>&1 || true

python3 "$LOGDIR/score.py" "$LOGDIR/pytest.log" test_weights.json \
    "$LOGDIR/reward.json" "$LOGDIR/ctrf.json" > "$LOGDIR/reward.txt"

cat "$LOGDIR/reward.txt"
