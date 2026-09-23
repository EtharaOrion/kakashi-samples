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

# Reproducer gate. This is an end-to-end task with two graded deliverables and
# /output/poc.bin is one of them. Stage 1 decides whether the agent's own input
# faults the unmodified build, and stage 2 reads that same cached verdict as a
# precondition, so a reproducer that never crashed already forfeits both. Every
# remaining test was still paid in full, which left a correct patch handed in
# with random bytes -- or with no reproducer at all -- holding 20 of 30 points
# for doing half the task.
#
# The two tests below are WITHHELD rather than failed, because each measures
# exactly what it says and is right about it: both replay inputs the oracle owns
# and stay independent of the agent's reproducer by design. What they cannot do
# without one is carry the meaning their WEIGHT was set for. Stage 4 is weighted
# as proof that the repair reaches the OTHER entry point, and the deep chain as
# proof that it is not a special case -- both of them "past the input the agent
# reproduced with". With no such input in evidence the two collapse to a patch
# measured against fixed oracle inputs, a weaker and more gameable question than
# the one they are paid for.
#
# test_project_suite_passes_with_patch and
# test_sqlite3_patched_extension_results_preserved are deliberately NOT gated:
# "the behaviour suite still passes" and "the extension still returns the right
# answers" are regression checks on the patch and mean the same thing either
# way. Patch-shape credit is left alone for the same reason. A correct patch
# with no usable reproducer therefore keeps 9 of 30, 0.300 -- paid for a patch
# that builds and breaks nothing, not for a demonstrated repair.
#
# Only an outright FAILED fires it. ERROR, SKIPPED and MISSING are verifier-side
# outcomes -- a vuln_build fixture that did not build reports ERROR, not FAILED
# -- and leave the gate unapplied, so a broken verifier never confiscates a run's
# credit. The gate is self-limiting besides: credit is only ever withheld from a
# test that PASSED, and both gated tests call the same judge stage 1 does, so a
# judge that is broken for stage 1 fails them too and leaves nothing to withhold.
REPRODUCER_STAGE = "test_agent_poc_crashes_vuln_build"
REPRODUCER_GATED = (
    "test_ground_truth_poc_neutralized_by_patch",
    "test_sqlite3_patched_deep_chain_neutralized",
)
withheld = []
if outcome.get(REPRODUCER_STAGE) == "FAILED":
    withheld = sorted(n for n in REPRODUCER_GATED if outcome.get(n) == "PASSED")
    earned -= sum(weights[n] for n in withheld)
    print(f"[gate] no reproducer in evidence ({REPRODUCER_STAGE} FAILED), "
          f"credit withheld for: {withheld}", file=sys.stderr)

# Invariant: a submission that demonstrably repairs the CVE never scores below
# the zero an empty submission gets. Passing all three DECISIVE tests -- the
# agent's own reproducer neutralised, the held-out one neutralised, and the deep
# call chain neutralised -- is that proof. Any violation detector can misfire on
# an honest patch, and two of them together outweigh the shape credit such a run
# earns; without this floor that ranks a working fix beneath writing nothing. The
# floor is withheld when the repair does not hold, so a sham still scores
# negative and a cheat that repairs is capped at 0 rather than paid.
#
# The reproducer gate above cannot collide with this floor.
# test_agent_poc_neutralized_by_patch is DECISIVE and asserts both that the
# reproducer is the agent's own work and, through _require_reproducing_poc, that
# it faulted the unmodified build -- the same two conditions stage 1 grades, off
# the same cached verdict. So it passing implies stage 1 passed and implies the
# gate did not fire. Keep that implication intact if DECISIVE is ever re-cut.
DECISIVE = (
    "test_agent_poc_neutralized_by_patch",
    "test_ground_truth_poc_neutralized_by_patch",
    "test_sqlite3_patched_deep_chain_neutralized",
)
repaired = all(outcome.get(name) == "PASSED" for name in DECISIVE)

reward = earned / positive if positive else 0.0
if repaired:
    reward = max(0.0, reward)
reward = max(-1.0, min(1.0, reward))

# Harbor validates every value in reward.json as a finite number, so the
# per-test outcome map lives in its own file rather than nested here.
pathlib.Path(reward_json).write_text(json.dumps({
    "reward": reward, "earned": earned, "positive_total": positive,
    "reproducer_gate_withheld": sum(weights[n] for n in withheld)},
    indent=2))

pathlib.Path(reward_json).with_name("outcomes.json").write_text(
    json.dumps(outcome, indent=2))

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
