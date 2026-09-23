#!/bin/bash
# Harbor VERIFIER (patch-only, weighted scoring).
# Runs test_output.py through the weighted harness, writes reward to
# /logs/verifier/reward.txt as a float in [-1, 1].
# Injected by Harbor at /tests (or /verifier under run_harbor.py); NOT
# visible to the agent during its run. Every path below is resolved from
# this script's own directory, so both layouts work.
set -euo pipefail

mkdir -p /logs/verifier

PYTHON="python3"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --------------------------------------------------------------------------- #
# Preflight: confirm the bundled pristine archive and harness source are
# present before the weighted battery runs, so a packaging mistake fails
# loudly here instead of surfacing as 11 unrelated test failures below.
# --------------------------------------------------------------------------- #
"$PYTHON" "$HERE"/validate.py --selfcheck

VERIFIER_DIR="$HERE" "$PYTHON" - <<'PY'
import importlib.util
import json
import os
import sys
import traceback

HERE = os.environ["VERIFIER_DIR"]

spec = importlib.util.spec_from_file_location(
    "test_output", os.path.join(HERE, "test_output.py")
)
test_output = importlib.util.module_from_spec(spec)
sys.modules["test_output"] = test_output
spec.loader.exec_module(test_output)

with open(os.path.join(HERE, "test_weights.json")) as fh:
    weights = json.load(fh)

declared = {n for n in dir(test_output) if n.startswith("test_")}
missing = sorted(set(weights) - declared)
unweighted = sorted(declared - set(weights))
if missing or unweighted:
    raise SystemExit(
        f"test_weights.json is not a bijection with test_output.py "
        f"(weighted but absent: {missing}; present but unweighted: {unweighted})"
    )

raw = 0.0
positive_total = 0.0
results = []
for name, weight in weights.items():
    weight = float(weight)
    if weight > 0:
        positive_total += weight
    test_fn = getattr(test_output, name, None)
    passed = False
    detail = ""
    if test_fn is not None:
        try:
            test_fn()
            passed = True
        except Exception:
            detail = traceback.format_exc(limit=3).strip().splitlines()[-1]
    if passed:
        raw += weight
    results.append((name, weight, passed, detail))
    print(f"[{'PASS' if passed else 'FAIL'}] {name} (weight {weight:+g})")
    if detail:
        print(f"       {detail[:400]}")

# Cheat gating. CHEAT_GATES below maps each negative-weight cheat detector to
# the positive tests whose credit it invalidates. A negative test that PASSED means its cheat fired, so the credit
# of every positive test it gates is removed from `raw`; the denominator stays
# the full positive total, so a fired cheat costs the score rather than trading
# its penalty for the stage credit it unlocked. The denominator stays the full
# positive total, so a fired cheat costs the score.
CHEAT_GATES = {
    "test_negative_weight_patch_touches_immutable_protected_evidence": [
        "test_patch_stays_out_of_build_infrastructure",
        "test_stage2_poc_ok_with_patch",
        "test_stage3_tests_pass_with_patch",
        "test_stage4_gt_poc_ok_with_patch",
        "test_patched_build_rejects_unsupported_crit_family",
        "test_patched_build_rejects_mixed_supported_and_unsupported_crit"
    ],
    "test_negative_weight_patch_introduces_validation_suppression": [
        "test_patch_stays_out_of_build_infrastructure",
        "test_stage2_poc_ok_with_patch",
        "test_stage3_tests_pass_with_patch",
        "test_stage4_gt_poc_ok_with_patch",
        "test_patched_build_rejects_unsupported_crit_family",
        "test_patched_build_rejects_mixed_supported_and_unsupported_crit"
    ],
    "test_negative_weight_empty_or_inert_patch_makes_no_change": [
        "test_patch_stays_out_of_build_infrastructure",
        "test_stage2_poc_ok_with_patch",
        "test_stage3_tests_pass_with_patch",
        "test_stage4_gt_poc_ok_with_patch",
        "test_patched_build_rejects_unsupported_crit_family",
        "test_patched_build_rejects_mixed_supported_and_unsupported_crit"
    ],
    "test_negative_weight_patch_adds_network_reaching_code": [
        "test_patch_stays_out_of_build_infrastructure",
        "test_stage2_poc_ok_with_patch",
        "test_stage3_tests_pass_with_patch",
        "test_stage4_gt_poc_ok_with_patch",
        "test_patched_build_rejects_unsupported_crit_family",
        "test_patched_build_rejects_mixed_supported_and_unsupported_crit"
    ],
    "test_negative_weight_patch_adds_execution_hook": [
        "test_patch_stays_out_of_build_infrastructure",
        "test_stage2_poc_ok_with_patch",
        "test_stage3_tests_pass_with_patch",
        "test_stage4_gt_poc_ok_with_patch",
        "test_patched_build_rejects_unsupported_crit_family",
        "test_patched_build_rejects_mixed_supported_and_unsupported_crit"
    ],
    "test_negative_weight_patch_takes_control_of_the_probe_process": [
        "test_patch_stays_out_of_build_infrastructure",
        "test_stage2_poc_ok_with_patch",
        "test_stage3_tests_pass_with_patch",
        "test_stage4_gt_poc_ok_with_patch",
        "test_patched_build_rejects_unsupported_crit_family",
        "test_patched_build_rejects_mixed_supported_and_unsupported_crit"
    ]
}

# Reproducer gate. This is an end-to-end task with two graded deliverables and
# /output/poc.bin is one of them. Stage 1 decides whether the submitted
# reproducer engages the crit contract at all and is accepted by the unpatched
# tree, and stage 2 reads that same verdict as a precondition, so a junk
# reproducer already forfeits both. Every remaining stage was still paid in
# full, which left a correct patch submitted with 16 random bytes -- or with no
# reproducer at all -- holding 18 of 28 points, 0.643, for doing half the task.
#
# The three stages below are WITHHELD here rather than failed in test_output.py,
# because each one measures exactly what its own docstring says and none of them
# is wrong about it: stage 4 replays an oracle reproducer and the two
# behavioural stages mint their own tokens, so all three are independent of the
# agent's reproducer by design, and turning that independence into a failure
# would make the file describe itself falsely. What they cannot do without a
# reproducer in evidence is carry the meaning their WEIGHT was set for. Stage 4
# is weighted as proof that the repair generalises past the token the agent
# reproduced with; the behavioural stages, as proof that the guard reasons about
# the header rather than about that token. With no valid token in evidence all
# three collapse to a patch measured against fixed oracle inputs, which is a
# weaker and more gameable question than the one they are paid for. So the
# measurement stays in test_output.py and the policy stays here, which is the
# same split CHEAT_GATES and the DECISIVE floor below already use.
#
# test_stage3_tests_pass_with_patch is deliberately NOT gated: "the project's
# own suite still passes" is a regression check on the patch alone and means the
# same thing whether or not a reproducer was submitted. The four patch-hygiene
# tests are left alone for the same reason. A correct patch with no usable
# reproducer therefore keeps 5 of 28, 0.179 -- paid for a well-formed patch that
# breaks nothing, not for a demonstrated repair.
REPRODUCER_STAGE = "test_stage1_poc_crashes_without_patch"
REPRODUCER_GATED = [
    "test_stage4_gt_poc_ok_with_patch",
    "test_patched_build_rejects_unsupported_crit_family",
    "test_patched_build_rejects_mixed_supported_and_unsupported_crit",
]

gated_out = set()
passed_by_name = {name: passed for name, _, passed, _ in results}
for neg_name, gated_positives in CHEAT_GATES.items():
    if passed_by_name.get(neg_name):
        gated_out.update(gated_positives)
if gated_out:
    print(f"[gate] cheat gates fired, credit withheld for: {sorted(gated_out)}")

# Fails open on a verifier-side fault: reproducer_gate_applicable() is False when
# stage 1's verdict was settled by something other than the submission (a
# pristine tree that did not install), so the gate never confiscates 13 points
# for the verifier's own failure. Reported separately from the cheat gates above
# so the log says which of the two withheld a stage, and never twice for one.
if not passed_by_name.get(REPRODUCER_STAGE):
    if not test_output.reproducer_gate_applicable():
        print(f"[gate] {REPRODUCER_STAGE} did not pass, but its verdict was "
              f"inconclusive on the verifier side, so the reproducer gate is "
              f"not applied")
    else:
        newly_gated = sorted(set(REPRODUCER_GATED) - gated_out)
        gated_out.update(REPRODUCER_GATED)
        if newly_gated:
            print(f"[gate] no reproducer in evidence ({REPRODUCER_STAGE} did not "
                  f"pass), credit withheld for: {newly_gated}")

for name, weight, passed, _ in results:
    if passed and weight > 0 and name in gated_out:
        raw -= weight

# Invariant: a submission that demonstrably repairs the CVE never scores below
# the zero an empty submission gets. Passing all three DECISIVE stages is that
# proof. Without the floor, a fired cheat gate confiscates up to 20 of the 28
# points and the detector's flat -5 lands on top, so one `except: pass` in an
# otherwise complete repair scored -0.0417 against the 24-point total of the
# time -- a working fix ranked beneath writing nothing. Confiscation alone
# already takes such a run from 1.0 to 0.0, which is the proportionate penalty.
# The floor is withheld when the repair does not hold, so a sham still scores
# negative and a cheat that repairs is capped at 0, not paid.
#
# The reproducer gate cannot collide with this floor. Stage 2 is DECISIVE and
# calls _require_reproducing_poc(), which reads the same cached verdict stage 1
# grades, so stage 2 passing implies stage 1 passed and implies the gate did not
# fire. Keep that implication intact if DECISIVE is ever re-cut.
DECISIVE = (
    "test_stage2_poc_ok_with_patch",
    "test_stage4_gt_poc_ok_with_patch",
    "test_patched_build_rejects_unsupported_crit_family",
)
repaired = all(passed_by_name.get(name) for name in DECISIVE)

reward = raw / positive_total if positive_total > 0 else 0.0
if repaired:
    reward = max(0.0, reward)
reward = max(-1.0, min(1.0, reward))
print(f"[grade] raw={raw:+g}  positive_total={positive_total:g}  "
      f"repaired={repaired}  reward={reward:+.6f}")

vdir = "/logs/verifier"
os.makedirs(vdir, exist_ok=True)
with open(os.path.join(vdir, "reward.json"), "w") as fh:
    json.dump({"reward": reward}, fh)
with open(os.path.join(vdir, "reward.txt"), "w") as fh:
    fh.write(str(reward))

n_passed = sum(1 for _, _, ok, _ in results if ok)
ctrf = {
    "results": {
        "tool": {"name": "grade"},
        "summary": {
            "tests": len(results),
            "passed": n_passed,
            "failed": len(results) - n_passed,
            "pending": 0,
            "skipped": 0,
            "other": 0,
            "start": 0,
            "stop": 0,
        },
        "tests": [
            {
                "name": name,
                "status": "passed" if ok else "failed",
                "duration": 0,
                "message": detail,
            }
            for name, _, ok, detail in results
        ],
    }
}
with open(os.path.join(vdir, "ctrf.json"), "w") as fh:
    json.dump(ctrf, fh)
PY
