#!/bin/bash
set -euo pipefail

mkdir -p /logs/verifier

PYTHON="python3"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"$PYTHON" "$HERE"/validate.py --selfcheck

# --------------------------------------------------------------------------- #
# Reward is a two-channel weighted ledger (tests/test_weights.json):
#   traj_tests  the deterministic oracle -- the scorer over test_output.py
#   rubric      an LLM-judged semantic channel -- _judge/rubric_judge_cli.py
# reward = max(0, sum(w*v)/sum(w)) over the channels that produced a value. The
# rubric channel is DROPPED (reward falls back to traj_tests alone) when no judge
# key is configured or the judge fails, so an offline grade still produces the
# deterministic reward rather than a spurious zero.
# --------------------------------------------------------------------------- #
TRAJ=/tmp/agent_trajectory.json
"$PYTHON" - <<'PYEOF' || true
import json, pathlib

AGENT_DIR = pathlib.Path("/logs/agent")
traj_file = pathlib.Path("/tmp/agent_trajectory.json")

candidates = [AGENT_DIR / "trajectory.json", AGENT_DIR / "oracle.txt"]
candidates += sorted((p for p in AGENT_DIR.glob("*.txt") if p not in candidates),
                     key=lambda f: f.stat().st_size, reverse=True) \
              if AGENT_DIR.is_dir() else []
log = next((p for p in candidates if p.exists() and p.stat().st_size), None)

steps, final_message, pending = [], "", {}

def _text_of(raw):
    if isinstance(raw, list) and raw:
        return raw[0].get("text", "") if isinstance(raw[0], dict) else str(raw[0])
    return raw

def _parse_json(raw):
    try:
        return json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, TypeError):
        return {"text": str(raw)}

def _atif(doc):
    out, by_id, final = [], {}, ""
    for st in doc.get("steps") or []:
        if st.get("source") != "agent":
            continue
        msg = st.get("message")
        if isinstance(msg, list):
            msg = " ".join(p.get("text") or "" for p in msg
                           if isinstance(p, dict) and p.get("type") == "text")
        if isinstance(msg, str) and msg.strip():
            final = msg
        for tc in st.get("tool_calls") or []:
            cid = tc.get("tool_call_id") or ""
            if cid and cid in by_id:
                continue
            entry = {"tool": tc.get("function_name", ""),
                     "arguments": tc.get("arguments") or {}, "response": None}
            out.append(entry)
            if cid:
                by_id[cid] = entry
        results = (st.get("observation") or {}).get("results") or []
        for r in results:
            target = by_id.get(r.get("source_call_id"))
            if target is None and len(results) == 1 and out and out[-1]["response"] is None:
                target = out[-1]
            if target is not None and target["response"] is None:
                target["response"] = _parse_json(_text_of(r.get("content")))
    return out, final

lines = []
if log and log.suffix == ".json":
    try:
        steps, final_message = _atif(json.loads(log.read_text()))
    except (json.JSONDecodeError, AttributeError):
        steps, final_message = [], ""
else:
    lines = log.read_text(errors="ignore").splitlines() if log else []

for line in lines:
    line = line.strip()
    if not line:
        continue
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        continue
    if not isinstance(ev, dict):
        continue
    etype = ev.get("type")
    msg = ev.get("message") or {}
    if etype == "assistant":
        content = msg.get("content") or []
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use":
                pending[block.get("id", "")] = {"tool": block.get("name", ""),
                                                "arguments": block.get("input") or {}, "response": None}
            elif block.get("type") == "text" and block.get("text"):
                final_message = block["text"]
    elif etype == "user":
        content = msg.get("content") or []
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_result":
                continue
            tid = block.get("tool_use_id", "")
            if tid in pending:
                pending[tid]["response"] = _parse_json(_text_of(block.get("content")))
                steps.append(pending.pop(tid))
    elif etype == "message" and msg.get("role"):
        role = msg.get("role")
        if role == "assistant":
            for tc in msg.get("tool_calls") or []:
                fn = tc.get("function") or {}
                args = fn.get("arguments")
                if isinstance(args, str):
                    args = _parse_json(args)
                pending[tc.get("id", "")] = {"tool": fn.get("name", ""),
                                             "arguments": args if isinstance(args, dict) else {}, "response": None}
            if isinstance(msg.get("content"), str) and msg["content"].strip() and not msg.get("tool_calls"):
                final_message = msg["content"]
        elif role == "tool":
            tid = msg.get("tool_call_id", "")
            if tid in pending:
                pending[tid]["response"] = _parse_json(msg.get("content"))
                steps.append(pending.pop(tid))
    elif etype == "result":
        r = ev.get("result", "")
        if isinstance(r, str) and r:
            final_message = r

steps.extend(pending.values())
traj_file.write_text(json.dumps({"steps": steps, "final_message": final_message}, indent=2))
print(f"[trajectory] {len(steps)} steps from {log.name if log else 'NO AGENT LOG'} -> {traj_file}")
PYEOF

JUDGE_WIRE="$(printf '%s' "${JUDGE_WIRE:-openai}" | tr '[:upper:]' '[:lower:]')"
case "$JUDGE_WIRE" in
    openai)    JUDGE_KEY="${OPENAI_API_KEY:-}" ;;
    anthropic) JUDGE_KEY="${ANTHROPIC_API_KEY:-}" ;;
    gemini)    JUDGE_KEY="${GEMINI_API_KEY:-}" ;;
    *)         JUDGE_KEY="" ;;
esac
rm -f /logs/verifier/rubric_breakdown.json /logs/verifier/rubric_judge_failed.txt
if [ -f "$HERE/_judge/rubric_judge_cli.py" ] && [ -n "$JUDGE_KEY" ]; then
    echo "[rubric] judging over wire=$JUDGE_WIRE model=${JUDGE_MODEL:-<wire default>}"
    if timeout "${JUDGE_TOTAL_TIMEOUT_SEC:-1200}" \
            "$PYTHON" "$HERE/_judge/rubric_judge_cli.py" --rubric "$HERE/rubric.json" \
            --trajectory "$TRAJ" --output /logs/verifier/rubric_breakdown.json \
            --token-output /logs/verifier/judge_tokens.json \
            --wire "$JUDGE_WIRE" ${JUDGE_MODEL:+--model "$JUDGE_MODEL"}; then
        echo "[rubric] judged -> /logs/verifier/rubric_breakdown.json"
    else
        echo "ERROR: rubric judge ran but failed; rubric channel UNSCORED." >&2
        echo "rubric judge failed or timed out ($JUDGE_WIRE)" > /logs/verifier/rubric_judge_failed.txt
        rm -f /logs/verifier/rubric_breakdown.json
    fi
else
    echo "[rubric] no judge key for wire=$JUDGE_WIRE; rubric channel UNSCORED (reward = traj_tests channel)"
fi

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
    _wdoc = json.load(fh)
# Deterministic per-test weights live under components.traj_tests.tests in the
# two-channel ledger; fall back to a flat map if an older file is passed. The
# bijection check below still runs over the test-name keys.
weights = (((_wdoc.get("components") or {}).get("traj_tests") or {}).get("tests")
           or (_wdoc if all(isinstance(v, (int, float)) for v in _wdoc.values()) else {}))

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

# ---------------------------------------------------------- fold the ledger
VERIFIER_DIR="$HERE" "$PYTHON" - <<'PY'
import json
import os

HERE = os.environ["VERIFIER_DIR"]
vdir = os.environ.get("RUBRIC_VDIR", "/logs/verifier")
os.makedirs(vdir, exist_ok=True)


def _clamp(x, lo, hi):
    return max(lo, min(hi, x))


# The deterministic channel: the scorer already applied the reproducer/cheat
# gates and the decisive repaired floor. Floor it at 0 for the ledger, matching
# the rubric channel's [0, 1] range.
with open(os.path.join(vdir, "reward.json")) as fh:
    det = json.load(fh)
pytest_score = float(det.get("reward", 0.0))
traj_value = max(0.0, pytest_score)

# The LLM-judged channel: present only when the judge ran and scored.
rubric_value = None
rubric_doc = {}
rb_path = os.path.join(vdir, "rubric_breakdown.json")
if os.path.isfile(rb_path):
    try:
        rubric_doc = json.loads(open(rb_path).read())
        v = rubric_doc.get("score")
        if isinstance(v, (int, float)):
            rubric_value = _clamp(float(v), 0.0, 1.0)
    except (OSError, ValueError):
        rubric_value = None

with open(os.path.join(HERE, "test_weights.json")) as fh:
    comps = (json.load(fh).get("components") or {})

values = {"traj_tests": traj_value, "rubric": rubric_value}
num, den, ledger = 0.0, 0.0, {}
for name, spec in comps.items():
    spec = spec or {}
    w = spec.get("weight") or 0
    if not spec.get("graded") or w <= 0:
        ledger[name] = {"status": "retired", "weight": w, "value": None}
        continue
    v = values.get(name)
    if v is None:
        ledger[name] = {"status": "unscored", "weight": w, "value": None}
        continue
    ledger[name] = {"status": "scored", "weight": w, "value": round(float(v), 6)}
    num += w * float(v)
    den += w

reward = _clamp(max(0.0, num / den) if den else 0.0, -1.0, 1.0)
rubric_scored = rubric_value is not None

print(f"[reward] traj_tests={traj_value:+.6f}  "
      f"rubric={'unscored' if rubric_value is None else f'{rubric_value:+.6f}'}  "
      f"reward={reward:+.6f}  scoring="
      f"{'traj_and_rubric_ledger' if rubric_scored else 'traj_only'}")

det.update({"reward": reward, "pytest_score": pytest_score,
            "traj_tests": traj_value, "rubric_score": rubric_value,
            "rubric_scored": rubric_scored, "ledger": ledger})
# Harbor rejects non-numeric reward.json values and reports a single "Mean"
# only when reward.json has exactly one key, so write just the reward here;
# the full detail (earned/possible, rubric status, ledger) is in score_breakdown.json.
with open(os.path.join(vdir, "reward.json"), "w") as fh:
    json.dump({"reward": reward}, fh, indent=2)
with open(os.path.join(vdir, "reward.txt"), "w") as fh:
    fh.write(str(reward))

with open(os.path.join(vdir, "rubric_score.json"), "w") as fh:
    json.dump({"rubric_score": rubric_value, "evaluator": "llm",
               "rubric_scored": rubric_scored,
               "rc": rubric_doc.get("rc"), "rb": rubric_doc.get("rb"),
               "rubric_passed": rubric_doc.get("rubric_passed"),
               "per_criterion": rubric_doc.get("per_criterion", [])}, fh, indent=2)

with open(os.path.join(vdir, "score_breakdown.json"), "w") as fh:
    json.dump({"reward": reward, "pytest_score": pytest_score,
               "traj_tests": traj_value, "rubric_score": rubric_value,
               "scoring": "traj_and_rubric_ledger" if rubric_scored else "traj_only",
               "rubric_evaluator": "llm", "rubric_scored": rubric_scored,
               "ledger": ledger, "deterministic": det}, fh, indent=2)
PY
