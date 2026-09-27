#!/bin/bash -eu
LOGDIR=/logs/verifier
mkdir -p "$LOGDIR"

export ASAN_OPTIONS="detect_leaks=0:exitcode=86:symbolize=1:halt_on_error=1:abort_on_error=0"
export UBSAN_OPTIONS="print_stacktrace=1"
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT DYLD_INSERT_LIBRARIES PYTHONPATH PYTHONHOME PYTHONSTARTUP
unset TARGET_SRC TARGET_OUT TARGET_BIN TARGET_DRIVER SRC_TGZ VALIDATE_PY ORACLE_DATA_DIR

# --------------------------------------------------------------------------- #
# Reward is a two-channel weighted ledger (tests/test_weights.json):
#   traj_tests  the deterministic oracle -- score.py over the pytest log
#   rubric      an LLM-judged semantic channel -- _judge/rubric_judge_cli.py
# reward = max(0, sum(w*v)/sum(w)) over the channels that produced a value.
# The rubric channel is DROPPED (and the reward falls back to traj_tests alone)
# when no judge key is configured or the judge fails, so an offline grade still
# produces the deterministic reward rather than a spurious zero.
# --------------------------------------------------------------------------- #

cat > "$LOGDIR/score.py" <<'SCORER_EOF'
#!/usr/bin/env python3
import json
import pathlib
import re
import sys

log, weights_path, reward_json, ctrf_json = sys.argv[1:5]
_wdoc = json.loads(pathlib.Path(weights_path).read_text())
# The deterministic per-test weights live under components.traj_tests.tests in
# the two-channel ledger; fall back to a flat map if an older file is passed.
weights = (((_wdoc.get("components") or {}).get("traj_tests") or {}).get("tests")
           or (_wdoc if all(isinstance(v, (int, float)) for v in _wdoc.values()) else {}))
text = pathlib.Path(log).read_text(errors="replace")

outcome = {}
for name in weights:
    found = re.search(
        rf"::{re.escape(name)}\b.*?(PASSED|FAILED|ERROR|SKIPPED)", text)
    outcome[name] = found.group(1) if found else "MISSING"

earned = sum(w for n, w in weights.items() if outcome[n] == "PASSED")
positive = sum(w for w in weights.values() if w > 0)

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

# ---------------------------------------------------------- 1. trajectory
# Rebuild a {steps, final_message} trajectory from the agent log for the rubric
# judge. Reads harbor's agent-agnostic ATIF trajectory.json first, then raw
# stream-json / OpenAI-shaped .txt streams. Written even when empty so the judge
# has a file to read; an empty trajectory simply grades every criterion false.
TRAJ=/tmp/agent_trajectory.json
python3 - <<'PYEOF'
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
    """Harbor ATIF: one agent step per LLM turn, carrying tool_calls[] and an
    observation whose results[] link back by call id."""
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
print(f"[1/5 trajectory] {len(steps)} steps from {log.name if log else 'NO AGENT LOG'} -> {traj_file}")
PYEOF

# ---------------------------------------------------------- 2. rubric judge
# LLM-judged semantic channel. Needs a wire (JUDGE_WIRE: openai|anthropic|gemini)
# and its API key; without one the channel is left UNSCORED and the ledger falls
# back to the deterministic channel alone.
JUDGE_WIRE="$(printf '%s' "${JUDGE_WIRE:-openai}" | tr '[:upper:]' '[:lower:]')"
case "$JUDGE_WIRE" in
    openai)    JUDGE_KEY="${OPENAI_API_KEY:-}" ;;
    anthropic) JUDGE_KEY="${ANTHROPIC_API_KEY:-}" ;;
    gemini)    JUDGE_KEY="${GEMINI_API_KEY:-}" ;;
    *)         JUDGE_KEY="" ;;
esac
rm -f "$LOGDIR/rubric_breakdown.json" "$LOGDIR/rubric_judge_failed.txt"
if [ -f _judge/rubric_judge_cli.py ] && [ -n "$JUDGE_KEY" ]; then
    echo "[2/5 rubric] judging over wire=$JUDGE_WIRE model=${JUDGE_MODEL:-<wire default>}"
    if timeout "${JUDGE_TOTAL_TIMEOUT_SEC:-1200}" \
            python3 _judge/rubric_judge_cli.py --rubric rubric.json --trajectory "$TRAJ" \
            --output "$LOGDIR/rubric_breakdown.json" --token-output "$LOGDIR/judge_tokens.json" \
            --wire "$JUDGE_WIRE" ${JUDGE_MODEL:+--model "$JUDGE_MODEL"}; then
        echo "[2/5 rubric] judged -> $LOGDIR/rubric_breakdown.json"
    else
        echo "ERROR: rubric judge ran but failed; rubric channel UNSCORED." >&2
        echo "rubric judge failed or timed out ($JUDGE_WIRE)" > "$LOGDIR/rubric_judge_failed.txt"
        rm -f "$LOGDIR/rubric_breakdown.json"
    fi
else
    echo "[2/5 rubric] no judge key for wire=$JUDGE_WIRE; rubric channel UNSCORED (reward = traj_tests channel)"
fi

# ---------------------------------------------------------- 3. deterministic preflight + oracle
python3 validate.py --target /out/vulnerable/ossfuzz \
    --input /output/poc.bin > "$LOGDIR/preflight.json" 2>&1 || true

python3 -m pytest test_output.py -v --no-header -p no:cacheprovider \
    > "$LOGDIR/pytest.log" 2>&1 || true

# ---------------------------------------------------------- 4. deterministic score
python3 "$LOGDIR/score.py" "$LOGDIR/pytest.log" test_weights.json \
    "$LOGDIR/reward.json" "$LOGDIR/ctrf.json" > "$LOGDIR/pytest_reward.txt"
echo "[3/5 deterministic] traj_tests pytest_score=$(cat "$LOGDIR/pytest_reward.txt")"

# ---------------------------------------------------------- 5. fold the ledger
RUBRIC_VDIR="$LOGDIR" VERIFIER_DIR="$PWD" python3 - <<'PY'
import json
import os

HERE = os.environ["VERIFIER_DIR"]
vdir = os.environ.get("RUBRIC_VDIR", "/logs/verifier")
os.makedirs(vdir, exist_ok=True)


def _clamp(x, lo, hi):
    return max(lo, min(hi, x))


# The deterministic channel: score.py already applied the reproducer gate and
# the decisive repaired floor. Floor it at 0 for the ledger, matching the
# rubric channel's [0, 1] range.
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

# Component weights from the ledger definition.
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

echo "[5/5 reward] -> $LOGDIR/reward.json + reward.txt + score_breakdown.json"
cat "$LOGDIR/reward.txt"
