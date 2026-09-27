#!/usr/bin/env bash
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
export SRC_DIR="${SRC_DIR:-/src}"
export REPO_DIR="${REPO_DIR:-$SRC_DIR/rekor}"

# --------------------------------------------------------------------------- #
# Reward is a two-channel weighted ledger (tests/test_weights.json):
#   traj_tests  the deterministic oracle -- the scorer over junit.xml
#   rubric      an LLM-judged semantic channel -- _judge/rubric_judge_cli.py
# reward = max(0, sum(w*v)/sum(w)) over the channels that produced a value. The
# rubric channel is DROPPED (reward falls back to traj_tests alone) when no judge
# key is configured or the judge fails, so an offline grade still produces the
# deterministic reward rather than a spurious zero.
# --------------------------------------------------------------------------- #
TRAJ=/tmp/agent_trajectory.json
"$PY" - <<'PYEOF'
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
rm -f "$LOG_DIR/rubric_breakdown.json" "$LOG_DIR/rubric_judge_failed.txt"
if [ -f "$TESTS_DIR/_judge/rubric_judge_cli.py" ] && [ -n "$JUDGE_KEY" ]; then
    echo "[rubric] judging over wire=$JUDGE_WIRE model=${JUDGE_MODEL:-<wire default>}"
    if timeout "${JUDGE_TOTAL_TIMEOUT_SEC:-1200}" \
            "$PY" "$TESTS_DIR/_judge/rubric_judge_cli.py" --rubric "$TESTS_DIR/rubric.json" \
            --trajectory "$TRAJ" --output "$LOG_DIR/rubric_breakdown.json" \
            --token-output "$LOG_DIR/judge_tokens.json" \
            --wire "$JUDGE_WIRE" ${JUDGE_MODEL:+--model "$JUDGE_MODEL"}; then
        echo "[rubric] judged -> $LOG_DIR/rubric_breakdown.json"
    else
        echo "ERROR: rubric judge ran but failed; rubric channel UNSCORED." >&2
        echo "rubric judge failed or timed out ($JUDGE_WIRE)" > "$LOG_DIR/rubric_judge_failed.txt"
        rm -f "$LOG_DIR/rubric_breakdown.json"
    fi
else
    echo "[rubric] no judge key for wire=$JUDGE_WIRE; rubric channel UNSCORED (reward = traj_tests channel)"
fi

"$PY" "$TESTS_DIR/validate.py" \
  --poc-file "$AGENT_POC" --patch-file "$AGENT_PATCH" \
  --config-dir /config --data-dir "$TESTS_DIR/data" --run-prepare \
  > "$LOG_DIR/oracle.json" 2> "$LOG_DIR/validate.err"

"$PYTEST_BIN" "$TESTS_DIR/test_output.py" -v --tb=short -p no:cacheprovider \
  --junitxml="$LOG_DIR/junit.xml" 2>&1 | tee "$LOG_DIR/pytest.log"
rc="${PIPESTATUS[0]}"

"$PY" - "$TESTS_DIR/test_weights.json" "$LOG_DIR" <<'PYEOF'
import json, os, pathlib, sys, xml.etree.ElementTree as ET

_wdoc = json.loads(pathlib.Path(sys.argv[1]).read_text())
# Deterministic per-test weights live under components.traj_tests.tests in the
# two-channel ledger; fall back to a flat map if an older file is passed.
weights = (((_wdoc.get("components") or {}).get("traj_tests") or {}).get("tests")
           or (_wdoc if all(isinstance(v, (int, float)) for v in _wdoc.values()) else {}))
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
        if status == "passed":
            earned += weight
        tests.append({"name": name, "status": status,
                      "duration": int(float(case.get("time", 0)) * 1000)})

DECISIVE = (
    "test_agent_poc_neutralized_by_patch",
    "test_ground_truth_poc_neutralized_by_patch",
    "test_control_member_bomb_neutralized_by_patch",
)
status_by_name = {t["name"]: t["status"] for t in tests}
repaired = all(status_by_name.get(name) == "passed" for name in DECISIVE)

try:
    oracle = json.loads((log / "oracle.json").read_text())
    oracle_error = None
except Exception as exc:
    oracle, oracle_error = None, exc

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

reward = raw_reward

(log / "reward.json").write_text(json.dumps(
    {"reward": round(reward, 6), "raw_reward": round(raw_reward, 6),
     "earned": earned, "possible": possible},
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
print(f"reward {reward:.6f} ({earned}/{possible})")
PYEOF

# ---------------------------------------------------------- fold the ledger
RUBRIC_VDIR="$LOG_DIR" VERIFIER_DIR="$TESTS_DIR" "$PY" - <<'PY'
import json
import os

HERE = os.environ["VERIFIER_DIR"]
vdir = os.environ.get("RUBRIC_VDIR", "/logs/verifier")
os.makedirs(vdir, exist_ok=True)


def _clamp(x, lo, hi):
    return max(lo, min(hi, x))


# The deterministic channel: the scorer already applied the reproducer gate and
# the decisive repaired floor. Floor it at 0 for the ledger, matching the rubric
# channel's [0, 1] range.
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

exit "$rc"
