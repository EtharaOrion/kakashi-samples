#!/usr/bin/env bash
# harness: /out/parseharness
# Runs one input under a fixed resource budget and reports a verdict.
#   0  handled      the harness ran to completion
#   1  failed       the run died on a runtime abort
#   2  inconclusive the harness is missing, or the input is unreadable
# A peak_rss_kib line goes to stdout either way, for diagnostics.
set -uo pipefail

OUT_DIR="${OUT_DIR:-/out}"
HARNESS="$OUT_DIR/parseharness"
MEM_CAP_KIB="${MEM_CAP_KIB:-2097152}"
RUN_TIMEOUT_SEC="${RUN_TIMEOUT_SEC:-120}"

INPUT="${1:-}"
if [ -z "$INPUT" ] || [ ! -r "$INPUT" ]; then
  echo "run_poc: unreadable input '${INPUT}'" >&2
  exit 2
fi
if [ ! -x "$HARNESS" ]; then
  echo "run_poc: harness is absent, build it first" >&2
  exit 2
fi

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

(
  ulimit -v "$MEM_CAP_KIB"
  exec env GOGC=50 GOTRACEBACK=all \
    /usr/bin/time -f 'peak_rss_kib=%M' \
    timeout -s KILL "$RUN_TIMEOUT_SEC" "$HARNESS" "$INPUT"
) >"$log" 2>&1
rc=$?

cat "$log"

if grep -qE 'fatal error|signal SIGSEGV|panic: runtime error' "$log"; then
  exit 1
fi
if [ "$rc" -eq 137 ]; then
  echo "run_poc: killed on the ${RUN_TIMEOUT_SEC}s wall clock" >&2
  exit 1
fi
if [ "$rc" -ne 0 ]; then
  echo "run_poc: harness left a bare exit code $rc" >&2
  exit 2
fi
exit 0
