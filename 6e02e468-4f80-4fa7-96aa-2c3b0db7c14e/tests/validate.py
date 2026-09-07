#!/usr/bin/env python3
"""The judge: decide whether one input faults a staged build of the library.

`crash` means the sanitizer reported a memory error and the process aborted.
`clean` means the statement ran to completion inside the build's own limits.
`timeout` means the run did not finish, which is neither of the above and is
never scored as a repair.

The verdict record carries the sanitizer's own bug label and the innermost
frame it named, so a graded run and a run the agent performed by hand cannot
disagree about what happened.
"""
import argparse
import json
import os
import re
import subprocess
import sys

SAN_ERROR = re.compile(
    r"ERROR:\s*(?:Address|Leak|Memory|Thread|UndefinedBehavior)Sanitizer:\s*"
    r"([A-Za-z0-9_-]+)")
# Deliberately not anchored to the start of the line. A runner that prefixes each
# line, with a timestamp or a stream tag, would otherwise hide the frame and leave
# crash_function null on a run that did report one. The verdict itself never
# depended on this pattern, but the record it prints is read by humans resolving a
# scoring dispute, so it has to survive a prefixed log.
FRAME_ZERO = re.compile(r"#0\s+0x[0-9a-f]+\s+in\s+([A-Za-z_][A-Za-z0-9_]*)")
DEFAULT_TIMEOUT = 120


def validate(target, input_path, timeout=DEFAULT_TIMEOUT):
    """Run one input through `target` and classify what came back."""
    env = dict(os.environ)
    # Leak accounting only; nothing here changes whether a memory error is
    # reported or what exit code it produces.
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    try:
        proc = subprocess.run([target, "-runs=1", input_path],
                              capture_output=True, text=True,
                              timeout=timeout, env=env)
        output = (proc.stdout or "") + (proc.stderr or "")
        exit_code, timed_out = proc.returncode, False
    except subprocess.TimeoutExpired as expired:
        output = "".join(
            stream.decode("utf-8", "replace") if isinstance(stream, bytes)
            else (stream or "")
            for stream in (expired.stdout, expired.stderr))
        exit_code, timed_out = None, True
    except OSError as err:
        return {"verdict": "error", "bug_type": None, "crash_function": None,
                "exit_code": None, "target": target, "input": input_path,
                "detail": str(err)}

    error = SAN_ERROR.search(output)
    frame = FRAME_ZERO.search(output)
    if timed_out:
        verdict = "timeout"
    elif error:
        verdict = "crash"
    else:
        verdict = "clean"
    return {
        "verdict": verdict,
        "bug_type": error.group(1) if error else None,
        "crash_function": frame.group(1) if frame else None,
        "exit_code": exit_code,
        "target": target,
        "input": input_path,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Run one input against a staged build and report a verdict")
    parser.add_argument("--target", required=True, help="staged entry point")
    parser.add_argument("--input", required=True, help="path to the input file")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="seconds before the run is called a timeout")
    parser.add_argument("--expect", choices=["crash", "clean", "timeout"],
                        help="exit non-zero unless the verdict matches")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    result = validate(args.target, args.input, args.timeout)
    print(result["verdict"] if args.quiet else json.dumps(result, indent=2))
    if args.expect:
        sys.exit(0 if result["verdict"] == args.expect else 1)


if __name__ == "__main__":
    main()
