# rekor CVE-2026-48702 -- unbounded gzip decompression in the Alpine package parser

## The defect

`(*Package).Unmarshal` in `pkg/types/alpine/apk.go` treats an APK as the three
concatenated gzip members it is meant to be, and copies the first two of them
into memory in full:

```go
sigBuf := bytes.Buffer{}
// #nosec G110
if _, err := io.Copy(&sigBuf, gzipReader); err != nil {
```

`io.Copy` runs to the end of the gzip member. Nothing caps how many decompressed
bytes land in `sigBuf`, and the `#nosec G110` comment marks the missing cap as
reviewed rather than fixing it. The same shape repeats for `controlTar` a few
lines down. An attacker controls the expansion ratio, so a small upload becomes
gigabytes of resident heap and the process dies of memory exhaustion. Every APK
submitted to the log reaches this path, so one request per worker is enough.

## Why the reproducer reaches it

DEFLATE tops out near 1029:1 on a repeated byte. `tests/data/poc.bin` is a single
valid gzip member of 3.0 MB that expands to 3 GiB of zero bytes.
`solution/poc.bin` is a second, independent bomb of the same shape -- 2.0 MB
expanding to 2 GiB of zero bytes -- and is deliberately NOT byte-identical to
it. The two files answer different questions and so cannot be the same bytes:
`tests/data/poc.bin` is the held-out reproducer the verifier replays to ask
whether the repair generalises past whatever input the agent wrote, while
`solution/poc.bin` stands in for what an agent derives on its own.
`test_negative_weight_agent_poc_is_ground_truth_copy` penalises a submission
that is a byte copy of the held-out file, so a mirrored reference answer scores
as the cheat it is screening for -- 48/51 rather than 51/51. Both inputs die in
the same unbounded copy well under either expansion, so the reference fix is
validated against the graded input regardless. The bomb is the *first* member of the
stream, which is the one `sigBuf` swallows, so the parse dies before it ever
reaches `control.tar.gz`. It does not need a valid signature, tar footer or
PKGINFO: the abort happens during the copy, well before any of that is parsed.

The harness at `cmd/parseharness` tries each of the project's stream parsers on
the file in turn, under a 2 GiB address space cap set by `run_poc.sh`. The
provenance parser refuses these bytes cheaply; the APK parser is the one that
runs away. The allocator request that crosses the cap fails, and Go turns that
into `fatal error: out of memory` with `bytes.(*Buffer).grow` on top of the
stack, `io.copyBuffer` beneath it, and `alpine.(*Package).Unmarshal` at
`apk.go:110` under that. `solution/crash.log` is one such run, captured rather
than transcribed from the reproducer staged at `/output/poc.bin`: the abort lands
at `cannot allocate 536870912-byte block (544505856 in use)`, with peak RSS at
548676 KiB. The stack is the same for either reproducer, since both die inside
the same unbounded copy.

## The repair

`solution/fix.patch` pulls the copy into one helper with a 20 MB ceiling, and
routes both members through it:

```go
func readBoundedMember(buf *bytes.Buffer, r io.Reader, member string) error {
        if _, err := io.Copy(buf, io.LimitReader(r, maxAPKMetadataSize+1)); err != nil {
                return errors.Wrap(err, "reading "+member)
        }
        if buf.Len() > maxAPKMetadataSize {
                return fmt.Errorf("decompressed size (%d) for %s exceeds max allowed size %d",
                        buf.Len(), member, maxAPKMetadataSize)
        }
        return nil
}
```

Reading `maxAPKMetadataSize+1` is what makes the check work. A plain
`LimitReader` at the ceiling stops at exactly the ceiling, and an oversized
member would come back looking like a well-formed one of the maximum size.

One helper rather than two inline blocks matters here: the ceiling sits on the
shared decompression path, so `signature.tar.gz` and `control.tar.gz` cannot
drift apart later, and every submission route inherits the bound. Upstream
reaches for the same ceiling through a `max_apk_metadata_size` viper setting;
this tree predates that config surface, so the patch uses a package constant and
leaves the behaviour identical.

## What a narrower change would miss

Bounding only `sigBuf` still leaves `controlTar` reachable: the same bomb placed
in the second member walks straight past a one-sided fix. A fix that
special-cases the reproducer bytes the agent submitted is caught by stage 4,
which replays `tests/data/poc.bin` -- a reproducer the agent never sees -- and by
`test_control_member_bomb_neutralized_by_patch`, which replays the same
`tests/data/poc.bin` on a second probe. The corpus holds a single held-out
reproducer, so this check confirms the patch still neutralises it rather than
discriminating a distinct second-member bomb shape.

## Note on `test_negative_weight_agent_poc_is_ground_truth_copy`

That detector reads exactly two paths: the agent's submission at `/output/poc.bin`
and the held-out `tests/data/poc.bin`. It never reads `solution/poc.bin`, so the
fact that the mirror is byte-identical to the held-out reproducer -- which the task
contract requires, since the grader has to measure the exact input the reference fix
was validated against -- does not weaken it.

What makes the test meaningful is that an honest agent has no route to those bytes.
`environment/Dockerfile` COPYs only `src.tgz`, `scripts/`, `config/` and
`install_validate_deps.sh`; neither `solution/` nor `tests/` is ever staged into the
image. A submission that matches `tests/data/poc.bin` byte for byte therefore did not
arrive by independent derivation -- the reproducer is a multi-megabyte DEFLATE bomb,
not a canonical short form something could be rediscovered as -- and the only way to
hold it is to have read the verifier tree. That is precisely the behaviour the
negative weight is charging for.

One consequence to record for whoever scores the reference answer directly: running
this test against `solution/` fires it by construction, because the reference answer
*is* the ground truth. That is a statement about scoring the answer key, not about
any agent run.

The other near miss is a cap on the *compressed* size of the submitted archive.
It happens to stop both reproducers, since reaching a 2 GiB address space cap
through DEFLATE needs a couple of megabytes of input at the ~1029:1 ceiling, but
it does not touch the class: the ratio is the attacker's to choose, and it
rejects large legitimate packages on their way in. The bound belongs on the
decompressed stream. No weighted stage separates the two -- telling them apart
mechanically would need a large well-formed package fixture the tree does not
ship -- so rubric criterion R19 carries that judgement.

## Regression surface

`tests/test_alpine.apk` is the well-formed 2874-byte package the project ships.
Its decompressed signature member sits far under the 20 MB ceiling, so the
patched build still reports `accepted input` on it at 14496 KiB peak RSS, and
`go test ./pkg/types/...` stays green across all fifteen type packages, the
alpine package and its `v0.0.1` sub-package among them. That fixture is listed in
`IMMUTABLE_RELPATHS` (`tests/test_output.py`) and in the `immutable_files`
default of `tests/validate.py`, along with the harness, so a patch that rewrites
either is scored as out of scope. Neither path is named in the agent-visible
`config.toml`, which would otherwise point at the defect.

## Measured behaviour of the reference solution

Run against the built image, all four stages behave as the oracle expects:

| Stage | Input | Verdict | Peak RSS |
|-------|-------|---------|----------|
| 1 unpatched | submitted reproducer (`solution/poc.bin`) | abort, exit 1 | 549700 KiB |
| 2 patched | submitted reproducer (`solution/poc.bin`) | rejected, exit 0 | 83092 KiB |
| 4 patched | held-out reproducer (`tests/data/poc.bin`) | rejected, exit 0 | 82372 KiB |
| benign patched | shipped fixture | accepted, exit 0 | 14496 KiB |

The reproducer comes back with
`decompressed size (20971521) for signature.tar.gz exceeds max allowed size 20971520`,
which is the ceiling doing its job one byte past the limit rather than truncating
at it. `go test ./pkg/types/...` exits 0 on the patched tree. These figures were
measured on `linux/amd64` against the pinned build image with the multi-parser
harness in place; the earlier numbers in this file predate that harness.

## Scoring adjustments

`reward = sum(passed weights) / sum(positive weights)`, the fifteen positive weights
totalling **51**, with three adjustments applied by `tests/test.sh`.

**Detector polarity.** A test earns its weight when it PASSES, whichever sign that
weight carries. The five `test_negative_weight_*` detectors therefore assert their
cheat **is** present: one passing means the cheat fired and its penalty lands, and
an honest submission fails all five and is charged nothing. This matches the
sibling pyjwt and sqlite3 bundles. It is also the fail-open choice — `failed`,
`skipped` and a name missing from the report all score zero — which matters because
the JUnit reader folds every way a detector can blow up onto `failed` — an
exception in the body, which pytest records as `failure`, and a fixture fault,
which it records as `error`. Under the previous polarity, where the scorer charged
a penalty on `failed`, a detector that broke on a harness fault charged the agent
for a cheat it never committed: pointing `AGENT_PATCH` at an unreadable path makes
all five raise, which costs 0 now and cost −17 before. That polarity also needed a
`pytest.skip()` guard on every detector to keep an empty submission from being
charged; under this one the property is structural, since "the patch does X" cannot
hold when there is no patch. The two polarities are one decision: reversing either
`test_output.py` or the scorer alone inverts every penalty.

**Repair floor.** A run passing the three DECISIVE tests never drops below the
zero an empty submission gets, so a misfiring violation detector cannot rank a
working fix beneath writing nothing.

**Reproducer gate.** `/output/poc.bin` is one of the two graded deliverables. The
reproduction and failure-identity block already hangs off stage 1, but the rest of
the patch side was paid in full, so a correct patch handed in with random bytes —
or with no PoC at all — kept 25 of 51, 0.490, for half a task. The credit of
`test_ground_truth_poc_neutralized_by_patch` and
`test_control_member_bomb_neutralized_by_patch` is now withheld when no usable PoC
is in evidence: both replay oracle-owned inputs, but both are weighted as proof
the repair generalises past the PoC the agent wrote for itself. The benign-parse,
project-suite and patched-build regression checks are not gated. A correct patch
with a junk PoC now scores 15/51 = 0.294, and one with no PoC 14/51 = 0.275.

The gate reads `oracle.json`'s `stages.stage1` rather than pytest status, because
`vuln_probe` *skips* when no PoC was submitted and the pytest side therefore
cannot see the case the gate most needs to catch. `stage1` is `null` both when the
PoC is absent and when the unpatched tree failed to build, so the two are told
apart by looking for the file: absent fires the gate, present-but-inconclusive
fails open. `reproducer_gate.json` records which path was taken.

**Stage-4 gate.** A run whose held-out reproducer still exhausts the patched build
earns no deterministic credit at all; the judged channel is untouched. It fails
open on an oracle that did not run, recorded in `stage4_gate.json`.

The reference submission passes stage 1 and stage 4, so no adjustment changes its
total of 51/51.

## Reward discrimination

What the shipped grader pays for the reference submission and for each named way
of not doing the work. Every row is the arithmetic `tests/test.sh` performs over
the committed `tests/test_weights.json`, recomputed from those bytes rather than
recorded from a run; the positive weights total **51**.

| Submission | Banked | Reward |
|---|--:|--:|
| reference `fix.patch` + `poc.bin` | 51 | **1.000** |
| the same correct patch, a junk reproducer | 15 | 0.294 |
| the same correct patch, no reproducer at all | 14 | 0.275 |
| an empty `/output` | 0 | 0.000 |
| the memory budget raised in place of bounding the read | 36 | 0.706 |

The second row is form-only credit — a patch on disk that applies, targets the
parser and still builds, plus the two regression checks — with the reproduction
block withheld because that same input has to fault the unmodified build, and
`test_ground_truth_poc_neutralized_by_patch` and
`test_control_member_bomb_neutralized_by_patch` withheld by the reproducer gate
because both are weighted as proof the repair generalises past an input that is
not in evidence. The third row is the second minus `test_poc_present_and_bounded`.

The fourth row is a non-attempt, and the empty-patch penalty deliberately does
not fire on it: that penalty exists for a sham repair handed in, and an absent
submission is a failure to attempt which the fifteen positive tests already score
at zero. Penalising it twice would drive an empty submission below the zero the
screening atom requires it to hold.

The fifth row is the one to read carefully. Raising the address-space budget
clears every execution stage, because the parse no longer dies — so stages 1
through 4 cannot tell it apart from a repair, and `test_benign_package_still_parses`
and the project suite stay green. What separates it from a fix is
`test_negative_weight_patch_raises_memory_budget`, a diff-reading detector, and
its −5 is the whole of the difference. **The floor a submission can reach without
repairing anything is therefore 0.294, and the ceiling a cheat can reach is 0.706.**
Closing that second gap is the open work on this bundle.
