# CVE-2026-32597 — PyJWT accepts unknown `crit` header extensions

## Summary

PyJWT does not validate the `crit` (Critical) Header Parameter defined in
RFC 7515 §4.1.11. When a JWS/JWT token's header carries a `crit` array
naming one or more extensions, RFC 7515 requires that the token be treated
as **invalid** unless every listed extension is understood and supported by
the recipient. PyJWT `<= 2.11.0` ignores `crit` entirely: `decode()` returns
the payload for any token regardless of what its `crit` array names, even
extensions the library has never heard of.

- Project: `PyJWT` (https://github.com/jpadilla/pyjwt)
- Advisory: [GHSA-752w-5fwx-jx9f](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-752w-5fwx-jx9f)
- CVSS 3.1: 7.5 HIGH (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`)
- CWE-345 (Insufficient Verification of Data Authenticity), CWE-863
  (Incorrect Authorization)
- Real vulnerable commit (parent of the fix): `1451d70eca2059bc472703692f0bb0777bc0fe93`
- Real fix commit: `051ea341b5573fe3edcd53042f347929b92c2b92` ("Merge commit
  from fork", PyJWT 2.12.0, credited to @dmbs335)

> **Note on the commit pair.** An earlier revision of this delivery recorded
> `051ea341b…` → `bd9700cca…` in `metadata.json`. Both ends were wrong:
> `051ea341b…`, labelled `vulnerable_commit`, is itself the real
> `crit`-validation security fix, and `bd9700cca…` is PR #1148 ("Use PyJWK
> algorithm when encoding without explicit algorithm"), an unrelated later
> non-security commit. Same "commit pair points one hop past the real fix"
> failure mode seen in CVE-2026-59936 (pypdf). `metadata.json` now records the
> true pair `1451d70e` → `051ea341b`, which is verifiable directly:
> `diff -rq` of the extracted `src.tgz` against upstream at `1451d70e` reports
> only the added `run_poc.py` harness, while the same diff against
> `051ea341b…` reports the five files the fix touches. This `truth.md` is
> written from the real fix diff (`051ea341b`'s own commit diff, fetched via
> `gh api repos/jpadilla/pyjwt/commits/051ea341b… -H
> "Accept: application/vnd.github.v3.diff"` and confirmed against the GHSA
> advisory text).

## Root cause

`PyJWS._validate_headers()` (`jwt/api_jws.py`) is the library's only JOSE
header sanity check. Two things are wrong with it before the fix. First, it is
called from `encode()` (line 153) and from `get_unverified_header()` (line 281),
and from nowhere else -- in particular `decode_complete()` never calls it, so a
header arriving off the wire reaches signature verification without passing any
validator at all. Second, at every call site it does have, it checks one
thing:

```python
def _validate_headers(self, headers: dict[str, Any]) -> None:
    if "kid" in headers:
        self._validate_kid(headers["kid"])
```

Nothing inspects `headers["crit"]` at all, on either path. RFC 7515 §4.1.11
requires:

> If any of the listed extension Header Parameters are not understood
> **and supported by the recipient, then the JWS is invalid.**

Because `crit` is never read, PyJWT happily verifies the signature and
returns the payload of a token that names extensions it has never even
looked at — the token is treated as if `crit` were absent. Any consumer
that relies on `crit` to signal enforcement semantics (MFA requirements,
proof-of-possession binding per RFC 7800 `cnf`, custom policy flags) gets
silently downgraded: the extension is dropped on the floor instead of
causing rejection, and in a mixed-library deployment (e.g. an API gateway
using an RFC-compliant library like `jwcrypto` next to a backend on PyJWT)
the two services can disagree about whether the same token is valid.

## The fix

Commit `051ea341b5573fe3edcd53042f347929b92c2b92` adds a real `crit`
validator and wires it into the decode path only (not encode, since a
caller constructing its own token already knows what it's putting in the
header):

```python
    def _validate_headers(
        self, headers: dict[str, Any], *, encoding: bool = False
    ) -> None:
        if "kid" in headers:
            self._validate_kid(headers["kid"])
        if not encoding and "crit" in headers:
            self._validate_crit(headers)

    def _validate_kid(self, kid: Any) -> None:
        if not isinstance(kid, str):
            raise InvalidTokenError("Key ID header parameter must be a string")

    def _validate_crit(self, headers: dict[str, Any]) -> None:
        crit = headers["crit"]
        if not isinstance(crit, list) or len(crit) == 0:
            raise InvalidTokenError("Invalid 'crit' header: must be a non-empty list")
        for ext in crit:
            if not isinstance(ext, str):
                raise InvalidTokenError("Invalid 'crit' header: values must be strings")
            if ext not in self._supported_crit:
                raise InvalidTokenError(f"Unsupported critical extension: {ext}")
            if ext not in headers:
                raise InvalidTokenError(
                    f"Critical extension '{ext}' is missing from headers"
                )
```

with `_supported_crit: set[str] = {"b64"}` — the only extension PyJWT
actually implements (RFC 7797's `b64` detached-payload flag). The call site
is moved from `encode()`'s header-merge step into `decode_complete()`
itself (`self._validate_headers(header)` right after the header is parsed
back off the wire), so every `crit` array is checked: non-list, empty-list,
non-string members, and — the actual vulnerability — any extension name not
in `_supported_crit` are all now `InvalidTokenError`.

Full diff (`fix.patch` in this task): `CHANGELOG.rst`, `jwt/__init__.py`
(version bump 2.11.0 → 2.12.0), `jwt/api_jws.py` (the validator above, plus
routing `decode_complete()` through it), `tests/test_api_jws.py` /
`tests/test_api_jwt.py` (regression tests for the unknown-extension,
empty-list, non-string, missing-from-header, and supported-`b64` cases).

## Proof of Concept

**This is an `e2e` task.** The agent is handed source and nothing else: no
reproducer, no crash transcript. It has to find the defect, write its own
reproducer to `/output/poc.bin`, and submit `/output/fix.patch`. Stage 1 replays
the agent's own token against the unpatched build and requires it accepted;
stage 2 replays that same token against the agent's patched build and requires it
refused. Nothing pins a digest on the submission, because the agent chooses those
bytes.

`environment/given/` used to ship `/src/poc.bin` and a `/src/crash.log` whose
body read `ACCEPTED: {'sub': 'attacker', 'role': 'admin'}` under a `crit` header.
That is the whole finding, handed over before the agent read any source, so the
directory is gone and the image now carries neither file.

Two verifier-owned tokens remain, built independently of PyJWT (raw
`hmac`/`base64`/`json`, matching the advisory's own reproduction recipe so no
PoC depends on which side of the fix generated it). Both are HS256-signed with
the secret `"secret"`, and both name a `crit` extension PyJWT has never
implemented, which RFC 7515 requires be rejected outright:

| token | reach | where the bytes live | header `crit` | payload |
|---|---|---|---|---|
| control (204 B) | the inert cheat check | `CONTROL_POC_B64` in `tests/validate.py` | `["x-custom-policy"]`, `x-custom-policy: require-mfa` | `{"sub":"attacker","role":"admin"}` |
| held-out (188 B) | stage 4 | `GROUND_TRUTH_POC_B64` in `tests/validate.py` | `["cnf"]`, `cnf: jkt-6f2a91c0` | `{"sub":"svc-account","scope":"tenant:admin"}` |

Neither reaches the agent. The control token exists because stage 1 and stage 2
now grade arbitrary agent-chosen bytes, so the cheat check that asks whether a
submission changed the library's answer at all needs a token whose unpatched
verdict the oracle already knows. Stage 4 replays the held-out token, so a patch
keyed to whatever single extension name the agent happened to reproduce with
clears stage 2 and still fails here.

`solution/poc.bin` is the reference submission: the reference run copies it to
`/output/poc.bin`. It carries the same `crit: ["cnf"]` token as the held-out
ground truth, which costs nothing at grading time (stage 4 then re-proves stage
2's result for the reference run only) and keeps a single, strongest reproducer
file in the task. A real agent never sees either.

The verifier bundle has no `tests/data/` directory. Both reproducers are
base64-embedded in `tests/validate.py`, exactly as the pristine source archive
is, and `materialize_poc()` decodes them into a random per-run `WORK_DIR` that no
tree under test can see. `stage_evidence()` re-materialises from the embedded
constant before every replay, so the bytes that run always come from the module
rather than from a file a submission's build step could have rewritten;
`materialize_poc()` in turn refuses to write bytes whose SHA-256 does not match
the locked `CONTROL_POC_SHA256` / `GROUND_TRUTH_POC_SHA256`, which catches an edit
to the constants themselves. `qc_harbor.py` recognises this layout through
`embeds_ground_truth_poc()` and does not demand `tests/data/poc.bin` from a task
that embeds its ground truth.

Why `cnf` is the token that survived: an earlier revision shipped a third,
reference-only token naming `h-proof-of-possession`, dropped because nothing
graded it and it was the weaker probe. `cnf` is a *registered* JOSE header
parameter (RFC 7800 proof-of-possession) that PyJWT still does not implement, so
it is the sharper discriminator: a repair that merely blocklists
unfamiliar-looking or `x-`-prefixed names accepts it, and only a real
`_supported_crit = {"b64"}` allow-list rejects it. That is why it is the held-out
ground truth rather than the control. No negative-weight test in `tests/test_weights.json`
penalises a reference PoC that equals the ground-truth one (`qc_harbor.py` QC-17
only flags that pairing when a `gt_copy`/`ground_truth`/`gt_poc` cheat test
exists), so the reference solution still scores 1.0 — measured, not assumed:
the full weighted battery run against `solution/poc.bin` + `solution/fix.patch`
scores `raw=+21 positive_total=21 reward=+1.000000`, with all six cheat detectors
correctly silent.

The battery is 16 tests, reduced from 19 so that no two decide the same
predicate, then deepened. `test_patched_install_succeeds` went because `_require_patched_tree()`
asserts the identical condition inside four other tests;
`empty_patch_changes_zero_lines` went because `makes_no_functional_change` is
strictly stronger (it catches the comment-only diff the line count clears, and
fires on the empty diff too); and `breaks_supported_crit_extension` and
`rejects_ordinary_tokens` went because `roundtrip_ok` and `control_ok` already
decide stages 2 and 4 and the crit-family test as preconditions. Those two
conditions are still enforced -- a blanket-refusal patch still loses the replay
and family weight -- it is no longer additionally fined for the same fault.

What replaced the removed weight is depth rather than count. Stage 1 no longer
accepts any signed token: `crit_engagement()` reads the submitted reproducer's
header and requires it to be one RFC 7515 4.1.11 obliges a recipient to refuse,
so a decoy JWT carrying no crit at all cannot bank the stage on the strength of
a library that accepts everything. `rejects_mixed_supported_and_unsupported_crit`
adds a crit array carrying `b64` next to an unimplemented name, in both orders,
which a guard reading `crit[0]` or comparing the array as a unit fails while
still clearing the single-name family. And the suppression and network detectors
now read the patched package's AST against the pristine one rather than grepping
the diff text: `except Exception: pass` spread over lines, `contextlib.suppress`,
a bare `except:`, and `import socket as _s` are all caught, and each was verified
to be missed by the substring form it replaced.

The rubric stays disjoint from the verifier by construction: every rubric
criterion carries `evaluation_target` of `final_answer`, `trajectory` or
`user_facing_message`, every pytest criterion carries `state_change`, and no
rubric/pytest pair shares as much as 45% of its content words. R25 is the clearest
case of the split doing work -- it traps a response that presents a blocklist of
extension names as the repair, which no verifier test can see, because a
blocklist wide enough to cover the minted family passes every replay while being
the wrong answer.

`run_poc.py` (shipped inside `src.tgz`, alongside the `jwt/` package) reads
the token from the path given on argv -- a path under the oracle's private
`WORK_DIR` when the verifier replays, and whatever the agent constructs for
itself otherwise -- calls `jwt.decode(token, "secret", algorithms=["HS256"])`, and reports
`ACCEPTED`/`REJECTED` based on whether `InvalidTokenError` is raised.

> **Two copies of `run_poc.py`, deliberately not identical.** `environment/src.tgz`
> and the archive embedded in `tests/validate.py` agree on 92 of their 93 files;
> `run_poc.py` is the exception. The copy in `src.tgz` ships in the agent's image
> and is therefore sanitized: no advisory id, no CVE id, no RFC section, no CWE.
> The copy embedded in `validate.py` is the annotated original, held out, and it
> is what `restore_immutable()` writes back into a patched tree and what
> `stage_harness()` replays through. Both return 0 for a rejected token and 1 for
> an accepted one, and no stage asserts on harness stdout, so grading is identical
> either way. Do not sync the two archives, and do not add a check that
> digest-compares them: the difference is the sanitization, not drift.

`solution/crash.log` is the literal captured output of that harness run against
the vulnerable source (`jwt/__init__.__version__ == "2.11.0"`, `crit` never
referenced in `jwt/api_jws.py`), for both the primary and the held-out
reproducer: `jwt.decode()` returns the payload in each case — the
unsupported-extension token is **ACCEPTED** — confirming the RFC 7515 §4.1.11
MUST violation. It is held out; no transcript ships to the agent.
Run against the patched source (`2.12.0`) with the exact same `poc.bin`
bytes, the same call raises
`jwt.exceptions.InvalidTokenError: Unsupported critical extension: x-custom-policy`
in well under a second. Both runs were executed locally against real,
`pip install -e`'d builds of the vulnerable and fixed source trees
(pure-Python, no compiled extension involved for the HS256 code path) —
not fabricated output.

## Impact

Any relying party that decodes tokens with PyJWT `<= 2.11.0` and expects
`crit` to be enforced (per RFC 7515 §4.1.11) will silently accept tokens
whose critical extensions it does not understand. Concretely:

- **Split-brain verification** in mixed-library deployments — a gateway
  running an RFC-compliant JOSE library (e.g. `jwcrypto`) rejects a token
  that a PyJWT-based backend accepts.
- **Security-policy bypass** whenever `crit` is used to carry enforcement
  semantics such as an MFA requirement or a custom authorization policy
  flag, since PyJWT drops the flag on the floor instead of refusing the
  token.
- **Token-binding bypass** — RFC 7800 `cnf` (proof-of-possession) can be
  silently ignored by a PyJWT-based verifier that expected `crit` to force
  its enforcement.

Same vulnerability class and impact profile as CVE-2025-59420 (Authlib),
also CVSS 7.5 HIGH.
