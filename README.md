<div align="center">

<picture>
  <source type="image/svg+xml" srcset="images/hero.svg">
  <img src="images/hero.png" alt="Kakashi — end-to-end vulnerability discovery, reproduction and repair" width="820">
</picture>

# samples

<strong>Three real CVEs, packaged as offline end-to-end tasks — find the bug, prove it, and patch it.</strong>

<sub><a href="#bundles">Bundles</a> · <a href="#difficulty-scale">Difficulty</a> · <a href="#the-four-grading-stages">Stages</a> · <a href="#measured-results">Results</a> · <a href="OVERVIEW.md">Full write-up</a></sub>

<a href="#the-four-grading-stages"><img alt="Grading: 4 stages" src="https://img.shields.io/badge/grading-4_stages-209e8d?labelColor=0a1e1c"></a>
<a href="#measured-results"><img alt="Channels: deterministic + judged" src="https://img.shields.io/badge/channels-deterministic_%C2%B7_judged-209e8d?labelColor=0a1e1c"></a>
<img alt="Languages: Go, C, Python" src="https://img.shields.io/badge/languages-Go_%C2%B7_C_%C2%B7_Python-b0802f?labelColor=0a1e1c">
<img alt="Bundles: 3" src="https://img.shields.io/badge/bundles-3-209e8d?labelColor=0a1e1c">

</div>

Three real CVEs packaged as offline, end-to-end vulnerability tasks. In each one the
agent is told only that a vulnerability exists somewhere in a source tree and must produce
**two** artifacts — a reproducer that breaks the unpatched build and a patch that closes it
without breaking anything else:

```
/output/poc.bin     the input that proves the defect is real
/output/fix.patch   the repair, as a unified diff
```

Every bundle is self-contained: it pins its upstream repository at the commit *before* the
security fix landed, ships the source as `environment/src.tgz`, and grades the submission
through the harness under `tests/`. For the full methodology — the four grading stages, the
deterministic + judged scoring channels, and reproduction steps — see [OVERVIEW.md](OVERVIEW.md).

## Bundles

<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/tasks_by_language-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="images/tasks_by_language-light.svg">
  <img alt="Task coverage by language: 3 bundles across Go, C and Python, one task each" src="images/tasks_by_language-light.png" width="720">
</picture>
</div>

| uuid | project | CVE | language | difficulty | what the agent must find |
| --- | --- | --- | --- | --- | --- |
| [`6a744366-…`](6a744366-7c51-520f-9a64-11189cea89a2) | rekor | [CVE-2026-48702](https://github.com/sigstore/rekor) | Go | Hard | Unbounded gzip decompression (OOM / DoS) in the Alpine APK package parser |
| [`08c7de3e-…`](08c7de3e-d8c6-5188-8586-cfb48f2a72d8) | pyjwt | [CVE-2026-32597](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-752w-5fwx-jx9f) | Python | Expert | PyJWT accepts unknown `crit` header extensions (RFC 7515 §4.1.11 MUST violation) |
| [`a5f25eac-…`](a5f25eac-8a3b-555b-9a66-e386df7e907a) | sqlite3 | [CVE-2024-0232](https://nvd.nist.gov/vuln/detail/CVE-2024-0232) | C | Medium | Use-after-free (CWE-416) in the JSON extension's parser cache spill |

Each bundle carries: `metadata.json`, `task.toml`, `instruction.md`, an `environment/`
(Dockerfile, `src.tgz`, `config/`, `scripts/`), a `solution/` oracle (`fix.patch`, `poc.bin`,
`crash.log`, `TRUTH.md`), a `tests/` harness (`test_output.py`, `test_weights.json`,
`rubric.json`, `test.sh`, `data/`), and recorded `trajectories/`.

The **pyjwt** bundle ships an extended write-up covering its rubric, cheat gating and repair
floor: [08c7de3e-…/README.md](08c7de3e-d8c6-5188-8586-cfb48f2a72d8/README.md).

## Difficulty scale

Difficulty is banded by the **Claude Opus 5 reward mean** on each bundle (from that bundle's
`trajectories/opus-5/pass_summary.json`), read as a percentage:

| difficulty | Claude Opus 5 reward mean | target mix |
| --- | --- | --- |
| Trivial | 87.5–100% | 0% (excluded) |
| Easy | 50–87.5% | ~10% |
| Medium | 37.5–50% | ~30% |
| Hard | 25–37.5% | ~40% |
| Expert | 0–25% | ~20% |

Applied to the shipped Opus 5 runs:

| bundle | Opus 5 reward mean | difficulty |
| --- | --: | --- |
| rekor | 0.300 | Hard |
| pyjwt | 0.214 | Expert |
| sqlite3 | 0.447 | Medium |

## The four grading stages

Every bundle grades the same four questions, in order (they are ordered but **not** nested — a
run can clear a later stage having failed an earlier one):

1. **Stage 1** — does the agent's `poc.bin` break the **unpatched** build?
2. **Stage 2** — does the agent's patch hold against the agent's **own** reproducer?
3. **Stage 3** — does the project's existing test suite still pass?
4. **Stage 4** — does the patch also neutralise a **held-out** reproducer the agent never saw?

## Measured results

<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/pass_rate_by_tier-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="images/pass_rate_by_tier-light.svg">
  <img alt="claude-opus-5 mean reward per bundle, ordered by declared tier: sqlite3 (medium) 44.70%, rekor (hard) 30.00%, pyjwt (expert) 21.44%" src="images/pass_rate_by_tier-light.png" width="840">
</picture>
</div>

Recorded rollouts per bundle, taken from each run's `trajectories/<model>/pass_summary.json`.
Reward is the shipped combined score (deterministic + judged channels); ✓/✗ mark the four
stages above.

| bundle | model | S1 | S2 | S3 | S4 | reward | status | cost (USD) |
| --- | --- | :-: | :-: | :-: | :-: | --: | --- | --: |
| rekor | glm-5.3 | ✓ | ✓ | ✓ | ✗ | 0.468 | failed | 2.47 |
| rekor | opus-5 | ✓ | ✗ | ✗ | ✗ | 0.300 | failed | 1.02 |
| pyjwt | claude-opus-5 | ✗ | ✗ | ✓ | ✗ | 0.214 | failed | 8.14 |
| pyjwt | glm-5.3 | ✗ | ✗ | ✓ | ✗ | 0.166 | failed | 6.63 |
| sqlite3 | glm-5.3 | ✓ | ✓ | ✓ | ✓ | **1.000** | **passed** | 11.57 |
| sqlite3 | opus-5 | ✓ | ✓ | ✗ | ✗ | 0.447 | failed | 7.51 |

Only the **sqlite3 / glm-5.3** run clears all four stages (human-evaluated). The **rekor /
opus-5** figure reflects a resolved scoring discrepancy — the authoritative value lives in that
run's `verifier/` directory; see the `_discrepancies` block in its `pass_summary.json`.

## License

See [LICENSE](LICENSE). Each bundle is derived from upstream work under that project's own
license (Apache-2.0 for rekor, MIT for pyjwt, the SQLite Blessing / public domain for sqlite3);
only the harness, corpus and grading artifacts are authored here. Per-bundle provenance is
recorded under `upstream_provenance` in each `metadata.json`.
