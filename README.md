GENERATED SECTION. DO NOT HAND-EDIT.

<p align="center"><img src="images/hero.svg" alt="Kakashi" width="720"></p>

# Kakashi: samples

<p align="center"><b>The samples lane: 3 of 30 Harbor task bundles.</b></p>

<p align="center"><a href="#summary"><img src="https://img.shields.io/badge/bundles-3_of_30-845EF7" alt="bundles: 3 of 30"></a> <a href="#evidence-status"><img src="https://img.shields.io/badge/sealed-0-845EF7" alt="sealed: 0"></a> <a href="#difficulty-tiers"><img src="https://img.shields.io/badge/difficulty-measured-845EF7" alt="difficulty: measured"></a></p>

<p align="center"><sub><a href="#abstract">Abstract</a> | <a href="#summary">Summary</a> | <a href="#difficulty-tiers">Difficulty tiers</a> | <a href="#evidence-status">Evidence status</a> | <a href="#coverage">Coverage</a> | <a href="#dataset-structure">Dataset structure</a> | <a href="#trajectory-structure">Trajectory structure</a> | <a href="#verification-and-quality-assurance">Verification and quality assurance</a> | <a href="#reproduction">Reproduction</a> | <a href="#cite">Cite</a> | <a href="#license">License</a> | <a href="#contact">Contact</a></sub></p>

## Abstract

The curated lane of this corpus: at most 30 Harbor task bundles, every anchor seated first and every other bundle in seal order. Bundles past that ceiling live in `delivery/`.

Each bundle is one Harbor task in a directory named by its content-derived uuid5, so the name doubles as an integrity check. This page is rendered from the resident bundles on every reconcile; a value a bundle does not carry reads `absent`, and the page never fills one in.

## Summary

| Property | Value |
| --- | --- |
| Bundles | 3 of 30 |
| Sealed | 0 of 3 |
| Registrations | adopted (3) |
| Audit verdicts | none (3) |
| Harbor schema | 1.4 (3) |

## Difficulty tiers

Difficulty is measured by the signed pilot alone and never declared in a bundle, so this page states no tier a bundle claims.

## Evidence status

The verdict is the audit outcome recorded at the sealed digest, and `none` means no verdict has landed for that digest yet. Only a FORGE invocation removes a bundle from this lane, so removal waits for the next one.

| uuid | Verdict | Sealed digest | Stream |
| --- | --- | --- | --- |
| 08c7de3e-d8c6-5188-8586-cfb48f2a72d8 | none | absent | none |
| 6a744366-7c51-520f-9a64-11189cea89a2 | none | absent | none |
| a5f25eac-8a3b-555b-9a66-e386df7e907a | none | absent | none |

## Coverage

| Keyword | Bundles |
| --- | --- |
| security | 3 |
| authentication | 1 |
| c | 1 |
| denial-of-service | 1 |
| e2e | 1 |
| go | 1 |
| input-validation | 1 |
| memory-safety | 1 |
| python | 1 |
| resource-exhaustion | 1 |
| use-after-free | 1 |

## Dataset structure

| Bundle | Task | Keywords | Registration | Sealed at |
| --- | --- | --- | --- | --- |
| [`08c7de3e-d8c6-5188-8586-cfb48f2a72d8`](08c7de3e-d8c6-5188-8586-cfb48f2a72d8/) | `ethara/pyjwt-cve-2026-32597` | authentication, input-validation, python, security | adopted | unsealed |
| [`6a744366-7c51-520f-9a64-11189cea89a2`](6a744366-7c51-520f-9a64-11189cea89a2/) | `ethara/rekor-cve-2026-48702` | denial-of-service, go, resource-exhaustion, security | adopted | unsealed |
| [`a5f25eac-8a3b-555b-9a66-e386df7e907a`](a5f25eac-8a3b-555b-9a66-e386df7e907a/) | `ethara/sqlite3-cve-2024-0232` | c, e2e, memory-safety, security, use-after-free | adopted | unsealed |

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#131a33","primaryTextColor":"#e8ecff","primaryBorderColor":"#845EF7","lineColor":"#22d3ee","fontFamily":"monospace"}}}%%
flowchart LR
    bundle["&lt;uuid&gt;/"]
    bundle --> n0["task.toml<br/>runner manifest"]
    bundle --> n1["instruction.md<br/>objective the agent reads"]
    bundle --> n2["environment/<br/>agent sandbox image"]
    bundle --> n3["tests/<br/>verifier, hidden from the agent"]
    bundle --> n4["solution/<br/>private oracle"]
    bundle --> n5["trajectories/<br/>private rollout evidence"]
    bundle --> n6["metadata.json"]
```

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#131a33","primaryTextColor":"#e8ecff","primaryBorderColor":"#845EF7","lineColor":"#22d3ee","fontFamily":"monospace"}}}%%
flowchart LR
    staging["staging/"]
    staging --> samples["samples/<br/>3 of 30"]
    samples --> delivery["delivery/<br/>0 of 10000"]
    delivery --> stock["stock/<br/>0 of 10000"]
```

## Trajectory structure

3 of 3 resident bundles carry a `trajectories/` subtree of private rollout evidence. The signed pilot reads it; this page never restates a rollout.

## Verification and quality assurance

Each bundle's signed provenance carrier holds its screening roots, screening instant, and absolute expiry. Placement moves that carrier into the private derivation set, which this page never reads, so reconcile lists no root it cannot verify here.

## Reproduction

Each bundle directory is a complete Harbor task: `task.toml` is the runner manifest, `instruction.md` the objective, `environment/` the sandbox image, and `tests/` the verifier. Point a Harbor runner at one bundle directory to reproduce it; `solution/` and `trajectories/` stay private.

## Cite

```bibtex
@misc{kakashi2026,
  title        = {Kakashi: end-to-end vulnerability discovery, reproduction, and repair tasks with measured difficulty},
  author       = {{Ethara.AI}},
  year         = {2026},
  howpublished = {\url{https://github.com/EtharaOrion/kakashi}},
  note         = {Task format after CyberGym-E2E, arXiv:2606.04460}
}
```

## License

MIT. See `LICENSE`. Each submodule carries its own license, and every bundle records its upstream project's license in `metadata.json`.

## Contact

Ethara.AI on GitHub at [EtharaOrion](https://github.com/EtharaOrion) and [Ethara-Ai](https://github.com/Ethara-Ai). Report a leaked task byte, a contamination path, or a gameable shortcut privately to security@ethara.ai rather than in a public issue, under the disclosure process in [SECURITY.md](SECURITY.md). Contributions follow the measured-never-claimed directive in the governance contracts, with `requirements/` and `touchstones/` remaining human-write-only, and [CONTRIBUTING.md](CONTRIBUTING.md) states how to open one.
