# samples

GENERATED SECTION. DO NOT HAND-EDIT.

## Promoted set

3 bundle directory resident under `samples/`. Promotion is byte-bound and revocable, and only a FORGE invocation removes bytes from this root, so the removal lag named in each row is bounded rather than instantaneous.

No bundle in this root is promoted to sample grade. Phase 4.5 item 2d requires five conditions at transition, `SHIP`, a current signed pilot, freshly re-proven frozen-byte conformance, zero open gaps, and current CONTAMINATION-SCREENING. No bundle here satisfies any of them, so every row stands unpromoted.

## Standing

| uuid | canonical uuid5 | disposition | pilot measured | promoted | screening instant | bound interval | absolute expiry | declared difficulty | removal lag |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `42d756c8-abda-48ce-a4a1-5fc887d53386` | uuid-shaped | HOLD:PILOT_REQUIRED | none | none | none | none | none | Medium (claimed, unmeasured) | next FORGE invocation |
| `6e02e468-4f80-4fa7-96aa-2c3b0db7c14e` | uuid-shaped | HOLD:PILOT_REQUIRED | none | none | none | none | none | Medium (claimed, unmeasured) | next FORGE invocation |
| `7658f933-e5ad-4ce1-b9fa-0e1d75badb0e` | uuid-shaped | HOLD:PILOT_REQUIRED | none | none | none | none | none | Expert (claimed, unmeasured) | next FORGE invocation |

Every `none` in this table is an absent measurement rather than a passing one. A disposition of `HOLD:PILOT_REQUIRED` means the local design is valid and unproven, and `SHIP` is unreachable for every row while no external pilot operator exists. A declared difficulty marked claimed and unmeasured violates the measured-never-claimed rule, because only an external signed pilot over frozen task bytes establishes a tier.

## Screening roots

| root | standing | immutable digest |
| --- | --- | --- |
| `exclusion-list` | effective | `9cc0695db02c5245f72650bc69b8d283` |
| `freeze-date-table` | structure_present_values_unresolved | `db0d21e1ca7d6537043f8e7c7a4874a1` |
| `near-duplicate-index` | absent | none |
| `source-attestation-trust-root` | absent | none |

A root standing at anything other than `effective` cannot certify a screen. An unresolvable root caps every bundle in this root at `HOLD:PILOT_REQUIRED` with reason `screening-unverified`, and an absent source-attestation trust root caps with reason `attestation-unavailable`. Neither condition is a pass.

Narrative overview for this root, hand-authored and outside the generated skeleton above, lives at [OVERVIEW.md](OVERVIEW.md). Phase 1 item 2g governs the three sections above and leaves prose elsewhere, and invariant 35 names `samples/` a public root, so the overview is preserved rather than regenerated.
