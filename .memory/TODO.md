# TODO

GENERATED SECTION. DO NOT HAND-EDIT.

Source of truth: `.memory/capabilities.yaml` in this repository. This backlog is regenerated from that block and from the named coverage gaps of each run, so editing it by hand is drift the next regeneration overwrites.

Seeded into `samples` by the parent project's genesis pass. Every optional capability below sits at the default posture, which is the honest starting point rather than a claim, and each row names what a stronger posture would require.

| Capability | State | What a stronger state requires | Consequence today |
| --- | --- | --- | --- |
| `autonomous_gates` | default | a named gatekeeper identity with an authorized role, its work-order digest, a model-lineage diversity requirement, a calibration policy with a demotion threshold, and a per-gate blast-radius tier table | every digest gate stays human |
| `contamination` | default | one pinned corpus snapshot digest both instruments can audit | no contamination hit can be computed |
| `multi_operator_witness` | default | a named witness network with deterministic confirmation | a single-operator checkpoint log is the only integrity witness |
| `orthogonality` | default | signed pilot outcomes to fit the groups against, rather than authored priors | group coverage is a named gap and no fitted estimate promotes a row |
| `stronger_identity_policy` | default | an objective byte-level policy naming the exact operators and bound artifacts | identity rests on the default provider-signature path |

## Standing obligations

- No `bucket_d_status` block exists yet. It is generated from a conformance report on the first ENGRAM run in this repository and is never hand-maintained.
- This repository carries no `.seed/` or `.audit/` harness. Standing those up belongs to the authoring and audit instruments respectively and proceeds only after human confirmation.
