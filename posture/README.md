# Reference posture

Owner: B.

The motivating example is not a claim violation. PSS Restricted asserts nothing
about AF_ALG, and RuntimeDefault's contract is whatever the runtime ships.
Measured against the manifest alone, the AF_ALG case produces no finding.

What failed was an expectation. The reference posture is that model: a
versioned document asserting, per security tier, which kernel entry families a
workload at that tier should not reach. Every assertion carries a rationale and
a citation — a CVE, a documented escape technique, a vendor advisory — so the
posture is auditable rather than assertion by authority. It is deliberately
stronger than the tiers it is named after, and that gap is the point.

It also supplies the target that remediation is minimal with respect to.

## Layout and format

The evaluator (`control/`, #34) reads the posture and joins it against the
fingerprint, so the normative artefact is machine-readable and the argument
for it is prose beside it:

```
posture/
  README.md          this file
  CHANGELOG.md       revision history and release notes
  v1/
    posture.yaml     normative: tiers, assertions, citations (#21, #22)
    RATIONALE.md     the argument, per tier and per assertion
```

`posture.yaml` carries `posture_revision`, `status`, `tiers[]` (name, `named_after` PSS
level, the workload class it describes, how it is stronger than that level)
and `assertions[]` (tier, `family`, optional `probe_ids`, `expect`,
`rationale`, `citations[]`). Families and probe ids are the corpus's, exactly
as `caliper-probe --dump-corpus` spells them, so an assertion maps one to one
onto results. Tiers inherit downward: an assertion at `restricted` holds at
`untrusted-multi-tenant` too, and is written once.

### Revisions and findings (#23)

`posture_revision` is the single public identifier for the policy (currently
`v1`). Keeping one identifier avoids a schema-version/policy-version drift. A
change to a shipped policy is a new `posture/vN/` directory, a new
`posture_revision`, and a `CHANGELOG.md` entry; released revisions are never
edited in place.

The current `v1` document is marked `status: draft` while the corrections
tracked by issue #94 are pending. It must be marked released only after those
assertions are fixed and reviewed.

Every finding emitted by the control plane records the exact
`posture_revision` used for evaluation. The field is provenance, not a claim
that the finding came from a trusted signer, and is distinct from the
fingerprint's `format_version` and `corpus_revision`:

```json
{
  "kind": "expectation-violation",
  "posture_revision": "v1",
  "tier": "untrusted-multi-tenant",
  "family": "socket",
  "probe_id": "socket.family.af_alg"
}
```

The posture directory is part of the instrument release. A release therefore
ships the posture revision and its changelog alongside the engine and control
plane, so a finding can always be reproduced against the declared policy.

## Tier definitions (#21)

`posture/v1/posture.yaml` currently defines four named tiers:

- `privileged`: node agents and infrastructure workloads that legitimately
  need broad host-facing kernel access.
- `baseline`: ordinary trusted services that need normal application access,
  but not host administration primitives.
- `restricted`: services handling untrusted input under a standard hardened
  deployment.
- `untrusted-multi-tenant`: operator-untrusted code sharing a node with other
  tenants, such as pull-request CI and customer plugin sandboxes.

Each tier records the PSS level it is named after, the workload class it
describes, and why it is deliberately stronger than that PSS level. The
`untrusted-multi-tenant` tier is named after Restricted because PSS has no
stronger level; that gap is intentional. Assertions are added in #22 and
posture revisions are handled in #23.
