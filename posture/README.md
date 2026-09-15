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
  v1/
    posture.yaml     normative: tiers, assertions, citations (#21, #22)
    RATIONALE.md     the argument, per tier and per assertion
```

`posture.yaml` carries `posture_version`, `tiers[]` (name, `named_after` PSS
level, the workload class it describes, how it is stronger than that level)
and `assertions[]` (tier, `family`, optional `probe_ids`, `expect`,
`rationale`, `citations[]`). Families and probe ids are the corpus's, exactly
as `caliper-probe --dump-corpus` spells them, so an assertion maps one to one
onto results. Tiers inherit downward: an assertion at `restricted` holds at
`untrusted-multi-tenant` too, and is written once.

Versioning is #23. A change to a shipped version is a new version; findings
cite the version they were evaluated against.
