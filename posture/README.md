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
