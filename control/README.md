# Control plane (Go)

Owner: C, with delivery and remediation from D.

Fingerprint handling, the diff engine and its divergence classifier, manifest
parsing, the evaluator, and reporting in JSON and human-readable form (SARIF
is an extension). Go for the container ecosystem libraries.

The diff engine classifies every divergence as architecture-explained,
kernel-version-explained, runtime-class-explained or policy-explained (see
`spec/fingerprint.md`). That classification is the contribution, not a
correction — without it the headline divergence metric is dominated by
architecture, or by what gVisor and Kata do not implement, rather than by
policy.

`BuildReport` combines evaluator findings, classified divergences, and
attribution details. `WriteJSONReport` and `WriteTextReport` render the same
report in machine-readable and human-readable forms. Both include the
authorization notice and the undecidable attribution fraction; its denominator
is all denied probe results, as specified in proposal §11.2. SARIF remains
deferred.
