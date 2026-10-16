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
attribution details. Each fingerprint is labeled by input position and the
first 12 hex digits of its digest; its cell fields remain available as detail.
`WriteJSONReport` and `WriteTextReport` render the same report in
machine-readable and human-readable forms. Both include the
authorization notice and the undecidable attribution fraction; its denominator
is all denials, including SIGSYS-killed results, as specified in proposal §11.2.
SARIF remains deferred.

Attribution is an optional refinement of the raw reachability measurement.
`Attribute` assigns every result one confidence grade: **high** for a positive
oracle proof, **medium** for an oracle's structural reading without a guaranteed
errno, and **low** for correlation or an unresolved denial. `BuildReport` also
accepts fingerprints without attribution: it retains their reachability verdicts
and reports those denials as unknown and undecidable, rather than inventing a
mechanism. The undecidable fraction is therefore a measured result, not an
assumption that the residual is zero.
