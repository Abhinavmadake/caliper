# Control plane (Go)

Owner: C, with delivery and remediation from D.

Fingerprint handling, the diff engine and its divergence classifier, manifest
parsing, the evaluator, and reporting in JSON and human-readable form (SARIF
is an extension). Go for the container ecosystem libraries.

The diff engine classifies every divergence as architecture-explained,
kernel-version-explained or policy-explained. That classification is the
contribution, not a correction — without it the headline divergence metric is
dominated by architecture rather than by policy.
