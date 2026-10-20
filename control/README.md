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

Remediation closure is measured from the original fingerprints and a new
fingerprint captured after the generated policy has been installed. For each
policy-explained denied/permitted pair, `MeasureRemediationClosure` requires a
known denial mechanism and a re-probe from the previously open cell. A
seccomp-attributed probe is closed when its re-probed verdict is denied or
killed; a permitted re-probe remains open. Missing re-probes remain in the
denominator as unclosed. The re-probe must match the same cell's architecture,
kernel release, runtime, runtime class, distribution, and LSM identity; volatile
MCS labels and module snapshots are ignored. The JSON and text report expose the
seccomp rate with its 100 per
cent target, and rates for LSM, capability and mount attribution without a
success threshold. Unattributed policy divergences are listed separately.
Verification requires the operator to declare `self-managed-node`, following
proposal §§11.2 and 12; managed-cluster measurements cannot satisfy this gate.

`cmd/caliper-remediation-report` runs the complete metric from three
fingerprints and the corpus index:

```sh
cd control
go run ./cmd/caliper-remediation-report \
  -left before-a.json -right before-b.json -reprobe after.json \
  -self-managed-node -format json
```
