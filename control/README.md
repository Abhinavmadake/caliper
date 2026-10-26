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

Run from `control/` to regenerate the six-cell metric:

```sh
go run ./cmd/caliper-ci-report -cell-fixtures ../fixtures/cells -metrics-out ../fixtures/metrics/finding-metrics.json
```

The command evaluates the six committed GCE fingerprints against the selected
posture and workload. The committed report contains totals and per-cell counts
with probe IDs grouped by family for expectation, claim, and undeclared
exposure findings. It also records the count of distinct cells with expectation
violations and whether the three-cell criterion is met. Cell IDs are derived
from the fingerprint cell identity, excluding kernel modules, and the
fingerprint filename is retained as the source. A test regenerates this report
from `fixtures/cells/` and compares it with the committed file.

Attribution is an optional refinement of the raw reachability measurement.
`Attribute` assigns every result one confidence grade: **high** for a positive
oracle proof, **medium** for an oracle's structural reading without a guaranteed
errno, and **low** for correlation or an unresolved denial. `BuildReport` also
accepts fingerprints without attribution: it retains their reachability verdicts
and reports those denials as unknown and undecidable, rather than inventing a
mechanism. The undecidable fraction is therefore a measured result, not an
assumption that the residual is zero.

Issue #44 measures the attributor against single-cause environments: probe
runs on cell 2 in which one mechanism is the only control in force
(`deploy/gce/measure.sh`'s ground-truth modes), plus a control run with none,
whose denials are the kernel's own and are left out. Regenerate the committed
record with:

```sh
go run ./cmd/caliper-attribution-accuracy \
  -ground-truth ../fixtures/ground-truth/attribution.json \
  -out ../fixtures/metrics/attribution-accuracy.json
```

It reports accuracy over attributed denials and the undecidable fraction over
all denials, overall and per environment.

Issue #46 reports residual state and runtime cost from the runs in
`fixtures/runtime/` (`docs/issue-46-residual-runtime.md`):

```sh
go run ./cmd/caliper-residual-metrics -out ../fixtures/metrics/residual-metrics.json
```

`GenerateRemediation` turns posture expectation violations into the smallest
available seccomp policy. Its primary output is an SPO `SeccompProfile` custom
resource, which the Security Profiles Operator distributes to nodes; it also
renders an OCI Localhost profile. The generator takes the target runtime's
actual RuntimeDefault profile as input, retains its default action and
allowlist, then adds only the measured closure rules.
Socket families, netlink protocols, and clone/unshare flags use seccomp-BPF
argument comparisons. A pathname, device, mount type, or other pointer-backed
datum is reported as not closable instead of emitting an over-broad rule.

`cmd/caliper-remediate` is the file-producing entry point used by deployment:
it accepts an evaluated findings report (or a full CALIPER report), the
runtime's actual default profile, the runtime gate architecture (such as
`amd64`), the output libseccomp architecture (such as `SCMP_ARCH_X86_64`),
the target capabilities and kernel release, then writes both the SPO YAML and
OCI Localhost JSON. Runtime-only `includes` and `excludes` are resolved for
that target before either portable output is rendered.
