# AF_ALG RuntimeDefault demonstration

Issue #43's workload is [the standard CALIPER probe Job](../deploy/k8s/af-alg-demonstration.yaml).
It is admitted by a PSS Restricted namespace, runs as a non-root UID with all
capabilities dropped, and requests `RuntimeDefault`. It uses the ordinary
`caliper-probe` image and has neither an AF_ALG-specific image nor a bespoke
seccomp profile.

The evaluator is deliberately run at the `untrusted-multi-tenant` reference
posture tier. That tier is stronger than PSS Restricted; PSS itself makes no
AF_ALG assertion. A permitted `socket.family.af_alg` result is therefore an
**expectation violation**, not a manifest claim violation. The finding carries
the assertion's evidence, including `CVE-2026-31431`, from `posture/v1`. At
the `restricted` tier, which CI uses, the same result is an undeclared
exposure.

## Results

| Recording | Runtime | AF_ALG | Finding |
|---|---|---|---|
| [`cells/cell2.json`](../fixtures/cells/cell2.json) | containerd 2.2.1 | permitted | expectation violation |
| [`cells/cell4.json`](../fixtures/cells/cell4.json) | containerd 1.7.12 | permitted | expectation violation |
| [`gke-cos-containerd-2.2.7.json`](../fixtures/gke-cos-containerd-2.2.7.json) | containerd 2.2.7 | denied (EPERM) | none |

containerd added an AF_ALG deny to its RuntimeDefault seccomp profile in
May 2026 (containerd#13327), released in 2.2.4 and backported to 1.7.32.
Cell 4's 1.7.12 and cell 2's 2.2.1 both predate it, so both permit AF_ALG,
matching the published result that containerd's RuntimeDefault did not block
it. The GKE node runs 2.2.7, which carries the deny. The same admitted
manifest is exposed on one node and not on the other, and neither manifest
records the difference.

The cell recordings come from the CRI path on the GCE cells
(`deploy/gce/cells.sh measure`). The GKE recording is this manifest applied
to the `caliper-ci` cluster (COS, kernel 6.12.105+), where the namespace's
`restricted` enforcement admitted the pod. It was measured with the probe
image built from `1333578b`, whose engine is identical to this commit's, and
completed with `caliper-complete`.

## algif_aead

Copy Fail is in `algif_aead`, so exploitability depends on that module. The
engine records the loaded module set before any probe runs, as
`cell.kernel.modules`. `algif_aead` is absent from that snapshot on every
recording above.

The probe only calls `socket(AF_ALG, ...)`. It never binds an `aead`
algorithm, so it does not load `algif_aead`, and the recordings do not
measure whether that module can be autoloaded. They do show that autoload is
permitted for the family: on cells 2 and 4 `af_alg` was absent before the run
and loaded by it. Each expectation finding carries this state for its probe's
kernel-dependency module, and both reports print it:

```
af_alg: not loaded before run, loaded by run
```

`control/cmd/caliper-ci-report`'s AF_ALG tests check all three recordings,
the module state, and that the demonstration Job spec stays identical to
`deploy/k8s/job.yaml`.
