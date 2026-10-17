# Delivery and evaluation harness

Owner: D. Also the integrator, responsible for the components composing
correctly.

- Kubernetes `Job` (single-node measurement) and `DaemonSet` (every node)
  manifests. Unprivileged, no added capabilities, `RuntimeDefault`.
- Environment-matrix bring-up for the six required cells, with runtime versions
  pinned, as disposable Compute Engine VMs rebuilt from pinned images.

## The six required cells

Reproduced from proposal §11.1 so it does not have to be read out of the PDF.
**Cell 2 is the baseline**; every other cell moves as few axes as possible
relative to it, so a divergence is attributable to one thing.

| # | Arch | Distribution | Runtime | RuntimeClass | LSM | Moves vs cell 2 |
|---|------|--------------|---------|--------------|-----|-----------------|
| 1 | arm64 | Ubuntu 24.04 | containerd 2.2 + runc | runc | AppArmor | architecture (+ kernel build) |
| 2 | amd64 | Ubuntu 24.04 | containerd 2.2 + runc | runc | AppArmor | — baseline |
| 3 | amd64 | Rocky Linux 9 | containerd 2.2 + runc | runc | SELinux | LSM (+ distribution) |
| 4 | amd64 | Ubuntu 24.04 | containerd **1.7.12** + runc | runc | AppArmor | runtime version |
| 5 | amd64 | Ubuntu 24.04 | containerd 2.2 | **gVisor** | AppArmor | RuntimeClass |
| 6 | amd64 | Ubuntu 24.04 | containerd 2.2 | **Kata** | AppArmor | RuntimeClass |

Cells 4, 5 and 6 each move exactly one axis. Cells 1 and 3 move two, because no
distribution builds an identical kernel for both architectures and SELinux is
not a supported Ubuntu configuration — divergence in those two is attributed to
architecture or to policy only after the kernel-version class has been excluded
probe by probe.

**Why the containerd versions are pinned rather than left to the host's patch
state:** Ubuntu 24.04 ships 1.7.12 in its release pocket and 2.2 in updates, and
the io_uring deny entered the default seccomp profile in 2.0. So an unpatched and
a patched host of the *same release* sit on either side of the change. Cell 4 also
carries the AF_ALG reproduction, whose `RuntimeDefault` profile must predate any
AF_ALG deny.

**Counting rule:** kind, minikube and k3s on one host are **one** cell, not
three — all three are containerd on the same kernel. Docker Desktop and Colima
on macOS would be two, since they run different guest kernels; neither is used,
and every cell here is a Compute Engine VM.

**Three further cells** are additions, attempted only if the schedule permits:
amd64 Podman + crun, and amd64 Moby, both on the AppArmor host (moving the
runtime axis rather than only its version); a managed cluster (EKS on AL2023 or
GKE on COS); and Talos, the platform the motivating result was published on.
- CI workflow definitions under `.github/workflows/`, and the reduced CI corpus
  (under 5 seconds).
- The remediation generator itself is Go and lives in `control/`; closure
  verification by re-probing is driven from here.

## Pull request target-cluster evaluation

`.github/workflows/cluster-evaluation.yml` runs the reduced corpus on a named
Kubernetes context and posts that cell's evaluation to the pull request. It
deliberately does not measure the GitHub runner's container. The workflow
builds the PR's probe image for amd64 only and runs the Job under the same
unprivileged security context as `deploy/k8s/job.yaml`. The report evaluates
the fingerprint against `posture/v1` at the `restricted` tier, with
`deploy/k8s/job.yaml` as the workload's manifest, and lists expectation
violations, claim violations, undeclared exposures and attribution confidence.

Configure these repository settings before enabling the workflow:

- Repository variable `CALIPER_TARGET_CONTEXT`: exact kubeconfig context name
  for the cluster to measure.
- Repository secret `CALIPER_KUBECONFIG`: the kubeconfig contents for a
  service account limited to the evaluation namespace.
- Optional repository variable `CALIPER_NAMESPACE`: pre-created namespace for
  measurement Jobs; defaults to `default`.
- Make the published `ghcr.io/<owner>/caliper` package public, or add a
  pull secret to the selected namespace and adapt the Job template for that
  secret.

The service account needs permission to create, read, wait for, read logs
from, and delete Jobs and their pods in the selected namespace. The workflow
skips fork-originated pull requests because they must not receive cluster
credentials. If either cluster setting is missing, it skips cluster evaluation
cleanly with a workflow notice. Its report comment is updated in place on later
pushes to the same pull request. The Go reporter uses
`control.DecodeFingerprint` and `go-github` for GitHub API calls.

The target configured for this repository is a GKE zonal cluster on
Container-Optimized OS (context `gke-caliper-ci`, namespace `caliper-ci`,
which enforces the `restricted` Pod Security level).

The local CI job separately enforces the proposal's under-five-second
measurement budget with `scripts/check-reduced-runtime.sh` against the release
binary. Kubernetes scheduling and image-pull time are outside that
measurement budget.

## Bringing up the cells

Each cell is a Compute Engine VM in project `caliper-ci`, built from a pinned
image by `deploy/gce/cells.sh` and the cell's script in `deploy/gce/provision/`.
Compute Engine supplies what a laptop could not: native amd64, and nested
virtualisation for the Kata cell. Cells 2, 4, 5 and 6 boot the same image, so
against cell 2 only the runtime moves.

| Cell | Machine | Image | Runtime |
|---|---|---|---|
| 1 | `c4a-standard-2` (arm64) | `ubuntu-2404-noble-arm64-v20261016` | containerd `2.2.1-0ubuntu1~24.04.3`, runc `1.3.4-0ubuntu1~24.04.1` |
| 2 | `e2-standard-2` | `ubuntu-2404-noble-amd64-v20261016` | containerd `2.2.1-0ubuntu1~24.04.3`, runc `1.3.4-0ubuntu1~24.04.1` |
| 3 | `e2-standard-2` | `rocky-linux-9-v20261015` | `containerd.io-2.2.1-1.el9` (Docker repository), SELinux enforcing |
| 4 | `e2-standard-2` | `ubuntu-2404-noble-amd64-v20261016` | containerd `1.7.12-0ubuntu4`, runc `1.1.12-0ubuntu3` (release pocket) |
| 5 | `e2-standard-2` | as cell 2 | as cell 2, plus gVisor `release-20261005.0` as handler `runsc` |
| 6 | `n2-standard-2`, nested virtualisation | as cell 2 | as cell 2, plus Kata `3.14.0` as handler `kata` |

Provisioning fails unless the containerd on `PATH`, the running daemon and runc
are the pinned versions (#90), and unless the cell's handler is registered.
Ubuntu cells read the archive through the snapshot `20261016T120000Z`, so a cell
rebuilt later gets the same packages; the kernel, AppArmor, libseccomp and the
runtime are held, unattended upgrades are off, and cell 3 version-locks its
runtime, policy and kernel. Every download is checked against a pinned hash.
The packages that define a cell are recorded in `/etc/caliper/packages`
(`cells.sh packages <cell>`). The cells mount nothing from the host.

```bash
deploy/gce/cells.sh create  cell2              # VM, then provisioning
deploy/gce/cells.sh measure cell2 > cell2.raw  # reboot, full corpus, probe output on stdout
deploy/gce/cells.sh stop    cell2              # always: a running VM is billed
deploy/gce/cells.sh start   cell2              # later runs
deploy/gce/cells.sh delete  cell2              # rollback: delete, then create again
```

`measure` reboots the cell first, so modules an earlier run autoloaded are not
recorded as the node's, then runs `deploy/gce/measure.sh` on it. That builds
the pod the way the kubelet builds `deploy/k8s/job.yaml`'s and runs it through
containerd's CRI with `crictl`: its own network and PID namespaces, the
kubelet's default masked and read-only paths, RuntimeDefault seccomp, the
AppArmor default where AppArmor is on, SELinux labelling and a relabelled
`/tmp` where it is enforcing, uid 65534, all capabilities dropped, no new
privileges and a read-only root filesystem. Cells 5 and 6 pass the RuntimeClass
handler to the sandbox. It fails if the probe fails or does not finish, and
prints the cell's packages and what containerd applied to stderr.

The amd64 cells pull the probe image published by the cluster-evaluation
workflow, pinned by digest in `cells.sh`. That image is amd64 only, so cell 1
takes an arm64 build:

```bash
docker build -t caliper-probe:arm64-<commit> engine/   # on an arm64 machine
docker save caliper-probe:arm64-<commit> -o caliper-probe-arm64.tar
deploy/gce/cells.sh load cell1 caliper-probe-arm64.tar
deploy/gce/cells.sh measure cell1 docker.io/library/caliper-probe:arm64-<commit> > cell1.raw
```

The probe cannot see the distribution, runtime or RuntimeClass, so the raw
output is completed with them as operator-sourced facts, and digested, by
`control/cmd/caliper-complete`. `-runtime-class` is the RuntimeClass handler,
as the Kubernetes path records it, and `-node-kernel` the cell's own `kernel`
line from `cells.sh packages`, which sets `sandbox_claimed` for cells 5 and 6.

```bash
cd control && go run ./cmd/caliper-complete -distribution "Ubuntu 24.04" \
    -runtime containerd -runtime-version 2.2.1 -runtime-class runc \
    -node-kernel 7.0.0-1014-gcp < ../cell2.raw > ../fixtures/cells/cell2.json
```

`fixtures/cells/` holds a full-corpus recording of every cell, each from a
fresh boot, completed with handler `runc` for cells 1 to 4, `runsc` for cell 5
and `kata` for cell 6. Beside each, `cellN.packages` records the probe image
(the amd64 digest, or the arm64 build's image ID, both from `c85897b`), the
cell's packages, and what containerd applied.
