# Delivery and evaluation harness

Owner: D. Also the integrator, responsible for the components composing
correctly.

- Kubernetes `Job` (single-node measurement) and `DaemonSet` (every node)
  manifests. Unprivileged, no added capabilities, `RuntimeDefault`.
- Environment-matrix bring-up for the six required cells, with runtime versions
  pinned. Disposable VMs with snapshot rollback.

## The six required cells

Reproduced from proposal §11.1 so it does not have to be read out of the PDF.
**Cell 2 is the baseline**; every other cell moves as few axes as possible
relative to it, so a divergence is attributable to one thing.

| # | Arch | Distribution | Runtime | RuntimeClass | LSM | Moves vs cell 2 |
|---|------|--------------|---------|--------------|-----|-----------------|
| 1 | arm64 | Ubuntu 24.04 under Lima | containerd 2.2 + runc | runc | AppArmor | architecture (+ kernel build) |
| 2 | amd64 | Ubuntu 24.04 | containerd 2.2 + runc | runc | AppArmor | — baseline |
| 3 | amd64 | Fedora or Rocky | containerd 2.2 + runc | runc | SELinux | LSM (+ distribution) |
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
and cell 1 names its guest explicitly.

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

The cells need an amd64 host with hardware virtualisation: the Kata cell
requires it outright, and the other amd64 cells run on an arm64 laptop only
under emulation. Confirming that machine is the first D task (week 1).

## Bringing up the cells

The environment is automated using Lima virtual machines to ensure repeatability across the six required cells. Cells 2 and 4 represent the baseline and the unpatched runtime version, while cells 1, 3, 5, and 6 cover architecture, LSM, and RuntimeClass changes.

Cells 2 and 4 are the same distribution (Ubuntu 24.04) on either side of one change: the release pocket ships containerd 1.7.12, and the updates pocket ships 2.2.1. This demonstrates the change in default confinement.

### Exact package versions

| Pocket | `containerd` | `runc` | Cell |
|---|---|---|---|
| noble (release) | `1.7.12-0ubuntu4` | `1.1.12-0ubuntu3` | 4 |
| noble-updates | `2.2.1-0ubuntu1~24.04.3` | `1.3.4-0ubuntu1~24.04.1` | 2 |

> **runc version decision:** Cell 4 represents the unpatched release pocket host, moving runc 1.1→1.3 alongside containerd 1.7→2.2. This aligns with the "runtime version" axis in proposal §11.1 which treats an unpatched host as one thing.

### Snapshot commands

```bash
# Bring up a cell (the yaml provisions it fully on first start)
for cell in cell1-arm64 cell2-baseline cell3-selinux cell4-unpatched cell5-gvisor cell6-kata; do
  limactl start --name caliper-${cell%%-*} deploy/${cell}.yaml
  limactl snapshot create caliper-${cell%%-*} --tag clean
done

# Roll back after a run
for cell in cell1 cell2 cell3 cell4 cell5 cell6; do
  limactl snapshot apply caliper-${cell} --tag clean
done

# Throw the whole thing away
for cell in cell1 cell2 cell3 cell4 cell5 cell6; do
  limactl delete --force caliper-${cell}
done
```

### Build-and-import flow

The cells have no Docker, so the probe must enter through containerd itself. Build once on the amd64 host, then import the tarball into each cell.

```bash
# on the amd64 host, from ~/caliper
docker build -t caliper-probe engine/

# Import into each cell
for cell in cell1 cell2 cell3 cell4 cell5 cell6; do
  docker save caliper-probe | limactl shell caliper-${cell} -- sudo ctr images import -
done

# Verify execution without triggering probes
for cell in cell1 cell2 cell3 cell4 cell5 cell6; do
  runtime=""
  if [ "$cell" = "cell5" ]; then runtime="--runtime io.containerd.runsc.v1"; fi
  if [ "$cell" = "cell6" ]; then runtime="--runtime io.containerd.kata.v2"; fi
  limactl shell caliper-${cell} -- sudo ctr run --rm --seccomp $runtime docker.io/library/caliper-probe:latest probe --noop
done
```

