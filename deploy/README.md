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

The cells need an amd64 host with hardware virtualisation: the Kata cell
requires it outright, and the other amd64 cells run on an arm64 laptop only
under emulation. Confirming that machine is the first D task (week 1).

## Bringing up cells 2 and 4

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
limactl start --name caliper-cell2 deploy/cell2-baseline.yaml
limactl start --name caliper-cell4 deploy/cell4-unpatched.yaml

# Snapshot the clean, provisioned state before running anything
limactl snapshot create caliper-cell2 --tag clean
limactl snapshot create caliper-cell4 --tag clean

# Roll back after a run
limactl snapshot apply caliper-cell2 --tag clean
limactl snapshot apply caliper-cell4 --tag clean

# Throw the whole thing away
limactl delete --force caliper-cell2
```

### Build-and-import flow

The cells have no Docker, so the probe must enter through containerd itself. Build once on the amd64 host, then import the tarball into each cell.

```bash
# on the amd64 host, from ~/caliper
docker build -t caliper-probe engine/
docker save caliper-probe | limactl shell caliper-cell2 -- sudo ctr images import -
docker save caliper-probe | limactl shell caliper-cell4 -- sudo ctr images import -

# Verify execution without triggering probes (probes are deferred to #8/#10)
limactl shell caliper-cell2 -- sudo ctr run --rm --seccomp docker.io/library/caliper-probe:latest probe --noop
limactl shell caliper-cell4 -- sudo ctr run --rm --seccomp docker.io/library/caliper-probe:latest probe --noop
```

