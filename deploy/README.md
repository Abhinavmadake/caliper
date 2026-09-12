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
