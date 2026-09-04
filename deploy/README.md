# Delivery and evaluation harness

Owner: D. Also the integrator, responsible for the components composing
correctly.

- Kubernetes `Job` (single-node measurement) and `DaemonSet` (every node)
  manifests. Unprivileged, no added capabilities, `RuntimeDefault`.
- Environment-matrix bring-up for the six required cells in proposal §11.1,
  with runtime versions pinned (containerd 1.7.12 held for cell 4; 2.2 for the
  rest). Disposable VMs with snapshot rollback.
- CI workflow definitions under `.github/workflows/`, and the reduced CI corpus
  (under 5 seconds).
- The remediation generator itself is Go and lives in `control/`; closure
  verification by re-probing is driven from here.

The cells need an amd64 host with hardware virtualisation: the Kata cell
requires it outright, and the other amd64 cells run on an arm64 laptop only
under emulation. Confirming that machine is the first D task (week 1).
