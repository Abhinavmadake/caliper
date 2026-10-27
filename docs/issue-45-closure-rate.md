# Remediation closure rate

Issue #45 reports the §11.2 closure rate: every seccomp-attributed divergence
closed, divergences attributed to other mechanisms reported without a
threshold, every closure verified by re-probing, on self-managed nodes.

The runs are in `fixtures/pipeline/`, one directory per cell. Each comes from
`deploy/gce/run-pipeline.sh <cell>` with `CALIPER_POSTURE_TIER=untrusted-multi-tenant`:

1. Measure the full corpus under RuntimeDefault from a fresh boot, and capture
   the RuntimeDefault containerd applied (`containerd-runtime-default.json`).
2. Evaluate the fingerprint against `posture/v1` and generate a profile from
   that RuntimeDefault and the expectation violations (`pipeline/`).
3. Measure again from a fresh boot under the generated Localhost profile
   (`<cell>-remediated.json`).

The six cells are Compute Engine VMs, which are self-managed nodes (§12).
Cells 5 and 6 also run under a second handler that applies the OCI seccomp
profile inside the sandbox (`CALIPER_HANDLER=runsc-seccomp` and
`kata-seccomp`, in `cell5-runsc-seccomp/` and `cell6-kata-seccomp/`). Their
default handlers are what an operator gets without changing the runtime. The
tier is `untrusted-multi-tenant`, which includes every `restricted` assertion;
at `restricted`, cells 1 to 3 have nothing to close. The amd64 cells use the
published image pinned in `cells.sh`; cell 1 uses a local arm64 build of
`85af88a`, whose ID is in `cell1.packages`.

```sh
cd control && go run ./cmd/caliper-closure-metrics -out ../fixtures/metrics/closure-metrics.json
```

The test regenerates the metric from `fixtures/pipeline/` and compares it with
the committed file.

## What is counted

A finding is an expectation violation at the baseline. It is closed when its
probe is denied or killed in the re-probe; the generator's own verdict is not
counted. It is seccomp-attributed when the generator writes a seccomp-BPF rule
for it and the cell enforces seccomp (mode 2 at the baseline). Every other
finding is reported under `other`, with the reason.

## Results

| Cell | Seccomp enforced | Findings | Seccomp closed | Other closed |
|---|---|---:|---:|---:|
| cell1 (arm64) | yes | 5 | 5 of 5 | |
| cell2 | yes | 5 | 5 of 5 | |
| cell3 (SELinux) | yes | 4 | 4 of 4 | |
| cell4 (containerd 1.7) | yes | 58 | 58 of 58 | |
| cell5 (gVisor, `runsc`) | no | 3 | | 0 of 3 |
| cell5 (gVisor, `runsc-seccomp`) | yes | 1 | | 0 of 1 |
| cell6 (Kata, `kata`) | no | 59 | | 0 of 59 |
| cell6 (Kata, `kata-seccomp`) | yes | 3 | 3 of 3 | |
| all | | 138 | 75 of 75 | 0 of 63 |

All 75 seccomp-attributed findings are closed. The 100 per cent covers the
runs whose runtime applies seccomp: cells 1 to 4 and the two seccomp handlers.
On cells 1 to 3 the findings are AF_ALG and the crypto, netfilter, rdma and
xfrm netlink protocols (cell 3 has no rdma finding). Cell 4 adds 53 io_uring
probes, since containerd 1.7's RuntimeDefault allows io_uring; one rule
denying `io_uring_setup`, `io_uring_enter` and `io_uring_register` closes them
all. Under `kata-seccomp` they are AF_ALG, netfilter and xfrm.

The 75 findings take six distinct rules. The generator's user-namespace and
capability rules are not exercised: no cell that applies seccomp permits those
probes.

## Seccomp-attributed, not enforced by the runtime

Under their default handlers gVisor and Kata run the workload with seccomp
mode 0, so neither RuntimeDefault nor a generated profile reaches it. None of
their 62 findings is closed, and all are counted under `other`.

- 57 are already denied by RuntimeDefault: the io_uring probes on Kata, and
  `clone.flags.newuser` and `unshare.flags.newuser` on both. Cells 1 to 3
  deny the same probes. The generator has no allow rule to narrow and reports
  them as not closable.
- AF_ALG, netfilter and xfrm on Kata get rules, and the re-probe shows them
  still permitted (`unenforced` in `verification.json`).
- `device.open.fuse` on gVisor and `mount.reach` on Kata take a pathname or a
  filesystem type, which seccomp-BPF cannot inspect.

## With the runtime applying seccomp

`runsc-seccomp` sets runsc's `oci-seccomp` through the shim's config file, and
`kata-seccomp` points the shim at a copy of Kata's configuration with
`disable_guest_seccomp = false`. Under both, the baseline reports seccomp mode
2 and RuntimeDefault takes effect.

- gVisor: the two user-namespace probes are denied at the baseline. What is
  left is `device.open.fuse`, which no seccomp rule can close (0 of 1, other).
- Kata: io_uring, the user-namespace probes and `mount.reach` are denied at
  the baseline, and the generated profile closes the other three (3 of 3).

The SPO step was skipped (no kubectl on the machine that ran this). Cell 2's
`remediation.spo.yaml` is unchanged from the one SPO installed on 2026-10-24
(`pipeline/remediation.spo.accepted.json`); the other cells' SPO forms were
not installed.
