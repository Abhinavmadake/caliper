# Issue #28 validation record

This record captures the end-to-end format and comparison checks for the
week-9 fingerprint freeze. The WSL result is a Linux container measurement;
WSL does not expose AppArmor or hardware virtualization in this setup.

## Format and control-plane path

- The fingerprint contract is frozen at format version 1. Changes to
  established fields, types, meanings, requiredness, or enum spellings require
  a new format version. Optional additive fields and enum values remain
  compatible.
- The Rust engine built for `x86_64-unknown-linux-musl` in WSL. Its reduced
  probe set ran in containerd with seccomp enabled and UID/GID 65534.
- The emitted measurement decoded as a Go `ProbeMeasurement`, was completed
  with operator metadata, and passed through fingerprint digest generation,
  diffing, and classification.

## Environment diff

The live WSL fingerprint was compared with the committed
`x86_64-apparmor.json` recording (Ubuntu 24.04, kernel 6.8.0-142, Docker
29.1.3). The live environment was Ubuntu 24.04.3 under WSL2, kernel
6.6.87.2-microsoft-standard-WSL2, containerd 2.2.1, and runc 1.3.4. It
reported `lsm=none`; WSL's generic `kernel` attribute label is not an SELinux
context or an AppArmor profile.

The Go control plane compared corpus revisions 0.2.0 and 0.1.0: 30 probes
were shared, with no corpus-set skew among them; 28 probes were unmeasured in
the live reduced run. It reported 6 divergences, all classified as policy,
and none as kernel, runtime-class, or architecture differences. The corpus
revision mismatch means this is a useful live cross-environment check, not a
same-revision benchmark.

## Ancestor-tool comparison

Both checks used WSL targets launched by containerd with the default seccomp
filter and UID/GID 65534. `amicontained` ran inside its target container;
`seccomp-diff` inspected a running BusyBox target from the WSL host:

- `seccomp-diff` listed the live BusyBox process and disassembled its active
  seccomp-BPF filter.
- `amicontained` v0.4.9 reported seccomp filtering and 64 blocked syscalls.
  It identified the WSL generic `kernel` label as an AppArmor profile, while
  CALIPER records the LSM as none. It also reported the runtime as
  `not-found` in this containerd setup.

These are first-run comparator checks under the same kernel and container
isolation settings. They do not constitute the full identical-workload study
planned for week 15.
