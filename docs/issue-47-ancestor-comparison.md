# Issue #47: ancestor-tool comparison

## Scope and method

This comparison uses a target on `caliper-cell2` in `asia-south1-a`.
CALIPER and `amicontained` inspected the same long-lived container. After the
cell was restarted, `seccomp-diff` captured the filter from a fresh BusyBox
container with the same image and CRI security settings. Its OCI image was
BusyBox 1.36.1
(`sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662`).
The CALIPER probe binary came from the committed probe image
`ghcr.io/abhinavmadake/caliper@sha256:9be163f1b987f8563f9d71114d6a025d9335b9627cdafc4676da2b327da3f969`.

The container was created through CRI with the settings from
`deploy/gce/measure.sh`: UID/GID 65534, all capabilities dropped,
`no_new_privs`, read-only root filesystem, RuntimeDefault seccomp, the
containerd AppArmor profile, kubelet's masked and read-only paths, and an
isolated PID namespace. CALIPER ran its probe in that container;
`amicontained` ran there as well; `seccomp-diff` attached from the host to the
container's init process to extract its active seccomp-BPF filter. The
container's filter had default action `SCMP_ACT_ERRNO`; in the captured BPF,
the default return is `ERRNO(1)`. The x86_64 table below was decoded from the
`AUDIT_ARCH_X86_64` branch of the raw filter. The upstream summary's ABI labels
did not preserve that branch correctly, so its mixed-ABI row counts are not
used here.

The cell reported Ubuntu 24.04, kernel `7.0.0-1014-gcp`, containerd 2.2.1,
runc 1.3.4, and enforced AppArmor. The CALIPER result used corpus revision
0.3.2 and contained 185 probe results. This is a same-target comparison for
cell 2, not a six-cell matrix.

## Findings side by side

| Tool | Findings on the shared target | What the output describes |
| --- | --- | --- |
| CALIPER | 107 denied, 53 permitted, and 25 unimplemented probe results | Individual probe outcomes, including argument-level, filesystem, mount, and kernel-dependent behavior. |
| `amicontained` v0.4.9 | Seccomp filtering; 65 blocked syscall names; PID namespace present, user namespace absent; enforced AppArmor profile; empty capability listing; runtime reported as `not-found` | A container summary and coarse blocked-syscall list. The runtime socket was not mounted into the target, so `not-found` does not mean containerd was absent on the host. |
| `seccomp-diff` at `68d4f4571c6f570ecd31c3a9ed614aeb74439d2e` | Across syscall numbers 0–456 in the native x86_64 BPF branch: 297 `ALLOW`, 156 default `ERRNO(1)`, 3 `CONDITION` (`clone`, `personality`, `socket`), 1 explicit `ERRNO(38)` (`clone3`), and 0 `KILL`. | The active x86_64 seccomp-BPF filter, not observed syscall reachability or the effects of other isolation controls. |

The counts have different units and are not scores against one another. CALIPER
reports probe outcomes; `amicontained` reports a coarse syscall list and
container metadata; `seccomp-diff` renders filter decisions. In particular,
the `seccomp-diff` table is not a one-to-one mapping to CALIPER probe IDs and
does not account for capability checks, LSM policy, path masking, mount
visibility, kernel modules, or behavior behind syscall arguments.

## CALIPER findings neither ancestor reports at probe level

- **Path policy:** CALIPER reported masked paths such as
  `path.masked.proc_kcore` (`errno 61`) and read-only paths such as
  `path.readonly.proc_sys` (`errno 30`). Neither comparator reports these
  per-path access outcomes.
- **Mount behavior:** CALIPER reported outcomes for `mount.fs.*`,
  `mount.reach`, and individual `mount.type.*` probes. The two comparators do
  not probe filesystem mount attempts or report per-filesystem reachability.
- **Socket families:** CALIPER reported `socket.family.af_alg` as permitted.
  The re-decoded x86_64 filter marks `socket` as `CONDITION`: it allows family
  values other than 40, including AF_ALG (38). It does not report the
  family-level probe result; `amicontained` does not enumerate socket families
  either.
- **Socket and netlink probes:** CALIPER reported 10 permitted, 5 denied, and
  9 unimplemented `socket.family.*` results, plus 15 permitted and 3
  unimplemented `netlink.protocol.*` results. The ancestor tools do not
  enumerate those family- or protocol-level outcomes.
- **Kernel-dependent unimplemented results:** CALIPER marked nine socket
  families unimplemented (`errno 97`), three netlink protocols unimplemented
  (`errno 93`), nine mount types unimplemented (`errno 19`), and four masked
  paths absent (`errno 2`). These results describe what this kernel exposes on
  this cell. Neither ancestor reports the corresponding probe outcomes.
- **Argument-level behavior:** CALIPER reports individual `clone.flags` and
  `unshare.flags` outcomes. The ancestor outputs do not report those
  per-argument probe results.

The tools still provide useful overlapping evidence: `amicontained` reports
capability and namespace state, and `seccomp-diff` exposes the active filter
that CALIPER's probe results alone do not explain. Their outputs are therefore
complementary, not interchangeable.

## Limits

This run establishes same-target behavior on cell 2 only. It does not establish
that the numerical results generalize to the other five cells. `seccomp-diff`
also requires host privilege to inspect another process, and its syscall table
must not be interpreted as a reachability or whole-container security score.
Raw outputs and the exact commands used to produce them are committed under
`fixtures/ancestors/cell2/`.
