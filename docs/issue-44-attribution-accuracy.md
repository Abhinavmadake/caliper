# Attribution accuracy against measured single-cause environments

Issue #44 measures attribution against environments in which each denial has
one known cause (§11.2). They are probe runs on cell 2 (Ubuntu 24.04, kernel
7.0.0-1014-gcp, containerd 2.2.1, runc 1.3.4), each from a fresh boot, made
with `deploy/gce/measure.sh`'s ground-truth modes. Every control is off
(UID 0, all capabilities, seccomp and AppArmor unconfined, no masked or
read-only paths) except the one the mode names. The capability environment
runs as UID 65534, so its probes reach their own capability checks rather than
a root-owned file's permissions:

| Environment | Only control in force | Fingerprint |
|---|---|---|
| control | none | `gt-none.json` |
| seccomp | containerd's RuntimeDefault | `gt-seccomp.json` |
| seccomp-hardened | `engine/fixtures/seccomp/hardened.json` as a Localhost profile | `gt-seccomp-hardened.json` |
| apparmor | containerd's RuntimeDefault AppArmor profile, enforcing | `gt-apparmor.json` |
| capability | all capabilities dropped, UID 65534, Ubuntu's AppArmor user-namespace restriction lifted | `gt-capability.json` |
| paths | kubelet's masked and read-only paths | `gt-paths.json` |
| userns | `user.max_user_namespaces=0`, with Ubuntu's `kernel.apparmor_restrict_unprivileged_userns` lifted for the run | `gt-userns.json` |

The control run's eight denials (seven `device.open.*` with ENOENT, nodes the
runtime does not create, and `capability.sys_ptrace` with EFAULT, its capable
path) are the kernel's own, so the same probe denied with the same errno is
left out of every environment.

```sh
cells.sh measure cell2 <image> "" <mode>
cells.sh measure cell2 <image> engine/fixtures/seccomp/hardened.json seccomp
```

The raw output is completed with `caliper-complete` as the six cells are. The
fingerprints, and the environment list in
[`fixtures/ground-truth/attribution.json`](../fixtures/ground-truth/attribution.json),
are committed; the metric is regenerated from them by
`control/cmd/caliper-attribution-accuracy` and checked against
[`fixtures/metrics/attribution-accuracy.json`](../fixtures/metrics/attribution-accuracy.json)
by its test.

## Result

| Environment | Denials | Correct | Incorrect | Undecidable |
|---|---:|---:|---:|---:|
| seccomp | 54 | 54 | 0 | 0 |
| seccomp-hardened | 123 | 123 | 0 | 0 |
| apparmor | 3 | 3 | 0 | 0 |
| capability | 27 | 24 | 0 | 3 |
| paths | 12 | 12 | 0 | 0 |
| userns | 4 | 4 | 0 | 0 |
| **Total** | **223** | **220** | **0** | **3** |

Both criteria are met: 100% of attributed denials are correct, and 1.3% of
denials are undecidable. The two cases §6.1 marks ambiguous are included:
`clone3.args.short` denied with ENOSYS under the hardened profile, and the
AppArmor profile's `deny mount` answering `mount.fs.*` with EACCES. The three
undecidable denials are in the capability environment:
`capability.sys_nice`'s EACCES without CAP_DAC_OVERRIDE, which a
file-permission check could also have produced, and the EPERM of
`capability.sys_ptrace` and `capability.sys_rawio`, which Yama and lockdown
can also return whatever the major LSM's label says.

With the oracle and correlations alone, without the cell elimination below,
140 of the 223 denials are attributed correctly and 83 are undecidable. The
cell decides 80 of those 83, all EPERM or EACCES, and these environments are
built so that it can.

## What makes these decidable

The oracles alone leave most EPERM undecidable (seccomp or an LSM, seccomp
or a missing capability). The probe now records the seccomp mode and filter
count from `/proc/self/status` (`cell.seccomp`, as §6.1 always specified), and
the attributor rules a candidate out when the cell does: seccomp mode 0
installs no filter, a non-enforcing AppArmor or SELinux label refuses nothing
(except through Yama or lockdown, which have no label, so a ptrace or raw-I/O
denial keeps the LSM),
and a capability in the effective set is not missing. One survivor is the
attribution, at medium confidence.

A held capability counts only in the initial user namespace, which the probe
also records (`user_namespaces.initial`, from `/proc/self/uid_map`): under
`hostUsers: false` it need not hold against the node's objects. An EACCES on a
capability-gated call is decided only when CAP_DAC_OVERRIDE is held, since
otherwise a file-permission check, which is not one of the mechanisms the
attributor names, could have answered it.

That is why these environments, built so that the cell rules out all but one
mechanism, are fully decided. A production cell with several controls in
force is not: the reduced GKE run still reports about a third of its denials
undecidable, and §11.2's undecidable fraction there is a property of the
cell, not of this ground truth.
