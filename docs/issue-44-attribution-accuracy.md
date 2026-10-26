# Attribution accuracy against measured single-cause environments

Issue #44 measures attribution against environments in which each denial has
one known cause (§11.2). They are probe runs on cell 2 (Ubuntu 24.04, kernel
7.0.0-1014-gcp, containerd 2.2.1, runc 1.3.4), each from a fresh boot, made
with `deploy/gce/measure.sh`'s ground-truth modes. Every control is off
(UID 0, all capabilities, seccomp and AppArmor unconfined, no masked or
read-only paths) except the one the mode names:

| Environment | Only control in force | Fingerprint |
|---|---|---|
| control | none | `gt-none.json` |
| seccomp | containerd's RuntimeDefault | `gt-seccomp.json` |
| seccomp-hardened | `engine/fixtures/seccomp/hardened.json` as a Localhost profile | `gt-seccomp-hardened.json` |
| apparmor | containerd's RuntimeDefault AppArmor profile, enforcing | `gt-apparmor.json` |
| capability | all capabilities dropped | `gt-capability.json` |
| paths | kubelet's masked and read-only paths | `gt-paths.json` |
| userns | `user.max_user_namespaces=0`, with Ubuntu's `kernel.apparmor_restrict_unprivileged_userns` lifted for the run | `gt-userns.json` |

The control run's eight denials (seven `device.open.*` with ENOENT, nodes the
runtime does not create, and `capability.sys_ptrace` with EFAULT) are the
kernel's own, so those probes are left out of every environment.

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
| seccomp-hardened | 122 | 122 | 0 | 0 |
| apparmor | 3 | 3 | 0 | 0 |
| capability | 23 | 23 | 0 | 0 |
| paths | 12 | 12 | 0 | 0 |
| userns | 4 | 4 | 0 | 0 |
| **Total** | **218** | **218** | **0** | **0** |

Both criteria are met: 100% of attributed denials are correct, and 0% of
denials are undecidable. The two cases §6.1 marks ambiguous are included:
`clone3.args.short` denied with ENOSYS under the hardened profile, and the
AppArmor profile's `deny mount` answering `mount.fs.*` with EACCES.

## What makes these decidable

The oracles alone leave most EPERM undecidable (seccomp or an LSM, seccomp
or a missing capability). The probe now records the seccomp mode and filter
count from `/proc/self/status` (`cell.seccomp`, as §6.1 always specified), and
the attributor rules a candidate out when the cell does: seccomp mode 0
installs no filter, a non-enforcing AppArmor or SELinux label refuses nothing,
and a capability in the effective set is not missing. One survivor is the
attribution, at medium confidence.

That is why these environments, built so that the cell rules out all but one
mechanism, are fully decided. A production cell with several controls in
force is not: the reduced GKE run still reports about a third of its denials
undecidable, and §11.2's undecidable fraction there is a property of the
cell, not of this ground truth.
