# Corpus safety review

Issue #50 asks for confirmation that the corpus contains no exploit code and
no operation whose success confers privilege (proposal §7, §13). This review
covers the 185 committed probes of corpus revision 0.3.3, read from
`engine/crates/corpus/src/`. Deferred probes have no implementation and are
never run.

Every probe runs in a forked child (spec/probe.md), so whatever a probe
obtains ends with the child. Objects that outlive it are measured by the
residual snapshot (#46).

## By family

| Family | Probes | What the probe does |
|---|---:|---|
| socket | 24 | `socket(family, type, 0)` and nothing else: no bind, connect or send. AF_ALG is opened, never bound to an algorithm, so `algif_aead` is not reached. |
| netlink | 18 | `socket(AF_NETLINK, SOCK_RAW, protocol)` and nothing else: no message is sent. |
| io_uring | 53 | `io_uring_setup` with zero entries (EINVAL), `io_uring_register(INT_MAX, ...)` (EBADF), and `IORING_REGISTER_PROBE` on a one-entry ring to enumerate opcodes. No submission queue entry is ever submitted. |
| mount | 38 | 34 read `/proc/filesystems`. `mount.reach` mounts onto a path that does not exist (ENOENT). `mount.fs.*` mount proc or overlay on the run's own directory under `/tmp` and unmount at once; fuse fails with EINVAL before anything is mounted. |
| clone | 19 | `clone`/`unshare` with one namespace flag; the new task or namespace is discarded at once (the clone child calls `exit_group`). `clone3` with a short size (EINVAL). |
| path | 17 | `openat(O_PATH)` and `fstatfs`: no read or write of the object. |
| device | 8 | `openat(O_RDONLY \| O_NONBLOCK \| O_NOCTTY)` and close; nothing is read or written. |
| capability | 8 | one capability-gated call each; see below. |

No probe contains a payload, shellcode, a crafted structure for a known
vulnerability, or a sequence beyond the single call under test.

## Where success can grant something

A probe measures whether a call is reachable, so where the cell permits it,
the call succeeds. For most probes success yields nothing usable: the call is
built to fail after the check under test, with the error the oracle
guarantees (`capability.sys_boot` EINVAL, `sys_module` EBADF, `sys_ptrace`
EFAULT, `mount.reach` ENOENT, `mount.fs.fuse` EINVAL), or it changes nothing
(`sys_time` is `settimeofday(NULL, NULL)`; `mknod` creates a `/dev/null` node,
`makedev(1, 3)`, and unlinks it).

Five succeed in a way that does hand the child something, and none uses it:

| Probe | On success the child holds | Then |
|---|---|---|
| `capability.sys_rawio` | I/O privilege level 3 (`iopl(3)`), x86 only | exits without any port I/O |
| `capability.sys_nice` | a nice value one lower (`setpriority(..., -1)`) on itself | exits |
| `capability.net_bind_service` | a socket bound to TCP port 1 in its network namespace | exits without `listen` |
| `device.open.*` | a read-only descriptor, for example on `/dev/mem` | closes it without reading |
| `clone.*` / `unshare.*` with a user namespace | capabilities inside the new, empty user namespace | exits |

Each grant is the capability or permission the cell already gave the
workload: the probe shows that it is reachable and does not use it.
`sys_rawio` is the strongest, and the only one that raises a hardware
privilege. If that is judged to be over the line, the alternative is to drop
it to the deferred set, which loses the CAP_SYS_RAWIO measurement.

## Conclusion

No exploit code. No probe uses what a successful call grants, and every grant
ends with the probe's child. The five cases above are listed so that the
claim "no operation whose success confers privilege" is read with them in
view rather than as an absolute.
