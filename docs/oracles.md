# Oracle Argument Sets Design

This document records the errno-oracle design and the cross-family review for
the frozen corpus. Every committed probe has a non-empty oracle; the complete
id/guarantee/isolation/absence sweep is in [`oracle-sweep.md`](oracle-sweep.md).

## ENOSYS Handling Agreement

As agreed by all members and documented in `spec/probe.md`, the `ENOSYS` error returned from a syscall that the cell's kernel is known to implement is treated as **ambiguous** (i.e., a filter) rather than as `unimplemented`.

## 1. Socket Address Families (`AF_*`)

- **Probed Syscall:** `socket(family, type, protocol)`
- **Oracle Argument Set:** `socket(AF_TARGET, -1, 0)`
  - We use the targeted address family (`AF_TARGET`) to ensure any family-specific filtering triggers.
  - We pass a deliberately invalid `type` (`-1`) to structurally guarantee `EINVAL`.
- **Hook Ordering:** In `net/socket.c`, `__sys_socket_create` returns `EINVAL` for a bad type before `sock_create`, and `__sock_create` range-checks the type again before `security_socket_create`. Thus, `type = -1` never reaches the LSM hook or the family lookup.
- **What it proves:** 
  - If the probe returns `EPERM` instead of `EINVAL`, it definitively **isolates seccomp** (like the `EBADF` oracle).
  - An `EINVAL` says nothing about whether AppArmor or SELinux permit the family, because the invalid type is caught before the LSM hook. (This is why `spec/probe.md` uses an `EAFNOSUPPORT` oracle for sockets, which is produced after the hook).

## 2. Netlink Protocol Numbers (`NETLINK_*`)

- **Probed Syscall:** `socket(AF_NETLINK, SOCK_RAW, NETLINK_TARGET)`
- **Oracle Argument Set:** `socket(AF_NETLINK, -1, NETLINK_TARGET)`
  - We probe the specific `NETLINK_TARGET` protocol.
  - Similar to address families, passing an invalid `type` (`-1`) structurally guarantees `EINVAL`.
- **Hook Ordering:** Like other `socket(2)` calls, the invalid `type = -1` causes an `EINVAL` return before reaching the LSM hook (`security_socket_create`) or the family lookup. (By contrast, the netlink protocol check in `netlink_create`, which produces `EPROTONOSUPPORT`, happens *after* both the hook and the family lookup).
- **What it proves:**
  - An `EPERM` against this oracle **isolates seccomp**, just like the address family oracle, because the structural `EINVAL` prevents the LSM hook from running.
  - An `EINVAL` says nothing about whether an LSM permits the netlink protocol creation.

## 3. io_uring Opcode Reach (`IORING_REGISTER_PROBE`)

- **Probed Syscall:** `io_uring_register(fd, IORING_REGISTER_PROBE, arg, nr_args)`
- **Oracle Argument Set:** `io_uring_register(-1, IORING_REGISTER_PROBE, NULL, 0)`
  - We pass an invalid file descriptor (`fd = -1`) which structurally guarantees `EBADF`.
- **Hook Ordering:** File descriptor resolution (`fdget()`) occurs at the very beginning of the syscall, preceding any LSM hook or io_uring specific checks.
- **What it proves:**
  - If the probe returns `EPERM` instead of the guaranteed `EBADF`, it proves interception occurred before descriptor resolution. Since `seccomp` acts on the syscall entry before `fd` resolution, this EBADF oracle **isolates seccomp**. Any `EPERM` is definitively from a seccomp filter and not from an LSM or capability check.

## 4. Capability Effects

Capability probes deliberately use `Isolates::Undecidable`: the syscall's
own missing-capability result is the observation, and the engine correlates it
with `cell.capabilities` rather than claiming that an `EPERM` came from a
filter. The argument sets are chosen so the privileged path is harmless and
the unprivileged path is distinctive:

- `settimeofday(NULL, NULL)` checks `CAP_SYS_TIME` before the no-op update.
- `reboot(0, 0, LINUX_REBOOT_CMD_CAD_OFF, NULL)` checks `CAP_SYS_BOOT` before
  malformed-command validation, which guarantees `EINVAL` after the check.
- `finit_module(-1, "", 0)` checks `CAP_SYS_MODULE` before descriptor lookup,
  which guarantees `EBADF` after the check.
- `mknodat` resolves the existing `/tmp` parent in `filename_create` before
  `vfs_mknod` checks `CAP_MKNOD`; the no-capability path is `EPERM`, and a
  capable child removes the newly created node before exit. If the child is
  killed before cleanup, `/tmp/caliper-mknod` can remain.
- `process_vm_readv` uses a non-zero local iovec and an invalid remote address,
  so `ptrace_may_access` runs before the deliberate `EFAULT`; the non-dumpable
  probe parent makes the no-capability path `EPERM`, including Yama and
  AppArmor ptrace policy denials.
- Binding an IPv4 socket to port 1 checks `CAP_NET_BIND_SERVICE` and returns
  `EACCES` without it; the descriptor dies with the child.
- `setpriority(..., -1)` checks `CAP_SYS_NICE`; only the child's nice value is
  changed.
- x86_64 `iopl(3)` checks `CAP_SYS_RAWIO` and is `not-applicable` on other
  architectures.

The kernel locations and man-page errno contracts are recorded beside each
probe in `engine/crates/corpus/src/capability.rs`.

## 5. Mount filesystem types (#77)

The 37 filesystem-type probes enumerate `/proc/filesystems` rather than
calling `mount(2)`. `registered()` reads the kernel's list with `openat`,
`read`, and `close`; `get_fs_type` reports `ENODEV` for an absent type, which
is the declared `kernel.absent_errno`. The oracle is `Undecidable` because an
`EPERM` here can be the runtime's procfs policy, not a mount denial. The three
mount-operation probes use `path_mount`, `may_mount`, and
`security_sb_mount`; their `EINVAL`/`ENOENT` guarantees are after the
capability/LSM ordering described in `mount.rs`.

Review record: #77 was reviewed before the freeze. The 38 mount entries are
included in the sweep and index regenerated by #19.

## 6. Masked/read-only paths (#15)

Path probes use `openat(O_PATH)` followed by `fstatfs`. `ENODATA` identifies a
masked filesystem and `EROFS` identifies a read-only mount; both are encoded as
the path oracle's structural answers. Missing paths use `ENOENT` as the
kernel-dependency absence value. The relevant ordering is in `paths.rs`, and
the one-probe `/proc/asound` entry is intentionally not expanded into child
paths.

## 7. Device nodes (#16)

Device probes perform only the read-only, nonblocking `openat` reachability
operation. They never read or write the device, and the child exit reclaims a
successful descriptor. `ENOENT` means the image did not provision the node;
`EACCES`/`EPERM` remain `Undecidable` because DAC, device cgroups, LSM policy,
and driver capability checks can all answer.

## 8. Clone/unshare flags (#14)

Invalid flags use `EINVAL` before namespace creation and therefore isolate
seccomp. Namespace-creation probes are `Undecidable`: `create_new_namespaces`
and `copy_namespaces` perform capability checks as part of the operation, so
`EPERM` is not attributable to a filter without the capability correlate.

## Cross-family review record (#18)

The review was performed against the kernel locations named in each probe and
the corresponding man-page errno contract. The merged family work was:

| family | probes | review record |
|---|---:|---|
| socket | 24 | #70, `net/socket.c:__sock_create`, `security_socket_create` |
| netlink | 18 | #70, `net/netlink/af_netlink.c:netlink_create` |
| io_uring | 53 | #71, `io_uring/io_uring.c:io_uring_register`, opcode probe path |
| mount | 38 | #77, `fs/namespace.c:may_mount`, `get_fs_type`, `security_sb_mount` |
| clone | 19 | #14, `kernel/fork.c:copy_process`, `kernel/namespace.c:create_new_namespaces` |
| path | 17 | #15, `fs/namei.c:filename_lookup`, `statfs`/`fstatfs` |
| device | 8 | #16, `fs/open.c:do_filp_open`, device-cgroup gate |
| capability | 8 | #17, the capability-specific kernel functions in `capability.rs` |

The sweep records 185 probes. It found no empty oracle, no guaranteed `EPERM`,
and no `Seccomp` oracle whose documented answer is ordered after the relevant
LSM/capability hook. The merged PR threads above are the review locations; this
table is the durable summary required by §8.
