# Oracle Argument Sets Design

This document records the errno-oracle design and the cross-family review for
the frozen corpus. Every committed probe has a non-empty oracle; the complete
id/guarantee/isolation/absence sweep is in [`oracle-sweep.md`](oracle-sweep.md).

## ENOSYS Handling Agreement

As agreed by all members and documented in `spec/probe.md`, the `ENOSYS` error returned from a syscall that the cell's kernel is known to implement is treated as **ambiguous** (i.e., a filter) rather than as `unimplemented`.

## 1. Socket Address Families (`AF_*`)

- **Probed Syscall:** `socket(AF_TARGET, type, 0)`, one probe per family.
- **Oracle:** one probe, `socket.family.out_of_range`: `socket(1000, SOCK_STREAM, 0)`, guaranteed `EAFNOSUPPORT`.
- **Hook Ordering:** `__sock_create` rejects a family at or beyond `NPROTO` before `security_socket_create` and before the family table is consulted, so only a filter at syscall entry can answer `EPERM` first. This oracle **isolates seccomp**.
- **Per-family probes:** the family's create function runs after `security_socket_create`, so `EPERM` is seccomp or an LSM (`seccomp-or-lsm`), or `undecidable` where the family checks a capability itself (`AF_PACKET`, `AF_KEY`, `AF_XDP`, `AF_PHONET`). `EAFNOSUPPORT` is the family absent or its module not loadable, recorded as the kernel dependency; `ax25`, `appletalk`, `x25` and `ieee802154` also answer it outside the initial network namespace, after the module has loaded, which the module snapshot shows.

## 2. Netlink Protocol Numbers (`NETLINK_*`)

- **Probed Syscall:** `socket(AF_NETLINK, SOCK_RAW, NETLINK_TARGET)`, one probe per protocol.
- **Oracle:** one probe, `netlink.protocol.out_of_range`: `socket(AF_NETLINK, SOCK_RAW, 32)`, guaranteed `EPROTONOSUPPORT`.
- **Hook Ordering:** `netlink_create` rejects a protocol at or beyond `MAX_LINKS` before looking for a handler, but after `security_socket_create` and the family lookup. `EPROTONOSUPPORT` proves the netlink family itself is reachable; `EPERM` is seccomp or an LSM and is not separable (`seccomp-or-lsm`).
- **Per-protocol probes:** creating the socket checks no capability (`CAP_NET_ADMIN` and the audit capabilities are checked on messages, not on create), so `EPERM` is seccomp or an LSM. `EPROTONOSUPPORT` is the handler absent, recorded as the kernel dependency, except for `route`, `usersock` and `generic`, which every supported kernel registers.

## 3. io_uring Opcode Reach (`IORING_REGISTER_PROBE`)

- **Probed Syscall:** `io_uring_register(fd, IORING_REGISTER_PROBE, arg, nr_args)`
- **Oracle Argument Set:** `io_uring_register(INT_MAX, IORING_REGISTER_PROBE, NULL, 0)`
  - We pass a descriptor above the `nr_open` ceiling (`fd = INT_MAX`), which structurally guarantees `EBADF`. Not `-1`: since 6.13 that selects the blind register path, which answers `EINVAL`.
- **Hook Ordering:** File descriptor resolution (`fget()`) occurs at the very beginning of the syscall, preceding any LSM hook or io_uring specific checks.
- **What it proves:**
  - If the probe returns `EPERM` instead of the guaranteed `EBADF`, it proves interception occurred before descriptor resolution. Since `seccomp` acts on the syscall entry before `fd` resolution, this EBADF oracle **isolates seccomp**. Any `EPERM` is definitively from a seccomp filter and not from an LSM or capability check.

- **Kernel 6.15 and later:** `io_uring_setup` calls `security_uring_allowed()`
  before checking its parameters, so for the setup and opcode probes an `EPERM`
  is seccomp or an LSM from 6.15 on. The probes record this as the kernel
  dependency's `lsm_hook_since: [6, 15]`, and attribution applies it to the
  cell's kernel. `io_uring.register.probe` is unaffected: its `EBADF` comes from
  `io_uring_register`, which has no such hook.

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

The 34 filesystem-type probes enumerate `/proc/filesystems` rather than
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

## Deferred families (#20)

Specified in `engine/crates/corpus/src/deferred.rs`, never run. Each probe's
oracle carries its kernel ordering; the strategy per family:

- **ioctl:** `ioctl(-1, CMD, ...)`. `fdget` fails before `security_file_ioctl`,
  so `EBADF` isolates seccomp and the probe measures filtering on the request
  code alone.
- **bpf:** commands use a non-zero byte past `union bpf_attr`, so
  `bpf_check_uarg_tail_zero` answers `E2BIG` before `security_bpf`. Before 6.3,
  `__sys_bpf` refused `BPF_MAP_CREATE` and `BPF_PROG_LOAD` with `EPERM` under
  `unprivileged_bpf_disabled` first, so those two are `Undecidable`;
  `BPF_BTF_LOAD` isolates seccomp. Program types sit behind the attr pointer,
  out of a filter's sight, and are `Undecidable` against their capability.
- **keyctl:** a serial that cannot exist answers `ENOKEY` from `key_lookup`
  before any key permission hook; an undefined operation answers `EOPNOTSUPP`.
  Both isolate seccomp, and nothing is created.
- **prctl:** `security_task_prctl` runs before the option switch, so every
  `EINVAL` oracle is `SeccompOrLsm`.
- **perf_event_open:** bad flags (`EINVAL`) and a bad attr size (`E2BIG`) are
  both answered before `security_perf_event_open`. The CPU-wide event is
  gated by `perf_event_paranoid` (`EACCES`) and `CAP_PERFMON`.
- **userfaultfd:** `UFFD_USER_MODE_ONLY` passes the sysctl gate, so an unknown
  flag beside it answers `EINVAL` before any hook. Kernel-mode faults are
  `Undecidable` against `CAP_SYS_PTRACE`.
- **open_by_handle_at:** before 6.10 `handle_to_path` checks
  `CAP_DAC_READ_SEARCH` first, so the open is `Undecidable`.
  `name_to_handle_at` rejects unknown flags before path lookup and isolates
  seccomp.
- **module:** `init_module` and `delete_module` check `CAP_SYS_MODULE` first;
  both are `Undecidable`, like `capability.sys_module`.
- **seccomp_notify:** `seccomp(2)` has no LSM hook, so `EFAULT` from a NULL
  program or size buffer isolates seccomp; the notification ioctl uses the
  `EBADF` oracle.

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
