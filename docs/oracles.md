# Oracle Argument Sets Design

This document describes the errno oracle design for the first three corpus families, as required by Workstream B in Phase 1 (Weeks 1-3). It is intended to be authored into the corresponding probe family issues (#11 and #12) in week 4.

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
- `mknodat` checks `CAP_MKNOD` before resolving the deliberately missing
  parent, which guarantees `ENOENT` after the check.
- `process_vm_readv` checks `CAP_SYS_PTRACE` before a zero-byte transfer.
- Binding an IPv4 socket to port 80 checks `CAP_NET_BIND_SERVICE` and returns
  `EACCES` without it; the descriptor dies with the child.
- `setpriority(..., -1)` checks `CAP_SYS_NICE`; only the child's nice value is
  changed.
- x86_64 `iopl(3)` checks `CAP_SYS_RAWIO` and is `not-applicable` on other
  architectures.

The kernel locations and man-page errno contracts are recorded beside each
probe in `engine/crates/corpus/src/capability.rs`.
