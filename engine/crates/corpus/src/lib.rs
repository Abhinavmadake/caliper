// Copyright 2026 Abhinav Ajit Madake, Sahil Tatyabhau Waje,
// Ritesh Aresh Saindane, Yogesh Babaji Palve
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The probe corpus. Probes are Rust definitions compiled into the engine
//! (`spec/probe.md`, decision 1): there is no data file read at run time.
//! `caliper-probe --dump-corpus` emits this crate's contents as JSON, as an
//! output only.
//!
//! A and B both author here. What a probe *is* — [`Probe`] and its fields —
//! is defined in `caliper-engine`. The ten-probe reference corpus (#10) is
//! here, one module per entry family; the committed families (#11–#17)
//! extend those modules. Every probe is authored complete: oracle,
//! capability requirement and side-effect declaration, none deferred.

//! # Authoring a probe
//!
//! The pattern to copy. This compiles and is checked by `cargo test --doc`, so
//! it cannot rot silently.
//!
//! ```
//! use std::time::Duration;
//! use caliper_corpus::Probe;
//! use caliper_engine::{
//!     Applicability, Errno, Isolates, KernelDependency, Oracle, RawResult, RiskClass, SideEffects,
//! };
//!
//! /// `close(2)` on a descriptor that cannot be valid.
//! ///
//! /// The oracle: `EBADF` is structurally guaranteed if the call reaches the
//! /// kernel at all, because descriptor resolution happens before every LSM
//! /// hook. So `EPERM` here proves interception *before* that point, which
//! /// isolates seccomp specifically (`spec/probe.md`, errno oracle).
//! fn close_bad_fd() -> RawResult {
//!     // A raw syscall, not the libc wrapper: a wrapper can hide a second
//!     // syscall — musl's `socket()` retries without SOCK_CLOEXEC on EINVAL —
//!     // and the oracle reasons about the exact sequence the child issues.
//!     let r = unsafe { libc::syscall(libc::SYS_close, -1) };
//!     if r < 0 {
//!         Err(Errno::last())
//!     } else {
//!         Ok(())
//!     }
//! }
//!
//! const EXAMPLE: Probe = Probe {
//!     id: "example.close.bad_fd",
//!     family: "example",
//!     description: "close(2) on an invalid descriptor",
//!     // requires_fork is the author's claim about side effects, reviewed in
//!     // #18; the engine forks for every probe regardless.
//!     risk: RiskClass::new(true, Duration::from_millis(500)),
//!     // close(2) exists everywhere and on every supported kernel, so no
//!     // errno from it can mean "absent". A probe of a newer entry point
//!     // names the release it appeared in and the errno absence produces:
//!     // `KernelDependency { since: Some((5, 1)), absent_errno: Some(Errno::ENOSYS) }`
//!     // for io_uring, say. That is what separates `unimplemented` from
//!     // `denied` (#8).
//!     arch: Applicability::All,
//!     kernel: KernelDependency::NONE,
//!     // The oracle on the record: what the argument set guarantees, what
//!     // an EPERM against it isolates, and the hook-order argument for a
//!     // reader — it goes onto the fingerprint's `attribution.reason`
//!     // verbatim. `guarantees: None` is a call expected to succeed.
//!     oracle: Oracle {
//!         guarantees: Some(Errno::EBADF),
//!         isolates: Isolates::Seccomp,
//!         reason: "descriptor resolution precedes every LSM hook, so EBADF is \
//!                  produced before any of them; only a filter at syscall entry \
//!                  answers EPERM first",
//!     },
//!     // The operation's documented capability, for correlation against
//!     // the effective and bounding sets; close(2) has none.
//!     capability: None,
//!     // Considered: a bad descriptor creates nothing. A probe that may
//!     // leave something a process does not reclaim names the class —
//!     // `SideEffects::Declared { residual: &[ResidualClass::SysvIpc],
//!     // module_autoload: false }` — and removes it itself before
//!     // returning; the engine measures whether it did. Leave the field
//!     // out (`..Default::default()`) and it is `Undeclared`: the engine
//!     // refuses to run the probe, and the corpus test refuses the merge.
//!     effects: SideEffects::NONE,
//!     run: close_bad_fd,
//! };
//! ```
//!
//! Rules the probe function must hold to, from `spec/probe.md` and §6.2. It runs
//! in a forked child with nothing between the `clone` and the call:
//!
//! - no allocation, no `std` I/O, no panics — nothing but the syscalls under test
//! - reachability only. Never an operation whose success confers privilege
//! - prefer an enumeration interface where one answers the question:
//!   `IORING_REGISTER_PROBE` over submitting queue entries
//! - a probe that can make the kernel autoload a module declares it; that side
//!   effect cannot be rolled back
//! - a POSIX IPC object it creates is named `caliper-…` and a System V key is
//!   in the instrument's range (`caliper_engine::effects`), so the end-of-run
//!   janitor can recognise what the child could not remove

pub use caliper_engine::Probe;

mod clone;
mod common;
mod io_uring;
mod mount;
mod netlink;
mod paths;
mod socket;

/// Which corpus a run came from: `corpus_revision` in the fingerprint.
/// The crate version, so it moves with the corpus and nothing else.
pub const REVISION: &str = env!("CARGO_PKG_VERSION");

/// Every probe the engine knows about, in corpus order. The order is the
/// run order (snapshots depend on it) and the order in the fingerprint.
pub fn probes() -> &'static [Probe] {
    &[
        socket::AF_INET,
        socket::AF_ALG,
        socket::AF_PACKET,
        socket::OUT_OF_RANGE_FAMILY,
        socket::AF_UNIX,
        socket::AF_INET6,
        socket::AF_KEY,
        socket::AF_BLUETOOTH_RFCOMM,
        socket::AF_CAN_RAW,
        socket::AF_TIPC,
        socket::AF_RDS,
        socket::AF_XDP,
        socket::AF_RXRPC,
        socket::AF_PHONET,
        socket::AF_IEEE802154,
        socket::AF_NFC,
        socket::AF_VSOCK,
        socket::AF_KCM,
        socket::AF_QIPCRTR,
        socket::AF_SMC,
        socket::AF_MCTP,
        socket::AF_AX25,
        socket::AF_APPLETALK,
        socket::AF_X25,
        netlink::ROUTE,
        netlink::USERSOCK,
        netlink::SOCK_DIAG,
        netlink::NFLOG,
        netlink::XFRM,
        netlink::SELINUX,
        netlink::ISCSI,
        netlink::AUDIT,
        netlink::FIB_LOOKUP,
        netlink::CONNECTOR,
        netlink::NETFILTER,
        netlink::KOBJECT_UEVENT,
        netlink::GENERIC,
        netlink::SCSITRANSPORT,
        netlink::RDMA,
        netlink::CRYPTO,
        netlink::SMC,
        netlink::OUT_OF_RANGE_PROTOCOL,
        io_uring::REGISTER_PROBE,
        io_uring::SETUP_ZERO_ENTRIES,
        io_uring::OP_NOP,
        io_uring::OP_READV,
        io_uring::OP_WRITEV,
        io_uring::OP_FSYNC,
        io_uring::OP_READ_FIXED,
        io_uring::OP_WRITE_FIXED,
        io_uring::OP_POLL_ADD,
        io_uring::OP_SYNC_FILE_RANGE,
        io_uring::OP_SENDMSG,
        io_uring::OP_RECVMSG,
        io_uring::OP_TIMEOUT,
        io_uring::OP_ACCEPT,
        io_uring::OP_CONNECT,
        io_uring::OP_FALLOCATE,
        io_uring::OP_OPENAT,
        io_uring::OP_CLOSE,
        io_uring::OP_STATX,
        io_uring::OP_READ,
        io_uring::OP_WRITE,
        io_uring::OP_FADVISE,
        io_uring::OP_MADVISE,
        io_uring::OP_SEND,
        io_uring::OP_RECV,
        io_uring::OP_OPENAT2,
        io_uring::OP_EPOLL_CTL,
        io_uring::OP_SPLICE,
        io_uring::OP_TEE,
        io_uring::OP_SHUTDOWN,
        io_uring::OP_RENAMEAT,
        io_uring::OP_UNLINKAT,
        io_uring::OP_MKDIRAT,
        io_uring::OP_SYMLINKAT,
        io_uring::OP_LINKAT,
        io_uring::OP_MSG_RING,
        io_uring::OP_FSETXATTR,
        io_uring::OP_SETXATTR,
        io_uring::OP_FGETXATTR,
        io_uring::OP_GETXATTR,
        io_uring::OP_SOCKET,
        io_uring::OP_URING_CMD,
        io_uring::OP_SEND_ZC,
        io_uring::OP_SENDMSG_ZC,
        io_uring::OP_READ_MULTISHOT,
        io_uring::OP_WAITID,
        io_uring::OP_FUTEX_WAIT,
        io_uring::OP_FUTEX_WAKE,
        io_uring::OP_FUTEX_WAITV,
        io_uring::OP_FIXED_FD_INSTALL,
        io_uring::OP_FTRUNCATE,
        io_uring::OP_BIND,
        io_uring::OP_LISTEN,
        mount::REACH,
        paths::MASKED_PROC_KCORE,
        paths::MASKED_PROC_KEYS,
        paths::MASKED_PROC_LATENCY_STATS,
        paths::MASKED_PROC_TIMER_LIST,
        paths::MASKED_PROC_TIMER_STATS,
        paths::MASKED_PROC_SCHED_DEBUG,
        paths::MASKED_PROC_ACPI,
        paths::MASKED_PROC_ASOUND,
        paths::MASKED_PROC_SCSI,
        paths::MASKED_SYS_FIRMWARE,
        paths::MASKED_SYS_POWERCAP,
        paths::READONLY_PROC_BUS,
        paths::READONLY_PROC_FS,
        paths::READONLY_PROC_IRQ,
        paths::READONLY_PROC_SYS,
        paths::READONLY_PROC_SYSRQ_TRIGGER,
        paths::CONTROL_PROC_SELF_STATUS,
        clone::UNSHARE_INVALID_FLAGS,
        clone::UNSHARE_FLAGS_NEWUSER,
        clone::UNSHARE_FLAGS_NEWNS,
        clone::UNSHARE_FLAGS_NEWNET,
        clone::UNSHARE_FLAGS_NEWPID,
        clone::UNSHARE_FLAGS_NEWIPC,
        clone::UNSHARE_FLAGS_NEWUTS,
        clone::UNSHARE_FLAGS_NEWCGROUP,
        clone::UNSHARE_FLAGS_NEWTIME,
        clone::UNSHARE_FLAGS_NEWUSER_NEWNET,
        clone::CLONE_FLAGS_NEWUSER,
        clone::CLONE_FLAGS_NEWNS,
        clone::CLONE_FLAGS_NEWNET,
        clone::CLONE_FLAGS_NEWPID,
        clone::CLONE_FLAGS_NEWIPC,
        clone::CLONE_FLAGS_NEWUTS,
        clone::CLONE_FLAGS_NEWCGROUP,
        clone::CLONE_FLAGS_NEWUSER_NEWNET,
        clone::CLONE3_SHORT_ARGS,
    ]
}

#[cfg(test)]
mod tests {
    use super::probes;
    use std::collections::BTreeSet;

    /// #10: ten probes across at least three entry families.
    #[test]
    fn the_reference_corpus_is_ten_probes_over_three_families() {
        assert!(probes().len() >= 10, "{} probes", probes().len());
        let families: BTreeSet<_> = probes().iter().map(|p| p.family).collect();
        assert!(families.len() >= 3, "{families:?}");
    }

    /// Every probe is authored complete: the oracle's reasoning is on the
    /// record, and a guaranteed errno is never the one the kernel
    /// dependency reads as absence — that would make `unimplemented`
    /// unreachable for the probe.
    #[test]
    fn every_oracle_is_reasoned_and_distinct_from_absence() {
        for p in probes() {
            assert!(!p.oracle.reason.trim().is_empty(), "{}: no reason", p.id);
            if let (Some(g), Some(a)) = (p.oracle.guarantees, p.kernel.absent_errno) {
                assert_ne!(g, a, "{}: the oracle guarantees the absent errno", p.id);
            }
        }
    }

    /// The merge gate for #9: `Undeclared` is for authoring, not for
    /// `main`. Every probe in the compiled corpus has considered its side
    /// effects, or this fails in CI.
    #[test]
    fn every_probe_declares_its_side_effects() {
        let undeclared: Vec<_> = probes()
            .iter()
            .filter(|p| !p.effects.is_declared())
            .map(|p| p.id)
            .collect();
        assert!(
            undeclared.is_empty(),
            "probes with SideEffects::Undeclared: {undeclared:?}"
        );
    }

    #[test]
    fn probe_ids_are_unique() {
        let mut ids: Vec<_> = probes().iter().map(|p| p.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate probe ids");
    }
}
