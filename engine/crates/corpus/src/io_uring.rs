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

//! io_uring opcode reach (`corpus/README.md`, committed set; #12). The
//! proposal prefers the enumeration interface: `IORING_REGISTER_PROBE`
//! reports the supported opcodes without submitting a queue entry (§6.2),
//! and that is the only way an opcode is measured here. No SQE is ever
//! written, let alone submitted.
//!
//! Two reach probes first, each with an answer the kernel produces before
//! any hook: `io_uring_register(-1, …)` for `EBADF`, `io_uring_setup(0, …)`
//! for `EINVAL`. Then one probe per opcode: the child creates a one-entry
//! ring, registers a probe buffer, and reads the opcode's
//! `IO_URING_OP_SUPPORTED` bit. The ring is a descriptor; the child's exit
//! reclaims it. Two rings' worth of kernel memory per opcode probe, freed
//! the same way.
//!
//! What the answers mean, per `io_uring/io_uring.c` and
//! `io_uring/register.c` (6.x): `io_uring_setup` has no LSM hook; it checks
//! `kernel.io_uring_disabled` first (since 6.6: `2` answers `EPERM` to
//! everyone, `1` to callers without `CAP_SYS_ADMIN` or the configured
//! group), then the parameters. `IORING_REGISTER_PROBE` has no hook and no
//! capability check. So an `EPERM` on any opcode probe is a filter on
//! either syscall or the sysctl, and every opcode probe on the cell says
//! the same thing: io_uring denied outright. An opcode whose bit is clear
//! is absent from this kernel, by version or configuration: the probe
//! returns `ENOSYS` for it, the errno the syscall itself answers with when
//! io_uring is not built at all, and one `io_uring_register` never produces
//! for a ring it has just accepted. That is the encoding `spec/probe.md`'s
//! decision on masked paths allows: named here, read by the attributor as
//! absence, and recorded as `unimplemented` through the kernel dependency.
//! Presence is decided by version and configuration together, so the
//! dependency carries no `since`; the release each opcode appeared in is
//! in its description, for the reader.
//!
//! That is the distinction #12 asks for: denied outright is `denied 1` on
//! every opcode probe (and on the reach probes); an opcode unavailable is
//! `unimplemented 38` on that opcode alone.

use caliper_engine::{
    Applicability, Errno, Isolates, KernelDependency, Oracle, Probe, RawResult, SideEffects,
};

use crate::common::{result, ONE_CALL};

/// `include/uapi/linux/io_uring.h`; not in the libc crate.
const IORING_REGISTER_PROBE: libc::c_uint = 8;

/// `sizeof(struct io_uring_params)`, as fifteen zeroed words: the kernel
/// copies exactly that many bytes and rejects a non-zero `resv`.
const IO_URING_PARAMS_WORDS: usize = 15;

/// `struct io_uring_probe`: a 16-byte header (`last_op`, `ops_len`, resv)
/// followed by `ops[]` of 8-byte `struct io_uring_probe_op` (`op`, resv,
/// `flags` u16, resv2 u32). Room for every opcode number the ABI can name.
const PROBE_HEADER: usize = 16;
const PROBE_OP_SIZE: usize = 8;
const PROBE_OPS: usize = 256;
const PROBE_BUF: usize = PROBE_HEADER + PROBE_OP_SIZE * PROBE_OPS;
/// `IO_URING_OP_SUPPORTED` in `io_uring_probe_op.flags`.
const IO_URING_OP_SUPPORTED: u16 = 1;

/// Is `opcode` supported on this kernel? A one-entry ring, a probe
/// registration, one bit. Every failure is the kernel's own errno; a clear
/// bit is `ENOSYS`, per the module comment.
fn opcode_supported(opcode: u8) -> RawResult {
    let params = [0u64; IO_URING_PARAMS_WORDS];
    // SAFETY: a zeroed, correctly sized params block on the stack; the
    // kernel fills it in and returns a descriptor the child's exit closes.
    let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1 as libc::c_uint, params.as_ptr()) };
    if fd < 0 {
        return Err(Errno::last());
    }
    let mut buf = [0u8; PROBE_BUF];
    // SAFETY: the descriptor we were just given, a zeroed buffer of the
    // size we declare, and the opcode count that fits in it.
    let r = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            fd as libc::c_int,
            IORING_REGISTER_PROBE,
            buf.as_mut_ptr(),
            PROBE_OPS as libc::c_uint,
        )
    };
    if r < 0 {
        return Err(Errno::last());
    }
    let ops_len = buf[1] as usize;
    let i = opcode as usize;
    if i >= ops_len {
        return Err(Errno::ENOSYS);
    }
    let at = PROBE_HEADER + PROBE_OP_SIZE * i;
    let flags = u16::from_ne_bytes([buf[at + 2], buf[at + 3]]);
    if flags & IO_URING_OP_SUPPORTED != 0 {
        Ok(())
    } else {
        Err(Errno::ENOSYS)
    }
}

/// One opcode. `$since` is the kernel release it appeared in, for the
/// description only (see the module comment on why the dependency carries
/// none).
macro_rules! opcode {
    ($konst:ident, $f:ident, $id:literal, $op:literal, $name:literal, $since:literal, $what:literal) => {
        fn $f() -> RawResult {
            opcode_supported($op)
        }
        pub const $konst: Probe = Probe {
            id: $id,
            family: "io_uring",
            description: concat!(
                "IORING_REGISTER_PROBE reports ", $name, " (", $op, ", since ", $since, "): ",
                $what
            ),
            risk: ONE_CALL,
            arch: Applicability::All,
            kernel: CONFIG_GATED,
            oracle: Oracle {
                guarantees: None,
                isolates: Isolates::Seccomp,
                reason: "io_uring_setup has no LSM hook and IORING_REGISTER_PROBE no hook or \
                         capability check, so EPERM is a filter at entry on either syscall; since \
                         6.6 the kernel.io_uring_disabled sysctl also answers EPERM at setup, and \
                         on such a cell the filter is not isolated. A clear SUPPORTED bit is \
                         returned as ENOSYS, which io_uring_register never produces for an \
                         accepted ring: absence, read as unimplemented",
            },
            capability: None,
            effects: SideEffects::NONE,
            run: $f,
        };
    };
}

fn register_probe_bad_fd() -> RawResult {
    // SAFETY: integer arguments and a null pointer the kernel never reads,
    // because -1 fails descriptor resolution first.
    result(unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            -1 as libc::c_int,
            IORING_REGISTER_PROBE,
            std::ptr::null::<libc::c_void>(),
            0 as libc::c_uint,
        )
    })
}

fn setup_zero_entries() -> RawResult {
    let params = [0u64; IO_URING_PARAMS_WORDS];
    // SAFETY: a zeroed, correctly sized params block on the stack; the
    // kernel reads it and rejects the entry count before it creates anything.
    result(unsafe { libc::syscall(libc::SYS_io_uring_setup, 0 as libc::c_uint, params.as_ptr()) })
}

/// `CONFIG_IO_URING=n` leaves the syscalls out: `ENOSYS` is absence.
const CONFIG_GATED: KernelDependency = KernelDependency {
    since: None,
    absent_errno: Some(Errno::ENOSYS),
};

pub const REGISTER_PROBE: Probe = Probe {
    id: "io_uring.register.probe",
    family: "io_uring",
    description: "io_uring_register(-1, IORING_REGISTER_PROBE, NULL, 0): guaranteed EBADF",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: CONFIG_GATED,
    oracle: Oracle {
        guarantees: Some(Errno::EBADF),
        isolates: Isolates::Seccomp,
        reason: "io_uring_register resolves the descriptor with fdget as soon as the opcode \
                 is in range, and -1 is never a descriptor; EBADF is produced before any \
                 LSM hook, so only a filter at syscall entry answers EPERM first",
    },
    capability: None,
    effects: SideEffects::NONE,
    run: register_probe_bad_fd,
};

pub const SETUP_ZERO_ENTRIES: Probe = Probe {
    id: "io_uring.setup.zero_entries",
    family: "io_uring",
    description: "io_uring_setup(0, &params): guaranteed EINVAL, no ring is created",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: CONFIG_GATED,
    oracle: Oracle {
        guarantees: Some(Errno::EINVAL),
        isolates: Isolates::Seccomp,
        reason: "io_uring_create rejects zero entries with EINVAL and io_uring_setup has no \
                 LSM hook. Since 6.6 the kernel.io_uring_disabled sysctl makes the kernel \
                 itself answer EPERM before that check; on such a cell EPERM does not \
                 isolate the filter",
    },
    capability: None,
    effects: SideEffects::NONE,
    run: setup_zero_entries,
};

opcode!(
    OP_NOP,
    op_nop,
    "io_uring.opcode.nop",
    0,
    "IORING_OP_NOP",
    "5.1",
    "the control: a ring that can be probed at all supports it"
);
opcode!(
    OP_READV,
    op_readv,
    "io_uring.opcode.readv",
    1,
    "IORING_OP_READV",
    "5.1",
    "vectored reads without read(2)"
);
opcode!(
    OP_WRITEV,
    op_writev,
    "io_uring.opcode.writev",
    2,
    "IORING_OP_WRITEV",
    "5.1",
    "vectored writes without write(2)"
);
opcode!(
    OP_FSYNC,
    op_fsync,
    "io_uring.opcode.fsync",
    3,
    "IORING_OP_FSYNC",
    "5.1",
    "fsync without fsync(2)"
);
opcode!(
    OP_READ_FIXED,
    op_read_fixed,
    "io_uring.opcode.read_fixed",
    4,
    "IORING_OP_READ_FIXED",
    "5.1",
    "reads into registered buffers"
);
opcode!(
    OP_WRITE_FIXED,
    op_write_fixed,
    "io_uring.opcode.write_fixed",
    5,
    "IORING_OP_WRITE_FIXED",
    "5.1",
    "writes from registered buffers"
);
opcode!(
    OP_POLL_ADD,
    op_poll_add,
    "io_uring.opcode.poll_add",
    6,
    "IORING_OP_POLL_ADD",
    "5.1",
    "poll without poll(2)"
);
opcode!(
    OP_SYNC_FILE_RANGE,
    op_sync_file_range,
    "io_uring.opcode.sync_file_range",
    8,
    "IORING_OP_SYNC_FILE_RANGE",
    "5.2",
    "sync_file_range without the syscall"
);
opcode!(
    OP_SENDMSG,
    op_sendmsg,
    "io_uring.opcode.sendmsg",
    9,
    "IORING_OP_SENDMSG",
    "5.3",
    "sendmsg without sendmsg(2)"
);
opcode!(
    OP_RECVMSG,
    op_recvmsg,
    "io_uring.opcode.recvmsg",
    10,
    "IORING_OP_RECVMSG",
    "5.3",
    "recvmsg without recvmsg(2)"
);
opcode!(
    OP_TIMEOUT,
    op_timeout,
    "io_uring.opcode.timeout",
    11,
    "IORING_OP_TIMEOUT",
    "5.4",
    "timers in the ring"
);
opcode!(
    OP_ACCEPT,
    op_accept,
    "io_uring.opcode.accept",
    13,
    "IORING_OP_ACCEPT",
    "5.5",
    "accept without accept4(2)"
);
opcode!(
    OP_CONNECT,
    op_connect,
    "io_uring.opcode.connect",
    16,
    "IORING_OP_CONNECT",
    "5.5",
    "connect without connect(2)"
);
opcode!(
    OP_FALLOCATE,
    op_fallocate,
    "io_uring.opcode.fallocate",
    17,
    "IORING_OP_FALLOCATE",
    "5.6",
    "fallocate without the syscall"
);
opcode!(
    OP_OPENAT,
    op_openat,
    "io_uring.opcode.openat",
    18,
    "IORING_OP_OPENAT",
    "5.6",
    "opening files without openat(2)"
);
opcode!(
    OP_CLOSE,
    op_close,
    "io_uring.opcode.close",
    19,
    "IORING_OP_CLOSE",
    "5.6",
    "close without close(2)"
);
opcode!(
    OP_STATX,
    op_statx,
    "io_uring.opcode.statx",
    21,
    "IORING_OP_STATX",
    "5.6",
    "statx without the syscall"
);
opcode!(
    OP_READ,
    op_read,
    "io_uring.opcode.read",
    22,
    "IORING_OP_READ",
    "5.6",
    "read without read(2)"
);
opcode!(
    OP_WRITE,
    op_write,
    "io_uring.opcode.write",
    23,
    "IORING_OP_WRITE",
    "5.6",
    "write without write(2)"
);
opcode!(
    OP_FADVISE,
    op_fadvise,
    "io_uring.opcode.fadvise",
    24,
    "IORING_OP_FADVISE",
    "5.6",
    "fadvise without the syscall"
);
opcode!(
    OP_MADVISE,
    op_madvise,
    "io_uring.opcode.madvise",
    25,
    "IORING_OP_MADVISE",
    "5.6",
    "madvise without madvise(2)"
);
opcode!(
    OP_SEND,
    op_send,
    "io_uring.opcode.send",
    26,
    "IORING_OP_SEND",
    "5.6",
    "send without send(2)"
);
opcode!(
    OP_RECV,
    op_recv,
    "io_uring.opcode.recv",
    27,
    "IORING_OP_RECV",
    "5.6",
    "recv without recv(2)"
);
opcode!(
    OP_OPENAT2,
    op_openat2,
    "io_uring.opcode.openat2",
    28,
    "IORING_OP_OPENAT2",
    "5.6",
    "openat2 without the syscall"
);
opcode!(
    OP_EPOLL_CTL,
    op_epoll_ctl,
    "io_uring.opcode.epoll_ctl",
    29,
    "IORING_OP_EPOLL_CTL",
    "5.6",
    "epoll_ctl without the syscall"
);
opcode!(
    OP_SPLICE,
    op_splice,
    "io_uring.opcode.splice",
    30,
    "IORING_OP_SPLICE",
    "5.7",
    "splice without splice(2)"
);
opcode!(
    OP_TEE,
    op_tee,
    "io_uring.opcode.tee",
    33,
    "IORING_OP_TEE",
    "5.8",
    "tee without tee(2)"
);
opcode!(
    OP_SHUTDOWN,
    op_shutdown,
    "io_uring.opcode.shutdown",
    34,
    "IORING_OP_SHUTDOWN",
    "5.11",
    "shutdown without shutdown(2)"
);
opcode!(
    OP_RENAMEAT,
    op_renameat,
    "io_uring.opcode.renameat",
    35,
    "IORING_OP_RENAMEAT",
    "5.11",
    "renames without renameat2(2)"
);
opcode!(
    OP_UNLINKAT,
    op_unlinkat,
    "io_uring.opcode.unlinkat",
    36,
    "IORING_OP_UNLINKAT",
    "5.11",
    "unlinks without unlinkat(2)"
);
opcode!(
    OP_MKDIRAT,
    op_mkdirat,
    "io_uring.opcode.mkdirat",
    37,
    "IORING_OP_MKDIRAT",
    "5.15",
    "mkdir without mkdirat(2)"
);
opcode!(
    OP_SYMLINKAT,
    op_symlinkat,
    "io_uring.opcode.symlinkat",
    38,
    "IORING_OP_SYMLINKAT",
    "5.15",
    "symlinks without symlinkat(2)"
);
opcode!(
    OP_LINKAT,
    op_linkat,
    "io_uring.opcode.linkat",
    39,
    "IORING_OP_LINKAT",
    "5.15",
    "hard links without linkat(2)"
);
opcode!(
    OP_MSG_RING,
    op_msg_ring,
    "io_uring.opcode.msg_ring",
    40,
    "IORING_OP_MSG_RING",
    "5.18",
    "messages and descriptors passed between rings"
);
opcode!(
    OP_FSETXATTR,
    op_fsetxattr,
    "io_uring.opcode.fsetxattr",
    41,
    "IORING_OP_FSETXATTR",
    "5.19",
    "fsetxattr without the syscall"
);
opcode!(
    OP_SETXATTR,
    op_setxattr,
    "io_uring.opcode.setxattr",
    42,
    "IORING_OP_SETXATTR",
    "5.19",
    "setxattr without the syscall"
);
opcode!(
    OP_FGETXATTR,
    op_fgetxattr,
    "io_uring.opcode.fgetxattr",
    43,
    "IORING_OP_FGETXATTR",
    "5.19",
    "fgetxattr without the syscall"
);
opcode!(
    OP_GETXATTR,
    op_getxattr,
    "io_uring.opcode.getxattr",
    44,
    "IORING_OP_GETXATTR",
    "5.19",
    "getxattr without the syscall"
);
opcode!(
    OP_SOCKET,
    op_socket,
    "io_uring.opcode.socket",
    45,
    "IORING_OP_SOCKET",
    "5.19",
    "socket creation without socket(2), any family"
);
opcode!(
    OP_URING_CMD,
    op_uring_cmd,
    "io_uring.opcode.uring_cmd",
    46,
    "IORING_OP_URING_CMD",
    "5.19",
    "driver passthrough commands (NVMe, ublk) without ioctl(2)"
);
opcode!(
    OP_SEND_ZC,
    op_send_zc,
    "io_uring.opcode.send_zc",
    47,
    "IORING_OP_SEND_ZC",
    "6.0",
    "zero-copy send"
);
opcode!(
    OP_SENDMSG_ZC,
    op_sendmsg_zc,
    "io_uring.opcode.sendmsg_zc",
    48,
    "IORING_OP_SENDMSG_ZC",
    "6.1",
    "zero-copy sendmsg"
);
opcode!(
    OP_READ_MULTISHOT,
    op_read_multishot,
    "io_uring.opcode.read_multishot",
    49,
    "IORING_OP_READ_MULTISHOT",
    "6.7",
    "multishot reads"
);
opcode!(
    OP_WAITID,
    op_waitid,
    "io_uring.opcode.waitid",
    50,
    "IORING_OP_WAITID",
    "6.7",
    "waitid without the syscall"
);
opcode!(
    OP_FUTEX_WAIT,
    op_futex_wait,
    "io_uring.opcode.futex_wait",
    51,
    "IORING_OP_FUTEX_WAIT",
    "6.7",
    "futex wait without futex(2)"
);
opcode!(
    OP_FUTEX_WAKE,
    op_futex_wake,
    "io_uring.opcode.futex_wake",
    52,
    "IORING_OP_FUTEX_WAKE",
    "6.7",
    "futex wake without futex(2)"
);
opcode!(
    OP_FUTEX_WAITV,
    op_futex_waitv,
    "io_uring.opcode.futex_waitv",
    53,
    "IORING_OP_FUTEX_WAITV",
    "6.7",
    "futex_waitv without the syscall"
);
opcode!(
    OP_FIXED_FD_INSTALL,
    op_fixed_fd_install,
    "io_uring.opcode.fixed_fd_install",
    54,
    "IORING_OP_FIXED_FD_INSTALL",
    "6.8",
    "a ring-registered descriptor installed into the process's table"
);
opcode!(
    OP_FTRUNCATE,
    op_ftruncate,
    "io_uring.opcode.ftruncate",
    55,
    "IORING_OP_FTRUNCATE",
    "6.9",
    "ftruncate without the syscall"
);
opcode!(
    OP_BIND,
    op_bind,
    "io_uring.opcode.bind",
    56,
    "IORING_OP_BIND",
    "6.11",
    "bind without bind(2)"
);
opcode!(
    OP_LISTEN,
    op_listen,
    "io_uring.opcode.listen",
    57,
    "IORING_OP_LISTEN",
    "6.11",
    "listen without listen(2)"
);
